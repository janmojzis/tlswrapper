#!/usr/bin/env python3

import argparse
import logging
import os
import select
import signal
import ssl
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

TIMEOUT = 4
EARLY_EXIT_TIMEOUT = 1.0
WORKSPACE = Path(__file__).resolve().parent
LOGGER = logging.getLogger(__name__)
WRAPPER_EXECUTABLE = WORKSPACE / "tlswrapper-test"
CERT_PATH = WORKSPACE / "testcerts" / "okcert-ec-prime256v1-ec-prime256v1-ok.pem"
DEFAULT_CHILD_LOG = WORKSPACE / "test-tlswrapper-child.log"
CHILD_CLOSES_CONTROL_PIPE = """
import os
import sys

os.close(5)
sys.stdin.buffer.read()
"""
CHILD_REPLY_AFTER_EOF = """
import os
import sys

log_path = os.environ["TLSWRAPPER_CHILD_LOG"]
data = sys.stdin.buffer.read()
with open(log_path, "w", encoding="utf-8") as handle:
    handle.write(f"received={data.decode('utf-8', errors='replace')}\\n")
    handle.write("saw_eof=yes\\n")

sys.stdout.buffer.write(b"reply-after-eof\\n")
sys.stdout.buffer.flush()
"""


class TestFailure(Exception):
    """Raised when a generic tlswrapper regression scenario fails."""

    pass


class TestTlswrapper:
    """Manage one generic `tlswrappernojail` process for regression tests."""

    def __init__(self, timeout: int, child_log_path: Path | None = None) -> None:
        """Prepare the generic tlswrapper test harness."""

        self.timeout = timeout
        self.child_log_path = child_log_path
        self.proc: subprocess.Popen[bytes] | None = None
        self.control_output = b""

        if not WRAPPER_EXECUTABLE.exists():
            raise TestFailure("Missing tlswrapper-test binary; build it before running tests")
        if not CERT_PATH.exists():
            raise TestFailure(f"Missing test certificate: {CERT_PATH}")

    def __enter__(self) -> "TestTlswrapper":
        """Return the active tlswrapper test harness."""

        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        """Release resources when leaving the context manager."""

        self.close()

    def start(self, child_script: str, *, delayed_encryption: bool = False) -> None:
        """Start the wrapper with a small inline Python child."""

        env = os.environ.copy()
        env.update(
            {
                "TCPREMOTEIP": "1.2.3.4",
                "TCPREMOTEPORT": "1234",
                "TCPLOCALIP": "1.2.3.4",
                "TCPLOCALPORT": "1234",
            }
        )
        if self.child_log_path is not None:
            if self.child_log_path.exists():
                self.child_log_path.unlink()
            env["TLSWRAPPER_CHILD_LOG"] = str(self.child_log_path)

        cmd = ["tlswrappernojail", "-Q"]
        if delayed_encryption:
            cmd.append("-n")
        cmd.extend(["-f", str(CERT_PATH), sys.executable, "-c", child_script])
        LOGGER.debug("Starting wrapper process: %s", " ".join(cmd))
        self.proc = subprocess.Popen(
            cmd,
            executable=str(WRAPPER_EXECUTABLE),
            cwd=WORKSPACE,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            preexec_fn=os.setsid,
        )

    def close(self) -> None:
        """Terminate the wrapper process group if it is still running."""

        if self.proc is not None and self.proc.poll() is None:
            try:
                LOGGER.debug("Terminating wrapper process group")
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=1)
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                LOGGER.warning("Wrapper process group did not terminate cleanly")

    def wait_for_early_exit(self, timeout: float = EARLY_EXIT_TIMEOUT) -> int:
        """Wait briefly for the wrapper to exit on delayed-encryption EOF."""

        if self.proc is None:
            raise TestFailure("Wrapper process has not been started")

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            returncode = self.proc.poll()
            if returncode is not None:
                LOGGER.debug("Wrapper exited early with rc=%s", returncode)
                return returncode
            time.sleep(0.05)

        raise TestFailure("Wrapper hung after child closed the control pipe")

    def collect_output_after_exit(self) -> tuple[str, str]:
        """Collect wrapper stdout and stderr after the process has exited."""

        if self.proc is None:
            raise TestFailure("Wrapper process has not been started")
        if self.proc.poll() is None:
            raise TestFailure("Wrapper is still running while collecting outputs")

        stdout = b""
        stderr = b""
        if self.proc.stdout is not None:
            try:
                stdout = self.proc.stdout.read()
            except OSError:
                stdout = b""
        if self.proc.stderr is not None:
            try:
                stderr = self.proc.stderr.read()
            except OSError:
                stderr = b""

        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )

    def wait_for_exit(self, expected_returncode: int = 0) -> tuple[str, str]:
        """Wait for wrapper exit and verify the return code."""

        if self.proc is None:
            raise TestFailure("Wrapper process has not been started")

        try:
            LOGGER.debug("Waiting for wrapper process to exit")
            returncode = self.proc.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise TestFailure("Wrapper did not exit in time") from exc

        stdout_text, stderr_text = self.collect_output_after_exit()
        if returncode != expected_returncode:
            raise TestFailure(
                f"Wrapper exited with {returncode}, expected {expected_returncode}: "
                f"{stderr_text.strip() or '<empty stderr>'}"
            )
        LOGGER.debug("Wrapper exited with rc=%s", returncode)
        return stdout_text, stderr_text

    def read_child_log(self) -> list[str]:
        """Read the optional child transcript log."""

        if self.child_log_path is None:
            raise TestFailure("Child log path is not configured")

        deadline = time.monotonic() + 1
        lines: list[str] = []
        while time.monotonic() < deadline:
            if self.child_log_path.exists():
                lines = self.child_log_path.read_text(encoding="utf-8").splitlines()
                if lines:
                    return lines
            time.sleep(0.05)

        if not self.child_log_path.exists():
            raise TestFailure("Child did not produce a transcript log")
        return self.child_log_path.read_text(encoding="utf-8").splitlines()


class TlsPipeClient:
    """Drive a TLS client over the wrapper stdin/stdout pipes."""

    def __init__(self, stdin: BinaryIO, stdout: BinaryIO, timeout: int) -> None:
        """Prepare a TLS client on top of process pipes."""

        self.stdin = stdin
        self.stdout = stdout
        self.timeout = timeout

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context.wrap_bio(
            self.incoming,
            self.outgoing,
            server_side=False,
            server_hostname="localhost",
        )

    def do_handshake(self) -> None:
        """Complete the TLS handshake with the wrapper."""

        while True:
            try:
                self.tls.do_handshake()
                self._flush_outgoing()
                return
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                self._feed_incoming()

    def write_plaintext(self, data: bytes) -> None:
        """Write plaintext bytes into the TLS session."""

        remaining = memoryview(data)
        while remaining:
            try:
                written = self.tls.write(remaining)
                remaining = remaining[written:]
                self._flush_outgoing()
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                self._feed_incoming()

    def read_plaintext_exact(self, size: int) -> bytes:
        """Read an exact amount of plaintext from the TLS session."""

        chunks = []
        total = 0

        while total < size:
            try:
                chunk = self.tls.read(size - total)
                if not chunk:
                    raise TestFailure("TLS client reached EOF before expected plaintext")
                chunks.append(chunk)
                total += len(chunk)
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                self._feed_incoming()
            except ssl.SSLEOFError as exc:
                raise TestFailure(
                    "TLS session ended before the expected plaintext arrived"
                ) from exc

        return b"".join(chunks)

    def transport_half_close(self) -> None:
        """Half-close the transport without sending a TLS close_notify."""

        self._flush_outgoing()
        self.stdin.close()

    def _flush_outgoing(self) -> None:
        while True:
            data = self.outgoing.read()
            if not data:
                return
            self.stdin.write(data)
            self.stdin.flush()

    def _feed_incoming(self) -> None:
        ready, _, _ = select.select([self.stdout], [], [], self.timeout)
        if not ready:
            raise TestFailure("Timed out waiting for TLS records from wrapper")

        data = os.read(self.stdout.fileno(), 65536)
        if not data:
            self.incoming.write_eof()
            return
        self.incoming.write(data)


def test_control_pipe_eof_before_starttls() -> None:
    """Verify control-pipe EOF before STARTTLS exits cleanly without hanging."""

    LOGGER.debug("Starting scenario: control_pipe_eof_before_starttls")
    with TestTlswrapper(TIMEOUT) as test:
        test.start(CHILD_CLOSES_CONTROL_PIPE, delayed_encryption=True)
        returncode = test.wait_for_early_exit()
        stdout_text, stderr_text = test.collect_output_after_exit()

    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_text:
        LOGGER.debug("Ignoring non-empty wrapper stdout: %r", stdout_text)
    LOGGER.debug("Finished scenario: control_pipe_eof_before_starttls")


def test_tls_reply_after_network_eof() -> None:
    """Verify wrapper forwards child reply even after TLS transport EOF."""

    LOGGER.debug("Starting scenario: tls_reply_after_network_eof")
    expected_reply = b"reply-after-eof\n"
    with TestTlswrapper(TIMEOUT, DEFAULT_CHILD_LOG) as test:
        test.start(CHILD_REPLY_AFTER_EOF)
        if test.proc is None or test.proc.stdin is None or test.proc.stdout is None:
            raise TestFailure("Wrapper stdio is not available")

        client = TlsPipeClient(test.proc.stdin, test.proc.stdout, TIMEOUT)
        client.do_handshake()
        client.write_plaintext(b"request-before-eof")
        client.transport_half_close()
        reply = client.read_plaintext_exact(len(expected_reply))
        _, stderr_text = test.wait_for_exit()
        child_log = test.read_child_log()

    if reply != expected_reply:
        raise TestFailure(f"Unexpected TLS reply: {reply!r}, expected {expected_reply!r}")
    if stderr_text.strip():
        LOGGER.debug("Ignoring non-empty wrapper stderr: %r", stderr_text)
    if child_log != ["received=request-before-eof", "saw_eof=yes"]:
        raise TestFailure(
            f"Unexpected child log: {child_log!r}, expected request receipt plus EOF"
        )
    LOGGER.debug("Finished scenario: tls_reply_after_network_eof")


TESTS: dict[str, Callable[[], None]] = {
    "control_pipe_eof_before_starttls": test_control_pipe_eof_before_starttls,
    "tls_reply_after_network_eof": test_tls_reply_after_network_eof,
}
# Keep the known-failing 0001 regression opt-in until the fix lands.
DEFAULT_TESTS = ["control_pipe_eof_before_starttls"]
ALL_TESTS = list(TESTS.keys())


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument("tests", nargs="*", help="Test names to execute")
    parser.add_argument(
        "--all-tests",
        action="store_true",
        help="Run all tests",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging",
    )
    return parser.parse_args(argv)


def configure_logging(debug: bool) -> None:
    """Configure application logging."""

    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")


def main(argv: list[str] | None = None) -> int:
    """Run the selected generic tlswrapper regression tests."""

    args = parse_args(sys.argv[1:] if argv is None else argv)
    configure_logging(args.debug)

    if args.tests:
        names = args.tests
    elif args.all_tests:
        names = ALL_TESTS
    else:
        names = DEFAULT_TESTS

    for name in names:
        test_fn = TESTS.get(name)
        if test_fn is None:
            LOGGER.error("Unknown test: %s", name)
            return 2

        LOGGER.info("Running %s", name)
        try:
            test_fn()
        except Exception as exc:
            LOGGER.error("%s: FAILED: %s", name, exc)
            return 1
        LOGGER.info("%s: OK", name)

    LOGGER.info("All tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
