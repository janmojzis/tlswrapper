#!/usr/bin/env python3

import argparse
import logging
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

TIMEOUT = 4
EARLY_EXIT_TIMEOUT = 1.0
WORKSPACE = Path(__file__).resolve().parent
LOGGER = logging.getLogger(__name__)
WRAPPER_EXECUTABLE = WORKSPACE / "tlswrapper-test"
CERT_PATH = WORKSPACE / "testcerts" / "okcert-ec-prime256v1-ec-prime256v1-ok.pem"
CHILD_SCRIPT = """
import os
import sys

os.close(5)
sys.stdin.buffer.read()
"""


class TestFailure(Exception):
    """Raised when a STARTTLS regression scenario fails."""

    pass


class TestStarttlsWrapper:
    """Manage one delayed-encryption wrapper process for regression tests."""

    def __init__(self, timeout: int) -> None:
        """Prepare the delayed-encryption test harness."""

        self.timeout = timeout
        self.proc: subprocess.Popen[bytes] | None = None

        if not WRAPPER_EXECUTABLE.exists():
            raise TestFailure("Missing tlswrapper-test binary; build it before running tests")
        if not CERT_PATH.exists():
            raise TestFailure(f"Missing test certificate: {CERT_PATH}")

    def __enter__(self) -> "TestStarttlsWrapper":
        """Return the active delayed-encryption test harness."""

        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        """Release resources when leaving the context manager."""

        self.close()

    def close(self) -> None:
        """Terminate the wrapper process group if it is still running."""

        if self.proc is not None and self.proc.poll() is None:
            try:
                LOGGER.debug("Terminating wrapper process group")
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=1)
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                LOGGER.warning("Wrapper process group did not terminate cleanly")

    def start_child_that_closes_control_pipe(self) -> None:
        """Start the wrapper with a child that closes fd 5 immediately."""

        env = os.environ.copy()
        env.update(
            {
                "TCPREMOTEIP": "1.2.3.4",
                "TCPREMOTEPORT": "1234",
                "TCPLOCALIP": "1.2.3.4",
                "TCPLOCALPORT": "1234",
            }
        )
        cmd = [
            "tlswrappernojail",
            "-Q",
            "-n",
            "-f",
            str(CERT_PATH),
            sys.executable,
            "-c",
            CHILD_SCRIPT,
        ]
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

    def wait_for_early_exit(self, timeout: float = EARLY_EXIT_TIMEOUT) -> int:
        """Wait briefly for the wrapper to exit on control-pipe EOF."""

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

        try:
            stdout, stderr = self.proc.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise TestFailure("Timed out while collecting wrapper outputs") from exc

        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )


def test_control_pipe_eof_before_starttls() -> None:
    """Verify control-pipe EOF before STARTTLS exits cleanly without hanging."""

    LOGGER.debug("Starting scenario: control_pipe_eof_before_starttls")
    with TestStarttlsWrapper(TIMEOUT) as test:
        test.start_child_that_closes_control_pipe()
        returncode = test.wait_for_early_exit()
        stdout_text, stderr_text = test.collect_output_after_exit()

    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_text:
        LOGGER.debug("Ignoring non-empty wrapper stdout: %r", stdout_text)
    LOGGER.debug("Finished scenario: control_pipe_eof_before_starttls")


TESTS: dict[str, Callable[[], None]] = {
    "control_pipe_eof_before_starttls": test_control_pipe_eof_before_starttls,
}


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument("tests", nargs="*", help="Test names to execute")
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
    """Run the selected delayed-encryption regression tests."""

    args = parse_args(sys.argv[1:] if argv is None else argv)
    configure_logging(args.debug)

    names = args.tests or list(TESTS.keys())

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
