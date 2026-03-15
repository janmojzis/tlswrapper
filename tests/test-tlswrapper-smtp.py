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
SMTP_MAX_LINE = 4096
SMTP_MAX_MAILFROM = 2048
SMTP_MAX_RCPTTO = 2048
SMTP_MAX_RCPTS = 256
SMTP_MAX_RCPTTODATA = 65536
WORKSPACE = Path(__file__).resolve().parent
LOGGER = logging.getLogger(__name__)
WRAPPER_PATH = WORKSPACE / "tlswrappernojail-smtp"


class TestFailure(Exception):
    """Raised when an SMTP test scenario fails."""

    pass


class TestSmtpWrapper:
    """Manage one fake SMTP child plus one `tlswrappernojail-smtp` process."""

    def __init__(self, timeout: int, child_log_path: Path) -> None:
        """Prepare the SMTP test harness."""

        self.timeout = timeout
        self.child_log_path = child_log_path
        self.proc: subprocess.Popen[bytes] | None = None
        self.control_output = b""

        if not WRAPPER_PATH.exists():
            raise TestFailure(
                "Missing tlswrappernojail-smtp symlink; create it before running tests"
            )

    def close(self) -> None:
        """Terminate the wrapper process."""

        if self.proc is not None and self.proc.poll() is None:
            try:
                LOGGER.debug("Terminating wrapper process group")
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=1)
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                LOGGER.warning("Wrapper process group did not terminate cleanly")

    def __enter__(self) -> "TestSmtpWrapper":
        """Return the active SMTP test harness."""

        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        """Release resources when leaving the context manager."""

        self.close()

    def run(
        self,
        session: bytes,
        with_control_pipe: bool = False,
    ) -> tuple[int, str, str, list[str]]:
        """Run one SMTP session and collect wrapper outputs."""

        cmd = [
            str(WRAPPER_PATH),
            "-q",
            "-t5",
            "-T3",
            sys.executable,
            str(WORKSPACE / "test-smtp-fake-child.py"),
            "--log",
            str(self.child_log_path),
        ]
        env = os.environ.copy()
        env["TCPREMOTEIP"] = "127.0.0.1"
        env["TCPREMOTEPORT"] = "2525"
        env["TCPLOCALIP"] = "127.0.0.1"
        env["TCPLOCALPORT"] = "25"
        self.control_output = b""

        control_read_fd: int | None = None
        control_write_fd: int | None = None
        saved_fd5: int | None = None
        if with_control_pipe:
            control_read_fd, control_write_fd = os.pipe()
            try:
                os.fstat(5)
            except OSError:
                saved_fd5 = None
            else:
                saved_fd5 = os.dup(5)
            os.dup2(control_write_fd, 5)
            os.set_inheritable(5, True)

        LOGGER.debug("Starting wrapper process: %s", " ".join(cmd))
        try:
            self.proc = subprocess.Popen(
                cmd,
                cwd=WORKSPACE,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=() if control_write_fd is None else (5,),
                preexec_fn=os.setsid,
            )
        finally:
            if control_write_fd is not None:
                os.close(control_write_fd)
            if with_control_pipe:
                if saved_fd5 is None:
                    os.close(5)
                else:
                    os.dup2(saved_fd5, 5)
                    os.close(saved_fd5)

        try:
            stdout, stderr = self.proc.communicate(session, timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            LOGGER.error("Wrapper did not finish in time")
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                stdout, stderr = self.proc.communicate(timeout=1)
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                stdout = b""
                stderr = b""
            raise TestFailure("Wrapper did not exit in time") from exc
        finally:
            if control_read_fd is not None:
                self.control_output = os.read(control_read_fd, 65536)
                os.close(control_read_fd)

        stdout_text = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")
        child_log = self.read_child_log()
        LOGGER.debug("Wrapper exited with rc=%s", self.proc.returncode)
        return self.proc.returncode, stdout_text, stderr_text, child_log

    def read_child_log(self) -> list[str]:
        """Read the fake-child transcript log."""

        deadline = time.monotonic() + 1
        lines: list[str] = []

        while time.monotonic() < deadline:
            if self.child_log_path.exists():
                lines = self.child_log_path.read_text(encoding="utf-8").splitlines()
                if lines:
                    return lines
            time.sleep(0.05)

        if not self.child_log_path.exists():
            raise TestFailure("Fake child did not produce a transcript log")
        return self.child_log_path.read_text(encoding="utf-8").splitlines()


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument("tests", nargs="*", help="Test names to execute")
    parser.add_argument(
        "--child-log",
        required=True,
        help="Path to the fake-child transcript log file",
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


def split_smtp_lines(text: str) -> list[str]:
    """Normalize SMTP output into line-oriented text."""

    return text.replace("\r\n", "\n").splitlines()


def test_short_session(child_log_path: Path) -> None:
    """Verify a short SMTP session succeeds end to end."""

    LOGGER.debug("Starting scenario: short_session")
    session = (
        b"EHLO client.example\r\n"
        b"MAIL FROM:<alice@example.com>\r\n"
        b"RCPT TO:<bob@example.com>\r\n"
        b"DATA\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"hello\r\n"
        b".\r\n"
        b"QUIT\r\n"
    )
    expected_stdout = [
        "220 ready",
        "250 ok",
        "250 ok",
        "250 ok",
        "354 go ahead",
        "250 queued",
        "221 bye",
    ]
    expected_child_log = [
        "reply 220 ready",
        "cmd EHLO client.example",
        "reply 250 ok",
        "cmd MAIL FROM:<alice@example.com>",
        "reply 250 ok",
        "cmd RCPT TO:<bob@example.com>",
        "reply 250 ok",
        "cmd DATA",
        "reply 354 go ahead",
        "data Subject: test",
        "data ",
        "data hello",
        "data-end",
        "reply 250 queued",
        "cmd QUIT",
        "reply 221 bye",
    ]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    if child_log != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log: {child_log!r}, expected {expected_child_log!r}"
        )
    LOGGER.debug("Finished scenario: short_session")


def test_line_too_long(child_log_path: Path) -> None:
    """Verify an overlong SMTP command line terminates the wrapper."""

    LOGGER.debug("Starting scenario: line_too_long")
    session = b"EHLO " + (b"x" * 4092) + b"\r\n"
    expected_stdout = ["220 ready"]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 111:
        raise TestFailure(
            f"Wrapper exited with {returncode}, expected 111: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    if not child_log:
        raise TestFailure("Fake child log is empty")
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if any(line.startswith("cmd ") for line in child_log):
        raise TestFailure(
            f"Fake child unexpectedly received a command before wrapper failed: {child_log!r}"
        )
    LOGGER.debug("Finished scenario: line_too_long")


def test_line_exact_limit(child_log_path: Path) -> None:
    """Verify an SMTP command line exactly at the limit still succeeds."""

    LOGGER.debug("Starting scenario: line_exact_limit")
    command = b"EHLO " + (b"x" * (SMTP_MAX_LINE - len(b"EHLO ") - 1))
    expected_stdout = ["220 ready", "250 ok", "221 bye"]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(command + b"\r\nQUIT\r\n")

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if not child_log[1].startswith("cmd EHLO "):
        raise TestFailure(f"Unexpected EHLO log line: {child_log[1]!r}")
    if len(child_log[1]) != len("cmd ") + len(command):
        raise TestFailure(
            f"Unexpected EHLO log line length: {len(child_log[1])!r}, expected {len('cmd ') + len(command)!r}"
        )
    if child_log[2:] != ["reply 250 ok", "cmd QUIT", "reply 221 bye"]:
        raise TestFailure(
            f"Unexpected fake child log tail: {child_log[2:]!r}, expected clean QUIT sequence"
        )
    LOGGER.debug("Finished scenario: line_exact_limit")


def test_mailfrom_too_long(child_log_path: Path) -> None:
    """Verify an overlong MAIL FROM value terminates the wrapper."""

    LOGGER.debug("Starting scenario: mailfrom_too_long")
    session = b"MAIL FROM:" + (b"x" * 2049) + b"\r\n"
    expected_stdout = ["220 ready"]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 111:
        raise TestFailure(
            f"Wrapper exited with {returncode}, expected 111: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    if not child_log:
        raise TestFailure("Fake child log is empty")
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if any(line.startswith("cmd ") for line in child_log):
        raise TestFailure(
            f"Fake child unexpectedly received a command before wrapper failed: {child_log!r}"
        )
    LOGGER.debug("Finished scenario: mailfrom_too_long")


def test_mailfrom_exact_limit(child_log_path: Path) -> None:
    """Verify a MAIL FROM value exactly at the limit still succeeds."""

    LOGGER.debug("Starting scenario: mailfrom_exact_limit")
    mailfrom = "x" * SMTP_MAX_MAILFROM
    session = f"MAIL FROM:{mailfrom}\r\nQUIT\r\n".encode("ascii")
    expected_stdout = ["220 ready", "250 ok", "221 bye"]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if not child_log[1].startswith("cmd MAIL FROM:"):
        raise TestFailure(f"Unexpected MAIL FROM log line: {child_log[1]!r}")
    if len(child_log[1]) != len("cmd MAIL FROM:") + SMTP_MAX_MAILFROM:
        raise TestFailure(
            f"Unexpected MAIL FROM log line length: {len(child_log[1])!r}, expected {len('cmd MAIL FROM:') + SMTP_MAX_MAILFROM!r}"
        )
    if child_log[2:] != ["reply 250 ok", "cmd QUIT", "reply 221 bye"]:
        raise TestFailure(
            f"Unexpected fake child log tail: {child_log[2:]!r}, expected clean QUIT sequence"
        )
    LOGGER.debug("Finished scenario: mailfrom_exact_limit")


def test_rcptto_too_long(child_log_path: Path) -> None:
    """Verify an overlong RCPT TO value terminates the wrapper."""

    LOGGER.debug("Starting scenario: rcptto_too_long")
    session = (
        b"MAIL FROM:<alice@example.com>\r\n"
        + b"RCPT TO:"
        + (b"x" * 2049)
        + b"\r\n"
    )
    expected_stdout = ["220 ready", "250 ok"]
    expected_child_log = [
        "reply 220 ready",
        "cmd MAIL FROM:<alice@example.com>",
        "reply 250 ok",
    ]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 111:
        raise TestFailure(
            f"Wrapper exited with {returncode}, expected 111: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    if child_log[: len(expected_child_log)] != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log prefix: {child_log!r}, expected prefix {expected_child_log!r}"
        )
    if any(line.startswith("cmd RCPT TO:") for line in child_log):
        raise TestFailure(
            f"Fake child unexpectedly received RCPT TO before wrapper failed: {child_log!r}"
        )
    LOGGER.debug("Finished scenario: rcptto_too_long")


def test_rcptto_exact_limit(child_log_path: Path) -> None:
    """Verify an RCPT TO value exactly at the limit still succeeds."""

    LOGGER.debug("Starting scenario: rcptto_exact_limit")
    rcptto = "y" * SMTP_MAX_RCPTTO
    session = (
        b"MAIL FROM:<alice@example.com>\r\n"
        + f"RCPT TO:{rcptto}\r\nQUIT\r\n".encode("ascii")
    )
    expected_stdout = ["220 ready", "250 ok", "250 ok", "221 bye"]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if child_log[1:3] != ["cmd MAIL FROM:<alice@example.com>", "reply 250 ok"]:
        raise TestFailure(
            f"Unexpected MAIL FROM log lines: {child_log[1:3]!r}"
        )
    if not child_log[3].startswith("cmd RCPT TO:"):
        raise TestFailure(f"Unexpected RCPT TO log line: {child_log[3]!r}")
    if len(child_log[3]) != len("cmd RCPT TO:") + SMTP_MAX_RCPTTO:
        raise TestFailure(
            f"Unexpected RCPT TO log line length: {len(child_log[3])!r}, expected {len('cmd RCPT TO:') + SMTP_MAX_RCPTTO!r}"
        )
    if child_log[4:] != ["reply 250 ok", "cmd QUIT", "reply 221 bye"]:
        raise TestFailure(
            f"Unexpected fake child log tail: {child_log[4:]!r}, expected clean QUIT sequence"
        )
    LOGGER.debug("Finished scenario: rcptto_exact_limit")


def test_too_many_rcpts(child_log_path: Path) -> None:
    """Verify the wrapper terminates when recipient count exceeds the limit."""

    LOGGER.debug("Starting scenario: too_many_rcpts")
    rcpt_lines = [
        f"RCPT TO:<r{i:03d}@example.com>\r\n".encode("ascii") for i in range(1, 258)
    ]
    session = b"MAIL FROM:<alice@example.com>\r\n" + b"".join(rcpt_lines)
    expected_stdout_len = 1 + 1 + 256

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 111:
        raise TestFailure(
            f"Wrapper exited with {returncode}, expected 111: {stderr_text.strip() or '<empty stderr>'}"
        )
    if len(stdout_lines) != expected_stdout_len:
        raise TestFailure(
            f"Unexpected wrapper stdout length: {len(stdout_lines)!r}, expected {expected_stdout_len!r}"
        )
    if stdout_lines[0] != "220 ready":
        raise TestFailure(
            f"Unexpected first wrapper stdout line: {stdout_lines[0]!r}, expected '220 ready'"
        )
    if stdout_lines[1] != "250 ok":
        raise TestFailure(
            f"Unexpected MAIL FROM reply: {stdout_lines[1]!r}, expected '250 ok'"
        )
    if any(line != "250 ok" for line in stdout_lines[2:]):
        raise TestFailure(
            f"Unexpected RCPT reply lines in wrapper stdout: {stdout_lines[2:]!r}"
        )

    cmd_rcpts = [line for line in child_log if line.startswith("cmd RCPT TO:")]
    reply_oks = [line for line in child_log if line == "reply 250 ok"]
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if child_log[1:3] != ["cmd MAIL FROM:<alice@example.com>", "reply 250 ok"]:
        raise TestFailure(
            f"Unexpected MAIL FROM log lines: {child_log[1:3]!r}"
        )
    if len(cmd_rcpts) != 256:
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected 256"
        )
    if len(reply_oks) != 257:
        raise TestFailure(
            f"Unexpected count of 'reply 250 ok' lines: {len(reply_oks)!r}, expected 257"
        )
    if cmd_rcpts[0] != "cmd RCPT TO:<r001@example.com>":
        raise TestFailure(
            f"Unexpected first RCPT log line: {cmd_rcpts[0]!r}"
        )
    if cmd_rcpts[-1] != "cmd RCPT TO:<r256@example.com>":
        raise TestFailure(
            f"Unexpected last forwarded RCPT log line: {cmd_rcpts[-1]!r}"
        )
    if any(line == "cmd RCPT TO:<r257@example.com>" for line in child_log):
        raise TestFailure(
            f"Fake child unexpectedly received RCPT 257: {child_log!r}"
        )
    LOGGER.debug("Finished scenario: too_many_rcpts")


def test_exact_rcpt_limit(child_log_path: Path) -> None:
    """Verify exactly the maximum number of recipients still succeeds."""

    LOGGER.debug("Starting scenario: exact_rcpt_limit")
    rcpt_lines = [
        f"RCPT TO:<r{i:03d}@example.com>\r\n".encode("ascii")
        for i in range(1, SMTP_MAX_RCPTS + 1)
    ]
    session = b"MAIL FROM:<alice@example.com>\r\n" + b"".join(rcpt_lines) + b"QUIT\r\n"
    expected_stdout_len = 1 + 1 + SMTP_MAX_RCPTS + 1

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if len(stdout_lines) != expected_stdout_len:
        raise TestFailure(
            f"Unexpected wrapper stdout length: {len(stdout_lines)!r}, expected {expected_stdout_len!r}"
        )
    if stdout_lines[0] != "220 ready":
        raise TestFailure(
            f"Unexpected first wrapper stdout line: {stdout_lines[0]!r}, expected '220 ready'"
        )
    if stdout_lines[-1] != "221 bye":
        raise TestFailure(
            f"Unexpected final wrapper stdout line: {stdout_lines[-1]!r}, expected '221 bye'"
        )
    if any(line != "250 ok" for line in stdout_lines[1:-1]):
        raise TestFailure(
            f"Unexpected non-250 reply before QUIT: {stdout_lines[1:-1]!r}"
        )

    cmd_rcpts = [line for line in child_log if line.startswith("cmd RCPT TO:")]
    reply_oks = [line for line in child_log if line == "reply 250 ok"]
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if child_log[1:3] != ["cmd MAIL FROM:<alice@example.com>", "reply 250 ok"]:
        raise TestFailure(
            f"Unexpected MAIL FROM log lines: {child_log[1:3]!r}"
        )
    if len(cmd_rcpts) != SMTP_MAX_RCPTS:
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected {SMTP_MAX_RCPTS}"
        )
    if len(reply_oks) != 1 + SMTP_MAX_RCPTS:
        raise TestFailure(
            f"Unexpected count of 'reply 250 ok' lines: {len(reply_oks)!r}, expected {1 + SMTP_MAX_RCPTS}"
        )
    if cmd_rcpts[0] != "cmd RCPT TO:<r001@example.com>":
        raise TestFailure(f"Unexpected first RCPT log line: {cmd_rcpts[0]!r}")
    if cmd_rcpts[-1] != f"cmd RCPT TO:<r{SMTP_MAX_RCPTS:03d}@example.com>":
        raise TestFailure(f"Unexpected final RCPT log line: {cmd_rcpts[-1]!r}")
    if child_log[-2:] != ["cmd QUIT", "reply 221 bye"]:
        raise TestFailure(
            f"Unexpected fake child log tail: {child_log[-2:]!r}, expected clean QUIT sequence"
        )
    LOGGER.debug("Finished scenario: exact_rcpt_limit")


def test_rcpttodata_too_large(child_log_path: Path) -> None:
    """Verify the wrapper terminates when aggregate RCPT storage exceeds the limit."""

    LOGGER.debug("Starting scenario: rcpttodata_too_large")
    rcpt_lines: list[bytes] = []
    forwarded_rcpts: list[str] = []

    for i in range(1, 34):
        local_part = f"r{i:03d}" + ("x" * 1982)
        address = f"<{local_part}@example.com>"
        rcpt_lines.append(f"RCPT TO:{address}\r\n".encode("ascii"))
        forwarded_rcpts.append(f"cmd RCPT TO:{address}")

    session = b"MAIL FROM:<alice@example.com>\r\n" + b"".join(rcpt_lines)
    expected_forwarded_count = 32
    expected_stdout_len = 1 + 1 + expected_forwarded_count

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 111:
        raise TestFailure(
            f"Wrapper exited with {returncode}, expected 111: {stderr_text.strip() or '<empty stderr>'}"
        )
    if len(stdout_lines) != expected_stdout_len:
        raise TestFailure(
            f"Unexpected wrapper stdout length: {len(stdout_lines)!r}, expected {expected_stdout_len!r}"
        )
    if stdout_lines[0] != "220 ready":
        raise TestFailure(
            f"Unexpected first wrapper stdout line: {stdout_lines[0]!r}, expected '220 ready'"
        )
    if stdout_lines[1] != "250 ok":
        raise TestFailure(
            f"Unexpected MAIL FROM reply: {stdout_lines[1]!r}, expected '250 ok'"
        )
    if any(line != "250 ok" for line in stdout_lines[2:]):
        raise TestFailure(
            f"Unexpected RCPT reply lines in wrapper stdout: {stdout_lines[2:]!r}"
        )

    cmd_rcpts = [line for line in child_log if line.startswith("cmd RCPT TO:")]
    reply_oks = [line for line in child_log if line == "reply 250 ok"]
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if child_log[1:3] != ["cmd MAIL FROM:<alice@example.com>", "reply 250 ok"]:
        raise TestFailure(
            f"Unexpected MAIL FROM log lines: {child_log[1:3]!r}"
        )
    if len(cmd_rcpts) != expected_forwarded_count:
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected {expected_forwarded_count}"
        )
    if len(reply_oks) != 1 + expected_forwarded_count:
        raise TestFailure(
            f"Unexpected count of 'reply 250 ok' lines: {len(reply_oks)!r}, expected {1 + expected_forwarded_count}"
        )
    if cmd_rcpts[0] != forwarded_rcpts[0]:
        raise TestFailure(
            f"Unexpected first RCPT log line: {cmd_rcpts[0]!r}"
        )
    if cmd_rcpts[-1] != forwarded_rcpts[expected_forwarded_count - 1]:
        raise TestFailure(
            f"Unexpected last forwarded RCPT log line: {cmd_rcpts[-1]!r}"
        )
    if forwarded_rcpts[expected_forwarded_count] in child_log:
        raise TestFailure(
            f"Fake child unexpectedly received overflow RCPT: {child_log!r}"
        )
    LOGGER.debug("Finished scenario: rcpttodata_too_large")


def test_rcpttodata_exact_limit(child_log_path: Path) -> None:
    """Verify aggregate RCPT storage exactly at the limit still succeeds."""

    LOGGER.debug("Starting scenario: rcpttodata_exact_limit")
    rcpt_lines: list[bytes] = []

    for i in range(1, 33):
        rcptto = f"r{i:03d}" + ("x" * (2047 - len(f"r{i:03d}")))
        rcpt_lines.append(f"RCPT TO:{rcptto}\r\n".encode("ascii"))

    session = b"MAIL FROM:<alice@example.com>\r\n" + b"".join(rcpt_lines) + b"QUIT\r\n"
    expected_stdout_len = 1 + 1 + len(rcpt_lines) + 1

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if len(stdout_lines) != expected_stdout_len:
        raise TestFailure(
            f"Unexpected wrapper stdout length: {len(stdout_lines)!r}, expected {expected_stdout_len!r}"
        )
    if stdout_lines[0] != "220 ready":
        raise TestFailure(
            f"Unexpected first wrapper stdout line: {stdout_lines[0]!r}, expected '220 ready'"
        )
    if stdout_lines[-1] != "221 bye":
        raise TestFailure(
            f"Unexpected final wrapper stdout line: {stdout_lines[-1]!r}, expected '221 bye'"
        )
    if any(line != "250 ok" for line in stdout_lines[1:-1]):
        raise TestFailure(
            f"Unexpected non-250 reply before QUIT: {stdout_lines[1:-1]!r}"
        )

    cmd_rcpts = [line for line in child_log if line.startswith("cmd RCPT TO:")]
    reply_oks = [line for line in child_log if line == "reply 250 ok"]
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if child_log[1:3] != ["cmd MAIL FROM:<alice@example.com>", "reply 250 ok"]:
        raise TestFailure(
            f"Unexpected MAIL FROM log lines: {child_log[1:3]!r}"
        )
    if len(cmd_rcpts) != len(rcpt_lines):
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected {len(rcpt_lines)}"
        )
    if len(reply_oks) != 1 + len(rcpt_lines):
        raise TestFailure(
            f"Unexpected count of 'reply 250 ok' lines: {len(reply_oks)!r}, expected {1 + len(rcpt_lines)}"
        )
    if len(cmd_rcpts[0]) != len("cmd RCPT TO:") + 2047:
        raise TestFailure(
            f"Unexpected first RCPT log line length: {len(cmd_rcpts[0])!r}, expected {len('cmd RCPT TO:') + 2047!r}"
        )
    if len(cmd_rcpts[-1]) != len("cmd RCPT TO:") + 2047:
        raise TestFailure(
            f"Unexpected last RCPT log line length: {len(cmd_rcpts[-1])!r}, expected {len('cmd RCPT TO:') + 2047!r}"
        )
    if child_log[-2:] != ["cmd QUIT", "reply 221 bye"]:
        raise TestFailure(
            f"Unexpected fake child log tail: {child_log[-2:]!r}, expected clean QUIT sequence"
        )
    LOGGER.debug("Finished scenario: rcpttodata_exact_limit")


def test_mail_resets_previous_rcpts(child_log_path: Path) -> None:
    """Verify a new MAIL FROM resets prior recipient state."""

    LOGGER.debug("Starting scenario: mail_resets_previous_rcpts")
    first_batch = [
        f"RCPT TO:<a{i:03d}@example.com>\r\n".encode("ascii") for i in range(1, 131)
    ]
    second_batch = [
        f"RCPT TO:<b{i:03d}@example.com>\r\n".encode("ascii") for i in range(1, 131)
    ]
    session = (
        b"MAIL FROM:<first@example.com>\r\n"
        + b"".join(first_batch)
        + b"MAIL FROM:<second@example.com>\r\n"
        + b"".join(second_batch)
        + b"QUIT\r\n"
    )
    expected_stdout_len = 1 + 1 + 130 + 1 + 130 + 1

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if len(stdout_lines) != expected_stdout_len:
        raise TestFailure(
            f"Unexpected wrapper stdout length: {len(stdout_lines)!r}, expected {expected_stdout_len!r}"
        )
    if stdout_lines[0] != "220 ready":
        raise TestFailure(
            f"Unexpected first wrapper stdout line: {stdout_lines[0]!r}, expected '220 ready'"
        )
    if stdout_lines[-1] != "221 bye":
        raise TestFailure(
            f"Unexpected final wrapper stdout line: {stdout_lines[-1]!r}, expected '221 bye'"
        )
    if any(line != "250 ok" for line in stdout_lines[1:-1]):
        raise TestFailure(
            f"Unexpected non-250 reply before QUIT: {stdout_lines[1:-1]!r}"
        )

    cmd_rcpts = [line for line in child_log if line.startswith("cmd RCPT TO:")]
    reply_oks = [line for line in child_log if line == "reply 250 ok"]
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if child_log[1:3] != ["cmd MAIL FROM:<first@example.com>", "reply 250 ok"]:
        raise TestFailure(
            f"Unexpected first MAIL FROM log lines: {child_log[1:3]!r}"
        )
    if "cmd MAIL FROM:<second@example.com>" not in child_log:
        raise TestFailure(f"Missing second MAIL FROM in fake child log: {child_log!r}")
    if len(cmd_rcpts) != 260:
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected 260"
        )
    if len(reply_oks) != 262:
        raise TestFailure(
            f"Unexpected count of 'reply 250 ok' lines: {len(reply_oks)!r}, expected 262"
        )
    if cmd_rcpts[0] != "cmd RCPT TO:<a001@example.com>":
        raise TestFailure(
            f"Unexpected first RCPT log line: {cmd_rcpts[0]!r}"
        )
    if cmd_rcpts[129] != "cmd RCPT TO:<a130@example.com>":
        raise TestFailure(
            f"Unexpected last first-batch RCPT log line: {cmd_rcpts[129]!r}"
        )
    if cmd_rcpts[130] != "cmd RCPT TO:<b001@example.com>":
        raise TestFailure(
            f"Unexpected first second-batch RCPT log line: {cmd_rcpts[130]!r}"
        )
    if cmd_rcpts[-1] != "cmd RCPT TO:<b130@example.com>":
        raise TestFailure(
            f"Unexpected final RCPT log line: {cmd_rcpts[-1]!r}"
        )
    if "cmd QUIT" not in child_log or child_log[-1] != "reply 221 bye":
        raise TestFailure(f"Missing clean QUIT sequence in fake child log: {child_log!r}")
    LOGGER.debug("Finished scenario: mail_resets_previous_rcpts")


def test_data_resets_envelope(child_log_path: Path) -> None:
    """Verify a successful DATA resets recipient state for the next message."""

    LOGGER.debug("Starting scenario: data_resets_envelope")
    first_batch = [
        f"RCPT TO:<c{i:03d}@example.com>\r\n".encode("ascii") for i in range(1, 131)
    ]
    second_batch = [
        f"RCPT TO:<d{i:03d}@example.com>\r\n".encode("ascii") for i in range(1, 131)
    ]
    session = (
        b"MAIL FROM:<first@example.com>\r\n"
        + b"".join(first_batch)
        + b"DATA\r\n"
        + b"first message\r\n"
        + b".\r\n"
        + b"MAIL FROM:<second@example.com>\r\n"
        + b"".join(second_batch)
        + b"DATA\r\n"
        + b"second message\r\n"
        + b".\r\n"
        + b"QUIT\r\n"
    )
    expected_stdout_len = 1 + 1 + 130 + 1 + 1 + 1 + 130 + 1 + 1 + 1

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if len(stdout_lines) != expected_stdout_len:
        raise TestFailure(
            f"Unexpected wrapper stdout length: {len(stdout_lines)!r}, expected {expected_stdout_len!r}"
        )
    if stdout_lines[0] != "220 ready":
        raise TestFailure(
            f"Unexpected first wrapper stdout line: {stdout_lines[0]!r}, expected '220 ready'"
        )
    if stdout_lines[-1] != "221 bye":
        raise TestFailure(
            f"Unexpected final wrapper stdout line: {stdout_lines[-1]!r}, expected '221 bye'"
        )
    if stdout_lines.count("354 go ahead") != 2:
        raise TestFailure(
            f"Unexpected DATA prompt count: {stdout_lines.count('354 go ahead')!r}, expected 2"
        )
    if stdout_lines.count("250 queued") != 2:
        raise TestFailure(
            f"Unexpected queued reply count: {stdout_lines.count('250 queued')!r}, expected 2"
        )
    if any(line not in {"220 ready", "250 ok", "354 go ahead", "250 queued", "221 bye"} for line in stdout_lines):
        raise TestFailure(f"Unexpected wrapper stdout lines: {stdout_lines!r}")

    cmd_rcpts = [line for line in child_log if line.startswith("cmd RCPT TO:")]
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if "cmd MAIL FROM:<first@example.com>" not in child_log:
        raise TestFailure(f"Missing first MAIL FROM in fake child log: {child_log!r}")
    if "cmd MAIL FROM:<second@example.com>" not in child_log:
        raise TestFailure(f"Missing second MAIL FROM in fake child log: {child_log!r}")
    if len(cmd_rcpts) != 260:
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected 260"
        )
    if cmd_rcpts[0] != "cmd RCPT TO:<c001@example.com>":
        raise TestFailure(
            f"Unexpected first RCPT log line: {cmd_rcpts[0]!r}"
        )
    if cmd_rcpts[129] != "cmd RCPT TO:<c130@example.com>":
        raise TestFailure(
            f"Unexpected last first-batch RCPT log line: {cmd_rcpts[129]!r}"
        )
    if cmd_rcpts[130] != "cmd RCPT TO:<d001@example.com>":
        raise TestFailure(
            f"Unexpected first second-batch RCPT log line: {cmd_rcpts[130]!r}"
        )
    if cmd_rcpts[-1] != "cmd RCPT TO:<d130@example.com>":
        raise TestFailure(
            f"Unexpected final RCPT log line: {cmd_rcpts[-1]!r}"
        )
    if child_log.count("cmd DATA") != 2:
        raise TestFailure(
            f"Unexpected DATA command count in fake child log: {child_log.count('cmd DATA')!r}, expected 2"
        )
    if child_log.count("data first message") != 1:
        raise TestFailure(
            f"Missing first message body in fake child log: {child_log!r}"
        )
    if child_log.count("data second message") != 1:
        raise TestFailure(
            f"Missing second message body in fake child log: {child_log!r}"
        )
    if child_log.count("data-end") != 2:
        raise TestFailure(
            f"Unexpected DATA termination count in fake child log: {child_log.count('data-end')!r}, expected 2"
        )
    if "cmd QUIT" not in child_log or child_log[-1] != "reply 221 bye":
        raise TestFailure(f"Missing clean QUIT sequence in fake child log: {child_log!r}")
    LOGGER.debug("Finished scenario: data_resets_envelope")


def test_starttls_unavailable_rejected(child_log_path: Path) -> None:
    """Verify STARTTLS is rejected when no control pipe is present."""

    LOGGER.debug("Starting scenario: starttls_unavailable_rejected")
    session = b"STARTTLS\r\nQUIT\r\n"
    expected_stdout = [
        "220 ready",
        "502 unimplemented (#5.5.1)",
        "221 bye",
    ]
    expected_child_log = [
        "reply 220 ready",
        "cmd QUIT",
        "reply 221 bye",
    ]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    if child_log != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log: {child_log!r}, expected {expected_child_log!r}"
        )
    LOGGER.debug("Finished scenario: starttls_unavailable_rejected")


def test_starttls_available_advertised(child_log_path: Path) -> None:
    """Verify EHLO advertises STARTTLS when control fd 5 exists."""

    LOGGER.debug("Starting scenario: starttls_available_advertised")
    session = b"EHLO client.example\r\nQUIT\r\n"
    expected_stdout = [
        "220 ready",
        "250-ok",
        "250 STARTTLS",
        "221 bye",
    ]
    expected_child_log = [
        "reply 220 ready",
        "cmd EHLO client.example",
        "reply 250 ok",
        "cmd QUIT",
        "reply 221 bye",
    ]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(
            session,
            with_control_pipe=True,
        )

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    if child_log != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log: {child_log!r}, expected {expected_child_log!r}"
        )
    LOGGER.debug("Finished scenario: starttls_available_advertised")


def test_starttls_control_pipe_banner(child_log_path: Path) -> None:
    """Verify STARTTLS writes its banner to fd 5 and sends internal RSET."""

    LOGGER.debug("Starting scenario: starttls_control_pipe_banner")
    session = b"EHLO client.example\r\nSTARTTLS\r\nQUIT\r\n"
    expected_stdout = [
        "220 ready",
        "250-ok",
        "250 STARTTLS",
        "221 bye",
    ]
    expected_control_output = b"220 ready to start TLS (#2.0.0)\r\n"
    expected_child_log = [
        "reply 220 ready",
        "cmd EHLO client.example",
        "reply 250 ok",
        "cmd RSET",
        "reply 250 reset",
        "cmd QUIT",
        "reply 221 bye",
    ]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(
            session,
            with_control_pipe=True,
        )
        control_output = test.control_output

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    if control_output != expected_control_output:
        raise TestFailure(
            f"Unexpected control-pipe output: {control_output!r}, expected {expected_control_output!r}"
        )
    if child_log != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log: {child_log!r}, expected {expected_child_log!r}"
        )
    LOGGER.debug("Finished scenario: starttls_control_pipe_banner")


def test_starttls_short_session(child_log_path: Path) -> None:
    """Verify a short SMTP session succeeds after STARTTLS."""

    LOGGER.debug("Starting scenario: starttls_short_session")
    session = (
        b"EHLO client.example\r\n"
        b"STARTTLS\r\n"
        b"MAIL FROM:<alice@example.com>\r\n"
        b"RCPT TO:<bob@example.com>\r\n"
        b"DATA\r\n"
        b"Subject: starttls test\r\n"
        b"\r\n"
        b"hello over starttls\r\n"
        b".\r\n"
        b"QUIT\r\n"
    )
    expected_stdout = [
        "220 ready",
        "250-ok",
        "250 STARTTLS",
        "250 ok",
        "250 ok",
        "354 go ahead",
        "250 queued",
        "221 bye",
    ]
    expected_control_output = b"220 ready to start TLS (#2.0.0)\r\n"
    expected_child_log = [
        "reply 220 ready",
        "cmd EHLO client.example",
        "reply 250 ok",
        "cmd RSET",
        "reply 250 reset",
        "cmd MAIL FROM:<alice@example.com>",
        "reply 250 ok",
        "cmd RCPT TO:<bob@example.com>",
        "reply 250 ok",
        "cmd DATA",
        "reply 354 go ahead",
        "data Subject: starttls test",
        "data ",
        "data hello over starttls",
        "data-end",
        "reply 250 queued",
        "cmd QUIT",
        "reply 221 bye",
    ]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(
            session,
            with_control_pipe=True,
        )
        control_output = test.control_output

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    if control_output != expected_control_output:
        raise TestFailure(
            f"Unexpected control-pipe output: {control_output!r}, expected {expected_control_output!r}"
        )
    if child_log != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log: {child_log!r}, expected {expected_child_log!r}"
        )
    LOGGER.debug("Finished scenario: starttls_short_session")


def test_starttls_resets_envelope(child_log_path: Path) -> None:
    """Verify STARTTLS resets envelope state via the internal RSET."""

    LOGGER.debug("Starting scenario: starttls_resets_envelope")
    first_batch = [
        f"RCPT TO:<e{i:03d}@example.com>\r\n".encode("ascii") for i in range(1, 131)
    ]
    second_batch = [
        f"RCPT TO:<f{i:03d}@example.com>\r\n".encode("ascii") for i in range(1, 131)
    ]
    session = (
        b"EHLO client.example\r\n"
        + b"MAIL FROM:<reset@example.com>\r\n"
        + b"".join(first_batch)
        + b"STARTTLS\r\n"
        + b"".join(second_batch)
        + b"DATA\r\n"
        + b"post-starttls message\r\n"
        + b".\r\n"
        + b"QUIT\r\n"
    )
    expected_control_output = b"220 ready to start TLS (#2.0.0)\r\n"
    expected_stdout_len = 1 + 2 + 1 + 130 + 130 + 1 + 1 + 1

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(
            session,
            with_control_pipe=True,
        )
        control_output = test.control_output

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if len(stdout_lines) != expected_stdout_len:
        raise TestFailure(
            f"Unexpected wrapper stdout length: {len(stdout_lines)!r}, expected {expected_stdout_len!r}"
        )
    if stdout_lines[0] != "220 ready":
        raise TestFailure(
            f"Unexpected first wrapper stdout line: {stdout_lines[0]!r}, expected '220 ready'"
        )
    if stdout_lines[1:3] != ["250-ok", "250 STARTTLS"]:
        raise TestFailure(
            f"Unexpected EHLO reply lines: {stdout_lines[1:3]!r}, expected ['250-ok', '250 STARTTLS']"
        )
    if stdout_lines[-1] != "221 bye":
        raise TestFailure(
            f"Unexpected final wrapper stdout line: {stdout_lines[-1]!r}, expected '221 bye'"
        )
    if stdout_lines.count("354 go ahead") != 1:
        raise TestFailure(
            f"Unexpected DATA prompt count: {stdout_lines.count('354 go ahead')!r}, expected 1"
        )
    if stdout_lines.count("250 queued") != 1:
        raise TestFailure(
            f"Unexpected queued reply count: {stdout_lines.count('250 queued')!r}, expected 1"
        )
    if any(line not in {"220 ready", "250-ok", "250 STARTTLS", "250 ok", "354 go ahead", "250 queued", "221 bye"} for line in stdout_lines):
        raise TestFailure(f"Unexpected wrapper stdout lines: {stdout_lines!r}")
    if control_output != expected_control_output:
        raise TestFailure(
            f"Unexpected control-pipe output: {control_output!r}, expected {expected_control_output!r}"
        )

    cmd_rcpts = [line for line in child_log if line.startswith("cmd RCPT TO:")]
    reply_oks = [line for line in child_log if line == "reply 250 ok"]
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if child_log[1:5] != [
        "cmd EHLO client.example",
        "reply 250 ok",
        "cmd MAIL FROM:<reset@example.com>",
        "reply 250 ok",
    ]:
        raise TestFailure(
            f"Unexpected initial fake child log lines: {child_log[1:5]!r}"
        )
    if child_log.count("cmd RSET") != 1 or child_log.count("reply 250 reset") != 1:
        raise TestFailure(
            f"Unexpected internal RSET sequence count in fake child log: {child_log!r}"
        )
    if len(cmd_rcpts) != 260:
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected 260"
        )
    if len(reply_oks) != 1 + 1 + 260:
        raise TestFailure(
            f"Unexpected count of 'reply 250 ok' lines: {len(reply_oks)!r}, expected 262"
        )
    if cmd_rcpts[0] != "cmd RCPT TO:<e001@example.com>":
        raise TestFailure(
            f"Unexpected first RCPT log line: {cmd_rcpts[0]!r}"
        )
    if cmd_rcpts[129] != "cmd RCPT TO:<e130@example.com>":
        raise TestFailure(
            f"Unexpected last first-batch RCPT log line: {cmd_rcpts[129]!r}"
        )
    if cmd_rcpts[130] != "cmd RCPT TO:<f001@example.com>":
        raise TestFailure(
            f"Unexpected first second-batch RCPT log line: {cmd_rcpts[130]!r}"
        )
    if cmd_rcpts[-1] != "cmd RCPT TO:<f130@example.com>":
        raise TestFailure(
            f"Unexpected final RCPT log line: {cmd_rcpts[-1]!r}"
        )
    if child_log.count("cmd DATA") != 1:
        raise TestFailure(
            f"Unexpected DATA command count in fake child log: {child_log.count('cmd DATA')!r}, expected 1"
        )
    if child_log.count("data post-starttls message") != 1:
        raise TestFailure(
            f"Missing post-STARTTLS message body in fake child log: {child_log!r}"
        )
    if child_log.count("data-end") != 1:
        raise TestFailure(
            f"Unexpected DATA termination count in fake child log: {child_log.count('data-end')!r}, expected 1"
        )
    if "cmd QUIT" not in child_log or child_log[-1] != "reply 221 bye":
        raise TestFailure(f"Missing clean QUIT sequence in fake child log: {child_log!r}")
    LOGGER.debug("Finished scenario: starttls_resets_envelope")


TESTS: dict[str, Callable[[Path], None]] = {
    "data_resets_envelope": test_data_resets_envelope,
    "exact_rcpt_limit": test_exact_rcpt_limit,
    "line_too_long": test_line_too_long,
    "line_exact_limit": test_line_exact_limit,
    "mailfrom_exact_limit": test_mailfrom_exact_limit,
    "mailfrom_too_long": test_mailfrom_too_long,
    "mail_resets_previous_rcpts": test_mail_resets_previous_rcpts,
    "rcpttodata_exact_limit": test_rcpttodata_exact_limit,
    "rcpttodata_too_large": test_rcpttodata_too_large,
    "rcptto_exact_limit": test_rcptto_exact_limit,
    "rcptto_too_long": test_rcptto_too_long,
    "short_session": test_short_session,
    "starttls_available_advertised": test_starttls_available_advertised,
    "starttls_control_pipe_banner": test_starttls_control_pipe_banner,
    "starttls_short_session": test_starttls_short_session,
    "starttls_resets_envelope": test_starttls_resets_envelope,
    "starttls_unavailable_rejected": test_starttls_unavailable_rejected,
    "too_many_rcpts": test_too_many_rcpts,
}


def main(argv: list[str] | None = None) -> int:
    """Run the selected SMTP wrapper tests."""

    args = parse_args(sys.argv[1:] if argv is None else argv)
    configure_logging(args.debug)
    child_log_path = Path(args.child_log)

    names = args.tests or list(TESTS.keys())

    for name in names:
        test_fn = TESTS.get(name)
        if test_fn is None:
            LOGGER.error("Unknown test: %s", name)
            return 2

        LOGGER.info("Running %s", name)
        try:
            test_fn(child_log_path)
        except Exception as exc:
            LOGGER.error("%s: FAILED: %s", name, exc)
            return 1
        LOGGER.info("%s: OK", name)

    LOGGER.info("All tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
