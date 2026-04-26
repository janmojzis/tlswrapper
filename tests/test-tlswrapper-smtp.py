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
STARTTLS_SIGNAL_REQUEST = b"\x00"
STARTTLS_SIGNAL_ACK = b"\x00"


class TestFailure(Exception):
    """Raised when an SMTP test scenario fails."""

    pass


def step(msg: str) -> None:
    """Print an indented test step."""
    print(f"  {msg}", flush=True)


def step_ok(label: str, detail: str = "") -> None:
    """Print an indented test step that passed."""
    suffix = f" {detail}" if detail else ""
    step(f"{label}:{suffix} ok")


def move_fd_away_from_reserved(fd: int) -> int:
    """Duplicate a pipe endpoint away from reserved control descriptors."""

    if fd not in {5, 6}:
        return fd
    moved = os.dup(fd)
    os.close(fd)
    return moved


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
        with_control_ack: bool | None = None,
        auto_ack: bool = True,
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
        if with_control_ack is None:
            with_control_ack = with_control_pipe

        control_read_fd: int | None = None
        control_write_fd: int | None = None
        ack_read_fd: int | None = None
        ack_write_fd: int | None = None
        saved_fd5: int | None = None
        saved_fd6: int | None = None
        if with_control_pipe:
            control_read_fd, control_write_fd = os.pipe()
            control_read_fd = move_fd_away_from_reserved(control_read_fd)
            control_write_fd = move_fd_away_from_reserved(control_write_fd)
            try:
                os.fstat(5)
            except OSError:
                saved_fd5 = None
            else:
                saved_fd5 = os.dup(5)
            try:
                os.fstat(6)
            except OSError:
                saved_fd6 = None
            else:
                saved_fd6 = os.dup(6)
            os.dup2(control_write_fd, 5)
            os.set_inheritable(5, True)
        if with_control_ack:
            ack_read_fd, ack_write_fd = os.pipe()
            ack_read_fd = move_fd_away_from_reserved(ack_read_fd)
            ack_write_fd = move_fd_away_from_reserved(ack_write_fd)
            if saved_fd6 is None:
                try:
                    os.fstat(6)
                except OSError:
                    saved_fd6 = None
                else:
                    saved_fd6 = os.dup(6)
            os.dup2(ack_read_fd, 6)
            os.set_inheritable(6, True)

        LOGGER.debug("Starting wrapper process: %s", " ".join(cmd))
        try:
            self.proc = subprocess.Popen(
                cmd,
                cwd=WORKSPACE,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=tuple(fd for fd, enabled in ((5, with_control_pipe), (6, with_control_ack)) if enabled),
                preexec_fn=os.setsid,
            )
            if ack_write_fd is not None and auto_ack:
                os.write(ack_write_fd, STARTTLS_SIGNAL_ACK)
        finally:
            if control_write_fd is not None:
                os.close(control_write_fd)
            if ack_read_fd is not None:
                os.close(ack_read_fd)
            if ack_write_fd is not None:
                os.close(ack_write_fd)
            if with_control_pipe:
                if saved_fd5 is None:
                    os.close(5)
                else:
                    os.dup2(saved_fd5, 5)
                    os.close(saved_fd5)
            if with_control_ack:
                if saved_fd6 is None:
                    os.close(6)
                else:
                    os.dup2(saved_fd6, 6)
                    os.close(saved_fd6)

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
        stdout_text = normalize_logid_suffix(stdout_text)
        if self.control_output:
            self.control_output = normalize_logid_suffix(
                self.control_output.decode("utf-8", errors="replace")
            ).encode("utf-8")
        child_log = self.read_child_log()
        LOGGER.debug("Wrapper exited with rc=%s", self.proc.returncode)
        return self.proc.returncode, stdout_text, stderr_text, child_log

    def read_child_log(self) -> list[str]:
        """Read the fake-child transcript log."""

        deadline = time.monotonic() + 1
        lines: list[str] = []
        previous: list[str] | None = None

        while time.monotonic() < deadline:
            if self.child_log_path.exists():
                lines = self.child_log_path.read_text(encoding="utf-8").splitlines()
                if lines and lines == previous:
                    return lines
                previous = lines
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
    return parser.parse_args(argv)


def normalize_logid_suffix(text: str) -> str:
    """Normalize SMTP output by stripping trailing `` [logid]`` suffixes."""

    normalized: list[str] = []

    for line in text.splitlines(keepends=True):
        ending = ""
        body = line

        if body.endswith("\r\n"):
            ending = "\r\n"
            body = body[:-2]
        elif body.endswith("\n"):
            ending = "\n"
            body = body[:-1]

        proc = subprocess.run(
            ["sed", "-E", r"s/ \[[[:alnum:]]+\]$//"],
            input=body,
            text=True,
            capture_output=True,
            check=True,
        )
        normalized.append(proc.stdout + ending)

    return "".join(normalized)


def split_smtp_lines(text: str) -> list[str]:
    """Normalize SMTP output into line-oriented text."""

    return text.replace("\r\n", "\n").splitlines()


def test_short_session(child_log_path: Path) -> None:
    """Verify a short SMTP session succeeds end to end."""

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
    step_ok("exit", str(returncode))
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    step_ok("stdout", f"{len(stdout_lines)} lines")
    if child_log != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log: {child_log!r}, expected {expected_child_log!r}"
        )
    step_ok("childlog", f"{len(child_log)} lines")


def test_line_too_long(child_log_path: Path) -> None:
    """Verify an overlong SMTP command line terminates the wrapper."""

    session = b"EHLO " + (b"x" * 4092) + b"\r\n"
    expected_stdout = ["220 ready"]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 111:
        raise TestFailure(
            f"Wrapper exited with {returncode}, expected 111: {stderr_text.strip() or '<empty stderr>'}"
        )
    step_ok("exit", "111")
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    step_ok("stdout", repr(expected_stdout))
    if not child_log:
        raise TestFailure("Fake child log is empty")
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    step_ok("childlog", "starts with 'reply 220 ready'")
    if any(line.startswith("cmd ") for line in child_log):
        raise TestFailure(
            f"Fake child unexpectedly received a command before wrapper failed: {child_log!r}"
        )
    step_ok("childlog", "no cmd forwarded")


def test_line_exact_limit(child_log_path: Path) -> None:
    """Verify an SMTP command line exactly at the limit still succeeds."""

    command = b"EHLO " + (b"x" * (SMTP_MAX_LINE - len(b"EHLO ") - 1))
    expected_stdout = ["220 ready", "250 ok", "221 bye"]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(command + b"\r\nQUIT\r\n")

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    step_ok("exit", str(returncode))
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    step_ok("stdout", f"{len(stdout_lines)} lines")
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
    step_ok("childlog", f"EHLO line length {len(child_log[1])}")
    if child_log[2:] != ["reply 250 ok", "cmd QUIT", "reply 221 bye"]:
        raise TestFailure(
            f"Unexpected fake child log tail: {child_log[2:]!r}, expected clean QUIT sequence"
        )
    step_ok("childlog", "clean QUIT")


def test_mailfrom_too_long(child_log_path: Path) -> None:
    """Verify an overlong MAIL FROM value terminates the wrapper."""

    session = b"MAIL FROM:" + (b"x" * 2049) + b"\r\n"
    expected_stdout = ["220 ready"]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(session)

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 111:
        raise TestFailure(
            f"Wrapper exited with {returncode}, expected 111: {stderr_text.strip() or '<empty stderr>'}"
        )
    step_ok("exit", "111")
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    step_ok("stdout", repr(expected_stdout))
    if not child_log:
        raise TestFailure("Fake child log is empty")
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    step_ok("childlog", "starts with 'reply 220 ready'")
    if any(line.startswith("cmd ") for line in child_log):
        raise TestFailure(
            f"Fake child unexpectedly received a command before wrapper failed: {child_log!r}"
        )
    step_ok("childlog", "no cmd forwarded")


def test_mailfrom_exact_limit(child_log_path: Path) -> None:
    """Verify a MAIL FROM value exactly at the limit still succeeds."""

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
    step_ok("exit", str(returncode))
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    step_ok("stdout", f"{len(stdout_lines)} lines")
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
    step_ok("childlog", f"MAIL FROM line length {len(child_log[1])}")
    if child_log[2:] != ["reply 250 ok", "cmd QUIT", "reply 221 bye"]:
        raise TestFailure(
            f"Unexpected fake child log tail: {child_log[2:]!r}, expected clean QUIT sequence"
        )
    step_ok("childlog", "clean QUIT")


def test_rcptto_too_long(child_log_path: Path) -> None:
    """Verify an overlong RCPT TO value terminates the wrapper."""

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
    step_ok("exit", "111")
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    step_ok("stdout", repr(expected_stdout))
    if child_log[: len(expected_child_log)] != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log prefix: {child_log!r}, expected prefix {expected_child_log!r}"
        )
    step_ok("childlog", f"{len(expected_child_log)}-line prefix")
    if any(line.startswith("cmd RCPT TO:") for line in child_log):
        raise TestFailure(
            f"Fake child unexpectedly received RCPT TO before wrapper failed: {child_log!r}"
        )
    step_ok("childlog", "no RCPT TO forwarded")


def test_rcptto_exact_limit(child_log_path: Path) -> None:
    """Verify an RCPT TO value exactly at the limit still succeeds."""

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
    step_ok("exit", str(returncode))
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    step_ok("stdout", f"{len(stdout_lines)} lines")
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if child_log[1:3] != ["cmd MAIL FROM:<alice@example.com>", "reply 250 ok"]:
        raise TestFailure(
            f"Unexpected MAIL FROM log lines: {child_log[1:3]!r}"
        )
    step_ok("childlog", "MAIL FROM")
    if not child_log[3].startswith("cmd RCPT TO:"):
        raise TestFailure(f"Unexpected RCPT TO log line: {child_log[3]!r}")
    if len(child_log[3]) != len("cmd RCPT TO:") + SMTP_MAX_RCPTTO:
        raise TestFailure(
            f"Unexpected RCPT TO log line length: {len(child_log[3])!r}, expected {len('cmd RCPT TO:') + SMTP_MAX_RCPTTO!r}"
        )
    step_ok("childlog", f"RCPT TO line length {len(child_log[3])}")
    if child_log[4:] != ["reply 250 ok", "cmd QUIT", "reply 221 bye"]:
        raise TestFailure(
            f"Unexpected fake child log tail: {child_log[4:]!r}, expected clean QUIT sequence"
        )
    step_ok("childlog", "clean QUIT")


def test_too_many_rcpts(child_log_path: Path) -> None:
    """Verify the wrapper terminates when recipient count exceeds the limit."""

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
    step_ok("exit", "111")
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
    step_ok("stdout", f"{len(stdout_lines)} lines")

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
    step_ok("childlog", "MAIL FROM")
    if len(cmd_rcpts) != 256:
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected 256"
        )
    if len(reply_oks) != 257:
        raise TestFailure(
            f"Unexpected count of 'reply 250 ok' lines: {len(reply_oks)!r}, expected 257"
        )
    step_ok("childlog", "256 RCPT forwarded")
    if cmd_rcpts[0] != "cmd RCPT TO:<r001@example.com>":
        raise TestFailure(
            f"Unexpected first RCPT log line: {cmd_rcpts[0]!r}"
        )
    if cmd_rcpts[-1] != "cmd RCPT TO:<r256@example.com>":
        raise TestFailure(
            f"Unexpected last forwarded RCPT log line: {cmd_rcpts[-1]!r}"
        )
    step_ok("childlog", "first/last RCPT")
    if any(line == "cmd RCPT TO:<r257@example.com>" for line in child_log):
        raise TestFailure(
            f"Fake child unexpectedly received RCPT 257: {child_log!r}"
        )
    step_ok("childlog", "overflow RCPT not forwarded")


def test_exact_rcpt_limit(child_log_path: Path) -> None:
    """Verify exactly the maximum number of recipients still succeeds."""

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
    step_ok("exit", str(returncode))
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
    step_ok("stdout", f"{len(stdout_lines)} lines")

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
    step_ok("childlog", "MAIL FROM")
    if len(cmd_rcpts) != SMTP_MAX_RCPTS:
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected {SMTP_MAX_RCPTS}"
        )
    if len(reply_oks) != 1 + SMTP_MAX_RCPTS:
        raise TestFailure(
            f"Unexpected count of 'reply 250 ok' lines: {len(reply_oks)!r}, expected {1 + SMTP_MAX_RCPTS}"
        )
    step_ok("childlog", f"{SMTP_MAX_RCPTS} RCPT forwarded")
    if cmd_rcpts[0] != "cmd RCPT TO:<r001@example.com>":
        raise TestFailure(f"Unexpected first RCPT log line: {cmd_rcpts[0]!r}")
    if cmd_rcpts[-1] != f"cmd RCPT TO:<r{SMTP_MAX_RCPTS:03d}@example.com>":
        raise TestFailure(f"Unexpected final RCPT log line: {cmd_rcpts[-1]!r}")
    step_ok("childlog", "first/last RCPT")
    if child_log[-2:] != ["cmd QUIT", "reply 221 bye"]:
        raise TestFailure(
            f"Unexpected fake child log tail: {child_log[-2:]!r}, expected clean QUIT sequence"
        )
    step_ok("childlog", "clean QUIT")


def test_rcpttodata_too_large(child_log_path: Path) -> None:
    """Verify the wrapper terminates when aggregate RCPT storage exceeds the limit."""

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
    step_ok("exit", "111")
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
    step_ok("stdout", f"{len(stdout_lines)} lines")

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
    step_ok("childlog", "MAIL FROM")
    if len(cmd_rcpts) != expected_forwarded_count:
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected {expected_forwarded_count}"
        )
    if len(reply_oks) != 1 + expected_forwarded_count:
        raise TestFailure(
            f"Unexpected count of 'reply 250 ok' lines: {len(reply_oks)!r}, expected {1 + expected_forwarded_count}"
        )
    step_ok("childlog", f"{expected_forwarded_count} RCPT forwarded")
    if cmd_rcpts[0] != forwarded_rcpts[0]:
        raise TestFailure(
            f"Unexpected first RCPT log line: {cmd_rcpts[0]!r}"
        )
    if cmd_rcpts[-1] != forwarded_rcpts[expected_forwarded_count - 1]:
        raise TestFailure(
            f"Unexpected last forwarded RCPT log line: {cmd_rcpts[-1]!r}"
        )
    step_ok("childlog", "first/last RCPT")
    if forwarded_rcpts[expected_forwarded_count] in child_log:
        raise TestFailure(
            f"Fake child unexpectedly received overflow RCPT: {child_log!r}"
        )
    step_ok("childlog", "overflow RCPT not forwarded")


def test_rcpttodata_exact_limit(child_log_path: Path) -> None:
    """Verify aggregate RCPT storage exactly at the limit still succeeds."""

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
    step_ok("exit", str(returncode))
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
    step_ok("stdout", f"{len(stdout_lines)} lines")

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
    step_ok("childlog", "MAIL FROM")
    if len(cmd_rcpts) != len(rcpt_lines):
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected {len(rcpt_lines)}"
        )
    if len(reply_oks) != 1 + len(rcpt_lines):
        raise TestFailure(
            f"Unexpected count of 'reply 250 ok' lines: {len(reply_oks)!r}, expected {1 + len(rcpt_lines)}"
        )
    step_ok("childlog", f"{len(rcpt_lines)} RCPT forwarded")
    if len(cmd_rcpts[0]) != len("cmd RCPT TO:") + 2047:
        raise TestFailure(
            f"Unexpected first RCPT log line length: {len(cmd_rcpts[0])!r}, expected {len('cmd RCPT TO:') + 2047!r}"
        )
    if len(cmd_rcpts[-1]) != len("cmd RCPT TO:") + 2047:
        raise TestFailure(
            f"Unexpected last RCPT log line length: {len(cmd_rcpts[-1])!r}, expected {len('cmd RCPT TO:') + 2047!r}"
        )
    step_ok("childlog", "RCPT line lengths")
    if child_log[-2:] != ["cmd QUIT", "reply 221 bye"]:
        raise TestFailure(
            f"Unexpected fake child log tail: {child_log[-2:]!r}, expected clean QUIT sequence"
        )
    step_ok("childlog", "clean QUIT")


def test_mail_resets_previous_rcpts(child_log_path: Path) -> None:
    """Verify a new MAIL FROM resets prior recipient state."""

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
    step_ok("exit", str(returncode))
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
    step_ok("stdout", f"{len(stdout_lines)} lines")

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
    step_ok("childlog", "both MAIL FROM")
    if len(cmd_rcpts) != 260:
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected 260"
        )
    if len(reply_oks) != 262:
        raise TestFailure(
            f"Unexpected count of 'reply 250 ok' lines: {len(reply_oks)!r}, expected 262"
        )
    step_ok("childlog", "260 RCPT forwarded")
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
    step_ok("childlog", "batch boundaries")
    if "cmd QUIT" not in child_log or child_log[-1] != "reply 221 bye":
        raise TestFailure(f"Missing clean QUIT sequence in fake child log: {child_log!r}")
    step_ok("childlog", "clean QUIT")


def test_data_resets_envelope(child_log_path: Path) -> None:
    """Verify a successful DATA resets recipient state for the next message."""

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
    step_ok("exit", str(returncode))
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
    step_ok("stdout", f"{len(stdout_lines)} lines")

    cmd_rcpts = [line for line in child_log if line.startswith("cmd RCPT TO:")]
    if child_log[0] != "reply 220 ready":
        raise TestFailure(
            f"Unexpected first fake child log line: {child_log[0]!r}, expected 'reply 220 ready'"
        )
    if "cmd MAIL FROM:<first@example.com>" not in child_log:
        raise TestFailure(f"Missing first MAIL FROM in fake child log: {child_log!r}")
    if "cmd MAIL FROM:<second@example.com>" not in child_log:
        raise TestFailure(f"Missing second MAIL FROM in fake child log: {child_log!r}")
    step_ok("childlog", "both MAIL FROM")
    if len(cmd_rcpts) != 260:
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected 260"
        )
    step_ok("childlog", "260 RCPT forwarded")
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
    step_ok("childlog", "batch boundaries")
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
    step_ok("childlog", "2 DATA + 2 data-end")
    if "cmd QUIT" not in child_log or child_log[-1] != "reply 221 bye":
        raise TestFailure(f"Missing clean QUIT sequence in fake child log: {child_log!r}")
    step_ok("childlog", "clean QUIT")


def test_starttls_unavailable_rejected(child_log_path: Path) -> None:
    """Verify STARTTLS is rejected when no control pipe is present."""

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
    step_ok("exit", str(returncode))
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    step_ok("stdout", f"{len(stdout_lines)} lines")
    if child_log != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log: {child_log!r}, expected {expected_child_log!r}"
        )
    step_ok("childlog", f"{len(child_log)} lines")


def test_starttls_available_advertised(child_log_path: Path) -> None:
    """Verify EHLO advertises STARTTLS only when both control fds exist."""

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
            with_control_ack=True,
        )

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    step_ok("exit", str(returncode))
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    step_ok("stdout", f"{len(stdout_lines)} lines")
    if child_log != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log: {child_log!r}, expected {expected_child_log!r}"
        )
    step_ok("childlog", f"{len(child_log)} lines")


def test_starttls_not_advertised_with_only_fd5(child_log_path: Path) -> None:
    """Verify EHLO does not advertise STARTTLS when only fd 5 exists."""

    session = b"EHLO client.example\r\nQUIT\r\n"

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(
            session,
            with_control_pipe=True,
            with_control_ack=False,
        )

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if "250 STARTTLS" in stdout_lines:
        raise TestFailure(f"Unexpected STARTTLS advertisement with only fd 5: {stdout_lines!r}")
    if child_log[-2:] != ["cmd QUIT", "reply 221 bye"]:
        raise TestFailure(f"Unexpected fake child QUIT sequence: {child_log!r}")
    step_ok("stdout", "STARTTLS hidden without fd 6")


def test_starttls_not_advertised_with_only_fd6(child_log_path: Path) -> None:
    """Verify EHLO does not advertise STARTTLS when only fd 6 exists."""

    session = b"EHLO client.example\r\nQUIT\r\n"

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(
            session,
            with_control_pipe=False,
            with_control_ack=True,
        )

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 0:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    if "250 STARTTLS" in stdout_lines:
        raise TestFailure(f"Unexpected STARTTLS advertisement with only fd 6: {stdout_lines!r}")
    if child_log[-2:] != ["cmd QUIT", "reply 221 bye"]:
        raise TestFailure(f"Unexpected fake child QUIT sequence: {child_log!r}")
    step_ok("stdout", "STARTTLS hidden without fd 5")


def test_starttls_control_pipe_signal(child_log_path: Path) -> None:
    """Verify STARTTLS writes only its signal to fd 5 and discards queued plaintext."""

    session = b"EHLO client.example\r\nSTARTTLS\r\nQUIT\r\n"
    expected_stdout = [
        "220 ready",
        "250-ok",
        "250 STARTTLS",
        "220 ready to start TLS (#2.0.0)",
    ]
    expected_control_output = STARTTLS_SIGNAL_REQUEST
    expected_child_log = [
        "reply 220 ready",
        "cmd EHLO client.example",
        "reply 250 ok",
        "cmd RSET",
        "reply 250 reset",
        "eof",
    ]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(
            session,
            with_control_pipe=True,
            with_control_ack=True,
        )
        control_output = test.control_output

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 111:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    step_ok("exit", str(returncode))
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    step_ok("stdout", f"{len(stdout_lines)} lines")
    if control_output != expected_control_output:
        raise TestFailure(
            f"Unexpected control-pipe output: {control_output!r}, expected {expected_control_output!r}"
        )
    step_ok("control", repr(control_output))
    if child_log != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log: {child_log!r}, expected {expected_child_log!r}"
        )
    step_ok("childlog", f"{len(child_log)} lines")


def test_starttls_short_session(child_log_path: Path) -> None:
    """Verify pipelined plaintext after STARTTLS is discarded."""

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
        "220 ready to start TLS (#2.0.0)",
    ]
    expected_control_output = STARTTLS_SIGNAL_REQUEST
    expected_child_log = [
        "reply 220 ready",
        "cmd EHLO client.example",
        "reply 250 ok",
        "cmd RSET",
        "reply 250 reset",
        "eof",
    ]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(
            session,
            with_control_pipe=True,
            with_control_ack=True,
        )
        control_output = test.control_output

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 111:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    step_ok("exit", str(returncode))
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    step_ok("stdout", f"{len(stdout_lines)} lines")
    if control_output != expected_control_output:
        raise TestFailure(
            f"Unexpected control-pipe output: {control_output!r}, expected {expected_control_output!r}"
        )
    step_ok("control", repr(control_output))
    if child_log != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log: {child_log!r}, expected {expected_child_log!r}"
        )
    step_ok("childlog", f"{len(child_log)} lines")


def test_starttls_fresh_transaction(child_log_path: Path) -> None:
    """Verify queued commands after STARTTLS are not forwarded."""

    session = (
        b"EHLO client.example\r\n"
        b"MAIL FROM:<before-starttls@example.com>\r\n"
        b"RCPT TO:<before-recipient@example.com>\r\n"
        b"STARTTLS\r\n"
        b"MAIL FROM:<after-starttls@example.com>\r\n"
        b"RCPT TO:<after-recipient@example.com>\r\n"
        b"DATA\r\n"
        b"Subject: fresh transaction\r\n"
        b"\r\n"
        b"body-after-starttls\r\n"
        b".\r\n"
        b"QUIT\r\n"
    )
    expected_stdout = [
        "220 ready",
        "250-ok",
        "250 STARTTLS",
        "250 ok",
        "250 ok",
        "220 ready to start TLS (#2.0.0)",
    ]
    expected_control_output = STARTTLS_SIGNAL_REQUEST
    expected_child_log = [
        "reply 220 ready",
        "cmd EHLO client.example",
        "reply 250 ok",
        "cmd MAIL FROM:<before-starttls@example.com>",
        "reply 250 ok",
        "cmd RCPT TO:<before-recipient@example.com>",
        "reply 250 ok",
        "cmd RSET",
        "reply 250 reset",
        "eof",
    ]

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(
            session,
            with_control_pipe=True,
            with_control_ack=True,
        )
        control_output = test.control_output

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 111:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    step_ok("exit", str(returncode))
    if stdout_lines != expected_stdout:
        raise TestFailure(
            f"Unexpected wrapper stdout: {stdout_lines!r}, expected {expected_stdout!r}"
        )
    step_ok("stdout", f"{len(stdout_lines)} lines")
    if control_output != expected_control_output:
        raise TestFailure(
            f"Unexpected control-pipe output: {control_output!r}, expected {expected_control_output!r}"
        )
    step_ok("control", repr(control_output))
    if child_log != expected_child_log:
        raise TestFailure(
            f"Unexpected fake child log: {child_log!r}, expected {expected_child_log!r}"
        )
    step_ok("childlog", f"{len(child_log)} lines")


def test_starttls_resets_envelope(child_log_path: Path) -> None:
    """Verify STARTTLS discards queued recipients and message data."""

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
    expected_control_output = STARTTLS_SIGNAL_REQUEST
    expected_stdout_len = 1 + 2 + 1 + 130 + 1

    with TestSmtpWrapper(TIMEOUT, child_log_path) as test:
        returncode, stdout_text, stderr_text, child_log = test.run(
            session,
            with_control_pipe=True,
            with_control_ack=True,
        )
        control_output = test.control_output

    stdout_lines = split_smtp_lines(stdout_text)
    if returncode != 111:
        raise TestFailure(
            f"Wrapper exited with {returncode}: {stderr_text.strip() or '<empty stderr>'}"
        )
    step_ok("exit", str(returncode))
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
    if "220 ready to start TLS (#2.0.0)" not in stdout_lines:
        raise TestFailure(f"Missing STARTTLS banner in wrapper stdout: {stdout_lines!r}")
    if stdout_lines.count("354 go ahead") != 0:
        raise TestFailure(
            f"Unexpected DATA prompt count: {stdout_lines.count('354 go ahead')!r}, expected 0"
        )
    if stdout_lines.count("250 queued") != 0:
        raise TestFailure(
            f"Unexpected queued reply count: {stdout_lines.count('250 queued')!r}, expected 0"
        )
    if any(
        line not in {"220 ready", "250-ok", "250 STARTTLS", "220 ready to start TLS (#2.0.0)", "250 ok"}
        for line in stdout_lines
    ):
        raise TestFailure(f"Unexpected wrapper stdout lines: {stdout_lines!r}")
    if stdout_lines.count("250 ok") != 1 + 130:
        raise TestFailure(
            f"Unexpected count of '250 ok' wrapper replies: {stdout_lines.count('250 ok')!r}, expected 131"
        )
    step_ok("stdout", f"{len(stdout_lines)} lines")
    if control_output != expected_control_output:
        raise TestFailure(
            f"Unexpected control-pipe output: {control_output!r}, expected {expected_control_output!r}"
        )
    step_ok("control", repr(control_output))

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
    step_ok("childlog", "EHLO + MAIL FROM")
    if child_log.count("cmd RSET") != 1 or child_log.count("reply 250 reset") != 1:
        raise TestFailure(
            f"Unexpected internal RSET sequence count in fake child log: {child_log!r}"
        )
    step_ok("childlog", "internal RSET")
    if len(cmd_rcpts) != 130:
        raise TestFailure(
            f"Unexpected forwarded RCPT count: {len(cmd_rcpts)!r}, expected 130"
        )
    if len(reply_oks) != 1 + 1 + 130:
        raise TestFailure(
            f"Unexpected count of 'reply 250 ok' lines: {len(reply_oks)!r}, expected 132"
        )
    step_ok("childlog", "130 RCPT forwarded")
    if cmd_rcpts[0] != "cmd RCPT TO:<e001@example.com>":
        raise TestFailure(
            f"Unexpected first RCPT log line: {cmd_rcpts[0]!r}"
        )
    if cmd_rcpts[129] != "cmd RCPT TO:<e130@example.com>":
        raise TestFailure(
            f"Unexpected last first-batch RCPT log line: {cmd_rcpts[129]!r}"
        )
    step_ok("childlog", "batch boundaries")
    if any(line.startswith("cmd RCPT TO:<f") for line in child_log):
        raise TestFailure(
            f"Unexpected post-STARTTLS RCPT in fake child log: {child_log!r}"
        )
    if child_log.count("cmd DATA") != 0:
        raise TestFailure(
            f"Unexpected DATA command count in fake child log: {child_log.count('cmd DATA')!r}, expected 0"
        )
    if child_log.count("data post-starttls message") != 0:
        raise TestFailure(
            f"Unexpected post-STARTTLS message body in fake child log: {child_log!r}"
        )
    if child_log.count("data-end") != 0:
        raise TestFailure(
            f"Unexpected DATA termination count in fake child log: {child_log.count('data-end')!r}, expected 0"
        )
    step_ok("childlog", "post-STARTTLS payload discarded")
    if child_log[-1] != "eof":
        raise TestFailure(f"Unexpected final fake child log line: {child_log[-1]!r}, expected 'eof'")
    step_ok("childlog", "clean EOF")


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
    "starttls_not_advertised_with_only_fd5": test_starttls_not_advertised_with_only_fd5,
    "starttls_not_advertised_with_only_fd6": test_starttls_not_advertised_with_only_fd6,
    "starttls_control_pipe_signal": test_starttls_control_pipe_signal,
    "starttls_fresh_transaction": test_starttls_fresh_transaction,
    "starttls_short_session": test_starttls_short_session,
    "starttls_resets_envelope": test_starttls_resets_envelope,
    "starttls_unavailable_rejected": test_starttls_unavailable_rejected,
    "too_many_rcpts": test_too_many_rcpts,
}


def main(argv: list[str] | None = None) -> int:
    """Run the selected SMTP wrapper tests."""

    args = parse_args(sys.argv[1:] if argv is None else argv)
    child_log_path = Path(args.child_log)

    names = args.tests or list(TESTS.keys())
    failed = 0

    for name in names:
        test_fn = TESTS.get(name)
        if test_fn is None:
            print(f"unknown test: {name}", file=sys.stderr)
            return 2

        print(f"=== {name} ===")
        try:
            test_fn(child_log_path)
            print("  PASS")
        except (TestFailure, Exception) as exc:
            print(f"  FAIL: {exc}")
            failed += 1
        print()

    if failed:
        print(f"{failed}/{len(names)} tests FAILED")
        return 1

    print(f"all {len(names)} tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
