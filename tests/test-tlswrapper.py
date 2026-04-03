#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import os
import select
import signal
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

TIMEOUT = 4
EARLY_EXIT_TIMEOUT = 1.0
SHORT_IDLE_TIMEOUT = 1
SHORT_HANDSHAKE_TIMEOUT = 1
TIMEOUT_TOLERANCE = 1.5
WORKSPACE = Path(__file__).resolve().parent
LOGGER = logging.getLogger(__name__)
WRAPPER_EXECUTABLE = WORKSPACE / "tlswrapper-test"
CERT_PATH = WORKSPACE / "testcerts" / "okcert-ec-prime256v1-ec-prime256v1-ok.pem"
DEFAULT_CHILD_LOG = WORKSPACE / "test-tlswrapper-child.log"
STARTTLS_BANNER = b"220 ready for tls\n"
PRETLS_GREETING = b"220-plaintext-before-starttls\n"
SMALL_REQUEST = b"request-before-eof"
MULTIWRITE_REQUEST = b"request-before-multi-write"
SILENT_EXIT_REQUEST = b"request-before-silent-exit"
IDLE_REQUEST = b"idle-after-activity"
BIG_REQUEST = (b"request-chunk-" * 400) + b"tail"
CHILD_EOF_WAIT_SECONDS = 2.0


class TestFailure(Exception):
    """Raised when a generic tlswrapper regression scenario fails."""

    pass


@dataclass(frozen=True)
class DelayedScenario:
    """One delayed-mode regression scenario."""

    name: str
    child_script: str
    client_payload: bytes = b""
    expected_child_log: list[str] | None = None
    expected_reply_chunks: list[bytes] = field(default_factory=list)
    expected_returncode: int = 0
    expect_early_exit: bool = False


@dataclass(frozen=True)
class TlsOnlyScenario:
    """One TLS-only regression scenario."""

    name: str
    child_script: str
    client_payload: bytes = b""
    expected_child_log: list[str] | None = None
    expected_reply_chunks: list[bytes] = field(default_factory=list)
    expected_returncode: int = 0


@dataclass(frozen=True)
class HybridScenario:
    """One delayed-then-TLS regression scenario."""

    name: str
    child_script: str
    expected_pre_tls_output_chunks: list[bytes]
    client_payload: bytes = b""
    expected_child_log: list[str] | None = None
    expected_reply_chunks: list[bytes] = field(default_factory=list)
    expected_returncode: int = 0


@dataclass(frozen=True)
class TimeoutScenario:
    """One timeout regression scenario."""

    name: str
    mode: str
    child_script: str
    expected_timeout: int
    expected_returncode: int = 0
    wrapper_timeout: int | None = None
    handshake_timeout: int | None = None
    driver: str = "none"
    expected_pre_tls_output_chunks: list[bytes] = field(default_factory=list)
    client_payload: bytes = b""
    child_read_size: int | None = None


@dataclass(frozen=True)
class ChildEofScenario:
    """One regression scenario that propagates child stdout EOF to the peer."""

    name: str
    mode: str
    child_script: str
    expected_child_log: list[str]
    client_payload_chunks: list[bytes] = field(default_factory=list)
    expected_reply_chunks: list[bytes] = field(default_factory=list)
    expected_pre_tls_output_chunks: list[bytes] = field(default_factory=list)


class TestTlswrapper:
    """Manage one generic `tlswrappernojail` process for regression tests."""

    def __init__(self, timeout: int, child_log_path: Path | None = None) -> None:
        self.timeout = timeout
        self.child_log_path = child_log_path
        self.proc: subprocess.Popen[bytes] | None = None
        self.peer_socket: socket.socket | None = None

        if not WRAPPER_EXECUTABLE.exists():
            raise TestFailure("Missing tlswrapper-test binary; build it before running tests")
        if not CERT_PATH.exists():
            raise TestFailure(f"Missing test certificate: {CERT_PATH}")

    def __enter__(self) -> "TestTlswrapper":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def start(
        self,
        child_script: str,
        *,
        delayed_encryption: bool = False,
        timeout: int | None = None,
        handshake_timeout: int | None = None,
        socket_transport: bool = False,
    ) -> None:
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
        if timeout is not None:
            cmd.extend(["-t", str(timeout)])
        if handshake_timeout is not None:
            cmd.extend(["-T", str(handshake_timeout)])
        cmd.extend(["-f", str(CERT_PATH), sys.executable, "-c", child_script])
        LOGGER.debug("Starting wrapper process: %s", " ".join(cmd))
        if socket_transport:
            peer_socket, child_socket = socket.socketpair()
            self.peer_socket = peer_socket
            try:
                self.proc = subprocess.Popen(
                    cmd,
                    executable=str(WRAPPER_EXECUTABLE),
                    cwd=WORKSPACE,
                    env=env,
                    stdin=child_socket.fileno(),
                    stdout=child_socket.fileno(),
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    pass_fds=(child_socket.fileno(),),
                    preexec_fn=os.setsid,
                )
            finally:
                child_socket.close()
        else:
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
        if self.proc is not None and self.proc.poll() is None:
            try:
                LOGGER.debug("Terminating wrapper process group")
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=1)
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                LOGGER.warning("Wrapper process group did not terminate cleanly")
        if self.peer_socket is not None:
            try:
                self.peer_socket.close()
            except OSError:
                pass
            self.peer_socket = None

    def wait_for_early_exit(self, timeout: float = EARLY_EXIT_TIMEOUT) -> int:
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
        while True:
            try:
                self.tls.do_handshake()
                self._flush_outgoing()
                return
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                self._feed_incoming()

    def write_plaintext(self, data: bytes) -> None:
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

    def read_plaintext_chunks(self, sizes: list[int]) -> list[bytes]:
        return [self.read_plaintext_exact(size) for size in sizes]

    def transport_half_close(self) -> None:
        self._flush_outgoing()
        self.stdin.close()

    def expect_eof(self) -> None:
        deadline = time.monotonic() + self.timeout

        while True:
            try:
                chunk = self.tls.read(1)
                if not chunk:
                    return
                raise TestFailure(f"TLS client expected EOF, received {chunk!r}")
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                if time.monotonic() >= deadline:
                    raise TestFailure("Timed out waiting for TLS EOF from wrapper")
                self._feed_incoming()
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
                return

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


class PlainPipeClient:
    """Drive the wrapper stdin/stdout pipes without TLS framing."""

    def __init__(self, stdin: BinaryIO, stdout: BinaryIO, timeout: int) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.timeout = timeout

    def write_plaintext(self, data: bytes) -> None:
        self.stdin.write(data)
        self.stdin.flush()

    def read_plaintext_exact(self, size: int) -> bytes:
        chunks = []
        total = 0
        while total < size:
            ready, _, _ = select.select([self.stdout], [], [], self.timeout)
            if not ready:
                raise TestFailure("Timed out waiting for plaintext bytes from wrapper")
            chunk = os.read(self.stdout.fileno(), size - total)
            if not chunk:
                raise TestFailure("Wrapper reached EOF before expected plaintext arrived")
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def read_plaintext_chunks(self, sizes: list[int]) -> list[bytes]:
        return [self.read_plaintext_exact(size) for size in sizes]

    def transport_half_close(self) -> None:
        self.stdin.close()

    def expect_eof(self) -> None:
        ready, _, _ = select.select([self.stdout], [], [], self.timeout)
        if not ready:
            raise TestFailure("Timed out waiting for plaintext EOF from wrapper")

        chunk = os.read(self.stdout.fileno(), 1)
        if chunk != b"":
            raise TestFailure(f"Plaintext client expected EOF, received {chunk!r}")


class PlainSocketClient:
    """Drive the wrapper over one full-duplex socket."""

    def __init__(self, sock: socket.socket, timeout: int) -> None:
        self.sock = sock
        self.timeout = timeout

    def write_plaintext(self, data: bytes) -> None:
        self.sock.sendall(data)

    def read_plaintext_exact(self, size: int) -> bytes:
        chunks = []
        total = 0
        while total < size:
            ready, _, _ = select.select([self.sock], [], [], self.timeout)
            if not ready:
                raise TestFailure("Timed out waiting for plaintext bytes from wrapper")
            chunk = self.sock.recv(size - total)
            if not chunk:
                raise TestFailure("Wrapper reached EOF before expected plaintext arrived")
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def read_plaintext_chunks(self, sizes: list[int]) -> list[bytes]:
        return [self.read_plaintext_exact(size) for size in sizes]

    def expect_eof(self, timeout: float | None = None) -> None:
        wait_timeout = self.timeout if timeout is None else timeout
        ready, _, _ = select.select([self.sock], [], [], wait_timeout)
        if not ready:
            raise TestFailure("Timed out waiting for plaintext EOF from wrapper")

        chunk = self.sock.recv(1)
        if chunk != b"":
            raise TestFailure(f"Plaintext client expected EOF, received {chunk!r}")

    def transport_half_close(self) -> None:
        self.sock.shutdown(socket.SHUT_WR)


class TlsSocketClient:
    """Drive TLS over one full-duplex socket."""

    def __init__(self, sock: socket.socket, timeout: int) -> None:
        self.sock = sock
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
        while True:
            try:
                self.tls.do_handshake()
                self._flush_outgoing()
                return
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                self._feed_incoming()

    def write_plaintext(self, data: bytes) -> None:
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

    def read_plaintext_chunks(self, sizes: list[int]) -> list[bytes]:
        return [self.read_plaintext_exact(size) for size in sizes]

    def expect_eof(self, timeout: float | None = None) -> None:
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)

        while True:
            try:
                chunk = self.tls.read(1)
                if not chunk:
                    return
                raise TestFailure(f"TLS client expected EOF, received {chunk!r}")
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                if time.monotonic() >= deadline:
                    raise TestFailure("Timed out waiting for TLS EOF from wrapper")
                self._feed_incoming(deadline - time.monotonic())
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
                return

    def transport_half_close(self) -> None:
        self._flush_outgoing()
        self.sock.shutdown(socket.SHUT_WR)

    def _flush_outgoing(self) -> None:
        while True:
            data = self.outgoing.read()
            if not data:
                return
            self.sock.sendall(data)

    def _feed_incoming(self, timeout: float | None = None) -> None:
        wait_timeout = self.timeout if timeout is None else max(timeout, 0.0)
        ready, _, _ = select.select([self.sock], [], [], wait_timeout)
        if not ready:
            raise TestFailure("Timed out waiting for TLS records from wrapper")

        data = self.sock.recv(65536)
        if not data:
            self.incoming.write_eof()
            return
        self.incoming.write(data)


def make_child_close_control_script() -> str:
    """Create a child that closes the delayed control pipe before STARTTLS."""

    return """import os
import sys

os.close(5)
sys.stdin.buffer.read()
"""


def make_child_log_then_reply_script(
    *,
    reply_chunks: list[bytes],
    read_size: int | None = None,
) -> str:
    """Create a child that reads stdin, logs it, then replies."""

    read_call = "sys.stdin.buffer.read()"
    if read_size is not None:
        read_call = f"sys.stdin.buffer.read({read_size})"

    return f"""import os
import sys
import time

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {read_call}
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write("saw_eof=yes\\n")

for chunk in {reply_chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep(0.01)
"""


def make_child_log_then_exit_script(*, read_size: int | None = None) -> str:
    """Create a child that reads stdin, logs it, and exits without replying."""

    read_call = "sys.stdin.buffer.read()"
    if read_size is not None:
        read_call = f"sys.stdin.buffer.read({read_size})"

    return f"""import os
import sys

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {read_call}
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write("saw_eof=yes\\n")
"""


def make_child_log_then_wait_for_more_input_script(*, read_size: int) -> str:
    """Create a child that logs one read and then blocks for more input."""

    return f"""import os
import sys

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = sys.stdin.buffer.read({read_size})
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write("saw_eof=yes\\n")

sys.stdin.buffer.read()
"""


def make_child_starttls_then_reply_script(
    *,
    reply_chunks: list[bytes],
    read_size: int | None = None,
) -> str:
    """Create a child that triggers STARTTLS, then logs stdin and replies."""

    read_call = "sys.stdin.buffer.read()"
    if read_size is not None:
        read_call = f"sys.stdin.buffer.read({read_size})"

    return f"""import os
import sys
import time

os.write(5, {STARTTLS_BANNER!r})
os.close(5)

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {read_call}
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write("saw_eof=yes\\n")

for chunk in {reply_chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep(0.01)
"""


def make_child_starttls_then_exit_script(*, read_size: int | None = None) -> str:
    """Create a child that triggers STARTTLS, then logs stdin and exits."""

    read_call = "sys.stdin.buffer.read()"
    if read_size is not None:
        read_call = f"sys.stdin.buffer.read({read_size})"

    return f"""import os
import sys

os.write(5, {STARTTLS_BANNER!r})
os.close(5)

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {read_call}
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write("saw_eof=yes\\n")
"""


def make_child_half_close_then_log_script(*, read_size: int | None = None) -> str:
    """Create a child that half-closes stdout, then reads stdin and logs it."""

    read_call = "sys.stdin.buffer.read()"
    if read_size is not None:
        read_call = f"sys.stdin.buffer.read({read_size})"

    return f"""import os
import sys

os.close(sys.stdout.fileno())

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {read_call}
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write("saw_eof=yes\\n")
"""


def make_child_half_close_then_read_exact_script(*, read_size: int) -> str:
    """Create a child that half-closes stdout, then reads one exact request."""

    return f"""import os
import sys

os.close(sys.stdout.fileno())

remaining = {read_size}
chunks = []
while remaining:
    chunk = sys.stdin.buffer.read(remaining)
    if not chunk:
        break
    chunks.append(chunk)
    remaining -= len(chunk)
data = b"".join(chunks)

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write(f"read_complete={{remaining == 0}}\\n")
"""


def make_child_starttls_then_half_close_then_log_script(
    *,
    read_size: int | None = None,
) -> str:
    """Create a child that starts TLS, half-closes stdout, then logs stdin."""

    read_call = "sys.stdin.buffer.read()"
    if read_size is not None:
        read_call = f"sys.stdin.buffer.read({read_size})"

    return f"""import os
import sys
import time

os.write(5, {STARTTLS_BANNER!r})
os.close(5)
time.sleep(0.05)
os.close(sys.stdout.fileno())

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {read_call}
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write("saw_eof=yes\\n")
"""


def make_child_starttls_then_half_close_then_read_exact_script(*, read_size: int) -> str:
    """Create a child that starts TLS, half-closes stdout, then reads one request."""

    return f"""import os
import sys
import time

os.write(5, {STARTTLS_BANNER!r})
os.close(5)
time.sleep(0.05)
os.close(sys.stdout.fileno())

remaining = {read_size}
chunks = []
while remaining:
    chunk = sys.stdin.buffer.read(remaining)
    if not chunk:
        break
    chunks.append(chunk)
    remaining -= len(chunk)
data = b"".join(chunks)

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write(f"read_complete={{remaining == 0}}\\n")
"""


def make_child_reply_then_half_close_then_read_exact_script(
    *,
    reply_chunks: list[bytes],
    read_size: int,
) -> str:
    """Create a child that reads one exact request, replies, then closes stdout."""

    return f"""import os
import sys
import time

remaining = {read_size}
chunks = []
while remaining:
    chunk = sys.stdin.buffer.read(remaining)
    if not chunk:
        break
    chunks.append(chunk)
    remaining -= len(chunk)
data = b"".join(chunks)

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write(f"read_complete={{remaining == 0}}\\n")

for chunk in {reply_chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep(0.01)

os.close(sys.stdout.fileno())
"""


def make_child_starttls_then_reply_then_half_close_then_read_exact_script(
    *,
    reply_chunks: list[bytes],
    read_size: int,
) -> str:
    """Create a child that starts TLS, reads a request, replies, then closes stdout."""

    return f"""import os
import sys
import time

os.write(5, {STARTTLS_BANNER!r})
os.close(5)

remaining = {read_size}
chunks = []
while remaining:
    chunk = sys.stdin.buffer.read(remaining)
    if not chunk:
        break
    chunks.append(chunk)
    remaining -= len(chunk)
data = b"".join(chunks)

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write(f"read_complete={{remaining == 0}}\\n")

for chunk in {reply_chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep(0.01)

os.close(sys.stdout.fileno())
"""


def make_child_starttls_then_wait_for_more_input_script(*, read_size: int) -> str:
    """Create a child that triggers STARTTLS, logs one read, then waits."""

    return f"""import os
import sys

os.write(5, {STARTTLS_BANNER!r})
os.close(5)

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = sys.stdin.buffer.read({read_size})
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write("saw_eof=yes\\n")

sys.stdin.buffer.read()
"""


def make_child_preplaintext_then_starttls_then_reply_script(
    *,
    pre_starttls_chunks: list[bytes],
    reply_chunks: list[bytes],
    read_size: int | None = None,
) -> str:
    """Create a child that emits plaintext, triggers STARTTLS, then replies."""

    read_call = "sys.stdin.buffer.read()"
    if read_size is not None:
        read_call = f"sys.stdin.buffer.read({read_size})"

    return f"""import os
import sys
import time

for chunk in {pre_starttls_chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep(0.01)

os.write(5, {STARTTLS_BANNER!r})
os.close(5)

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {read_call}
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write("saw_eof=yes\\n")

for chunk in {reply_chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep(0.01)
"""


def make_child_starttls_then_wait_script() -> str:
    """Create a child that requests STARTTLS and then waits for EOF."""

    return f"""import os
import sys

os.write(5, {STARTTLS_BANNER!r})
os.close(5)
sys.stdin.buffer.read()
"""


def process_stdio(proc: subprocess.Popen[bytes]) -> tuple[BinaryIO, BinaryIO]:
    """Return verified stdio pipes from the wrapper process."""

    if proc.stdin is None or proc.stdout is None:
        raise TestFailure("Wrapper stdio is not available")
    return proc.stdin, proc.stdout


def process_socket(test: TestTlswrapper) -> socket.socket:
    """Return the parent-side socket transport for the wrapper process."""

    if test.peer_socket is None:
        raise TestFailure("Wrapper socket transport is not available")
    return test.peer_socket


def read_expected_chunks(reader: PlainPipeClient | TlsPipeClient, expected: list[bytes]) -> None:
    """Read and compare one exact sequence of chunks."""

    replies = reader.read_plaintext_chunks([len(chunk) for chunk in expected])
    if replies != expected:
        raise TestFailure(f"Unexpected reply chunks: {replies!r}, expected {expected!r}")


def assert_child_log(
    test: TestTlswrapper,
    expected_child_log: list[str] | None,
) -> None:
    """Read and compare the optional child transcript."""

    if expected_child_log is None:
        return
    child_log = test.read_child_log()
    if child_log != expected_child_log:
        raise TestFailure(
            f"Unexpected child log: {child_log!r}, expected {expected_child_log!r}"
        )


def run_delayed_scenario(scenario: DelayedScenario) -> None:
    """Run one delayed-mode scenario."""

    LOGGER.debug("Starting delayed scenario: %s", scenario.name)
    child_log_path = DEFAULT_CHILD_LOG if scenario.expected_child_log is not None else None
    with TestTlswrapper(TIMEOUT, child_log_path) as test:
        test.start(scenario.child_script, delayed_encryption=True)
        if scenario.expect_early_exit:
            returncode = test.wait_for_early_exit()
            stdout_text, stderr_text = test.collect_output_after_exit()
            if returncode != scenario.expected_returncode:
                raise TestFailure(
                    f"Wrapper exited with {returncode}: "
                    f"{stderr_text.strip() or '<empty stderr>'}"
                )
            if stdout_text:
                LOGGER.debug("Ignoring non-empty wrapper stdout: %r", stdout_text)
            if stderr_text.strip():
                LOGGER.debug("Ignoring non-empty wrapper stderr: %r", stderr_text)
            return

        if test.proc is None:
            raise TestFailure("Wrapper process has not been started")
        stdin, stdout = process_stdio(test.proc)
        client = PlainPipeClient(stdin, stdout, TIMEOUT)
        if scenario.client_payload:
            client.write_plaintext(scenario.client_payload)
        client.transport_half_close()
        if scenario.expected_reply_chunks:
            read_expected_chunks(client, scenario.expected_reply_chunks)

        stdout_text, stderr_text = test.wait_for_exit(scenario.expected_returncode)
        if stdout_text:
            LOGGER.debug("Ignoring non-empty wrapper stdout after reads: %r", stdout_text)
        if stderr_text.strip():
            LOGGER.debug("Ignoring non-empty wrapper stderr: %r", stderr_text)
        assert_child_log(test, scenario.expected_child_log)


def run_tls_only_scenario(scenario: TlsOnlyScenario) -> None:
    """Run one TLS-only scenario."""

    LOGGER.debug("Starting TLS-only scenario: %s", scenario.name)
    child_log_path = DEFAULT_CHILD_LOG if scenario.expected_child_log is not None else None
    with TestTlswrapper(TIMEOUT, child_log_path) as test:
        test.start(scenario.child_script)
        if test.proc is None:
            raise TestFailure("Wrapper process has not been started")
        stdin, stdout = process_stdio(test.proc)
        client = TlsPipeClient(stdin, stdout, TIMEOUT)
        client.do_handshake()
        if scenario.client_payload:
            client.write_plaintext(scenario.client_payload)
        client.transport_half_close()
        if scenario.expected_reply_chunks:
            read_expected_chunks(client, scenario.expected_reply_chunks)

        stdout_text, stderr_text = test.wait_for_exit(scenario.expected_returncode)
        if stdout_text:
            LOGGER.debug("Ignoring non-empty wrapper stdout after reads: %r", stdout_text)
        if stderr_text.strip():
            LOGGER.debug("Ignoring non-empty wrapper stderr: %r", stderr_text)
        assert_child_log(test, scenario.expected_child_log)


def run_hybrid_scenario(scenario: HybridScenario) -> None:
    """Run one delayed-then-TLS scenario."""

    LOGGER.debug("Starting hybrid scenario: %s", scenario.name)
    child_log_path = DEFAULT_CHILD_LOG if scenario.expected_child_log is not None else None
    with TestTlswrapper(TIMEOUT, child_log_path) as test:
        test.start(scenario.child_script, delayed_encryption=True)
        if test.proc is None:
            raise TestFailure("Wrapper process has not been started")
        stdin, stdout = process_stdio(test.proc)

        plain_client = PlainPipeClient(stdin, stdout, TIMEOUT)
        read_expected_chunks(plain_client, scenario.expected_pre_tls_output_chunks)

        tls_client = TlsPipeClient(stdin, stdout, TIMEOUT)
        tls_client.do_handshake()
        if scenario.client_payload:
            tls_client.write_plaintext(scenario.client_payload)
        tls_client.transport_half_close()
        if scenario.expected_reply_chunks:
            read_expected_chunks(tls_client, scenario.expected_reply_chunks)

        stdout_text, stderr_text = test.wait_for_exit(scenario.expected_returncode)
        if stdout_text:
            LOGGER.debug("Ignoring non-empty wrapper stdout after reads: %r", stdout_text)
        if stderr_text.strip():
            LOGGER.debug("Ignoring non-empty wrapper stderr: %r", stderr_text)
        assert_child_log(test, scenario.expected_child_log)


def run_child_eof_scenario(scenario: ChildEofScenario) -> None:
    """Run one scenario where child stdout EOF must reach the peer."""

    LOGGER.debug("Starting child EOF scenario: %s", scenario.name)
    delayed = scenario.mode in ("delayed", "hybrid")
    with TestTlswrapper(TIMEOUT, DEFAULT_CHILD_LOG) as test:
        test.start(scenario.child_script, delayed_encryption=delayed)
        if test.proc is None:
            raise TestFailure("Wrapper process has not been started")
        stdin, stdout = process_stdio(test.proc)

        if scenario.mode == "delayed":
            client = PlainPipeClient(stdin, stdout, TIMEOUT)
            for chunk in scenario.client_payload_chunks:
                client.write_plaintext(chunk)
            if scenario.expected_reply_chunks:
                read_expected_chunks(client, scenario.expected_reply_chunks)
            client.expect_eof()
            client.transport_half_close()
        elif scenario.mode == "tls_only":
            client = TlsPipeClient(stdin, stdout, TIMEOUT)
            client.do_handshake()
            for chunk in scenario.client_payload_chunks:
                client.write_plaintext(chunk)
            if scenario.expected_reply_chunks:
                read_expected_chunks(client, scenario.expected_reply_chunks)
            client.expect_eof()
            client.transport_half_close()
        elif scenario.mode == "hybrid":
            plain_client = PlainPipeClient(stdin, stdout, TIMEOUT)
            read_expected_chunks(plain_client, scenario.expected_pre_tls_output_chunks)

            client = TlsPipeClient(stdin, stdout, TIMEOUT)
            client.do_handshake()
            for chunk in scenario.client_payload_chunks:
                client.write_plaintext(chunk)
            if scenario.expected_reply_chunks:
                read_expected_chunks(client, scenario.expected_reply_chunks)
            client.expect_eof()
            client.transport_half_close()
        else:
            raise TestFailure(f"Unknown child EOF mode: {scenario.mode}")

        stdout_text, stderr_text = test.wait_for_exit()
        if stdout_text:
            LOGGER.debug("Ignoring non-empty wrapper stdout after reads: %r", stdout_text)
        if stderr_text.strip():
            LOGGER.debug("Ignoring non-empty wrapper stderr: %r", stderr_text)
        assert_child_log(test, scenario.expected_child_log)


def test_delayed_child_half_close_socket_peer_observes_eof_before_wrapper_exit() -> None:
    """Verify delayed mode half-closes the socket before the child exits."""

    expected_child_log = [
        f"received={SMALL_REQUEST.decode('utf-8', errors='replace')}",
        "read_complete=True",
    ]
    with TestTlswrapper(TIMEOUT, DEFAULT_CHILD_LOG) as test:
        test.start(
            make_child_log_then_wait_after_read_script(
                read_size=len(SMALL_REQUEST),
                wait_seconds=CHILD_EOF_WAIT_SECONDS,
            ),
            delayed_encryption=True,
            socket_transport=True,
        )
        client = PlainSocketClient(process_socket(test), TIMEOUT)
        client.write_plaintext(SMALL_REQUEST)
        client.expect_eof(timeout=1.0)
        if test.proc is None or test.proc.poll() is not None:
            raise TestFailure("Wrapper exited before the transport EOF check finished")
        client.transport_half_close()

        stdout_text, stderr_text = test.wait_for_exit()
        if stdout_text:
            LOGGER.debug("Ignoring non-empty wrapper stdout after reads: %r", stdout_text)
        if stderr_text.strip():
            LOGGER.debug("Ignoring non-empty wrapper stderr: %r", stderr_text)
        assert_child_log(test, expected_child_log)


def test_tls_only_child_half_close_socket_peer_observes_eof_before_wrapper_exit() -> None:
    """Verify TLS mode closes the peer-facing socket before the child exits."""

    expected_child_log = [
        f"received={SMALL_REQUEST.decode('utf-8', errors='replace')}",
        "read_complete=True",
    ]
    with TestTlswrapper(TIMEOUT, DEFAULT_CHILD_LOG) as test:
        test.start(
            make_child_log_then_wait_after_read_script(
                read_size=len(SMALL_REQUEST),
                wait_seconds=CHILD_EOF_WAIT_SECONDS,
            ),
            socket_transport=True,
        )
        client = TlsSocketClient(process_socket(test), TIMEOUT)
        client.do_handshake()
        client.write_plaintext(SMALL_REQUEST)
        client.expect_eof(timeout=1.0)
        if test.proc is None or test.proc.poll() is not None:
            raise TestFailure("Wrapper exited before the transport EOF check finished")
        client.transport_half_close()

        stdout_text, stderr_text = test.wait_for_exit()
        if stdout_text:
            LOGGER.debug("Ignoring non-empty wrapper stdout after reads: %r", stdout_text)
        if stderr_text.strip():
            LOGGER.debug("Ignoring non-empty wrapper stderr: %r", stderr_text)
        assert_child_log(test, expected_child_log)


def test_hybrid_child_half_close_socket_peer_observes_eof_before_wrapper_exit() -> None:
    """Verify STARTTLS mode closes the peer-facing socket before the child exits."""

    expected_child_log = [
        f"received={SMALL_REQUEST.decode('utf-8', errors='replace')}",
        "read_complete=True",
    ]
    with TestTlswrapper(TIMEOUT, DEFAULT_CHILD_LOG) as test:
        test.start(
            make_child_starttls_then_wait_after_read_script(
                read_size=len(SMALL_REQUEST),
                wait_seconds=CHILD_EOF_WAIT_SECONDS,
            ),
            delayed_encryption=True,
            socket_transport=True,
        )
        plain_client = PlainSocketClient(process_socket(test), TIMEOUT)
        read_expected_chunks(plain_client, [STARTTLS_BANNER])

        client = TlsSocketClient(process_socket(test), TIMEOUT)
        client.do_handshake()
        client.write_plaintext(SMALL_REQUEST)
        client.expect_eof(timeout=1.0)
        if test.proc is None or test.proc.poll() is not None:
            raise TestFailure("Wrapper exited before the transport EOF check finished")
        client.transport_half_close()

        stdout_text, stderr_text = test.wait_for_exit()
        if stdout_text:
            LOGGER.debug("Ignoring non-empty wrapper stdout after reads: %r", stdout_text)
        if stderr_text.strip():
            LOGGER.debug("Ignoring non-empty wrapper stderr: %r", stderr_text)
        assert_child_log(test, expected_child_log)


def assert_timeout_elapsed(*, elapsed: float, expected_timeout: float, name: str) -> None:
    """Verify that a timeout-driven exit happened near the expected deadline."""

    lower_bound = max(0.7, expected_timeout * 0.7)
    upper_bound = expected_timeout + TIMEOUT_TOLERANCE
    if elapsed < lower_bound or elapsed > upper_bound:
        raise TestFailure(
            f"{name} elapsed {elapsed:.2f}s, expected timeout window "
            f"{lower_bound:.2f}s..{upper_bound:.2f}s"
        )


def drive_timeout_client(
    scenario: TimeoutScenario,
    proc: subprocess.Popen[bytes],
) -> None:
    """Drive the client side up to the point where inactivity should win."""

    stdin, stdout = process_stdio(proc)
    if scenario.driver == "none":
        return
    if scenario.driver == "tls_handshake_only":
        TlsPipeClient(stdin, stdout, TIMEOUT).do_handshake()
        return
    if scenario.driver == "tls_handshake_then_write":
        client = TlsPipeClient(stdin, stdout, TIMEOUT)
        client.do_handshake()
        if scenario.client_payload:
            client.write_plaintext(scenario.client_payload)
        return
    if scenario.driver == "plaintext_then_stop":
        client = PlainPipeClient(stdin, stdout, TIMEOUT)
        if scenario.client_payload:
            client.write_plaintext(scenario.client_payload)
        return
    if scenario.driver == "hybrid_expect_banner_then_stop":
        client = PlainPipeClient(stdin, stdout, TIMEOUT)
        read_expected_chunks(client, scenario.expected_pre_tls_output_chunks)
        return
    if scenario.driver == "hybrid_handshake_only":
        plain_client = PlainPipeClient(stdin, stdout, TIMEOUT)
        read_expected_chunks(plain_client, scenario.expected_pre_tls_output_chunks)
        TlsPipeClient(stdin, stdout, TIMEOUT).do_handshake()
        return
    if scenario.driver == "hybrid_handshake_then_write":
        plain_client = PlainPipeClient(stdin, stdout, TIMEOUT)
        read_expected_chunks(plain_client, scenario.expected_pre_tls_output_chunks)
        client = TlsPipeClient(stdin, stdout, TIMEOUT)
        client.do_handshake()
        if scenario.client_payload:
            client.write_plaintext(scenario.client_payload)
        return
    raise TestFailure(f"Unknown timeout driver: {scenario.driver}")


def run_timeout_scenario(scenario: TimeoutScenario) -> None:
    """Run one timeout scenario in delayed, TLS-only, or hybrid mode."""

    LOGGER.debug("Starting timeout scenario: %s", scenario.name)
    delayed = scenario.mode in ("delayed", "hybrid")
    child_log_path = DEFAULT_CHILD_LOG if scenario.child_read_size is not None else None
    with TestTlswrapper(scenario.expected_timeout + 4, child_log_path) as test:
        test.start(
            scenario.child_script,
            delayed_encryption=delayed,
            timeout=scenario.wrapper_timeout,
            handshake_timeout=scenario.handshake_timeout,
        )
        if test.proc is None:
            raise TestFailure("Wrapper process is not available")

        started_at = time.monotonic()
        drive_timeout_client(scenario, test.proc)
        stdout_text, stderr_text = test.wait_for_exit(scenario.expected_returncode)
        elapsed = time.monotonic() - started_at

    if stdout_text:
        LOGGER.debug("Ignoring non-empty wrapper stdout: %r", stdout_text)
    if stderr_text.strip():
        LOGGER.debug("Ignoring non-empty wrapper stderr: %r", stderr_text)
    assert_timeout_elapsed(
        elapsed=elapsed,
        expected_timeout=scenario.expected_timeout,
        name=scenario.name,
    )


DELAYED_SCENARIOS = [
    DelayedScenario(
        name="delayed_control_pipe_eof_before_starttls",
        child_script=make_child_close_control_script(),
        expect_early_exit=True,
    ),
    DelayedScenario(
        name="delayed_plaintext_reply_after_network_eof",
        child_script=make_child_log_then_reply_script(reply_chunks=[b"reply-after-eof\n"]),
        client_payload=SMALL_REQUEST,
        expected_child_log=["received=request-before-eof", "saw_eof=yes"],
        expected_reply_chunks=[b"reply-after-eof\n"],
    ),
    DelayedScenario(
        name="delayed_plaintext_reply_after_network_eof_without_payload",
        child_script=make_child_log_then_reply_script(
            reply_chunks=[b"reply-after-empty-eof\n"]
        ),
        expected_child_log=["received=", "saw_eof=yes"],
        expected_reply_chunks=[b"reply-after-empty-eof\n"],
    ),
    DelayedScenario(
        name="delayed_plaintext_reply_after_network_eof_large_payload",
        child_script=make_child_log_then_reply_script(
            reply_chunks=[b"reply-after-large-eof\n"]
        ),
        client_payload=BIG_REQUEST,
        expected_child_log=[
            f"received={BIG_REQUEST.decode('utf-8', errors='replace')}",
            "saw_eof=yes",
        ],
        expected_reply_chunks=[b"reply-after-large-eof\n"],
    ),
    DelayedScenario(
        name="delayed_plaintext_reply_after_network_eof_multiple_writes",
        child_script=make_child_log_then_reply_script(
            reply_chunks=[b"reply-", b"after-", b"multi-write\n"]
        ),
        client_payload=MULTIWRITE_REQUEST,
        expected_child_log=["received=request-before-multi-write", "saw_eof=yes"],
        expected_reply_chunks=[b"reply-", b"after-", b"multi-write\n"],
    ),
    DelayedScenario(
        name="delayed_network_eof_then_child_silent_exit",
        child_script=make_child_log_then_exit_script(),
        client_payload=SILENT_EXIT_REQUEST,
        expected_child_log=["received=request-before-silent-exit", "saw_eof=yes"],
    ),
    DelayedScenario(
        name="delayed_child_half_closes_without_plaintext_client_still_writes",
        child_script=make_child_half_close_then_log_script(),
        client_payload=SMALL_REQUEST,
        expected_child_log=["received=request-before-eof", "saw_eof=yes"],
    ),
]

TLS_ONLY_SCENARIOS = [
    TlsOnlyScenario(
        name="tls_only_reply_after_network_eof",
        child_script=make_child_log_then_reply_script(reply_chunks=[b"reply-after-eof\n"]),
        client_payload=SMALL_REQUEST,
        expected_child_log=["received=request-before-eof", "saw_eof=yes"],
        expected_reply_chunks=[b"reply-after-eof\n"],
    ),
    TlsOnlyScenario(
        name="tls_only_reply_after_network_eof_without_plaintext",
        child_script=make_child_log_then_reply_script(
            reply_chunks=[b"reply-after-empty-eof\n"]
        ),
        expected_child_log=["received=", "saw_eof=yes"],
        expected_reply_chunks=[b"reply-after-empty-eof\n"],
    ),
    TlsOnlyScenario(
        name="tls_only_reply_after_network_eof_large_payload",
        child_script=make_child_log_then_reply_script(
            reply_chunks=[b"reply-after-large-eof\n"]
        ),
        client_payload=BIG_REQUEST,
        expected_child_log=[
            f"received={BIG_REQUEST.decode('utf-8', errors='replace')}",
            "saw_eof=yes",
        ],
        expected_reply_chunks=[b"reply-after-large-eof\n"],
    ),
    TlsOnlyScenario(
        name="tls_only_reply_after_network_eof_multiple_writes",
        child_script=make_child_log_then_reply_script(
            reply_chunks=[b"reply-", b"after-", b"multi-write\n"]
        ),
        client_payload=MULTIWRITE_REQUEST,
        expected_child_log=["received=request-before-multi-write", "saw_eof=yes"],
        expected_reply_chunks=[b"reply-", b"after-", b"multi-write\n"],
    ),
    TlsOnlyScenario(
        name="tls_only_network_eof_then_child_silent_exit",
        child_script=make_child_log_then_exit_script(),
        client_payload=SILENT_EXIT_REQUEST,
        expected_child_log=["received=request-before-silent-exit", "saw_eof=yes"],
    ),
    TlsOnlyScenario(
        name="tls_only_child_half_closes_without_plaintext_client_still_writes",
        child_script=make_child_half_close_then_log_script(),
        client_payload=SMALL_REQUEST,
        expected_child_log=["received=request-before-eof", "saw_eof=yes"],
    ),
]

HYBRID_SCENARIOS = [
    HybridScenario(
        name="hybrid_starttls_then_tls_reply_after_network_eof",
        child_script=make_child_starttls_then_reply_script(
            reply_chunks=[b"reply-after-eof\n"]
        ),
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        client_payload=SMALL_REQUEST,
        expected_child_log=["received=request-before-eof", "saw_eof=yes"],
        expected_reply_chunks=[b"reply-after-eof\n"],
    ),
    HybridScenario(
        name="hybrid_starttls_then_tls_reply_after_network_eof_without_plaintext",
        child_script=make_child_starttls_then_reply_script(
            reply_chunks=[b"reply-after-empty-eof\n"]
        ),
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        expected_child_log=["received=", "saw_eof=yes"],
        expected_reply_chunks=[b"reply-after-empty-eof\n"],
    ),
    HybridScenario(
        name="hybrid_starttls_then_tls_reply_after_network_eof_large_payload",
        child_script=make_child_starttls_then_reply_script(
            reply_chunks=[b"reply-after-large-eof\n"]
        ),
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        client_payload=BIG_REQUEST,
        expected_child_log=[
            f"received={BIG_REQUEST.decode('utf-8', errors='replace')}",
            "saw_eof=yes",
        ],
        expected_reply_chunks=[b"reply-after-large-eof\n"],
    ),
    HybridScenario(
        name="hybrid_starttls_then_tls_reply_after_network_eof_multiple_writes",
        child_script=make_child_starttls_then_reply_script(
            reply_chunks=[b"reply-", b"after-", b"multi-write\n"]
        ),
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        client_payload=MULTIWRITE_REQUEST,
        expected_child_log=["received=request-before-multi-write", "saw_eof=yes"],
        expected_reply_chunks=[b"reply-", b"after-", b"multi-write\n"],
    ),
    HybridScenario(
        name="hybrid_starttls_then_tls_network_eof_child_silent_exit",
        child_script=make_child_starttls_then_exit_script(),
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        client_payload=SILENT_EXIT_REQUEST,
        expected_child_log=["received=request-before-silent-exit", "saw_eof=yes"],
    ),
    HybridScenario(
        name="hybrid_starttls_then_child_half_closes_without_plaintext_client_still_writes",
        child_script=make_child_starttls_then_half_close_then_log_script(),
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        client_payload=SMALL_REQUEST,
        expected_child_log=["received=request-before-eof", "saw_eof=yes"],
    ),
    HybridScenario(
        name="hybrid_starttls_flushes_plaintext_before_tls",
        child_script=make_child_preplaintext_then_starttls_then_reply_script(
            pre_starttls_chunks=[PRETLS_GREETING],
            reply_chunks=[b"reply-after-eof\n"],
        ),
        expected_pre_tls_output_chunks=[PRETLS_GREETING, STARTTLS_BANNER],
        client_payload=SMALL_REQUEST,
        expected_child_log=["received=request-before-eof", "saw_eof=yes"],
        expected_reply_chunks=[b"reply-after-eof\n"],
    ),
]

TIMEOUT_SCENARIOS = [
    TimeoutScenario(
        name="delayed_idle_before_starttls_timeout",
        mode="delayed",
        child_script=make_child_log_then_exit_script(),
        expected_timeout=SHORT_HANDSHAKE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
    ),
    TimeoutScenario(
        name="delayed_post_activity_idle_timeout",
        mode="delayed",
        child_script=make_child_log_then_wait_for_more_input_script(
            read_size=len(IDLE_REQUEST)
        ),
        expected_timeout=SHORT_IDLE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
        driver="plaintext_then_stop",
        client_payload=IDLE_REQUEST,
        child_read_size=len(IDLE_REQUEST),
    ),
    TimeoutScenario(
        name="tls_only_stalled_handshake_timeout",
        mode="tls_only",
        child_script=make_child_log_then_exit_script(),
        expected_timeout=SHORT_HANDSHAKE_TIMEOUT,
        expected_returncode=111,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
    ),
    TimeoutScenario(
        name="tls_only_idle_after_handshake_timeout",
        mode="tls_only",
        child_script=make_child_log_then_exit_script(),
        expected_timeout=SHORT_IDLE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        driver="tls_handshake_only",
    ),
    TimeoutScenario(
        name="tls_only_post_handshake_activity_idle_timeout",
        mode="tls_only",
        child_script=make_child_log_then_wait_for_more_input_script(
            read_size=len(IDLE_REQUEST)
        ),
        expected_timeout=SHORT_IDLE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        driver="tls_handshake_then_write",
        client_payload=IDLE_REQUEST,
        child_read_size=len(IDLE_REQUEST),
    ),
    TimeoutScenario(
        name="hybrid_stalled_after_starttls_request_timeout",
        mode="hybrid",
        child_script=make_child_starttls_then_wait_script(),
        expected_timeout=SHORT_HANDSHAKE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
        driver="hybrid_expect_banner_then_stop",
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
    ),
    TimeoutScenario(
        name="hybrid_idle_after_handshake_timeout",
        mode="hybrid",
        child_script=make_child_starttls_then_exit_script(),
        expected_timeout=SHORT_IDLE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
        driver="hybrid_handshake_only",
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
    ),
    TimeoutScenario(
        name="hybrid_post_handshake_activity_idle_timeout",
        mode="hybrid",
        child_script=make_child_starttls_then_wait_for_more_input_script(
            read_size=len(IDLE_REQUEST)
        ),
        expected_timeout=SHORT_IDLE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
        driver="hybrid_handshake_then_write",
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        client_payload=IDLE_REQUEST,
        child_read_size=len(IDLE_REQUEST),
    ),
]


def make_child_eof_scenarios() -> list[ChildEofScenario]:
    """Build the matrix of child EOF propagation scenarios."""

    small_payload_chunks = [SMALL_REQUEST]
    large_payload_chunks = [BIG_REQUEST]
    chunked_payload_chunks = [b"request-", b"before-", b"multi-write"]
    small_reply_chunks = [b"reply-before-eof\n"]
    large_reply_chunks = [b"reply-chunk-" * 300, b"reply-tail\n"]

    payload_variants = [
        ("without_payload", [], b""),
        ("small_payload", small_payload_chunks, SMALL_REQUEST),
        ("large_payload", large_payload_chunks, BIG_REQUEST),
        ("chunked_payload", chunked_payload_chunks, b"".join(chunked_payload_chunks)),
    ]
    reply_variants = [
        ("reply_before_eof", small_payload_chunks, SMALL_REQUEST, small_reply_chunks),
        ("large_reply_before_eof", small_payload_chunks, SMALL_REQUEST, large_reply_chunks),
    ]
    mode_prefixes = {
        "delayed": "delayed",
        "tls_only": "tls_only",
        "hybrid": "hybrid_starttls_then",
    }

    scenarios: list[ChildEofScenario] = []
    for mode, prefix in mode_prefixes.items():
        for suffix, chunks, payload in payload_variants:
            expected_child_log = [
                f"received={payload.decode('utf-8', errors='replace')}",
                "read_complete=True",
            ]
            if mode == "hybrid":
                child_script = make_child_starttls_then_half_close_then_read_exact_script(
                    read_size=len(payload)
                )
                expected_pre_tls_output_chunks = [STARTTLS_BANNER]
            else:
                child_script = make_child_half_close_then_read_exact_script(
                    read_size=len(payload)
                )
                expected_pre_tls_output_chunks = []
            scenarios.append(
                ChildEofScenario(
                    name=f"{prefix}_child_half_close_propagates_"
                    f"{'plaintext' if mode == 'delayed' else 'tls'}_eof_before_client_half_close_{suffix}",
                    mode=mode,
                    child_script=child_script,
                    client_payload_chunks=chunks,
                    expected_child_log=expected_child_log,
                    expected_pre_tls_output_chunks=expected_pre_tls_output_chunks,
                )
            )

        for suffix, chunks, payload, reply_chunks in reply_variants:
            expected_child_log = [
                f"received={payload.decode('utf-8', errors='replace')}",
                "read_complete=True",
            ]
            if mode == "hybrid":
                child_script = (
                    make_child_starttls_then_reply_then_half_close_then_read_exact_script(
                        reply_chunks=reply_chunks,
                        read_size=len(payload),
                    )
                )
                expected_pre_tls_output_chunks = [STARTTLS_BANNER]
            else:
                child_script = make_child_reply_then_half_close_then_read_exact_script(
                    reply_chunks=reply_chunks,
                    read_size=len(payload),
                )
                expected_pre_tls_output_chunks = []
            scenarios.append(
                ChildEofScenario(
                    name=f"{prefix}_child_half_close_propagates_"
                    f"{'plaintext' if mode == 'delayed' else 'tls'}_eof_before_client_half_close_{suffix}",
                    mode=mode,
                    child_script=child_script,
                    client_payload_chunks=chunks,
                    expected_reply_chunks=reply_chunks,
                    expected_child_log=expected_child_log,
                    expected_pre_tls_output_chunks=expected_pre_tls_output_chunks,
                )
            )

    return scenarios


CHILD_EOF_SCENARIOS = make_child_eof_scenarios()


def make_child_log_then_wait_after_read_script(*, read_size: int, wait_seconds: float) -> str:
    """Create a child that reads one exact request, closes stdout, then waits."""

    return f"""import os
import sys
import time

remaining = {read_size}
chunks = []
while remaining:
    chunk = sys.stdin.buffer.read(remaining)
    if not chunk:
        break
    chunks.append(chunk)
    remaining -= len(chunk)
data = b"".join(chunks)

os.close(sys.stdout.fileno())
time.sleep({wait_seconds!r})

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write(f"read_complete={{remaining == 0}}\\n")
"""


def make_child_starttls_then_wait_after_read_script(*, read_size: int, wait_seconds: float) -> str:
    """Create a child that starts TLS, reads one request, closes stdout, then waits."""

    return f"""import os
import sys
import time

os.write(5, {STARTTLS_BANNER!r})
os.close(5)

remaining = {read_size}
chunks = []
while remaining:
    chunk = sys.stdin.buffer.read(remaining)
    if not chunk:
        break
    chunks.append(chunk)
    remaining -= len(chunk)
data = b"".join(chunks)

os.close(sys.stdout.fileno())
time.sleep({wait_seconds!r})

log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
if log_path is not None:
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        handle.write(f"read_complete={{remaining == 0}}\\n")
"""


def wrap_delayed_scenario(scenario: DelayedScenario) -> callable:
    """Build one runnable test function from a delayed scenario."""

    def test() -> None:
        run_delayed_scenario(scenario)

    return test


def wrap_tls_only_scenario(scenario: TlsOnlyScenario) -> callable:
    """Build one runnable test function from a TLS-only scenario."""

    def test() -> None:
        run_tls_only_scenario(scenario)

    return test


def wrap_hybrid_scenario(scenario: HybridScenario) -> callable:
    """Build one runnable test function from a hybrid scenario."""

    def test() -> None:
        run_hybrid_scenario(scenario)

    return test


def wrap_timeout_scenario(scenario: TimeoutScenario) -> callable:
    """Build one runnable test function from a timeout scenario."""

    def test() -> None:
        run_timeout_scenario(scenario)

    return test


def wrap_child_eof_scenario(scenario: ChildEofScenario) -> callable:
    """Build one runnable test function from a child EOF scenario."""

    def test() -> None:
        run_child_eof_scenario(scenario)

    return test


TESTS: dict[str, callable] = {}
TEST_GROUPS: dict[str, list[str]] = {
    "delayed": [],
    "tls-only": [],
    "hybrid": [],
    "child-eof": [],
    "socket-halfclose": [],
}

for scenario in DELAYED_SCENARIOS:
    TESTS[scenario.name] = wrap_delayed_scenario(scenario)
    TEST_GROUPS["delayed"].append(scenario.name)

for scenario in TLS_ONLY_SCENARIOS:
    TESTS[scenario.name] = wrap_tls_only_scenario(scenario)
    TEST_GROUPS["tls-only"].append(scenario.name)

for scenario in HYBRID_SCENARIOS:
    TESTS[scenario.name] = wrap_hybrid_scenario(scenario)
    TEST_GROUPS["hybrid"].append(scenario.name)

for scenario in TIMEOUT_SCENARIOS:
    TESTS[scenario.name] = wrap_timeout_scenario(scenario)
    TEST_GROUPS[scenario.mode.replace("_", "-")].append(scenario.name)

for scenario in CHILD_EOF_SCENARIOS:
    TESTS[scenario.name] = wrap_child_eof_scenario(scenario)
    TEST_GROUPS[scenario.mode.replace("_", "-")].append(scenario.name)
    TEST_GROUPS["child-eof"].append(scenario.name)

TESTS[
    "delayed_child_half_close_socket_peer_observes_eof_before_wrapper_exit"
] = test_delayed_child_half_close_socket_peer_observes_eof_before_wrapper_exit
TEST_GROUPS["delayed"].append(
    "delayed_child_half_close_socket_peer_observes_eof_before_wrapper_exit"
)
TEST_GROUPS["socket-halfclose"].append(
    "delayed_child_half_close_socket_peer_observes_eof_before_wrapper_exit"
)

TESTS[
    "tls_only_child_half_close_socket_peer_observes_eof_before_wrapper_exit"
] = test_tls_only_child_half_close_socket_peer_observes_eof_before_wrapper_exit
TEST_GROUPS["tls-only"].append(
    "tls_only_child_half_close_socket_peer_observes_eof_before_wrapper_exit"
)
TEST_GROUPS["socket-halfclose"].append(
    "tls_only_child_half_close_socket_peer_observes_eof_before_wrapper_exit"
)

TESTS[
    "hybrid_child_half_close_socket_peer_observes_eof_before_wrapper_exit"
] = test_hybrid_child_half_close_socket_peer_observes_eof_before_wrapper_exit
TEST_GROUPS["hybrid"].append(
    "hybrid_child_half_close_socket_peer_observes_eof_before_wrapper_exit"
)
TEST_GROUPS["socket-halfclose"].append(
    "hybrid_child_half_close_socket_peer_observes_eof_before_wrapper_exit"
)

TEST_ALIASES = {
    "control_pipe_eof_before_starttls": "delayed_control_pipe_eof_before_starttls",
    "tls_reply_after_network_eof": "tls_only_reply_after_network_eof",
    "tls_reply_after_network_eof_without_plaintext": (
        "tls_only_reply_after_network_eof_without_plaintext"
    ),
    "tls_reply_after_network_eof_large_payload": (
        "tls_only_reply_after_network_eof_large_payload"
    ),
    "tls_reply_after_network_eof_multiple_writes": (
        "tls_only_reply_after_network_eof_multiple_writes"
    ),
    "tls_network_eof_then_child_silent_exit": "tls_only_network_eof_then_child_silent_exit",
    "tls_child_half_closes_without_plaintext_client_still_writes": (
        "tls_only_child_half_closes_without_plaintext_client_still_writes"
    ),
}

for alias, target in TEST_ALIASES.items():
    TESTS[alias] = TESTS[target]

DEFAULT_TESTS = list(TESTS.keys())
ALL_TESTS = list(TESTS.keys())


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument("tests", nargs="*", help="Test names or groups to execute")
    parser.add_argument("--all-tests", action="store_true", help="Run all tests")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")
    return parser.parse_args(argv)


def configure_logging(debug: bool) -> None:
    """Configure application logging."""

    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")


def expand_requested_tests(names: list[str]) -> list[str]:
    """Expand explicit test names and the three top-level groups."""

    expanded: list[str] = []
    for name in names:
        if name in TEST_GROUPS:
            expanded.extend(TEST_GROUPS[name])
            continue
        expanded.append(name)
    return expanded


def main(argv: list[str] | None = None) -> int:
    """Run the selected generic tlswrapper regression tests."""

    args = parse_args(sys.argv[1:] if argv is None else argv)
    configure_logging(args.debug)

    if args.tests:
        names = expand_requested_tests(args.tests)
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
