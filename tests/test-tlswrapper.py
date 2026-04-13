#!/usr/bin/env python3

"""Regression tests for tlswrapper with descriptive step output.

Every observable action is printed so that failures on remote
architectures (e.g. riscv64) are easy to diagnose.

Directions (matching the wrapper C variable names):

    peerin   = peer writes  -> wrapper reads   (netinfd)
    peerout  = wrapper writes -> peer reads    (netoutfd)
    childin  = wrapper writes -> child reads   (childinfd)
    childout = child writes  -> wrapper reads  (childoutfd)
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import select
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

TIMEOUT = 4
EARLY_EXIT_TIMEOUT = 1.0
SHORT_IDLE_TIMEOUT = 1
SHORT_HANDSHAKE_TIMEOUT = 1
TIMEOUT_TOLERANCE = 1.5
CLEAN_SHUTDOWN_TOLERANCE = 0.8
WORKSPACE = Path(__file__).resolve().parent
LOGGER = logging.getLogger(__name__)
WRAPPER_EXECUTABLE = WORKSPACE / "tlswrapper-test"
CERT_PATH = WORKSPACE / "testcerts" / "okcert-ec-prime256v1-ec-prime256v1-ok.pem"
CHILD_LOG: Path = WORKSPACE / "test-tlswrapper-child.log"

STARTTLS_BANNER = b"220 ready for tls\n"
PRETLS_GREETING = b"220-plaintext-before-starttls\n"
SMALL_REQUEST = b"request-before-eof"
MULTIWRITE_REQUEST = b"request-before-multi-write"
SILENT_EXIT_REQUEST = b"request-before-silent-exit"
IDLE_REQUEST = b"idle-after-activity"
BIG_REQUEST = (b"request-chunk-" * 400) + b"tail"
BIG_REPLY_CHUNKS = [b"reply-chunk-" * 300, b"reply-tail\n"]


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

class TestFailure(Exception):
    pass


def step(msg: str) -> None:
    print(f"  {msg}", flush=True)


def step_ok(label: str, detail: str = "") -> None:
    suffix = f" {detail}" if detail else ""
    step(f"{label}:{suffix} ok")


def format_step_bytes(data: bytes, *, limit: int = 96) -> str:
    rendered = repr(data)
    if len(rendered) <= limit:
        return rendered
    return f"{data[:32]!r}...{data[-16:]!r} ({len(data)} bytes)"


# ---------------------------------------------------------------------------
# Wrapper process management
# ---------------------------------------------------------------------------

class Wrapper:

    def __init__(self, timeout: int = TIMEOUT) -> None:
        self.timeout = timeout
        self.proc: subprocess.Popen[bytes] | None = None
        self.peer_socket: socket.socket | None = None

    def start(
        self,
        child_script: str,
        *,
        delayed: bool = False,
        wrapper_timeout: int | None = None,
        handshake_timeout: int | None = None,
        socket_transport: bool = False,
    ) -> tuple[BinaryIO, BinaryIO] | None:
        env = os.environ.copy()
        env.update({
            "TCPREMOTEIP": "1.2.3.4", "TCPREMOTEPORT": "1234",
            "TCPLOCALIP": "1.2.3.4", "TCPLOCALPORT": "1234",
        })
        if CHILD_LOG.exists():
            CHILD_LOG.unlink()
        env["TLSWRAPPER_CHILD_LOG"] = str(CHILD_LOG)

        cmd = ["tlswrappernojail", "-Q"]
        if delayed:
            cmd.append("-n")
        if wrapper_timeout is not None:
            cmd.extend(["-t", str(wrapper_timeout)])
        if handshake_timeout is not None:
            cmd.extend(["-T", str(handshake_timeout)])
        cmd.extend(["-f", str(CERT_PATH), sys.executable, "-c", child_script])

        if socket_transport:
            peer_sock, child_sock = socket.socketpair()
            self.peer_socket = peer_sock
            try:
                self.proc = subprocess.Popen(
                    cmd, executable=str(WRAPPER_EXECUTABLE), cwd=WORKSPACE,
                    env=env, stdin=child_sock.fileno(), stdout=child_sock.fileno(),
                    stderr=subprocess.PIPE, close_fds=True,
                    pass_fds=(child_sock.fileno(),), preexec_fn=os.setsid,
                )
            finally:
                child_sock.close()
            return None
        else:
            self.proc = subprocess.Popen(
                cmd, executable=str(WRAPPER_EXECUTABLE), cwd=WORKSPACE,
                env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, preexec_fn=os.setsid,
            )
            assert self.proc.stdin is not None and self.proc.stdout is not None
            return self.proc.stdin, self.proc.stdout

    def wait(self, expected_rc: int = 0) -> None:
        assert self.proc is not None
        try:
            rc = self.proc.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise TestFailure("wrapper did not exit in time") from exc
        if rc != expected_rc:
            stderr = self._read_stderr()
            raise TestFailure(f"exit code {rc}, expected {expected_rc}: {stderr}")
        step_ok("exit", str(rc))

    def wait_raw(self) -> int:
        assert self.proc is not None
        try:
            return self.proc.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise TestFailure("wrapper did not exit in time") from exc

    def wait_early_exit(self) -> int:
        assert self.proc is not None
        try:
            return self.proc.wait(timeout=EARLY_EXIT_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            raise TestFailure("wrapper did not exit early as expected") from exc

    def _read_stderr(self) -> str:
        if self.proc and self.proc.stderr:
            try:
                return self.proc.stderr.read().decode("utf-8", errors="replace").strip()
            except OSError:
                pass
        return ""

    def close(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=1)
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                pass


# ---------------------------------------------------------------------------
# Plain pipe client (delayed mode)
# ---------------------------------------------------------------------------

class PlainClient:

    def __init__(self, stdin: BinaryIO, stdout: BinaryIO) -> None:
        self.stdin = stdin
        self.stdout = stdout

    def write(self, data: bytes, label: str = "peerin") -> None:
        self.stdin.write(data)
        self.stdin.flush()
        step_ok(label, format_step_bytes(data))

    def read_exact(self, size: int, label: str = "peerout") -> bytes:
        chunks: list[bytes] = []
        total = 0
        while total < size:
            ready, _, _ = select.select([self.stdout], [], [], TIMEOUT)
            if not ready:
                raise TestFailure(f"{label}: timed out after {total}/{size} bytes")
            chunk = os.read(self.stdout.fileno(), size - total)
            if not chunk:
                raise TestFailure(f"{label}: EOF after {total}/{size} bytes")
            chunks.append(chunk)
            total += len(chunk)
        result = b"".join(chunks)
        step_ok(label, repr(result))
        return result

    def expect_chunks(self, expected: list[bytes], label: str = "peerout") -> None:
        for chunk in expected:
            got = self.read_exact(len(chunk), label=label)
            if got != chunk:
                raise TestFailure(f"{label}: got {got!r}, expected {chunk!r}")

    def expect_eof(self, label: str = "peerout", timeout: float | None = None) -> None:
        wait = timeout if timeout is not None else TIMEOUT
        ready, _, _ = select.select([self.stdout], [], [], wait)
        if not ready:
            raise TestFailure(f"{label}: timed out waiting for EOF")
        chunk = os.read(self.stdout.fileno(), 1)
        if chunk != b"":
            raise TestFailure(f"{label}: expected EOF, got {chunk!r}")
        step_ok(label, "EOF")

    def half_close(self, label: str = "peerin") -> None:
        self.stdin.close()
        step_ok(label, "half-close")


# ---------------------------------------------------------------------------
# TLS pipe client
# ---------------------------------------------------------------------------

class TlsClient:

    def __init__(self, stdin: BinaryIO, stdout: BinaryIO) -> None:
        self.stdin = stdin
        self.stdout = stdout
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = ctx.wrap_bio(
            self.incoming, self.outgoing,
            server_side=False, server_hostname="localhost",
        )

    def handshake(self) -> None:
        while True:
            try:
                self.tls.do_handshake()
                self._flush()
                step_ok("handshake")
                return
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()

    def write(self, data: bytes, label: str = "peerin") -> None:
        remaining = memoryview(data)
        while remaining:
            try:
                n = self.tls.write(remaining)
                remaining = remaining[n:]
                self._flush()
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
        step_ok(label, format_step_bytes(data))

    def read_exact(self, size: int, label: str = "peerout") -> bytes:
        chunks: list[bytes] = []
        total = 0
        while total < size:
            try:
                chunk = self.tls.read(size - total)
                if not chunk:
                    raise TestFailure(f"{label}: EOF after {total}/{size} bytes")
                chunks.append(chunk)
                total += len(chunk)
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
            except ssl.SSLEOFError as exc:
                raise TestFailure(
                    f"{label}: TLS EOF after {total}/{size} bytes"
                ) from exc
        result = b"".join(chunks)
        step_ok(label, repr(result))
        return result

    def expect_chunks(self, expected: list[bytes], label: str = "peerout") -> None:
        for chunk in expected:
            got = self.read_exact(len(chunk), label=label)
            if got != chunk:
                raise TestFailure(f"{label}: got {got!r}, expected {chunk!r}")

    def expect_eof(self, label: str = "peerout") -> None:
        deadline = time.monotonic() + TIMEOUT
        while True:
            try:
                chunk = self.tls.read(1)
                if not chunk:
                    step_ok(label, "EOF")
                    return
                raise TestFailure(f"{label}: expected EOF, got {chunk!r}")
            except ssl.SSLWantReadError:
                self._flush()
                if time.monotonic() >= deadline:
                    raise TestFailure(f"{label}: timed out waiting for EOF")
                self._feed()
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
                step_ok(label, "EOF")
                return

    def expect_clean_eof(self, label: str = "peerout") -> None:
        deadline = time.monotonic() + TIMEOUT
        while True:
            try:
                chunk = self.tls.read(1)
                if not chunk:
                    step_ok(label, "clean EOF")
                    return
                raise TestFailure(f"{label}: expected clean EOF, got {chunk!r}")
            except ssl.SSLWantReadError:
                self._flush()
                if time.monotonic() >= deadline:
                    raise TestFailure(f"{label}: timed out waiting for clean EOF")
                self._feed()
            except ssl.SSLZeroReturnError:
                step_ok(label, "clean EOF")
                return
            except ssl.SSLEOFError as exc:
                raise TestFailure(
                    f"{label}: unexpected TLS EOF without close_notify"
                ) from exc

    def half_close(self, label: str = "peerin") -> None:
        self._flush()
        self.stdin.close()
        step_ok(label, "half-close")

    def close_read(self) -> None:
        self.stdout.close()
        step_ok("peerout", "closed")

    def _flush(self) -> None:
        data = self.outgoing.read()
        if data:
            self.stdin.write(data)
            self.stdin.flush()

    def _feed(self) -> None:
        ready, _, _ = select.select([self.stdout], [], [], TIMEOUT)
        if not ready:
            raise TestFailure("timed out waiting for TLS records from wrapper")
        data = os.read(self.stdout.fileno(), 65536)
        if not data:
            self.incoming.write_eof()
            return
        self.incoming.write(data)


# ---------------------------------------------------------------------------
# Socket clients (for socket transport tests)
# ---------------------------------------------------------------------------

class PlainSocketClient:

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def write(self, data: bytes, label: str = "peerin") -> None:
        self.sock.sendall(data)
        step_ok(label, repr(data))

    def expect_eof(self, label: str = "peerout", timeout: float | None = None) -> None:
        wait = timeout if timeout is not None else TIMEOUT
        ready, _, _ = select.select([self.sock], [], [], wait)
        if not ready:
            raise TestFailure(f"{label}: timed out waiting for EOF")
        chunk = self.sock.recv(1)
        if chunk != b"":
            raise TestFailure(f"{label}: expected EOF, got {chunk!r}")
        step_ok(label, "EOF")

    def half_close(self, label: str = "peerin") -> None:
        self.sock.shutdown(socket.SHUT_WR)
        step_ok(label, "half-close")


class TlsSocketClient:

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = ctx.wrap_bio(
            self.incoming, self.outgoing,
            server_side=False, server_hostname="localhost",
        )

    def handshake(self) -> None:
        while True:
            try:
                self.tls.do_handshake()
                self._flush()
                step_ok("handshake")
                return
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()

    def write(self, data: bytes, label: str = "peerin") -> None:
        remaining = memoryview(data)
        while remaining:
            try:
                n = self.tls.write(remaining)
                remaining = remaining[n:]
                self._flush()
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
        step_ok(label, repr(data))

    def expect_eof(self, label: str = "peerout", timeout: float | None = None) -> None:
        deadline = time.monotonic() + (timeout if timeout is not None else TIMEOUT)
        while True:
            try:
                chunk = self.tls.read(1)
                if not chunk:
                    step_ok(label, "EOF")
                    return
                raise TestFailure(f"{label}: expected EOF, got {chunk!r}")
            except ssl.SSLWantReadError:
                self._flush()
                if time.monotonic() >= deadline:
                    raise TestFailure(f"{label}: timed out waiting for EOF")
                self._feed(max(deadline - time.monotonic(), 0.0))
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
                step_ok(label, "EOF")
                return

    def half_close(self, label: str = "peerin") -> None:
        self._flush()
        self.sock.shutdown(socket.SHUT_WR)
        step_ok(label, "half-close")

    def read_exact(self, size: int, label: str = "peerout") -> bytes:
        chunks: list[bytes] = []
        total = 0
        while total < size:
            try:
                chunk = self.tls.read(size - total)
                if not chunk:
                    raise TestFailure(f"{label}: EOF after {total}/{size} bytes")
                chunks.append(chunk)
                total += len(chunk)
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
        result = b"".join(chunks)
        step_ok(label, repr(result))
        return result

    def expect_chunks(self, expected: list[bytes], label: str = "peerout") -> None:
        for chunk in expected:
            got = self.read_exact(len(chunk), label=label)
            if got != chunk:
                raise TestFailure(f"{label}: got {got!r}, expected {chunk!r}")

    def _flush(self) -> None:
        while True:
            data = self.outgoing.read()
            if not data:
                return
            self.sock.sendall(data)

    def _feed(self, timeout: float | None = None) -> None:
        wait = timeout if timeout is not None else TIMEOUT
        ready, _, _ = select.select([self.sock], [], [], wait)
        if not ready:
            raise TestFailure("timed out waiting for TLS records from wrapper")
        data = self.sock.recv(65536)
        if not data:
            self.incoming.write_eof()
            return
        self.incoming.write(data)


# ---------------------------------------------------------------------------
# Child log verification
# ---------------------------------------------------------------------------

def read_child_log() -> list[str]:
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        if CHILD_LOG.exists():
            lines = CHILD_LOG.read_text(encoding="utf-8").splitlines()
            if lines:
                return lines
        time.sleep(0.05)
    if not CHILD_LOG.exists():
        raise TestFailure("child did not produce a log")
    return CHILD_LOG.read_text(encoding="utf-8").splitlines()


def check_child_log(expected: list[str]) -> None:
    got = read_child_log()
    if got != expected:
        raise TestFailure(f"child log {got!r}, expected {expected!r}")
    step_ok("childlog", " ".join(expected))


# ---------------------------------------------------------------------------
# Child script generators
# ---------------------------------------------------------------------------

def child_close_control() -> str:
    return """import os, sys
os.close(5)
sys.stdin.buffer.read()
"""


def child_log_then_reply(reply_chunks: list[bytes], read_size: int | None = None) -> str:
    rc = f"sys.stdin.buffer.read({read_size})" if read_size else "sys.stdin.buffer.read()"
    return f"""import os, sys, time
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {rc}
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write("saw_eof=yes\\n")
for chunk in {reply_chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep(0.01)
"""


def child_log_then_exit(read_size: int | None = None) -> str:
    rc = f"sys.stdin.buffer.read({read_size})" if read_size else "sys.stdin.buffer.read()"
    return f"""import os, sys
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {rc}
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write("saw_eof=yes\\n")
"""


def child_log_then_wait_for_more(read_size: int) -> str:
    return f"""import os, sys
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = sys.stdin.buffer.read({read_size})
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write("saw_eof=yes\\n")
sys.stdin.buffer.read()
"""


def child_half_close_then_log(read_size: int | None = None) -> str:
    rc = f"sys.stdin.buffer.read({read_size})" if read_size else "sys.stdin.buffer.read()"
    return f"""import os, sys
os.close(sys.stdout.fileno())
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {rc}
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write("saw_eof=yes\\n")
"""


def child_half_close_then_read_exact(read_size: int) -> str:
    return f"""import os, sys
os.close(sys.stdout.fileno())
remaining = {read_size}
chunks = []
while remaining:
    chunk = sys.stdin.buffer.read(remaining)
    if not chunk: break
    chunks.append(chunk)
    remaining -= len(chunk)
data = b"".join(chunks)
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write(f"read_complete={{remaining == 0}}\\n")
"""


def child_reply_then_half_close_then_read_exact(
    reply_chunks: list[bytes], read_size: int,
) -> str:
    return f"""import os, sys, time
remaining = {read_size}
chunks = []
while remaining:
    chunk = sys.stdin.buffer.read(remaining)
    if not chunk: break
    chunks.append(chunk)
    remaining -= len(chunk)
data = b"".join(chunks)
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write(f"read_complete={{remaining == 0}}\\n")
for chunk in {reply_chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep(0.01)
os.close(sys.stdout.fileno())
"""


def child_close_stdin_send_chunks(chunks: list[bytes], pause: float = 0.05) -> str:
    return f"""import os, sys, time
os.close(sys.stdin.fileno())
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
if log_path is not None:
    with open(log_path, "w") as f:
        f.write("stdin_closed=yes\\n")
for chunk in {chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep({pause!r})
"""


def child_close_stdout_read_chunks(
    chunk_sizes: list[int], pause: float = 0.05, marker: bytes | None = None,
) -> str:
    mb = ""
    if marker is not None:
        mb = f"\nsys.stdout.buffer.write({marker!r})\nsys.stdout.buffer.flush()\n"
    return f"""import os, sys, time
{mb}
os.close(sys.stdout.fileno())
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
chunks = []
for size in {chunk_sizes!r}:
    chunk = sys.stdin.buffer.read(size)
    if not chunk: break
    chunks.append(chunk.decode("utf-8", errors="replace"))
    time.sleep({pause!r})
rest = sys.stdin.buffer.read()
if log_path is not None:
    with open(log_path, "w") as f:
        for i, c in enumerate(chunks):
            f.write(f"chunk{{i}}={{c}}\\n")
        f.write("saw_eof=yes\\n")
"""


def child_write_marker_then_close_stdout_verify_sha256(
    *,
    marker: bytes,
    read_size: int,
    expected_sha256: str,
    close_delay: float = 0.2,
    starttls: bool = False,
) -> str:
    prefix = _starttls_prefix() if starttls else ""
    return f"""import hashlib, os, sys, time
{prefix}sys.stdout.buffer.write({marker!r})
sys.stdout.buffer.flush()
time.sleep({close_delay!r})
os.close(sys.stdout.fileno())
remaining = {read_size}
h = hashlib.sha256()
while remaining:
    chunk = sys.stdin.buffer.read(min(65536, remaining))
    if not chunk:
        break
    h.update(chunk)
    remaining -= len(chunk)
tail = sys.stdin.buffer.read()
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"read_complete={{remaining == 0}}\\n")
        f.write(f"saw_eof={{tail == b''}}\\n")
        f.write(f"sha256_ok={{h.hexdigest() == ({expected_sha256!r})}}\\n")
"""


def child_send_chunks(chunks: list[bytes], pause: float = 0.05) -> str:
    return f"""import sys, time
for chunk in {chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep({pause!r})
"""


# --- STARTTLS variants (write banner to FD 5) ---

def _starttls_prefix() -> str:
    return f"os.write(5, {STARTTLS_BANNER!r})\nos.close(5)\n"


def child_starttls_then_reply(reply_chunks: list[bytes], read_size: int | None = None) -> str:
    rc = f"sys.stdin.buffer.read({read_size})" if read_size else "sys.stdin.buffer.read()"
    return f"""import os, sys, time
{_starttls_prefix()}
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {rc}
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write("saw_eof=yes\\n")
for chunk in {reply_chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep(0.01)
"""


def child_starttls_then_exit(read_size: int | None = None) -> str:
    rc = f"sys.stdin.buffer.read({read_size})" if read_size else "sys.stdin.buffer.read()"
    return f"""import os, sys
{_starttls_prefix()}
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {rc}
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write("saw_eof=yes\\n")
"""


def child_starttls_then_half_close_then_log(read_size: int | None = None) -> str:
    rc = f"sys.stdin.buffer.read({read_size})" if read_size else "sys.stdin.buffer.read()"
    return f"""import os, sys, time
{_starttls_prefix()}
time.sleep(0.05)
os.close(sys.stdout.fileno())
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {rc}
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write("saw_eof=yes\\n")
"""


def child_starttls_then_immediate_half_close() -> str:
    return f"""import os, sys
{_starttls_prefix()}
os.close(sys.stdout.fileno())
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = sys.stdin.buffer.read()
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write("saw_eof=yes\\n")
"""


def child_starttls_then_half_close_then_read_exact(read_size: int) -> str:
    return f"""import os, sys, time
{_starttls_prefix()}
time.sleep(0.05)
os.close(sys.stdout.fileno())
remaining = {read_size}
chunks = []
while remaining:
    chunk = sys.stdin.buffer.read(remaining)
    if not chunk: break
    chunks.append(chunk)
    remaining -= len(chunk)
data = b"".join(chunks)
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write(f"read_complete={{remaining == 0}}\\n")
"""


def child_starttls_then_close_stdout_read_chunks(
    chunk_sizes: list[int], pause: float = 0.05,
) -> str:
    return f"""import os, sys, time
{_starttls_prefix()}
os.close(sys.stdout.fileno())
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
chunks = []
for size in {chunk_sizes!r}:
    chunk = sys.stdin.buffer.read(size)
    if not chunk: break
    chunks.append(chunk.decode("utf-8", errors="replace"))
    time.sleep({pause!r})
rest = sys.stdin.buffer.read()
if log_path is not None:
    with open(log_path, "w") as f:
        for i, c in enumerate(chunks):
            f.write(f"chunk{{i}}={{c}}\\n")
        f.write("saw_eof=yes\\n")
"""


def child_starttls_then_reply_then_half_close_then_read_exact(
    reply_chunks: list[bytes], read_size: int,
) -> str:
    return f"""import os, sys, time
{_starttls_prefix()}
remaining = {read_size}
chunks = []
while remaining:
    chunk = sys.stdin.buffer.read(remaining)
    if not chunk: break
    chunks.append(chunk)
    remaining -= len(chunk)
data = b"".join(chunks)
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write(f"read_complete={{remaining == 0}}\\n")
for chunk in {reply_chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep(0.01)
os.close(sys.stdout.fileno())
"""


def child_starttls_then_wait() -> str:
    return f"""import os, sys
{_starttls_prefix()}
sys.stdin.buffer.read()
"""


def child_starttls_then_wait_for_more(read_size: int) -> str:
    return f"""import os, sys
{_starttls_prefix()}
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = sys.stdin.buffer.read({read_size})
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write("saw_eof=yes\\n")
sys.stdin.buffer.read()
"""


def child_preplaintext_then_starttls_then_reply(
    pre_chunks: list[bytes], reply_chunks: list[bytes],
    read_size: int | None = None,
) -> str:
    rc = f"sys.stdin.buffer.read({read_size})" if read_size else "sys.stdin.buffer.read()"
    return f"""import os, sys, time
for chunk in {pre_chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep(0.01)
{_starttls_prefix()}
log_path = os.environ.get("TLSWRAPPER_CHILD_LOG")
data = {rc}
if log_path is not None:
    with open(log_path, "w") as f:
        f.write(f"received={{data.decode('utf-8', errors='replace')}}\\n")
        f.write("saw_eof=yes\\n")
for chunk in {reply_chunks!r}:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    time.sleep(0.01)
"""


# ---------------------------------------------------------------------------
# Unified scenario dataclass and runner
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Scenario:
    name: str
    mode: str  # "delayed", "tls_only", "hybrid"
    child_script: str

    client_payload: bytes = b""
    client_payload_chunks: list[bytes] | None = None

    expected_child_log: list[str] | None = None
    expected_reply_chunks: list[bytes] = field(default_factory=list)
    expected_pre_tls_output_chunks: list[bytes] = field(default_factory=list)
    expected_returncode: int = 0

    expect_early_exit: bool = False
    expect_eof: bool = False


def run_scenario(s: Scenario) -> None:
    w = Wrapper()
    try:
        pipes = w.start(s.child_script, delayed=s.mode in ("delayed", "hybrid"))
        if s.expect_early_exit:
            rc = w.wait_early_exit()
            if rc != s.expected_returncode:
                raise TestFailure(f"exit code {rc}, expected {s.expected_returncode}")
            step_ok("exit", f"{rc} (early)")
            return
        assert pipes is not None
        stdin, stdout = pipes

        # plaintext phase (delayed reads/writes plain, hybrid reads banner then upgrades)
        if s.mode == "delayed":
            client = PlainClient(stdin, stdout)
        elif s.mode == "hybrid":
            plain = PlainClient(stdin, stdout)
            for chunk in s.expected_pre_tls_output_chunks:
                got = plain.read_exact(len(chunk), label="childout[plain]")
                if got != chunk:
                    raise TestFailure(f"childout[plain]: got {got!r}, expected {chunk!r}")
            client = TlsClient(stdin, stdout)
            client.handshake()
        else:  # tls_only
            client = TlsClient(stdin, stdout)
            client.handshake()

        # peerin: send payload
        if s.client_payload_chunks is not None:
            for chunk in s.client_payload_chunks:
                client.write(chunk)
        elif s.client_payload:
            client.write(s.client_payload)

        # peerin: half-close (unless expect_eof — then read first)
        if not s.expect_eof:
            client.half_close()

        # peerout: read expected reply
        if s.expected_reply_chunks:
            client.expect_chunks(s.expected_reply_chunks, label="childout")

        # peerout: expect EOF from child half-close
        if s.expect_eof:
            client.expect_eof(label="childout")
            client.half_close()

        w.wait(s.expected_returncode)
        if s.expected_child_log is not None:
            check_child_log(s.expected_child_log)
    finally:
        w.close()


# ---------------------------------------------------------------------------
# Timeout scenario runner
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TimeoutScenario:
    name: str
    mode: str
    child_script: str
    expected_timeout: float
    expected_returncode: int = 0
    wrapper_timeout: int | None = None
    handshake_timeout: int | None = None
    driver: str = "none"
    expected_pre_tls_output_chunks: list[bytes] = field(default_factory=list)
    client_payload: bytes = b""
    child_read_size: int | None = None


def run_timeout_scenario(s: TimeoutScenario) -> None:
    w = Wrapper(timeout=int(s.expected_timeout) + 4)
    try:
        pipes = w.start(
            s.child_script,
            delayed=s.mode in ("delayed", "hybrid"),
            wrapper_timeout=s.wrapper_timeout,
            handshake_timeout=s.handshake_timeout,
        )
        assert pipes is not None
        stdin, stdout = pipes

        # drive client up to the stall point
        if s.driver == "none":
            pass
        elif s.driver == "plaintext_then_stop":
            client = PlainClient(stdin, stdout)
            if s.client_payload:
                client.write(s.client_payload)
            step_ok("driver", "plaintext_then_stop")
        elif s.driver == "tls_handshake_only":
            client = TlsClient(stdin, stdout)
            client.handshake()
        elif s.driver == "tls_handshake_then_write":
            client = TlsClient(stdin, stdout)
            client.handshake()
            if s.client_payload:
                client.write(s.client_payload)
        elif s.driver == "hybrid_expect_banner_then_stop":
            plain = PlainClient(stdin, stdout)
            for chunk in s.expected_pre_tls_output_chunks:
                got = plain.read_exact(len(chunk), label="childout[plain]")
                if got != chunk:
                    raise TestFailure(f"childout[plain]: got {got!r}, expected {chunk!r}")
        elif s.driver == "hybrid_handshake_only":
            plain = PlainClient(stdin, stdout)
            for chunk in s.expected_pre_tls_output_chunks:
                got = plain.read_exact(len(chunk), label="childout[plain]")
                if got != chunk:
                    raise TestFailure(f"childout[plain]: got {got!r}, expected {chunk!r}")
            client = TlsClient(stdin, stdout)
            client.handshake()
        elif s.driver == "hybrid_handshake_then_write":
            plain = PlainClient(stdin, stdout)
            for chunk in s.expected_pre_tls_output_chunks:
                got = plain.read_exact(len(chunk), label="childout[plain]")
                if got != chunk:
                    raise TestFailure(f"childout[plain]: got {got!r}, expected {chunk!r}")
            client = TlsClient(stdin, stdout)
            client.handshake()
            if s.client_payload:
                client.write(s.client_payload)
        else:
            raise TestFailure(f"unknown driver: {s.driver}")

        started_at = time.monotonic()
        rc = w.wait_raw()
        elapsed = time.monotonic() - started_at

        if rc != s.expected_returncode:
            raise TestFailure(f"exit code {rc}, expected {s.expected_returncode}")

        lower = max(0.7, s.expected_timeout * 0.7)
        upper = s.expected_timeout + TIMEOUT_TOLERANCE
        if elapsed < lower or elapsed > upper:
            raise TestFailure(
                f"elapsed {elapsed:.2f}s, expected {lower:.2f}s..{upper:.2f}s"
            )
        step_ok("timeout", f"~{s.expected_timeout}s")
        step_ok("exit", str(rc))
    finally:
        w.close()


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------

def _received_log(payload: bytes) -> list[str]:
    return [f"received={payload.decode('utf-8', errors='replace')}", "saw_eof=yes"]


SCENARIOS: list[Scenario] = []

# --- Delayed data-flow scenarios ---
SCENARIOS += [
    Scenario(
        name="delayed_control_pipe_eof_before_starttls",
        mode="delayed", child_script=child_close_control(),
        expect_early_exit=True,
    ),
    Scenario(
        name="delayed_reply_after_eof",
        mode="delayed",
        child_script=child_log_then_reply([b"reply-after-eof\n"]),
        client_payload=SMALL_REQUEST,
        expected_child_log=_received_log(SMALL_REQUEST),
        expected_reply_chunks=[b"reply-after-eof\n"],
    ),
    Scenario(
        name="delayed_reply_after_eof_no_payload",
        mode="delayed",
        child_script=child_log_then_reply([b"reply-after-empty-eof\n"]),
        expected_child_log=_received_log(b""),
        expected_reply_chunks=[b"reply-after-empty-eof\n"],
    ),
    Scenario(
        name="delayed_reply_after_eof_large",
        mode="delayed",
        child_script=child_log_then_reply([b"reply-after-large-eof\n"]),
        client_payload=BIG_REQUEST,
        expected_child_log=_received_log(BIG_REQUEST),
        expected_reply_chunks=[b"reply-after-large-eof\n"],
    ),
    Scenario(
        name="delayed_reply_after_eof_multi_write",
        mode="delayed",
        child_script=child_log_then_reply([b"reply-", b"after-", b"multi-write\n"]),
        client_payload=MULTIWRITE_REQUEST,
        expected_child_log=_received_log(MULTIWRITE_REQUEST),
        expected_reply_chunks=[b"reply-", b"after-", b"multi-write\n"],
    ),
    Scenario(
        name="delayed_eof_child_silent_exit",
        mode="delayed",
        child_script=child_log_then_exit(),
        client_payload=SILENT_EXIT_REQUEST,
        expected_child_log=_received_log(SILENT_EXIT_REQUEST),
    ),
    Scenario(
        name="delayed_child_half_closes_client_writes",
        mode="delayed",
        child_script=child_half_close_then_log(),
        client_payload=SMALL_REQUEST,
        expected_child_log=_received_log(SMALL_REQUEST),
    ),
]

# --- TLS-only data-flow scenarios ---
SCENARIOS += [
    Scenario(
        name="tls_only_reply_after_eof",
        mode="tls_only",
        child_script=child_log_then_reply([b"reply-after-eof\n"]),
        client_payload=SMALL_REQUEST,
        expected_child_log=_received_log(SMALL_REQUEST),
        expected_reply_chunks=[b"reply-after-eof\n"],
    ),
    Scenario(
        name="tls_only_reply_after_eof_no_payload",
        mode="tls_only",
        child_script=child_log_then_reply([b"reply-after-empty-eof\n"]),
        expected_child_log=_received_log(b""),
        expected_reply_chunks=[b"reply-after-empty-eof\n"],
    ),
    Scenario(
        name="tls_only_reply_after_eof_large",
        mode="tls_only",
        child_script=child_log_then_reply([b"reply-after-large-eof\n"]),
        client_payload=BIG_REQUEST,
        expected_child_log=_received_log(BIG_REQUEST),
        expected_reply_chunks=[b"reply-after-large-eof\n"],
    ),
    Scenario(
        name="tls_only_reply_after_eof_multi_write",
        mode="tls_only",
        child_script=child_log_then_reply([b"reply-", b"after-", b"multi-write\n"]),
        client_payload=MULTIWRITE_REQUEST,
        expected_child_log=_received_log(MULTIWRITE_REQUEST),
        expected_reply_chunks=[b"reply-", b"after-", b"multi-write\n"],
    ),
    Scenario(
        name="tls_only_eof_child_silent_exit",
        mode="tls_only",
        child_script=child_log_then_exit(),
        client_payload=SILENT_EXIT_REQUEST,
        expected_child_log=_received_log(SILENT_EXIT_REQUEST),
    ),
    Scenario(
        name="tls_only_child_half_closes_client_writes",
        mode="tls_only",
        child_script=child_half_close_then_log(),
        client_payload=SMALL_REQUEST,
        expected_child_log=_received_log(SMALL_REQUEST),
    ),
    Scenario(
        name="tls_only_child_closes_stdin_sends_chunks",
        mode="tls_only",
        child_script=child_close_stdin_send_chunks([b"chunk-1-", b"chunk-2-", b"chunk-3\n"]),
        expected_child_log=["stdin_closed=yes"],
        expected_reply_chunks=[b"chunk-1-", b"chunk-2-", b"chunk-3\n"],
    ),
    Scenario(
        name="tls_only_child_closes_stdout_reads_chunks",
        mode="tls_only",
        child_script=child_close_stdout_read_chunks([7, 7, 4]),
        client_payload=b"chunk-0chunk-1tail",
        expected_child_log=["chunk0=chunk-0", "chunk1=chunk-1", "chunk2=tail", "saw_eof=yes"],
    ),
    Scenario(
        name="tls_only_peer_closes_write_child_sends_chunks",
        mode="tls_only",
        child_script=child_send_chunks([b"chunk-1-", b"chunk-2-", b"chunk-3\n"]),
        expected_reply_chunks=[b"chunk-1-", b"chunk-2-", b"chunk-3\n"],
    ),
]

# --- Hybrid (STARTTLS) data-flow scenarios ---
SCENARIOS += [
    Scenario(
        name="hybrid_reply_after_eof",
        mode="hybrid",
        child_script=child_starttls_then_reply([b"reply-after-eof\n"]),
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        client_payload=SMALL_REQUEST,
        expected_child_log=_received_log(SMALL_REQUEST),
        expected_reply_chunks=[b"reply-after-eof\n"],
    ),
    Scenario(
        name="hybrid_reply_after_eof_no_payload",
        mode="hybrid",
        child_script=child_starttls_then_reply([b"reply-after-empty-eof\n"]),
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        expected_child_log=_received_log(b""),
        expected_reply_chunks=[b"reply-after-empty-eof\n"],
    ),
    Scenario(
        name="hybrid_reply_after_eof_large",
        mode="hybrid",
        child_script=child_starttls_then_reply([b"reply-after-large-eof\n"]),
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        client_payload=BIG_REQUEST,
        expected_child_log=_received_log(BIG_REQUEST),
        expected_reply_chunks=[b"reply-after-large-eof\n"],
    ),
    Scenario(
        name="hybrid_reply_after_eof_multi_write",
        mode="hybrid",
        child_script=child_starttls_then_reply([b"reply-", b"after-", b"multi-write\n"]),
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        client_payload=MULTIWRITE_REQUEST,
        expected_child_log=_received_log(MULTIWRITE_REQUEST),
        expected_reply_chunks=[b"reply-", b"after-", b"multi-write\n"],
    ),
    Scenario(
        name="hybrid_eof_child_silent_exit",
        mode="hybrid",
        child_script=child_starttls_then_exit(),
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        client_payload=SILENT_EXIT_REQUEST,
        expected_child_log=_received_log(SILENT_EXIT_REQUEST),
    ),
    Scenario(
        name="hybrid_child_half_closes_client_writes",
        mode="hybrid",
        child_script=child_starttls_then_half_close_then_log(),
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        client_payload=SMALL_REQUEST,
        expected_child_log=_received_log(SMALL_REQUEST),
    ),
    Scenario(
        name="hybrid_plaintext_before_starttls",
        mode="hybrid",
        child_script=child_preplaintext_then_starttls_then_reply(
            [PRETLS_GREETING], [b"reply-after-eof\n"],
        ),
        expected_pre_tls_output_chunks=[PRETLS_GREETING, STARTTLS_BANNER],
        client_payload=SMALL_REQUEST,
        expected_child_log=_received_log(SMALL_REQUEST),
        expected_reply_chunks=[b"reply-after-eof\n"],
    ),
]

# --- Child EOF propagation matrix ---

_PAYLOAD_VARIANTS = [
    ("no_payload", [], b""),
    ("small", [SMALL_REQUEST], SMALL_REQUEST),
    ("large", [BIG_REQUEST], BIG_REQUEST),
    ("chunked", [b"request-", b"before-", b"multi-write"], b"request-before-multi-write"),
]
_REPLY_VARIANTS = [
    ("reply", [b"reply-before-eof\n"]),
    ("large_reply", [b"reply-chunk-" * 300, b"reply-tail\n"]),
]
_MODES = [
    ("delayed", "delayed"),
    ("tls_only", "tls_only"),
    ("hybrid", "hybrid"),
]


def _make_child_eof_scenarios() -> list[Scenario]:
    scenarios: list[Scenario] = []
    for mode_name, mode in _MODES:
        prefix = "hybrid" if mode == "hybrid" else mode_name
        for suffix, chunks, payload in _PAYLOAD_VARIANTS:
            expected_log = [
                f"received={payload.decode('utf-8', errors='replace')}",
                "read_complete=True",
            ]
            if mode == "hybrid":
                script = child_starttls_then_half_close_then_read_exact(len(payload))
                pre_tls = [STARTTLS_BANNER]
            else:
                script = child_half_close_then_read_exact(len(payload))
                pre_tls = []
            scenarios.append(Scenario(
                name=f"{prefix}_child_eof_{suffix}",
                mode=mode, child_script=script,
                client_payload_chunks=chunks,
                expected_child_log=expected_log,
                expected_pre_tls_output_chunks=pre_tls,
                expect_eof=True,
            ))

        for rsuffix, reply_chunks in _REPLY_VARIANTS:
            for suffix, chunks, payload in _PAYLOAD_VARIANTS:
                expected_log = [
                    f"received={payload.decode('utf-8', errors='replace')}",
                    "read_complete=True",
                ]
                if mode == "hybrid":
                    script = child_starttls_then_reply_then_half_close_then_read_exact(
                        reply_chunks=reply_chunks, read_size=len(payload),
                    )
                    pre_tls = [STARTTLS_BANNER]
                else:
                    script = child_reply_then_half_close_then_read_exact(
                        reply_chunks=reply_chunks, read_size=len(payload),
                    )
                    pre_tls = []
                scenarios.append(Scenario(
                    name=f"{prefix}_child_eof_{rsuffix}_{suffix}",
                    mode=mode, child_script=script,
                    client_payload_chunks=chunks,
                    expected_reply_chunks=reply_chunks,
                    expected_child_log=expected_log,
                    expected_pre_tls_output_chunks=pre_tls,
                    expect_eof=True,
                ))
    return scenarios


SCENARIOS += _make_child_eof_scenarios()

# --- Timeout scenarios ---

TIMEOUT_SCENARIOS: list[TimeoutScenario] = [
    TimeoutScenario(
        name="delayed_idle_before_starttls_timeout",
        mode="delayed", child_script=child_log_then_exit(),
        expected_timeout=SHORT_HANDSHAKE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
    ),
    TimeoutScenario(
        name="delayed_post_activity_idle_timeout",
        mode="delayed",
        child_script=child_log_then_wait_for_more(len(IDLE_REQUEST)),
        expected_timeout=SHORT_IDLE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
        driver="plaintext_then_stop",
        client_payload=IDLE_REQUEST,
        child_read_size=len(IDLE_REQUEST),
    ),
    TimeoutScenario(
        name="tls_only_stalled_handshake_timeout",
        mode="tls_only", child_script=child_log_then_exit(),
        expected_timeout=SHORT_HANDSHAKE_TIMEOUT,
        expected_returncode=111,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
    ),
    TimeoutScenario(
        name="tls_only_idle_after_handshake_timeout",
        mode="tls_only", child_script=child_log_then_exit(),
        expected_timeout=SHORT_IDLE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        driver="tls_handshake_only",
    ),
    TimeoutScenario(
        name="tls_only_post_handshake_activity_idle_timeout",
        mode="tls_only",
        child_script=child_log_then_wait_for_more(len(IDLE_REQUEST)),
        expected_timeout=SHORT_IDLE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        driver="tls_handshake_then_write",
        client_payload=IDLE_REQUEST,
        child_read_size=len(IDLE_REQUEST),
    ),
    TimeoutScenario(
        name="hybrid_stalled_after_starttls_timeout",
        mode="hybrid", child_script=child_starttls_then_wait(),
        expected_timeout=SHORT_HANDSHAKE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
        driver="hybrid_expect_banner_then_stop",
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
    ),
    TimeoutScenario(
        name="hybrid_immediate_child_half_close_timeout",
        mode="hybrid", child_script=child_starttls_then_immediate_half_close(),
        expected_timeout=SHORT_HANDSHAKE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
        driver="hybrid_expect_banner_then_stop",
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
    ),
    TimeoutScenario(
        name="hybrid_idle_after_handshake_timeout",
        mode="hybrid", child_script=child_starttls_then_exit(),
        expected_timeout=SHORT_IDLE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
        driver="hybrid_handshake_only",
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
    ),
    TimeoutScenario(
        name="hybrid_post_handshake_activity_idle_timeout",
        mode="hybrid",
        child_script=child_starttls_then_wait_for_more(len(IDLE_REQUEST)),
        expected_timeout=SHORT_IDLE_TIMEOUT,
        wrapper_timeout=SHORT_IDLE_TIMEOUT,
        handshake_timeout=SHORT_HANDSHAKE_TIMEOUT,
        driver="hybrid_handshake_then_write",
        expected_pre_tls_output_chunks=[STARTTLS_BANNER],
        client_payload=IDLE_REQUEST,
        child_read_size=len(IDLE_REQUEST),
    ),
]


# ---------------------------------------------------------------------------
# Custom test functions (socket transport, timing assertions, etc.)
# ---------------------------------------------------------------------------

def _halfclose_log() -> list[str]:
    return [
        f"received={SMALL_REQUEST.decode('utf-8', errors='replace')}",
        "read_complete=True",
    ]


def test_delayed_socket_eof_after_child_exit() -> None:
    w = Wrapper()
    try:
        w.start(
            child_log_then_exit(len(SMALL_REQUEST)),
            delayed=True, socket_transport=True,
        )
        assert w.peer_socket is not None
        client = PlainSocketClient(w.peer_socket)
        client.write(SMALL_REQUEST)
        client.expect_eof(timeout=1.0)
        w.wait()
        check_child_log(_received_log(SMALL_REQUEST))
    finally:
        w.close()


def test_tls_only_socket_eof_after_child_exit() -> None:
    w = Wrapper()
    try:
        w.start(
            child_log_then_exit(len(SMALL_REQUEST)),
            socket_transport=True,
        )
        assert w.peer_socket is not None
        client = TlsSocketClient(w.peer_socket)
        client.handshake()
        client.write(SMALL_REQUEST)
        client.expect_eof(timeout=1.0)
        client.half_close()
        w.wait()
        check_child_log(_received_log(SMALL_REQUEST))
    finally:
        w.close()


def test_hybrid_socket_eof_after_child_exit() -> None:
    w = Wrapper()
    try:
        w.start(
            child_starttls_then_exit(len(SMALL_REQUEST)),
            delayed=True, socket_transport=True,
        )
        assert w.peer_socket is not None
        plain = PlainSocketClient(w.peer_socket)
        # read STARTTLS banner as plaintext
        ready, _, _ = select.select([w.peer_socket], [], [], TIMEOUT)
        if not ready:
            raise TestFailure("timed out waiting for STARTTLS banner")
        banner = w.peer_socket.recv(len(STARTTLS_BANNER))
        if banner != STARTTLS_BANNER:
            raise TestFailure(f"expected STARTTLS banner, got {banner!r}")
        step_ok("childout[plain]", repr(banner))

        client = TlsSocketClient(w.peer_socket)
        client.handshake()
        client.write(SMALL_REQUEST)
        client.expect_eof(timeout=1.0)
        client.half_close()
        w.wait()
        check_child_log(_received_log(SMALL_REQUEST))
    finally:
        w.close()


def test_tls_only_fast_shutdown() -> None:
    w = Wrapper()
    try:
        pipes = w.start(child_log_then_exit())
        assert pipes is not None
        stdin, stdout = pipes
        client = TlsClient(stdin, stdout)
        client.handshake()
        client.write(SILENT_EXIT_REQUEST)
        client.half_close()

        started_at = time.monotonic()
        rc = w.wait_raw()
        elapsed = time.monotonic() - started_at

        stderr = w._read_stderr()
        if "signal received, tls phase interrupted" in stderr:
            raise TestFailure("waited for self-pipe alarm instead of clean shutdown")
        if rc != 0:
            raise TestFailure(f"exit code {rc}, expected 0")
        if elapsed > CLEAN_SHUTDOWN_TOLERANCE:
            raise TestFailure(f"elapsed {elapsed:.2f}s > {CLEAN_SHUTDOWN_TOLERANCE}s")
        step_ok("shutdown", "fast")
        step_ok("exit", str(rc))
        check_child_log(_received_log(SILENT_EXIT_REQUEST))
    finally:
        w.close()


def test_tls_only_child_eof_requires_close_notify() -> None:
    w = Wrapper()
    try:
        pipes = w.start(child_half_close_then_read_exact(len(SMALL_REQUEST)))
        assert pipes is not None
        stdin, stdout = pipes
        client = TlsClient(stdin, stdout)
        client.handshake()
        client.write(SMALL_REQUEST)
        client.expect_clean_eof(label="childout")
        client.half_close()
        w.wait()
        check_child_log(_halfclose_log())
    finally:
        w.close()


def test_tls_only_large_reply_complete_before_clean_eof() -> None:
    w = Wrapper()
    try:
        pipes = w.start(
            child_reply_then_half_close_then_read_exact(
                reply_chunks=BIG_REPLY_CHUNKS,
                read_size=len(SMALL_REQUEST),
            )
        )
        assert pipes is not None
        stdin, stdout = pipes
        client = TlsClient(stdin, stdout)
        client.handshake()
        client.write(SMALL_REQUEST)
        client.expect_chunks(BIG_REPLY_CHUNKS, label="childout")
        client.expect_clean_eof(label="childout")
        client.half_close()
        w.wait()
        check_child_log(_halfclose_log())
    finally:
        w.close()


def test_tls_only_peer_closes_read_child_reads() -> None:
    w = Wrapper()
    try:
        pipes = w.start(child_close_stdout_read_chunks([7, 7, 4]))
        assert pipes is not None
        stdin, stdout = pipes
        client = TlsClient(stdin, stdout)
        client.handshake()
        step_ok("childout", "closed by child")
        client.write(b"chunk-0chunk-1tail")
        client.close_read()
        client.half_close()
        try:
            rc = w.proc.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            raise TestFailure("wrapper did not exit in time") from exc
        if rc != 0:
            raise TestFailure(f"exit code {rc}, expected 0")
        step_ok("exit", str(rc))
        check_child_log(["chunk0=chunk-0", "chunk1=chunk-1", "chunk2=tail", "saw_eof=yes"])
    finally:
        w.close()


def test_tls_only_child_closes_stdout_idle_peer_finishes() -> None:
    """After child stdout EOF, an idle peer should not keep child stdin open."""
    MARKER = b"ready"
    w = Wrapper()
    try:
        pipes = w.start(child_close_stdout_read_chunks([7, 7, 4], marker=MARKER))
        assert pipes is not None
        stdin, stdout = pipes
        client = TlsClient(stdin, stdout)
        client.handshake()
        marker = client.read_exact(len(MARKER), label="childout")
        if marker != MARKER:
            raise TestFailure(f"expected marker {MARKER!r}, got {marker!r}")
        step("childout: closed by child (waiting 0.2s)")
        time.sleep(0.2)
        w.wait()
        check_child_log(["saw_eof=yes"])
    finally:
        w.close()


def test_tls_only_large_inflight_payload_survives_child_stdout_close() -> None:
    """Verify an in-flight large client payload still reaches child stdin."""
    marker = b"ready-over-tls"
    payload = (b"inflight-payload-" * 16384) + b"tail"
    expected_sha256 = hashlib.sha256(payload).hexdigest()
    errors: list[Exception] = []

    w = Wrapper()
    try:
        pipes = w.start(
            child_write_marker_then_close_stdout_verify_sha256(
                marker=marker,
                read_size=len(payload),
                expected_sha256=expected_sha256,
                close_delay=0.2,
            )
        )
        assert pipes is not None
        stdin, stdout = pipes
        client = TlsClient(stdin, stdout)
        client.handshake()
        got_marker = client.read_exact(len(marker), label="childout")
        if got_marker != marker:
            raise TestFailure(f"expected marker {marker!r}, got {got_marker!r}")

        def writer() -> None:
            try:
                client.write(payload)
                client.half_close()
            except Exception as exc:
                errors.append(exc)

        writer_thread = threading.Thread(
            target=writer,
            name="tls-only-large-inflight-payload",
        )
        writer_thread.start()
        writer_thread.join(timeout=TIMEOUT + 1)
        if writer_thread.is_alive():
            raise TestFailure("peerin: timed out sending large inflight payload")
        if errors:
            raise errors[0]

        w.wait()
        check_child_log([
            "read_complete=True",
            "saw_eof=True",
            "sha256_ok=True",
        ])
    finally:
        w.close()


def test_hybrid_large_inflight_payload_survives_child_stdout_close() -> None:
    """Verify a large in-flight TLS payload survives child stdout close in STARTTLS mode."""
    marker = b"ready-over-tls"
    payload = (b"inflight-payload-" * 16384) + b"tail"
    expected_sha256 = hashlib.sha256(payload).hexdigest()
    errors: list[Exception] = []

    w = Wrapper()
    try:
        pipes = w.start(
            child_write_marker_then_close_stdout_verify_sha256(
                marker=marker,
                read_size=len(payload),
                expected_sha256=expected_sha256,
                close_delay=0.2,
                starttls=True,
            ),
            delayed=True,
        )
        assert pipes is not None
        stdin, stdout = pipes
        plain = PlainClient(stdin, stdout)
        got_banner = plain.read_exact(len(STARTTLS_BANNER), label="childout[plain]")
        if got_banner != STARTTLS_BANNER:
            raise TestFailure(f"expected banner {STARTTLS_BANNER!r}, got {got_banner!r}")
        client = TlsClient(stdin, stdout)
        client.handshake()
        got_marker = client.read_exact(len(marker), label="childout")
        if got_marker != marker:
            raise TestFailure(f"expected marker {marker!r}, got {got_marker!r}")

        def writer() -> None:
            try:
                client.write(payload)
                client.half_close()
            except Exception as exc:
                errors.append(exc)

        writer_thread = threading.Thread(
            target=writer,
            name="hybrid-large-inflight-payload",
        )
        writer_thread.start()
        writer_thread.join(timeout=TIMEOUT + 1)
        if writer_thread.is_alive():
            raise TestFailure("peerin: timed out sending large inflight payload")
        if errors:
            raise errors[0]

        w.wait()
        check_child_log([
            "read_complete=True",
            "saw_eof=True",
            "sha256_ok=True",
        ])
    finally:
        w.close()


def test_hybrid_child_closes_stdout_idle_peer_finishes() -> None:
    """After child stdout EOF in STARTTLS mode, an idle peer should not block shutdown."""
    w = Wrapper()
    try:
        pipes = w.start(
            child_starttls_then_close_stdout_read_chunks([7, 7, 4]),
            delayed=True,
        )
        assert pipes is not None
        stdin, stdout = pipes
        plain = PlainClient(stdin, stdout)
        banner = plain.read_exact(len(STARTTLS_BANNER), label="childout[plain]")
        if banner != STARTTLS_BANNER:
            raise TestFailure(f"expected STARTTLS banner, got {banner!r}")
        client = TlsClient(stdin, stdout)
        client.handshake()
        step("childout: closed by child (waiting 0.2s)")
        time.sleep(0.2)
        w.wait()
        check_child_log(["saw_eof=yes"])
    finally:
        w.close()


# ---------------------------------------------------------------------------
# Test registry and main
# ---------------------------------------------------------------------------

TESTS: dict[str, callable] = {}

for _s in SCENARIOS:
    def _make(s: Scenario = _s) -> callable:
        def test() -> None:
            run_scenario(s)
        return test
    TESTS[_s.name] = _make()

for _ts in TIMEOUT_SCENARIOS:
    def _make_t(s: TimeoutScenario = _ts) -> callable:
        def test() -> None:
            run_timeout_scenario(s)
        return test
    TESTS[_ts.name] = _make_t()

TESTS["delayed_socket_eof_after_child_exit"] = test_delayed_socket_eof_after_child_exit
TESTS["tls_only_socket_eof_after_child_exit"] = test_tls_only_socket_eof_after_child_exit
TESTS["hybrid_socket_eof_after_child_exit"] = test_hybrid_socket_eof_after_child_exit
TESTS["tls_only_fast_shutdown"] = test_tls_only_fast_shutdown
TESTS["tls_only_child_eof_requires_close_notify"] = test_tls_only_child_eof_requires_close_notify
TESTS["tls_only_large_reply_complete_before_clean_eof"] = test_tls_only_large_reply_complete_before_clean_eof
TESTS["tls_only_peer_closes_read_child_reads"] = test_tls_only_peer_closes_read_child_reads
TESTS["tls_only_child_closes_stdout_idle_peer_finishes"] = test_tls_only_child_closes_stdout_idle_peer_finishes
TESTS["tls_only_large_inflight_payload_survives_child_stdout_close"] = test_tls_only_large_inflight_payload_survives_child_stdout_close
TESTS["hybrid_large_inflight_payload_survives_child_stdout_close"] = test_hybrid_large_inflight_payload_survives_child_stdout_close
TESTS["hybrid_child_closes_stdout_idle_peer_finishes"] = test_hybrid_child_closes_stdout_idle_peer_finishes


def main() -> int:
    global CHILD_LOG

    parser = argparse.ArgumentParser()
    parser.add_argument("tests", nargs="*", help="Test names to execute")
    parser.add_argument(
        "--child-log",
        required=True,
        help="Path to the child transcript log file",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    CHILD_LOG = Path(args.child_log)

    names = args.tests or list(TESTS.keys())

    failed = 0
    for name in names:
        fn = TESTS.get(name)
        if fn is None:
            print(f"unknown test: {name}", file=sys.stderr)
            return 2

        print(f"=== {name} ===")
        if CHILD_LOG.exists():
            CHILD_LOG.unlink()
        try:
            fn()
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
