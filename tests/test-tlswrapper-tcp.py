#!/usr/bin/env python3

import argparse
import logging
import os
import select
import signal
import socket
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import BinaryIO


HOST = "127.0.0.1"
TIMEOUT = 4
LARGE_PAYLOAD = b"y" * (128 * 1024)
LOGGER = logging.getLogger(__name__)


class TestFailure(Exception):
    """Raised when a TCP test scenario fails."""

    pass


class TestTcpServer:
    """Manage one test peer plus one tlswrapper client process."""

    def __init__(self, host: str, timeout: int) -> None:
        """Start the local TCP server and connect `tlswrappernojail-tcp`."""

        self.host = host
        self.timeout = timeout
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((self.host, 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.conn: socket.socket | None = None
        self.stdin: BinaryIO | None = None
        self.stdout: BinaryIO | None = None
        self.stderr: BinaryIO | None = None

        cmd = ["./tlswrappernojail-tcp", "-v", "-t5", "-T3", host, str(self.port)]
        LOGGER.debug("Starting wrapper process: %s", " ".join(cmd))
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )

        self.listener.settimeout(self.timeout)
        try:
            LOGGER.debug("Waiting for wrapper to connect to %s:%d", self.host, self.port)
            self.conn, _ = self.listener.accept()
        except socket.timeout as exc:
            if self.proc.poll() is None:
                LOGGER.debug("Wrapper did not connect in time, terminating process group")
                try:
                    os.killpg(self.proc.pid, signal.SIGTERM)
                    self.proc.wait(timeout=1)
                except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                    LOGGER.debug("Wrapper termination after timeout did not complete cleanly")
                    pass

            stderr = self.proc.stderr.read() if self.proc.stderr is not None else b""
            if stderr:
                raise TestFailure(
                    f"tlswrappernojail-tcp did not connect: {stderr.decode('utf-8', errors='replace').strip()}"
                ) from exc
            raise TestFailure("Timed out waiting for tlswrappernojail-tcp to connect") from exc

        LOGGER.debug("Wrapper connected from %s", self.conn.getpeername())
        self.conn.settimeout(self.timeout)
        self.stdin = self.proc.stdin
        self.stdout = self.proc.stdout
        self.stderr = self.proc.stderr

    def close(self) -> None:
        """Close sockets, pipes, and the child process."""

        if self.conn is not None:
            try:
                LOGGER.debug("Closing accepted TCP connection")
                self.conn.close()
            except OSError:
                LOGGER.debug("Ignoring error while closing accepted TCP connection")
                pass
            self.conn = None

        try:
            LOGGER.debug("Closing listening socket")
            self.listener.close()
        except OSError:
            LOGGER.debug("Ignoring error while closing listening socket")
            pass

        if self.stdin is not None:
            try:
                LOGGER.debug("Closing wrapper stdin")
                self.stdin.close()
            except OSError:
                LOGGER.debug("Ignoring error while closing wrapper stdin")
                pass
            self.stdin = None

        if self.stdout is not None:
            try:
                LOGGER.debug("Closing wrapper stdout")
                self.stdout.close()
            except OSError:
                LOGGER.debug("Ignoring error while closing wrapper stdout")
                pass
            self.stdout = None

        if self.stderr is not None:
            try:
                LOGGER.debug("Closing wrapper stderr")
                self.stderr.close()
            except OSError:
                LOGGER.debug("Ignoring error while closing wrapper stderr")
                pass
            self.stderr = None

        if self.proc.poll() is None:
            try:
                LOGGER.debug("Terminating wrapper process group")
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=1)
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                LOGGER.debug("Ignoring error while terminating wrapper process group")
                pass

    def wait_for_exit(self, expected_returncode: int = 0) -> None:
        """Wait for wrapper exit and verify the return code."""

        try:
            LOGGER.debug("Waiting for wrapper process to exit")
            returncode = self.proc.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise TestFailure("Wrapper did not exit in time") from exc

        stderr = b""
        if self.stderr is not None:
            try:
                stderr = self.stderr.read()
            except OSError:
                stderr = b""

        if returncode != expected_returncode:
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            raise TestFailure(
                f"Wrapper exited with {returncode}, expected {expected_returncode}: {stderr_text}"
            )

        LOGGER.debug("Wrapper exited with rc=%s", returncode)

    def __enter__(self) -> "TestTcpServer":
        """Return the active test server context."""

        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        """Close all resources when leaving the context manager."""

        self.close()

    def _read_pipe_exact(self, size: int) -> bytes:
        chunks = []
        remaining = size

        while remaining > 0:
            if self.stdout is None:
                raise TestFailure("Client stdout is not available")

            LOGGER.debug("Waiting for %s bytes from wrapper stdout", remaining)
            ready, _, _ = select.select([self.stdout], [], [], self.timeout)
            if not ready:
                raise TestFailure("Client read timed out")

            data = os.read(self.stdout.fileno(), remaining)
            if not data:
                raise TestFailure("Client read EOF before expected data arrived")

            LOGGER.debug("Received %r from wrapper stdout", data)
            chunks.append(data)
            remaining -= len(data)

        return b"".join(chunks)

    def _read_socket_exact(self, size: int) -> bytes:
        chunks = []
        remaining = size

        while remaining > 0:
            if self.conn is None:
                raise TestFailure("Server socket is not available")

            LOGGER.debug("Waiting for %s bytes from remote peer socket", remaining)
            data = self.conn.recv(remaining)
            if not data:
                raise TestFailure("Server read EOF before expected data arrived")
            LOGGER.debug("Received %r from remote peer socket", data)
            chunks.append(data)
            remaining -= len(data)

        return b"".join(chunks)

    def client_write(self, data: bytes = b"") -> None:
        """Write bytes to wrapper stdin."""

        if self.stdin is None:
            raise TestFailure("Client stdin is not available")

        LOGGER.debug("Writing %r to wrapper stdin", data)
        self.stdin.write(data)
        self.stdin.flush()

    def client_read(self, expected: bytes = b"") -> None:
        """Read bytes from wrapper stdout and compare them."""

        data = self._read_pipe_exact(len(expected))
        if data != expected:
            raise TestFailure(f"Client read failed, data={data!r}, expected={expected!r}")
        LOGGER.debug("Wrapper stdout matched expected payload %r", expected)

    def server_read(self, expected: bytes = b"") -> None:
        """Read bytes from the accepted socket and compare them."""

        data = self._read_socket_exact(len(expected))
        if data != expected:
            raise TestFailure(f"Server read failed, data={data!r}, expected={expected!r}")
        LOGGER.debug("Server socket matched expected payload %r", expected)

    def server_write(self, data: bytes = b"") -> None:
        """Write bytes to the accepted socket."""

        if self.conn is None:
            raise TestFailure("Server socket is not available")

        LOGGER.debug("Writing %r to remote peer socket", data)
        self.conn.sendall(data)

    def client_half_close(self) -> None:
        """Close the wrapper stdin to signal EOF to the remote peer."""

        if self.stdin is None:
            raise TestFailure("Client stdin is not available")

        LOGGER.debug("Half-closing wrapper stdin")
        self.stdin.close()
        self.stdin = None

    def server_half_close(self) -> None:
        """Shutdown the write-half of the accepted socket."""

        if self.conn is None:
            raise TestFailure("Server socket is not available")

        LOGGER.debug("Half-closing remote peer socket write-half")
        self.conn.shutdown(socket.SHUT_WR)

    def server_expect_eof(self) -> None:
        """Verify that the accepted socket has reached EOF."""

        if self.conn is None:
            raise TestFailure("Server socket is not available")

        LOGGER.debug("Waiting for EOF on remote peer socket")
        data = self.conn.recv(1)
        if data != b"":
            raise TestFailure(f"Server expected EOF, received {data!r}")
        LOGGER.debug("Remote peer socket reached EOF")

    def server_close_connection(self) -> None:
        """Close the accepted socket without touching the listener."""

        if self.conn is None:
            raise TestFailure("Server socket is not available")

        LOGGER.debug("Closing accepted socket from test scenario")
        self.conn.close()
        self.conn = None

    def client_expect_eof(self) -> None:
        """Verify that wrapper stdout has reached EOF."""

        if self.stdout is None:
            raise TestFailure("Client stdout is not available")

        LOGGER.debug("Waiting for EOF on wrapper stdout")
        ready, _, _ = select.select([self.stdout], [], [], self.timeout)
        if not ready:
            raise TestFailure("Client EOF read timed out")

        data = os.read(self.stdout.fileno(), 1)
        if data != b"":
            raise TestFailure(f"Client expected EOF, received {data!r}")
        LOGGER.debug("Wrapper stdout reached EOF")


def test_server_pings_first() -> None:
    """Verify that data flows correctly when the server writes first."""

    LOGGER.debug("Starting scenario: server_pings_first")
    with TestTcpServer(HOST, TIMEOUT) as test:
        test.server_write(b"ping")
        test.client_read(b"ping")
        test.client_write(b"pong")
        test.server_read(b"pong")
    LOGGER.debug("Finished scenario: server_pings_first")


def test_client_pings_first() -> None:
    """Verify that data flows correctly when the client writes first."""

    LOGGER.debug("Starting scenario: client_pings_first")
    with TestTcpServer(HOST, TIMEOUT) as test:
        test.client_write(b"ping")
        test.server_read(b"ping")
        test.server_write(b"pong")
        test.client_read(b"pong")
    LOGGER.debug("Finished scenario: client_pings_first")


def test_reply_after_client_eof() -> None:
    """Verify delayed reply is forwarded only after peer sees client EOF."""

    LOGGER.debug("Starting scenario: reply_after_client_eof")
    with TestTcpServer(HOST, TIMEOUT) as test:
        request = b"request-before-eof"
        reply = b"reply-after-eof\n"

        test.client_write(request)
        test.client_half_close()
        test.server_read(request)
        test.server_expect_eof()
        test.server_write(reply)
        test.server_close_connection()
        test.client_read(reply)
        test.client_expect_eof()
        test.wait_for_exit()

    LOGGER.debug("Finished scenario: reply_after_client_eof")


def test_reply_after_empty_client_eof() -> None:
    """Verify delayed reply is forwarded even when stdin closes immediately."""

    LOGGER.debug("Starting scenario: reply_after_empty_client_eof")
    with TestTcpServer(HOST, TIMEOUT) as test:
        reply = b"reply-after-empty-eof\n"

        test.client_half_close()
        test.server_expect_eof()
        test.server_write(reply)
        test.server_close_connection()
        test.client_read(reply)
        test.client_expect_eof()
        test.wait_for_exit()

    LOGGER.debug("Finished scenario: reply_after_empty_client_eof")


def test_remote_silent_close() -> None:
    """Verify wrapper exits cleanly when the peer closes without replying."""

    LOGGER.debug("Starting scenario: remote_silent_close")
    with TestTcpServer(HOST, TIMEOUT) as test:
        request = b"request-before-silent-close"

        test.client_write(request)
        test.client_half_close()
        test.server_read(request)
        test.server_expect_eof()
        test.server_close_connection()
        test.client_expect_eof()
        test.wait_for_exit()

    LOGGER.debug("Finished scenario: remote_silent_close")


def test_both_sides_ping_simultaneously() -> None:
    """Verify both directions work when both peers start writing together."""

    LOGGER.debug("Starting scenario: both_sides_ping_simultaneously")
    with TestTcpServer(HOST, TIMEOUT) as test:
        barrier = threading.Barrier(2)
        errors: list[Exception] = []

        def client_flow() -> None:
            try:
                LOGGER.debug("Client flow waiting at barrier")
                barrier.wait(timeout=test.timeout)
                test.client_write(b"ping")
                test.client_read(b"pong")
            except Exception as exc:
                errors.append(exc)

        def server_flow() -> None:
            try:
                LOGGER.debug("Server flow waiting at barrier")
                barrier.wait(timeout=test.timeout)
                test.server_write(b"pong")
                test.server_read(b"ping")
            except Exception as exc:
                errors.append(exc)

        client_thread = threading.Thread(target=client_flow, name="client-simultaneous")
        server_thread = threading.Thread(target=server_flow, name="server-simultaneous")
        client_thread.start()
        server_thread.start()
        client_thread.join(timeout=test.timeout + 1)
        server_thread.join(timeout=test.timeout + 1)

        if client_thread.is_alive() or server_thread.is_alive():
            raise TestFailure("Simultaneous ping threads did not finish in time")
        if errors:
            raise errors[0]

    LOGGER.debug("Finished scenario: both_sides_ping_simultaneously")


def test_both_sides_half_close_after_pong() -> None:
    """Verify both peers can exchange data and half-close simultaneously."""

    LOGGER.debug("Starting scenario: both_sides_half_close_after_pong")
    with TestTcpServer(HOST, TIMEOUT) as test:
        start_barrier = threading.Barrier(2)
        half_close_barrier = threading.Barrier(2)
        errors: list[Exception] = []

        def client_flow() -> None:
            try:
                LOGGER.debug("Client half-close flow waiting at start barrier")
                start_barrier.wait(timeout=test.timeout)
                test.client_write(b"ping")
                test.client_read(b"pong")
                LOGGER.debug("Client half-close flow waiting at half-close barrier")
                half_close_barrier.wait(timeout=test.timeout)
                test.client_half_close()
                test.client_expect_eof()
            except Exception as exc:
                errors.append(exc)

        def server_flow() -> None:
            try:
                LOGGER.debug("Server half-close flow waiting at start barrier")
                start_barrier.wait(timeout=test.timeout)
                test.server_write(b"pong")
                test.server_read(b"ping")
                LOGGER.debug("Server half-close flow waiting at half-close barrier")
                half_close_barrier.wait(timeout=test.timeout)
                test.server_half_close()
                test.server_expect_eof()
            except Exception as exc:
                errors.append(exc)

        client_thread = threading.Thread(
            target=client_flow,
            name="client-both-half-close-after-pong",
        )
        server_thread = threading.Thread(
            target=server_flow,
            name="server-both-half-close-after-pong",
        )
        client_thread.start()
        server_thread.start()
        client_thread.join(timeout=test.timeout + 1)
        server_thread.join(timeout=test.timeout + 1)

        if client_thread.is_alive() or server_thread.is_alive():
            raise TestFailure("Both-sides half-close threads did not finish in time")
        if errors:
            raise errors[0]

    LOGGER.debug("Finished scenario: both_sides_half_close_after_pong")


def test_server_half_closes_after_pong() -> None:
    """Verify client-to-server traffic still works after server half-close."""

    LOGGER.debug("Starting scenario: server_half_closes_after_pong")
    with TestTcpServer(HOST, TIMEOUT) as test:
        test.client_write(b"ping")
        test.server_read(b"ping")
        test.server_write(b"pong")
        test.server_half_close()
        test.client_read(b"pong")
        test.client_write(b"ping")
        test.server_read(b"ping")
        test.client_half_close()
        test.server_expect_eof()
        test.client_expect_eof()
    LOGGER.debug("Finished scenario: server_half_closes_after_pong")


def test_client_half_closes_after_pong() -> None:
    """Verify server-to-client traffic still works after client half-close."""

    LOGGER.debug("Starting scenario: client_half_closes_after_pong")
    with TestTcpServer(HOST, TIMEOUT) as test:
        test.server_write(b"ping")
        test.client_read(b"ping")
        test.client_write(b"pong")
        test.client_half_close()
        test.server_read(b"pong")
        test.server_expect_eof()
        test.server_write(b"ping")
        test.client_read(b"ping")
    LOGGER.debug("Finished scenario: client_half_closes_after_pong")


def test_server_half_closes_without_sending_data_client_still_writes() -> None:
    """Verify client traffic still works after server half-close without data."""

    LOGGER.debug(
        "Starting scenario: server_half_closes_without_sending_data_client_still_writes"
    )
    with TestTcpServer(HOST, TIMEOUT) as test:
        test.server_half_close()
        test.client_write(b"ping1")
        test.server_read(b"ping1")
        test.client_write(b"ping2")
        test.server_read(b"ping2")
        test.client_half_close()
        test.server_expect_eof()
        test.client_expect_eof()
    LOGGER.debug(
        "Finished scenario: server_half_closes_without_sending_data_client_still_writes"
    )


def test_server_half_closes_and_client_sends_large_payload() -> None:
    """Verify a large client payload still reaches the server after half-close."""

    LOGGER.debug("Starting scenario: server_half_closes_and_client_sends_large_payload")
    with TestTcpServer(HOST, TIMEOUT) as test:
        received: list[bytes] = []
        errors: list[Exception] = []

        test.server_half_close()

        def read_large_payload() -> None:
            try:
                received.append(test._read_socket_exact(len(LARGE_PAYLOAD)))
            except Exception as exc:
                errors.append(exc)

        reader = threading.Thread(
            target=read_large_payload,
            name="server-half-close-large-payload",
        )
        reader.start()
        test.client_write(LARGE_PAYLOAD)
        reader.join(timeout=test.timeout + 1)

        if reader.is_alive():
            raise TestFailure("Server did not receive the large payload in time")
        if errors:
            raise errors[0]
        if received != [LARGE_PAYLOAD]:
            raise TestFailure("Server received an unexpected large payload")
        test.client_half_close()
        test.server_expect_eof()
        test.client_expect_eof()

    LOGGER.debug("Finished scenario: server_half_closes_and_client_sends_large_payload")


def test_client_half_closes_without_sending_data_server_still_writes() -> None:
    """Verify server traffic still works after client half-close without data."""

    LOGGER.debug(
        "Starting scenario: client_half_closes_without_sending_data_server_still_writes"
    )
    with TestTcpServer(HOST, TIMEOUT) as test:
        test.client_half_close()
        test.server_expect_eof()
        test.server_write(b"ping1")
        test.client_read(b"ping1")
        test.server_write(b"ping2")
        test.client_read(b"ping2")
    LOGGER.debug(
        "Finished scenario: client_half_closes_without_sending_data_server_still_writes"
    )


def test_client_half_closes_and_server_sends_large_payload() -> None:
    """Verify a large server payload still reaches the client after half-close."""

    LOGGER.debug("Starting scenario: client_half_closes_and_server_sends_large_payload")
    with TestTcpServer(HOST, TIMEOUT) as test:
        received: list[bytes] = []
        errors: list[Exception] = []

        test.client_half_close()
        test.server_expect_eof()

        def read_large_payload() -> None:
            try:
                received.append(test._read_pipe_exact(len(LARGE_PAYLOAD)))
            except Exception as exc:
                errors.append(exc)

        reader = threading.Thread(
            target=read_large_payload,
            name="client-half-close-large-payload",
        )
        reader.start()
        test.server_write(LARGE_PAYLOAD)
        reader.join(timeout=test.timeout + 1)

        if reader.is_alive():
            raise TestFailure("Client did not receive the large payload in time")
        if errors:
            raise errors[0]
        if received != [LARGE_PAYLOAD]:
            raise TestFailure("Client received an unexpected large payload")

    LOGGER.debug("Finished scenario: client_half_closes_and_server_sends_large_payload")


def test_both_sides_large_payload() -> None:
    """Verify both directions can transfer a large payload simultaneously."""

    LOGGER.debug("Starting scenario: both_sides_large_payload")
    with TestTcpServer(HOST, TIMEOUT) as test:
        start_barrier = threading.Barrier(2)
        errors: list[Exception] = []
        server_received: list[bytes] = []
        client_received: list[bytes] = []

        def client_send() -> None:
            try:
                LOGGER.debug("Client large-payload sender waiting at barrier")
                start_barrier.wait(timeout=test.timeout)
                test.client_write(LARGE_PAYLOAD)
            except Exception as exc:
                errors.append(exc)

        def server_send() -> None:
            try:
                LOGGER.debug("Server large-payload sender waiting at barrier")
                start_barrier.wait(timeout=test.timeout)
                test.server_write(LARGE_PAYLOAD)
            except Exception as exc:
                errors.append(exc)

        def client_recv() -> None:
            try:
                client_received.append(test._read_pipe_exact(len(LARGE_PAYLOAD)))
            except Exception as exc:
                errors.append(exc)

        def server_recv() -> None:
            try:
                server_received.append(test._read_socket_exact(len(LARGE_PAYLOAD)))
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=client_send, name="client-send-large-payload"),
            threading.Thread(target=server_send, name="server-send-large-payload"),
            threading.Thread(target=client_recv, name="client-recv-large-payload"),
            threading.Thread(target=server_recv, name="server-recv-large-payload"),
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=test.timeout + 1)

        if any(thread.is_alive() for thread in threads):
            raise TestFailure("Both-sides large payload threads did not finish in time")
        if errors:
            raise errors[0]
        if client_received != [LARGE_PAYLOAD]:
            raise TestFailure("Client received an unexpected large payload")
        if server_received != [LARGE_PAYLOAD]:
            raise TestFailure("Server received an unexpected large payload")

    LOGGER.debug("Finished scenario: both_sides_large_payload")


def test_server_half_closes_before_any_client_data() -> None:
    """Verify client traffic still works if server half-closes immediately."""

    LOGGER.debug("Starting scenario: server_half_closes_before_any_client_data")
    with TestTcpServer(HOST, TIMEOUT) as test:
        test.server_write(b"pong")
        test.server_half_close()
        test.client_read(b"pong")
        test.client_write(b"ping1")
        test.server_read(b"ping1")
        test.client_write(b"ping2")
        test.server_read(b"ping2")
        test.client_half_close()
        test.server_expect_eof()
        test.client_expect_eof()
    LOGGER.debug("Finished scenario: server_half_closes_before_any_client_data")


def test_client_half_closes_before_any_server_data() -> None:
    """Verify server traffic still works if client half-closes immediately."""

    LOGGER.debug("Starting scenario: client_half_closes_before_any_server_data")
    with TestTcpServer(HOST, TIMEOUT) as test:
        test.client_half_close()
        test.server_expect_eof()
        test.server_write(b"ping1")
        test.client_read(b"ping1")
        test.server_write(b"ping2")
        test.client_read(b"ping2")
    LOGGER.debug("Finished scenario: client_half_closes_before_any_server_data")


def test_both_sides_half_close_without_data() -> None:
    """Verify both peers can half-close immediately without sending data."""

    LOGGER.debug("Starting scenario: both_sides_half_close_without_data")
    with TestTcpServer(HOST, TIMEOUT) as test:
        barrier = threading.Barrier(2)
        errors: list[Exception] = []

        def client_flow() -> None:
            try:
                LOGGER.debug("Client no-data half-close flow waiting at barrier")
                barrier.wait(timeout=test.timeout)
                test.client_half_close()
                test.client_expect_eof()
            except Exception as exc:
                errors.append(exc)

        def server_flow() -> None:
            try:
                LOGGER.debug("Server no-data half-close flow waiting at barrier")
                barrier.wait(timeout=test.timeout)
                test.server_half_close()
                test.server_expect_eof()
            except Exception as exc:
                errors.append(exc)

        client_thread = threading.Thread(
            target=client_flow,
            name="client-both-half-close-without-data",
        )
        server_thread = threading.Thread(
            target=server_flow,
            name="server-both-half-close-without-data",
        )
        client_thread.start()
        server_thread.start()
        client_thread.join(timeout=test.timeout + 1)
        server_thread.join(timeout=test.timeout + 1)

        if client_thread.is_alive() or server_thread.is_alive():
            raise TestFailure("Both-sides no-data half-close threads did not finish in time")
        if errors:
            raise errors[0]

    LOGGER.debug("Finished scenario: both_sides_half_close_without_data")


TESTS: dict[str, Callable[[], None]] = {
    "server_pings_first": test_server_pings_first,
    "client_pings_first": test_client_pings_first,
    "reply_after_client_eof": test_reply_after_client_eof,
    "reply_after_empty_client_eof": test_reply_after_empty_client_eof,
    "remote_silent_close": test_remote_silent_close,
    "both_sides_ping_simultaneously": test_both_sides_ping_simultaneously,
    "both_sides_half_close_after_pong": test_both_sides_half_close_after_pong,
    "server_half_closes_after_pong": test_server_half_closes_after_pong,
    "client_half_closes_after_pong": test_client_half_closes_after_pong,
    "both_sides_large_payload": test_both_sides_large_payload,
    "server_half_closes_and_client_sends_large_payload": (
        test_server_half_closes_and_client_sends_large_payload
    ),
    "client_half_closes_and_server_sends_large_payload": (
        test_client_half_closes_and_server_sends_large_payload
    ),
    "server_half_closes_without_sending_data_client_still_writes": (
        test_server_half_closes_without_sending_data_client_still_writes
    ),
    "client_half_closes_without_sending_data_server_still_writes": (
        test_client_half_closes_without_sending_data_server_still_writes
    ),
    "server_half_closes_before_any_client_data": (
        test_server_half_closes_before_any_client_data
    ),
    "client_half_closes_before_any_server_data": (
        test_client_half_closes_before_any_server_data
    ),
    "both_sides_half_close_without_data": test_both_sides_half_close_without_data,
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
    """Run the selected TCP wrapper tests."""

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


