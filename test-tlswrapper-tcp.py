#!/usr/bin/env python3

import argparse
import logging
import os
import select
import signal
import socket
import subprocess
import sys
from collections.abc import Callable
from typing import BinaryIO


HOST = "127.0.0.1"
TIMEOUT = 4
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
        logcmd = ["./tlswrappernojail-tcp", "-v", "-t5", "-T3", host, "<port>"]
        LOGGER.debug("Starting wrapper process: %s", " ".join(logcmd))
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )

        self.listener.settimeout(self.timeout)
        try:
            LOGGER.debug("Waiting for wrapper to connect to %s:<port>", self.host)
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

        #LOGGER.debug("Wrapper connected from %s", self.conn.getpeername())
        LOGGER.debug("Wrapper connected")
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
                #LOGGER.debug("Terminating wrapper process group")
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=1)
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                #LOGGER.debug("Ignoring error while terminating wrapper process group")
                pass

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


def test_client_pings_first() -> None:
    """Verify that data flows correctly when the client writes first."""

    LOGGER.debug("Starting scenario: client_pings_first")
    with TestTcpServer(HOST, TIMEOUT) as test:
        test.client_write(b"ping")
        test.server_read(b"ping")
        test.server_write(b"pong")
        test.client_read(b"pong")
    LOGGER.debug("Finished scenario: client_pings_first")


def test_server_pings_first() -> None:
    """Verify that data flows correctly when the server writes first."""

    LOGGER.debug("Starting scenario: server_pings_first")
    with TestTcpServer(HOST, TIMEOUT) as test:
        test.server_write(b"ping")
        test.client_read(b"ping")
        test.client_write(b"pong")
        test.server_read(b"pong")
    LOGGER.debug("Finished scenario: server_pings_first")


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
        test.server_write(b"ping")
        test.client_read(b"ping")
    LOGGER.debug("Finished scenario: client_half_closes_after_pong")


TESTS: dict[str, Callable[[], None]] = {
    "client_pings_first": test_client_pings_first,
    "client_half_closes_after_pong": test_client_half_closes_after_pong,
    "server_pings_first": test_server_pings_first,
    "server_half_closes_after_pong": test_server_half_closes_after_pong,
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


