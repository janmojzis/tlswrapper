#!/usr/bin/env python3

import argparse
import logging
import sys
from pathlib import Path
from typing import TextIO

LOGGER = logging.getLogger(__name__)


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--log", help="Write a plain-text session log to this file")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging on stderr",
    )
    return parser.parse_args(argv)


def configure_logging(debug: bool) -> None:
    """Configure application logging."""

    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")


def write_reply(raw: TextIO, line: str) -> None:
    """Write one SMTP reply line to stdout."""

    LOGGER.debug("Sending reply: %r", line.rstrip("\r\n"))
    raw.write(line)
    raw.flush()


def strip_crlf(line: bytes) -> str:
    """Decode one SMTP line and trim trailing CRLF."""

    return line.rstrip(b"\r\n").decode("utf-8", errors="replace")


def log_line(handle: TextIO | None, line: str) -> None:
    """Append one stable transcript line to the optional log file."""

    if handle is None:
        return
    handle.write(line)
    handle.write("\n")
    handle.flush()


def main(argv: list[str] | None = None) -> int:
    """Run the fake SMTP child session."""

    args = parse_args(sys.argv[1:] if argv is None else argv)
    configure_logging(args.debug)

    log_handle: TextIO | None = None
    if args.log:
        log_handle = Path(args.log).open("w", encoding="utf-8")
        LOGGER.info("Writing transcript log to %s", args.log)

    try:
        replies = {
            "EHLO": "250 ok\r\n",
            "HELO": "250 ok\r\n",
            "MAIL": "250 ok\r\n",
            "RCPT": "250 ok\r\n",
            "RSET": "250 reset\r\n",
            "QUIT": "221 bye\r\n",
        }

        LOGGER.info("Starting fake SMTP child")
        write_reply(sys.stdout, "220 ready\r\n")
        log_line(log_handle, "reply 220 ready")

        in_data = False

        while True:
            raw_line = sys.stdin.buffer.readline()
            if raw_line == b"":
                if in_data:
                    LOGGER.warning("Received EOF while still inside DATA mode")
                else:
                    LOGGER.info("Received EOF on stdin")
                log_line(log_handle, "eof")
                return 0

            line = strip_crlf(raw_line)
            LOGGER.debug("Received line: %r", line)

            if in_data:
                if line == ".":
                    LOGGER.info("Finished DATA block")
                    log_line(log_handle, "data-end")
                    write_reply(sys.stdout, "250 queued\r\n")
                    log_line(log_handle, "reply 250 queued")
                    in_data = False
                    continue

                LOGGER.debug("Received DATA payload line")
                log_line(log_handle, f"data {line}")
                continue

            log_line(log_handle, f"cmd {line}")

            verb = line.split(" ", 1)[0].upper() if line else ""
            if verb == "DATA":
                LOGGER.info("Entering DATA mode")
                write_reply(sys.stdout, "354 go ahead\r\n")
                log_line(log_handle, "reply 354 go ahead")
                in_data = True
                continue

            reply = replies.get(verb, "250 ok\r\n")
            if verb not in replies:
                LOGGER.warning("Unknown command %r, using default reply", verb)
            write_reply(sys.stdout, reply)
            log_line(log_handle, f"reply {reply.rstrip()}")
            if verb == "QUIT":
                LOGGER.info("Session finished after QUIT")
                return 0
    except Exception:
        LOGGER.error("Fake SMTP child failed", exc_info=True)
        raise
    finally:
        if log_handle is not None:
            LOGGER.debug("Closing transcript log")
            log_handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
