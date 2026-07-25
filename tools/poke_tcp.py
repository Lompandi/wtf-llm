"""Send one frame to a TCP target, so a breakpoint on its parser actually fires.

This is the **stimulus** for snapshot acquisition. `prep/snapshot_win.py acquire`
sets `bp <module>!<parser>` and then `g`, and for a service that is sitting in
`recv` the breakpoint never fires on its own -- the acquisition would time out
having done nothing wrong. Something has to connect and send a byte.

That step is the one part of acquisition that **cannot be derived from the binary**.
This tool is deliberately generic about the two things that vary:

* **framing** -- `--length-prefix` covers the common "4-byte length, then that many
  bytes" shape (tlv_server's `main` does exactly this), and `none` sends the payload
  raw. Anything more exotic needs its own script.
* **when the service is ready** -- `--retry-for` keeps reconnecting, because the
  stimulus is started BEFORE kd blocks in `g` and a guest service may still be
  coming up. Without it the stimulus loses a race it cannot see and acquisition
  looks like "the breakpoint never fired".

Examples:

    # tlv_server: one Allocate command, 2-byte body, u32le length prefix
    python -m tools.poke_tcp --port 1337 --length-prefix u32le \\
        --hex 00000000 3905 0200 0102

    # raw bytes from a file, five times, half a second apart
    python -m tools.poke_tcp --port 8080 --file frame.bin --repeat 5 --delay 0.5

The port is the TARGET's, and this tool cannot guess it: read it off the binary
(Ghidra: look for `bind`/`htons`) or observe it in the guest with `netstat -ano`.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from pathlib import Path

PREFIX_FORMATS = {"none": None, "u32le": "<I", "u32be": ">I", "u16le": "<H", "u16be": ">H"}


def frame(payload: bytes, length_prefix: str) -> bytes:
    """Prepend the length in the requested encoding.

    The length counts the PAYLOAD only, not the prefix itself -- which is what
    tlv_server's `main` expects, and the opposite convention is common enough that
    it is worth stating rather than leaving to be inferred.
    """
    fmt = PREFIX_FORMATS[length_prefix]
    if fmt is None:
        return payload
    limit = 0xFFFF if fmt[-1] == "H" else 0xFFFFFFFF
    if len(payload) > limit:
        raise ValueError(f"{len(payload)} bytes does not fit a {length_prefix} prefix")
    return struct.pack(fmt, len(payload)) + payload


def poke(
    payload: bytes,
    *,
    host: str = "127.0.0.1",
    port: int,
    length_prefix: str = "u32le",
    repeat: int = 1,
    delay: float = 0.0,
    retry_for: float = 30.0,
    timeout: float = 5.0,
) -> int:
    """Send ``payload`` ``repeat`` times. Returns the number of frames delivered."""
    wire = frame(payload, length_prefix)
    delivered = 0
    deadline = time.monotonic() + retry_for

    for attempt in range(repeat):
        while True:
            try:
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    sock.sendall(wire)
                    delivered += 1
                break
            except OSError as exc:
                # Retry only while the service might still be starting. After the
                # window, report it: a stimulus that silently gave up is worse than
                # one that failed, because acquisition then blames the breakpoint.
                if time.monotonic() >= deadline:
                    print(
                        f"could not deliver frame {attempt + 1}/{repeat} to "
                        f"{host}:{port} after {retry_for:.0f}s: {exc}",
                        file=sys.stderr,
                    )
                    return delivered
                time.sleep(0.25)
        if delay and attempt + 1 < repeat:
            time.sleep(delay)
    return delivered


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True, help="the TARGET's port")
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument("--hex", nargs="+", help="payload as hex, spaces ignored")
    source.add_argument("--file", type=Path, help="payload read verbatim")
    ap.add_argument(
        "--length-prefix",
        default="u32le",
        choices=sorted(PREFIX_FORMATS),
        help="length encoding prepended to the payload (default u32le)",
    )
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between frames")
    ap.add_argument(
        "--retry-for",
        type=float,
        default=30.0,
        help="keep reconnecting for this long; the guest service may still be "
        "starting when the stimulus is launched",
    )
    args = ap.parse_args(argv)

    if args.file:
        payload = args.file.read_bytes()
    else:
        payload = bytes.fromhex("".join(args.hex).replace(" ", ""))

    delivered = poke(
        payload,
        host=args.host,
        port=args.port,
        length_prefix=args.length_prefix,
        repeat=args.repeat,
        delay=args.delay,
        retry_for=args.retry_for,
    )
    print(f"delivered {delivered}/{args.repeat} frame(s) of {len(payload)} bytes")
    return 0 if delivered == args.repeat else 1


if __name__ == "__main__":
    raise SystemExit(main())
