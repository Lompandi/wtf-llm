"""GhidraMCP client for on-demand decompilation (CLAUDE.md CP6).

Covers the gap A2 cannot: at triage time a fault may land in a function the
batch decompile never visited -- outside the entry closure, or in a module we did
not enumerate. This asks a live Ghidra for it.

**It is not a substitute for A2 and cannot be.** GhidraMCP is a GUI plugin: its
HTTP server exists only while a Ghidra GUI is open with the program loaded and
the plugin enabled (D-039). `analyzeHeadless` never instantiates it. So every
caller must treat absence as normal and degrade rather than fail --
:meth:`GhidraMcpClient.available` exists for exactly that.

Endpoint contract, read from the plugin's bytecode rather than its README:

===============  =========================================================
`/methods`       function names, one per line; takes ``offset`` and ``limit``
`/decompile`     **POST**, function **name** as the raw body -> pseudo-C
`/classes`       class names
`/segments`      memory segments
===============  =========================================================

Default port 8080 (``DEFAULT_PORT``), settable via the plugin's "Server Port"
option, which needs a Ghidra restart to take effect.

**Slow clock only.** This is an HTTP round trip to a decompiler; it must never be
called from the fast loop or the master (RULE 1, section 12.2).
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from arch.contracts import PseudoCEntry

__all__ = ["GhidraMcpError", "GhidraMcpUnavailable", "GhidraMcpClient"]

DEFAULT_BASE_URL = "http://127.0.0.1:8080"


class GhidraMcpError(RuntimeError):
    pass


class GhidraMcpUnavailable(GhidraMcpError):
    """The server is not running. Expected whenever Ghidra's GUI is closed."""


@dataclass
class GhidraMcpClient:
    base_url: str = DEFAULT_BASE_URL
    timeout_s: float = 60.0
    module: str = ""
    # Cache negative availability so a triage loop over 40 buckets does not
    # spend 40 timeouts discovering the same closed GUI.
    _known_down: bool = field(default=False, init=False)

    def _request(self, path: str, *, data: bytes | None = None, **params) -> str:
        if self._known_down:
            raise GhidraMcpUnavailable(
                f"{self.base_url} was already unreachable this session"
            )

        url = f"{self.base_url.rstrip('/')}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as response:
                return response.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as exc:
            # A connection refusal means the GUI is closed; an HTTP error means
            # the server is up but unhappy, which is a different problem.
            if isinstance(exc, urllib.error.HTTPError):
                raise GhidraMcpError(
                    f"{path} returned HTTP {exc.code}: {exc.reason}"
                ) from exc
            self._known_down = True
            raise GhidraMcpUnavailable(
                f"cannot reach GhidraMCP at {self.base_url}: {exc.reason}. "
                f"Its server only runs while a Ghidra GUI is open with the "
                f"program loaded and the plugin enabled (see docs/ENVIRONMENT.md)."
            ) from exc

    @property
    def available(self) -> bool:
        """Cheap health check. Never raises."""
        try:
            self._request("/methods", limit=1)
            return True
        except GhidraMcpError:
            return False

    def list_methods(self, *, offset: int = 0, limit: int = 1000) -> list[str]:
        text = self._request("/methods", offset=offset, limit=limit)
        return [ln.strip() for ln in text.splitlines() if ln.strip()]

    def decompile(self, function: str) -> str:
        """Pseudo-C for one function by name.

        The name goes in the POST **body**, not a query parameter.
        """
        if not function:
            raise ValueError("function name is required")
        code = self._request("/decompile", data=function.encode("utf-8"))
        if not code.strip():
            raise GhidraMcpError(
                f"GhidraMCP returned empty pseudo-C for {function!r}; the name "
                f"may not exist in the loaded program"
            )
        return code

    def decompile_entry(
        self, function: str, static_addr: int, *, module: str | None = None
    ) -> PseudoCEntry:
        """Decompile and wrap as a contract row, ready for the A2 cache.

        The **caller** supplies ``static_addr``: GhidraMCP's `/decompile` takes a
        name and returns text, so an address is not recoverable from the reply.
        Deriving one by guessing would put a wrong key into A2, which is worse
        than not caching at all.
        """
        return PseudoCEntry(
            module=module or self.module,
            static_addr=static_addr,
            function=function,
            code=self.decompile(function),
        )

    def fill_cache_miss(
        self,
        cache,  # prep.pseudoc_cache.PseudoCCache
        function: str,
        static_addr: int,
        *,
        module: str | None = None,
    ) -> PseudoCEntry:
        """Fetch on demand and write through to A2, tagged as ``ghidra_mcp``.

        Stored with ``min_static == max_static == static_addr``, because
        `/decompile` gives no body bounds. So the row is findable by exact
        address and by name, but NOT by a range query -- recorded honestly rather
        than by fabricating a span that later range lookups would trust.
        """
        entry = self.decompile_entry(function, static_addr, module=module)
        cache.put(entry, source="ghidra_mcp")
        return entry


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL)
    ap.add_argument("--list", action="store_true", help="list function names")
    ap.add_argument("--decompile", help="function name")
    ap.add_argument("--grep", help="filter --list output")
    args = ap.parse_args(argv)

    client = GhidraMcpClient(base_url=args.base_url)
    if not client.available:
        print(
            f"GhidraMCP is not reachable at {args.base_url}.\n"
            f"Open Ghidra, load the program, and enable GhidraMCP under\n"
            f"File -> Configure -> Developer (not Miscellaneous)."
        )
        return 1

    if args.list:
        for name in client.list_methods():
            if not args.grep or args.grep.lower() in name.lower():
                print(name)
        return 0

    if args.decompile:
        print(client.decompile(args.decompile))
        return 0

    print(f"GhidraMCP is up at {args.base_url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
