"""Launch and supervise the wtf master (CLAUDE.md CP4, section 12).

The master is the brain: it owns the corpus, runs our module's ``Mutator_t`` to
generate test-cases, aggregates coverage from every worker, and writes crashes.

**It is on the fast path.** Section 12.2: an LLM call inside the master stalls
every worker, so the slow clock is a separate process. Nothing in this module
touches an LLM.

Aggregate coverage is read from the master's stdout, parsed by
:mod:`engine_bridge.coverage`. Section 13.4 suggests watching an aggregated
``coverage.cov`` instead, but no writer for that file exists in this revision
(D-021).
"""

from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

from engine_bridge.coverage import MasterStats, parse_stat_line

__all__ = ["MasterProcess"]


@dataclass
class MasterProcess:
    """One ``wtf master``, with its stat lines tailed from a log file.

    **Why a file and not a pipe.** wtf prints through C stdio, which
    block-buffers when stdout is not a console. Through a pipe, a short run
    produces under one buffer's worth and we see *nothing at all* until the
    process exits -- and a terminated process never flushes, so the output is
    lost entirely. Measured: a 90-second run yielded zero parsable lines.

    Redirecting to a file and tailing it is what actually works. Stats still
    arrive in buffer-sized batches rather than instantly, which is fine for a
    slow-clock tick but means `latest()` lags the true state by up to a buffer.
    Do not tighten a plateau threshold below that lag.
    """

    wtf_exe: Path
    target_dir: Path
    name: str
    max_len: int
    runs: int
    env: dict[str, str]
    log_path: Path
    address: str | None = None

    proc: subprocess.Popen | None = field(default=None, init=False)
    stats: list[MasterStats] = field(default_factory=list, init=False)
    lines: list[str] = field(default_factory=list, init=False)
    _handle: object | None = field(default=None, init=False)
    _offset: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def command(self) -> list[str]:
        cmd = [
            str(self.wtf_exe),
            "master",
            f"--max_len={self.max_len}",
            f"--runs={self.runs}",
            "--target",
            ".",
            "--name",
            self.name,
        ]
        if self.address:
            cmd += ["--address", self.address]
        return cmd

    def start(self) -> None:
        if self.proc is not None:
            raise RuntimeError("master already started")

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.log_path.open("w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(
            self.command(),
            cwd=self.target_dir,
            env=self.env,
            stdout=self._handle,
            stderr=subprocess.STDOUT,
        )

    def drain(self) -> list[MasterStats]:
        """Read whatever the master has flushed since last time.

        Called from the tick loop rather than a background thread: there is no
        pipe to keep empty, so a thread would buy nothing and add a race.
        """
        fresh: list[MasterStats] = []
        if not self.log_path.exists():
            return fresh

        with self.log_path.open("r", encoding="utf-8", errors="replace") as fd:
            fd.seek(self._offset)
            chunk = fd.read()
            # Only consume up to the last complete line; a partial tail would be
            # re-read and double-counted next time otherwise.
            cut = chunk.rfind("\n")
            if cut == -1:
                return fresh
            consumed, chunk = chunk[: cut + 1], chunk[: cut + 1]
            self._offset += len(consumed)

        with self._lock:
            for line in chunk.splitlines():
                line = line.rstrip("\r")
                self.lines.append(line)
                stats = parse_stat_line(line)
                if stats is not None:
                    self.stats.append(stats)
                    fresh.append(stats)
        return fresh

    def latest(self) -> MasterStats | None:
        self.drain()
        with self._lock:
            return self.stats[-1] if self.stats else None

    def snapshot_stats(self) -> list[MasterStats]:
        with self._lock:
            return list(self.stats)

    @property
    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self, timeout: float = 10.0) -> int | None:
        if self.proc is None:
            return None
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=timeout)

        # Close our handle so the final buffer lands, then take one last read.
        if self._handle is not None:
            self._handle.close()  # type: ignore[attr-defined]
            self._handle = None
        self.drain()
        return self.proc.returncode

    def write_log(self) -> Path:
        """The master writes its own log directly; this just names it."""
        return self.log_path
