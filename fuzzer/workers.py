"""Launch and supervise N wtf workers (CLAUDE.md CP4, CP4b, section 12).

A worker runs ``Init`` / ``InsertTestcase`` / ``Restore`` from our module and
executes test-cases the master hands it over the wire. Interfaces 2 and 3 go to
**every** worker, not once to a single engine (section 3.2) -- getting that
backwards is the classic distributed-fuzzing bug.

CP4 runs one worker; CP4b scales to N. The count is a parameter here from the
start, because CP4 explicitly says not to hardcode single-worker assumptions.

Two silent failures this module is built to surface:

* A worker that cannot resolve its breakpoints dies in ``Init`` and contributes
  nothing, while the master keeps waiting for work to come back. On Windows that
  happens whenever ``_NT_SYMBOL_PATH`` is unset (D-023), so
  :meth:`WorkerPool.check` reports dead workers rather than letting the campaign
  look merely slow.
* Interface 3 is delivered by the ``.cov`` files in ``targets/<name>/coverage/``,
  since ``fuzz`` has no ``--coverage`` flag (D-017). A missing file there is a
  warning inside wtf, not an error.

**NO LLM ANYWHERE IN THIS MODULE.** Workers are the fast clock.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Worker", "WorkerPool"]


@dataclass
class Worker:
    worker_id: str
    proc: subprocess.Popen
    log_path: Path
    restarts: int = 0

    @property
    def is_running(self) -> bool:
        return self.proc.poll() is None


@dataclass
class WorkerPool:
    """A pool of ``wtf fuzz`` clients pointed at one master."""

    wtf_exe: Path
    target_dir: Path
    name: str
    backend: str
    limit: int
    env: dict[str, str]
    log_dir: Path
    count: int = 1
    address: str | None = None
    edges: bool = False

    workers: list[Worker] = field(default_factory=list, init=False)

    def command(self) -> list[str]:
        cmd = [
            str(self.wtf_exe),
            "fuzz",
            f"--backend={self.backend}",
            "--name",
            self.name,
            "--limit",
            str(self.limit),
        ]
        if self.address:
            cmd += ["--address", self.address]
        if self.edges:
            # bochscpu only; wtf raises a ParseError otherwise (wtf.cc:334-338).
            if self.backend != "bochscpu":
                raise ValueError("--edges is only valid with the bochscpu backend")
            cmd.append("--edges")
        return cmd

    def _spawn(self, worker_id: str) -> Worker:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.log_dir / f"{worker_id}.log"
        handle = log_path.open("w", encoding="utf-8", errors="replace")
        proc = subprocess.Popen(
            self.command(),
            cwd=self.target_dir,
            env=self.env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return Worker(worker_id=worker_id, proc=proc, log_path=log_path)

    def start(self) -> list[Worker]:
        if self.workers:
            raise RuntimeError("pool already started")
        for idx in range(self.count):
            self.workers.append(self._spawn(f"worker-{idx:02d}"))
        return self.workers

    def alive(self) -> list[Worker]:
        return [w for w in self.workers if w.is_running]

    def dead(self) -> list[Worker]:
        return [w for w in self.workers if not w.is_running]

    def check(self, *, restart: bool = False) -> list[Worker]:
        """Report dead workers, optionally restarting them.

        GATE 4b requires that killing one worker does not stop the campaign and
        that it comes back, which is what ``restart=True`` provides.
        """
        died = self.dead()
        if restart:
            for idx, worker in enumerate(self.workers):
                if worker.is_running:
                    continue
                replacement = self._spawn(worker.worker_id)
                replacement.restarts = worker.restarts + 1
                self.workers[idx] = replacement
        return died

    def stop(self, timeout: float = 10.0) -> None:
        for worker in self.workers:
            if worker.proc.poll() is None:
                worker.proc.terminate()
        for worker in self.workers:
            try:
                worker.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                worker.proc.kill()

    def failure_reasons(self) -> dict[str, str]:
        """Tail each dead worker's log, so a dead pool explains itself.

        The common cause is unresolved breakpoint symbols, which produces
        ``Could not set a breakpoint at ...`` and then ``Could not initialize
        target fuzzer.``
        """
        reasons: dict[str, str] = {}
        for worker in self.dead():
            try:
                text = worker.log_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            tail = [ln for ln in text.strip().splitlines() if ln.strip()][-5:]
            reasons[worker.worker_id] = "\n".join(tail)
        return reasons
