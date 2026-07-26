# Automating the one step of Linux snapshotting that needed a human.
#
# Taking a Linux snapshot runs TWO gdbs. The client debugs the target inside the
# guest over QEMU's gdbstub; the server debugs the QEMU process itself. `regs.json`
# has to come from the server, because it needs QEMU's internal `CPUX86State` --
# `lstar`, `star`, `sfmask`, `kernel_gs_base`, `apic_base`, `xcr0` and the rest are
# MSRs that QEMU's monitor does not print and the gdbstub does not expose. So the
# monitor cannot replace it and neither can the client.
#
# What made it manual was not that, though. It was that the server gdb is sitting in
# `continue` when the moment arrives, so somebody had to press Ctrl+C to get a prompt
# and type `cpu`:
#
#     print("In the QEMU tab, press Ctrl+C, run the `cpu` command")
#     while not REGS_JSON_FILENAME.exists():
#         time.sleep(1)
#
# Both halves of that are mechanical. Ctrl+C is SIGINT, and `cpu` is a line on stdin.
# Give the server gdb its stdin on a FIFO and record its pid, and the client can do
# exactly what the human did, at exactly the right moment -- which it already knows,
# because it is the thing that stopped the guest.
#
# This drives the SAME `cpu` command rather than reimplementing it. Reimplementing
# would mean producing a register dump by a path nobody has validated, for a file
# where a single wrong field silently corrupts every later address conversion.
#
# The manual path is preserved. If the pid file or the FIFO is absent -- an older
# gdb_server.sh, a server started by hand -- the client prints the instructions it
# always printed and waits, exactly as before.

import os
import pathlib
import signal
import time

PID_FILENAME = pathlib.Path("gdb_server.pid")
FIFO_FILENAME = pathlib.Path("gdb_server.fifo")

MANUAL_INSTRUCTIONS = "In the QEMU tab, press Ctrl+C, run the `cpu` command"

# How long to give gdb to reach a prompt after SIGINT before writing to its stdin.
# Writing early is harmless -- a FIFO write blocks until gdb reads, and gdb reads at
# the prompt -- so this only avoids a confusing ordering in the log.
_PROMPT_DELAY_S = 0.5


def server_pid(directory=None):
    """The server gdb's pid, or None if it was not recorded.

    None means "fall back to asking the human", never "guess a pid". Signalling the
    wrong process is not a recoverable mistake.
    """
    base = pathlib.Path(directory) if directory else pathlib.Path.cwd()
    path = base / PID_FILENAME
    try:
        pid = int(path.read_text().strip())
    except (OSError, ValueError):
        return None
    if pid <= 0:
        return None
    return pid


def is_alive(pid):
    """Whether `pid` exists. Signal 0 checks without delivering anything."""
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def can_trigger(directory=None):
    """Whether the automated path is available: a live pid AND a FIFO to write to."""
    base = pathlib.Path(directory) if directory else pathlib.Path.cwd()
    pid = server_pid(base)
    if pid is None or not is_alive(pid):
        return False
    fifo = base / FIFO_FILENAME
    try:
        return fifo.exists()
    except OSError:
        return False


def request_cpu_dump(directory=None, delay_s=_PROMPT_DELAY_S):
    """Do what the human did: interrupt the server gdb, then send it `cpu`.

    Returns a message describing what happened, for the caller to print. Never
    raises: every failure here has a working fallback (ask the human), and an
    exception thrown while the guest is stopped at the fuzz breakpoint would lose the
    snapshot rather than degrade it.
    """
    base = pathlib.Path(directory) if directory else pathlib.Path.cwd()
    pid = server_pid(base)
    if pid is None:
        return f"no {PID_FILENAME} -- {MANUAL_INSTRUCTIONS}"
    if not is_alive(pid):
        return f"gdb {pid} from {PID_FILENAME} is not running -- {MANUAL_INSTRUCTIONS}"

    fifo = base / FIFO_FILENAME
    if not fifo.exists():
        return f"no {FIFO_FILENAME} to write to -- {MANUAL_INSTRUCTIONS}"

    try:
        # SIGINT is Ctrl+C. It interrupts `continue` and returns gdb to its prompt.
        os.kill(pid, signal.SIGINT)
    except OSError as exc:
        return f"could not interrupt gdb {pid} ({exc}) -- {MANUAL_INSTRUCTIONS}"

    time.sleep(delay_s)

    try:
        # Opening a FIFO for writing blocks until a reader is present, and gdb reads
        # stdin at the prompt -- which the SIGINT above has just produced. Line
        # buffering is not enough here: gdb needs the newline to act on the command.
        with open(fifo, "w") as handle:
            handle.write("cpu\n")
            handle.flush()
    except OSError as exc:
        return f"could not send `cpu` to gdb {pid} ({exc}) -- {MANUAL_INSTRUCTIONS}"

    return f"interrupted gdb {pid} and sent `cpu`; waiting for regs.json"
