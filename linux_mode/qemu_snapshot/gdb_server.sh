#!/bin/bash

# get our environmental variables
export LINUX_MODE_BASE=../
export GDB_QEMU_PY_SCRIPT=${LINUX_MODE_BASE}qemu_snapshot/gdb_qemu.py
export QEMU=${LINUX_MODE_BASE}qemu_snapshot/target_vm/qemu/build/qemu-system-x86_64
export KERNEL=${LINUX_MODE_BASE}qemu_snapshot/target_vm/linux/arch/x86_64/boot/bzImage
export IMAGE=${LINUX_MODE_BASE}qemu_snapshot/target_vm/image/bookworm.img

# STDIN ON A FIFO, AND THE PID RECORDED.
#
# The one manual step in Linux snapshotting was pressing Ctrl+C in this tab and typing
# `cpu` at the moment the guest stopped at the fuzz breakpoint. Ctrl+C is SIGINT and
# `cpu` is a line on stdin, so with a FIFO for stdin and a pid to signal, the client
# gdb can do both itself -- it already knows the moment, because it is the thing that
# stopped the guest. See snapshot_trigger.py.
#
# `sleep infinity` holds the write end open so gdb never sees EOF on stdin and exits.
# Output goes to vm.log and is tailed rather than piped through tee, because a pipeline
# makes $! the pid of the last stage and the pid we need is gdb's.
FIFO=gdb_server.fifo
rm -f ${FIFO} gdb_server.pid
mkfifo ${FIFO}
sleep infinity > ${FIFO} &
FIFO_HOLDER=$!
TAIL_PID=""

cleanup() {
    kill ${FIFO_HOLDER} 2>/dev/null
    if [ -n "${TAIL_PID}" ]; then kill ${TAIL_PID} 2>/dev/null; fi
    rm -f ${FIFO} gdb_server.pid
}
trap cleanup EXIT

gdb \
    -q \
    --ex "set pagination off" \
    --ex "set confirm off" \
    --ex "starti" \
    --ex "handle SIGUSR1 noprint nostop" \
    -x ${GDB_QEMU_PY_SCRIPT} \
    --args ${QEMU} \
    -m 2G \
    -smp 1 \
    -kernel ${KERNEL} \
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial noapic ibpb=off ibrs=off kpti=0 l1tf=off mds=off mitigations=off no_stf_barrier noibpb noibrs pcil" \
    -machine type=pc,accel=kvm \
    -drive file=${IMAGE} \
    -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
    -monitor tcp:127.0.0.1:55555,server,nowait \
    -s \
    -net nic,model=e1000 \
    -nographic \
    -pidfile vm.pid \
    < ${FIFO} > vm.log 2>&1 &

GDB_PID=$!
echo ${GDB_PID} > gdb_server.pid
echo "server gdb is pid ${GDB_PID}; stdin on ${FIFO}; output in vm.log"
echo "the client interrupts it and runs 'cpu' itself -- no Ctrl+C needed"

tail -f vm.log &
TAIL_PID=$!

wait ${GDB_PID}

