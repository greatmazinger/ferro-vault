#!/usr/bin/env bash
#
# Automated smoke test for FerroVault's isolation layers — a scripted version
# of the "Testing FerroVault end-to-end" walkthrough in README.md.
#
# This runs the real manager binary, which calls unshare/mount/pivot_root and
# writes to cgroupfs. It needs real root / CAP_SYS_ADMIN and must be run from
# the repo root, inside the privileged Podman dev container described in
# README's "Development environment" section — never on a bare host.
#
# Usage: ./test.sh

set -uo pipefail

BIN="./target/debug/ferro-vault"
LOG="$(mktemp /tmp/ferrovault-test.XXXXXX.log)"
FIFO="$(mktemp -u /tmp/ferrovault-test.XXXXXX.fifo)"
PASS=0
FAIL=0
MANAGER_PID=""

cleanup() {
    if [[ -n "$MANAGER_PID" ]] && kill -0 "$MANAGER_PID" 2>/dev/null; then
        kill "$MANAGER_PID" 2>/dev/null
    fi
    exec {FIFO_FD}>&- 2>/dev/null || true
    rm -f "$FIFO"
}
trap cleanup EXIT

check() {
    local desc="$1" pattern="$2"
    if grep -qE "$pattern" "$LOG"; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

check_value() {
    local desc="$1" actual="$2" expected="$3"
    if [[ "$actual" == "$expected" ]]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (expected '$expected', got '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

wait_for() {
    local pattern="$1" timeout="${2:-15}"
    for _ in $(seq 1 $((timeout * 10))); do
        grep -qE "$pattern" "$LOG" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

echo "== FerroVault end-to-end smoke test =="
echo "log: $LOG"
echo

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (CAP_SYS_ADMIN) inside the privileged Podman dev container." >&2
    echo "       see README.md's 'Development environment' section." >&2
    exit 1
fi

if [[ ! -x rootfs/bin/busybox ]]; then
    echo "error: ./rootfs/ isn't provisioned (no rootfs/bin/busybox)." >&2
    echo "       see README.md's 'Root filesystem provisioning' section." >&2
    exit 1
fi

echo "-- building --"
if ! cargo build; then
    echo "error: build failed" >&2
    exit 1
fi
echo

echo "-- launching manager --"
mkfifo "$FIFO"
# Open the FIFO read-write on our own fd so it never sees EOF between writes —
# the manager's stdin (a plain read-end open) would otherwise get EOF the
# instant our first write-open closes.
exec {FIFO_FD}<>"$FIFO"
"$BIN" <&"$FIFO_FD" >"$LOG" 2>&1 &
MANAGER_PID=$!

if ! wait_for 'Container: /proc mounted' 15; then
    echo "error: container did not reach ready state in time; see $LOG" >&2
    exit 1
fi
echo "container ready (PID $MANAGER_PID)"
echo

echo "-- running checks from inside the container --"
{
    echo 'echo PID:$$'
    echo 'ls /home'
    echo 'touch /testfile'
    echo 'ls -la /proc/1/fd'
    echo 'cat /proc/self/cgroup'
} >&"$FIFO_FD"

sleep 1 # give the container time to run the above before we read cgroup files and exit it

echo "-- host-side cgroup checks (container still running) --"
MEMORY_MAX=$(cat /sys/fs/cgroup/ferrovault/memory.max 2>/dev/null || echo "MISSING")
CPU_MAX=$(cat /sys/fs/cgroup/ferrovault/cpu.max 2>/dev/null || echo "MISSING")
PIDS_MAX=$(cat /sys/fs/cgroup/ferrovault/pids.max 2>/dev/null || echo "MISSING")
echo "memory.max=$MEMORY_MAX cpu.max=$CPU_MAX pids.max=$PIDS_MAX"
echo

echo 'exit' >&"$FIFO_FD"
exec {FIFO_FD}>&-

wait "$MANAGER_PID"
MANAGER_PID=""

echo
echo "== results =="
check "PID namespace: entrypoint is PID 1"                    'PID:1$'
check "filesystem isolation: host tree is unreachable"        'No such file or directory'
check "filesystem isolation: root filesystem is read-only"    'Read-only file system'
check "identity injection: sealed memfd present at /proc/1/fd" 'memfd:ferrovault-identity'
check "cgroup membership: container is in /ferrovault"        '0::/ferrovault'
check "manager: container exited cleanly"                     'Container exited with status'
check "manager: cgroup directory removed after exit"          'Cgroup removed'

check_value "cgroup memory.max = 256 MB"        "$MEMORY_MAX" "268435456"
check_value "cgroup cpu.max = 50% (50000 100000)" "$CPU_MAX"   "50000 100000"
check_value "cgroup pids.max = 32"              "$PIDS_MAX"   "32"

if [[ -d /sys/fs/cgroup/ferrovault ]]; then
    echo "  FAIL: cgroup directory still exists after exit"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: cgroup directory actually gone after exit"
    PASS=$((PASS + 1))
fi

echo
echo "$PASS passed, $FAIL failed. Full combined log: $LOG"
[[ $FAIL -eq 0 ]]
