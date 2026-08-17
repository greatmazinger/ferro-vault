# FerroVault

A zero-trust ephemeral sandbox runtime written in Rust, built from raw Linux kernel primitives — no Docker, no OCI, no container runtime libraries.

FerroVault demonstrates how modern container isolation actually works beneath the abstractions, implementing namespace isolation, filesystem containment, resource enforcement, and in-memory identity injection from scratch.

## What it does

The manager process spins up an isolated container environment and provisions a cryptographic identity into it before the entrypoint executes. The identity is never written to disk and cannot be tampered with once provisioned.

On each run:

```
=== FerroVault Manager Starting ===
Manager: Identity provisioned — 32 bytes sealed in memfd (fd=3).
Manager:   memory.max = 268435456
Manager:   cpu.max = 50000 100000
Manager:   pids.max = 32
Manager: Cgroup ready at /sys/fs/cgroup/ferrovault.
Manager: Spawned container process PID 468
Container: Assigned to cgroup (PID 468).
Container: Namespaces created. Forking into new PID namespace...
Container: Entered new PID namespace. I am PID 1.
Container: pivoted into isolated rootfs at /workspace/rootfs (now read-only).
Container: /proc mounted. Only this namespace's processes are visible.
Container: Identity received — 0x2ac063390d6602fe6dd750a44f3609b6...
Container: seccomp filter installed — 56 syscalls allowed, everything else kills the process.
```

The container then drops into a minimal `sh` (BusyBox) shell for inspection.

## Isolation layers

### 1. Linux namespaces

Three namespaces are created via `unshare(2)` before the container process starts:

| Namespace | Flag | Effect |
|---|---|---|
| PID | `CLONE_NEWPID` | Container processes are invisible to the host; the entrypoint runs as PID 1 |
| Mount | `CLONE_NEWNS` | Mount operations are private; changes do not propagate to the host |
| IPC | `CLONE_NEWIPC` | Isolated System V IPC — no shared memory segments with the host |

**Note on `CLONE_NEWPID`:** `unshare(CLONE_NEWPID)` creates the namespace but does not move the calling process into it — only the next forked child enters it as PID 1. FerroVault uses a double-fork pattern to handle this correctly.

Verify from inside the container:
```bash
echo $$   # 1 — the entrypoint is PID 1 in its own namespace
ps        # only this shell and whatever you run under it — no host processes
```

### 2. Filesystem isolation

After entering the new mount namespace, FerroVault:

1. Remounts the root filesystem as `MS_PRIVATE | MS_REC`, severing all shared mount propagation from the host. Without this step, mounts inside the container propagate back to the host and corrupt `/proc`.
2. Pivots into a minimal, purpose-built root filesystem via `pivot_root(2)`: bind-mounts a rootfs directory onto itself (required so it qualifies as a distinct mount point), pivots into it, discards the old root, then remounts the new root `MS_RDONLY`. The container can no longer see or touch anything on the host filesystem — only the small tree it was pivoted into, and read-only at that. See [Root filesystem provisioning](#root-filesystem-provisioning) below.
3. Overmounts `/proc` with a fresh `procfs` scoped to the new PID namespace, with `MS_NOSUID | MS_NODEV | MS_NOEXEC` hardening flags. This ensures `ps` and `/proc` only reveal the container's own processes. This happens *after* the pivot, so procfs is mounted into the new root rather than the discarded old one.

Verify from inside the container:
```bash
ls -la /                 # only the minimal rootfs tree — no host directories
touch /testfile           # fails: Read-only file system
cat /proc/mounts          # root shows `ro`, no host-only mounts leaked through
```

### 3. Resource limits (cgroups v2)

The manager creates a cgroup at `/sys/fs/cgroup/ferrovault` and enforces:

| Limit | Value |
|---|---|
| Memory | 256 MB |
| CPU | 50% of one core (50ms quota per 100ms window) |
| Max processes | 32 |

The container process self-assigns to the cgroup before its second fork, ensuring all descendants — including the entrypoint — inherit the limits at birth.

Verify from inside the container:
```bash
cat /proc/self/cgroup        # shows 0::/ferrovault
```

The minimal rootfs has no `/sys`, so `memory.max`/`cpu.max` can no longer be read from inside the container once filesystem isolation (above) is active. Check them from the host, or from a second shell into the dev container, instead:
```bash
cat /sys/fs/cgroup/ferrovault/memory.max
cat /sys/fs/cgroup/ferrovault/cpu.max
```

### 4. Ephemeral identity injection

Before any fork, the manager:

1. Reads 32 cryptographically random bytes from `/dev/urandom`
2. Writes them into an anonymous in-RAM file via `memfd_create(2)` with `MFD_ALLOW_SEALING`
3. Applies four seals: `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL` — the identity is now read-only and the seal set itself is frozen
4. Passes the file descriptor number to the container via the `FERROVAULT_IDENTITY_FD` environment variable

The fd is created without `MFD_CLOEXEC` so it survives `execvp` and is inherited by the entrypoint. The identity is never written to disk, never transmitted over a network, and is unique per container run.

Verify from inside the container:
```bash
ls -la /proc/1/fd   # shows: N -> /memfd:ferrovault-identity (deleted)
```

`(deleted)` is correct — a memfd has no filesystem path. The file exists only as long as open file descriptors reference it.

### 5. Syscall filtering (seccomp)

As the last step before `execvp`, FerroVault installs a seccomp-BPF filter confining the entrypoint (and anything it forks or execs from then on) to an allowlist of 56 syscalls. The filter checks two things per syscall: that the calling process's syscall-table architecture is x86-64 (rejecting the classic 32-bit-ABI confusion attack), then the syscall number itself against the allowlist. Anything that falls through both is killed via `SECCOMP_RET_KILL_PROCESS` — a disallowed syscall terminates that process outright rather than failing gracefully with an error code.

The allowlist wasn't guessed: it comes from running the exact BusyBox build used in `./rootfs/` under `strace -f`, twice — once through the same command sequence `test.sh` and this README's walkthrough exercise, fed over a plain pipe, and once under a real pty. Those two traces disagree: a piped, non-interactive shell never touches job-control syscalls like `setpgid`/`getpgid`, but a real interactive terminal session does, immediately, before ever showing a prompt. A filter built from only the piped trace let `test.sh` pass while silently killing the shell the moment you ran the manager in an actual terminal — both traces are folded into the allowlist now, plus `chdir`, found afterward by hand: `cd` is an `ash` builtin that calls `chdir()` directly in the shell's own process rather than forking a child, so it killed the shell itself rather than just a forked command. It only covers what `/bin/sh` and the `ls`/`cat`/`touch`/`ps`/`grep` applets provisioned above actually need in these scenarios — running something outside that (a different applet, or one of those same applets doing something none of this exercised) can hit an unallowed syscall and get killed. That's expected, not a bug: the filter is scoped to what's documented and tested here, not a general-purpose shell environment.

Verify from inside the container:
```bash
cat /proc/1/status   # Seccomp: field reads 2 (SECCOMP_MODE_FILTER)
```

## Prior art

| Primitive | Credit |
|---|---|
| `memfd_create` + sealing | David Herrmann, Linux 3.17 (2014) |
| fd-passing via environment variable | Lennart Poettering, systemd socket activation |
| Sealed memfd credential provisioning | systemd `LoadCredential` / `SetCredential` (systemd 247, 2020) |

## Requirements

- Linux kernel 5.10+ (cgroups v2, memfd sealing)
- Root / `CAP_SYS_ADMIN` (required for `unshare`, `mount`, cgroup writes)
- Rust 1.77+
- A manually provisioned root filesystem at `./rootfs/` — see below

## Root filesystem provisioning

FerroVault does not fetch, build, or manage container images — no OCI, no image format, no network calls from the code itself. The container's root filesystem is a small tree you assemble by hand, once, before running the manager. It lives at `./rootfs/` (i.e. `/workspace/rootfs` inside the dev container), is gitignored, and survives the dev container being deleted and recreated since it lives in the bind-mounted repo directory rather than inside the container.

Build it around a single static [BusyBox](https://busybox.net/) binary. As of this writing, the newest prebuilt static binary published at busybox.net is 1.35.0 (2022-01-17); check [the binaries index](https://busybox.net/downloads/binaries/) for anything newer before using this. Note there's no checksum file published alongside it — this is trusting `busybox.net` over HTTPS with no independent checksum to verify against, not a verified download:

```bash
mkdir -p rootfs/{bin,proc,dev,etc,tmp}
curl -L -o rootfs/bin/busybox https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox
chmod +x rootfs/bin/busybox

# BusyBox dispatches by the name it's invoked as (argv[0]), so each command
# you want available needs its own symlink — `sh` alone isn't enough. `echo`
# doesn't need one; it's a built-in of BusyBox's ash shell itself. This list
# covers what README's verification steps and test.sh actually run; add more
# the same way if you need other commands inside the container.
for applet in sh ls touch cat ps; do
    ln -s busybox "rootfs/bin/$applet"
done

# Minimal device nodes BusyBox's sh expects for interactive use.
# mknod requires root — inside the Podman dev container you already are root,
# so no `sudo` needed; add it if running these commands directly on the host.
mknod -m 666 rootfs/dev/null c 1 3
mknod -m 666 rootfs/dev/zero c 1 5
mknod -m 666 rootfs/dev/tty c 5 0
```

`rootfs/proc` must exist as an empty directory — FerroVault mounts a fresh `procfs` there after pivoting in. `rootfs/dev` and `rootfs/tmp` are provided as empty mount points / working directories for future use; nothing currently mounts a `devtmpfs` or `tmpfs` over them.

## Development environment

Because FerroVault requires raw kernel access, development runs inside a privileged Podman container to prevent namespace and mount operations from affecting the host:

```bash
sudo podman run -it --privileged \
  --network=host \
  --cgroupns=host \
  --name ferrovault-dev \
  -v /path/to/ferro-vault:/workspace \
  -w /workspace \
  rust:latest bash
```

Inside the container (no `sudo` needed — already root):

```bash
cargo build
./target/debug/ferro-vault
```

Re-enter after exiting:
```bash
sudo podman start -ai ferrovault-dev
```

Open a second shell for inspection while the container is running:
```bash
sudo podman exec -it ferrovault-dev bash
```

## Testing FerroVault end-to-end

The sections above each show a quick check for their own layer. This walks through testing all of them in one ordered session. Prerequisites: `./rootfs/` is provisioned (see [Root filesystem provisioning](#root-filesystem-provisioning)) and you're inside the Podman dev container (see [Development environment](#development-environment)).

**Automated:** `./test.sh` scripts this whole walkthrough — builds, launches the manager, feeds it the same checks used below over its stdin, reads the cgroup files from the host while the container is still alive, and asserts on the combined output. Run it from the repo root, as root, inside the dev container:

```bash
./test.sh
```

It prints a PASS/FAIL line per check and exits non-zero if anything failed; the full combined manager/container log path is printed at the end for digging into a failure. The steps below are the same checks done by hand — useful for understanding what's actually being verified, or for poking around interactively beyond what the script checks.

### 1. Build and launch

```bash
cargo build
./target/debug/ferro-vault
```

The manager prints its startup transcript (identity, cgroup, namespace setup, pivot, procfs) and then blocks — it's waiting on the container process — while you land in the container's `sh` prompt. Keep this terminal open; its final lines (after you exit the shell in step 4) confirm the run completed cleanly.

### 2. Inside the container shell — check each layer

```bash
# PID namespace
echo $$                          # 1
ps                                # only this shell / whatever you run — no host processes

# Filesystem isolation
ls -la /                          # only bin, dev, proc, tmp, etc — no host directories
ls /home 2>&1                     # No such file or directory — host tree is unreachable
touch /testfile 2>&1              # Read-only file system
cat /proc/mounts | grep ' / '     # root shows `ro`

# Ephemeral identity
ls -la /proc/1/fd                 # N -> /memfd:ferrovault-identity (deleted)

# Resource limits (partial view — /sys isn't in this rootfs; rest is step 3)
cat /proc/self/cgroup             # 0::/ferrovault
```

### 3. From a second shell — check the enforced cgroup values

Without closing the first shell, open a second one into the same running dev container:

```bash
sudo podman exec -it ferrovault-dev bash
```

```bash
cat /sys/fs/cgroup/ferrovault/memory.max   # 268435456
cat /sys/fs/cgroup/ferrovault/cpu.max      # 50000 100000
cat /sys/fs/cgroup/ferrovault/pids.max     # 32
```

### 4. Exit and confirm cleanup

Back in the container shell, exit it (`exit` or Ctrl-D). In the first terminal, the manager should print:

```
Manager: Container exited with status: ...
Manager: Cgroup removed.
```

From the second shell, confirm the cgroup directory is actually gone:

```bash
ls /sys/fs/cgroup/ferrovault   # No such file or directory
```

If every check in steps 2–4 matches, all four isolation layers — namespaces, filesystem containment, resource limits, and identity injection — are working end-to-end for that run.
