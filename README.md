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
Container: /proc mounted. Only this namespace's processes are visible.
Container: Identity received — 0x2ac063390d6602fe6dd750a44f3609b6...
```

The container then drops into a bash shell for inspection.

## Isolation layers

### 1. Linux namespaces

Three namespaces are created via `unshare(2)` before the container process starts:

| Namespace | Flag | Effect |
|---|---|---|
| PID | `CLONE_NEWPID` | Container processes are invisible to the host; the entrypoint runs as PID 1 |
| Mount | `CLONE_NEWNS` | Mount operations are private; changes do not propagate to the host |
| IPC | `CLONE_NEWIPC` | Isolated System V IPC — no shared memory segments with the host |

**Note on `CLONE_NEWPID`:** `unshare(CLONE_NEWPID)` creates the namespace but does not move the calling process into it — only the next forked child enters it as PID 1. FerroVault uses a double-fork pattern to handle this correctly.

### 2. Filesystem isolation

After entering the new mount namespace, FerroVault:

1. Remounts the root filesystem as `MS_PRIVATE | MS_REC`, severing all shared mount propagation from the host. Without this step, mounts inside the container propagate back to the host and corrupt `/proc`.
2. Overmounts `/proc` with a fresh `procfs` scoped to the new PID namespace, with `MS_NOSUID | MS_NODEV | MS_NOEXEC` hardening flags. This ensures `ps` and `/proc` only reveal the container's own processes.

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
