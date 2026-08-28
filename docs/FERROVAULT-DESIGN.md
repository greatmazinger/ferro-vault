# FerroVault Design Document

A from-scratch, zero-trust ephemeral sandbox runtime for Linux, built directly on kernel primitives — no Docker, no OCI, no container-runtime libraries. This document has three parts: what the system does independent of any implementation language, how the existing Rust implementation builds that, and what a Go port needs to account for that the Rust version didn't have to.

Current Rust implementation: `src/main.rs` (~445 lines) + `src/seccomp.rs` (~315 lines), one dependency (`nix`), 15 unit tests, one external integration test (`test.sh`).

---

## Part 1 — Language-independent specification

This section describes behavior and guarantees. Every item here is a property of the Linux kernel APIs being used, not of Rust — a faithful port in any language must preserve all of it exactly.

### 1.1 Process model

A **manager** process:
1. Generates an ephemeral secret ("identity") before any isolation is set up.
2. Creates a resource-control group (cgroup) with fixed limits.
3. Spawns a **container** process tree that becomes progressively more isolated in stages, ending in an **entrypoint** process that is confined on every axis below.
4. Waits for the container to finish, reports its real exit status, and releases the cgroup.

No configuration file, no CLI arguments, no multi-container orchestration. Everything is fixed at build time. This is a deliberate scope boundary, not a gap to route around during a port.

### 1.2 Isolation layers

| Layer | Kernel mechanism | Guarantee |
|---|---|---|
| Process ID | PID namespace (`CLONE_NEWPID`) | Container processes invisible to the host; entrypoint runs as PID 1 in its own namespace |
| Mount | Mount namespace (`CLONE_NEWNS`) + private propagation | Mount operations inside the container never propagate to the host |
| IPC | IPC namespace (`CLONE_NEWIPC`) | No shared System V IPC objects with the host |
| Network | Network namespace (`CLONE_NEWNET`) | No interfaces, no routes, no host/outside connectivity. `lo` exists (every netns gets one) but stays administratively down — nothing here needs it |
| Filesystem | `pivot_root(2)` into a separate, minimal root, then read-only remount | Container cannot see or modify anything on the host filesystem; its own root is immutable after setup completes |
| Resources | cgroup v2 (memory, CPU, PID-count limits) | Bounded memory, CPU share, and process count; enforced by the kernel, cleaned up unconditionally after the container exits |
| Identity | Sealed anonymous memory (`memfd_create` + write-seal) | A fresh random secret exists only in kernel memory, never touches persistent disk, is immutable the instant it's provisioned, and is provided to the entrypoint before it runs |
| Syscalls | seccomp-BPF allowlist, installed last | The entrypoint (and anything it forks/execs) may only invoke an explicit, empirically-derived set of syscalls; anything else terminates the process immediately — no soft failure |

### 1.3 Required ordering (this is kernel semantics, not style)

Some of these orderings are correctness requirements, not preferences — get them wrong and the isolation either doesn't take effect or setup fails outright:

1. **cgroup self-assignment must happen before the second fork**, not after. Assigning the parent process to the cgroup guarantees every descendant inherits membership at birth; assigning after risks a race where a child is born before assignment lands.
2. **`CLONE_NEWPID` does not move the calling process into the new namespace** — only the *next* forked child becomes PID 1 there. Any implementation needs the equivalent of a second fork specifically to enter this namespace, unlike the other three namespace flags, which take effect immediately for the caller.
3. **Mount propagation must be severed (private remount of `/`) before any other mount work.** Without this, mounts made inside the container propagate back to the host and can corrupt it (e.g. the host's own `/proc`).
4. **`pivot_root` requires the new root to already be a mount point** distinct from its parent — a self-bind-mount is the standard way to satisfy this without a real second filesystem.
5. **The old root must be detached and its mountpoint removed *before* the read-only remount**, not after — once root is read-only, the directory used as `pivot_root`'s `put_old` can no longer be removed.
6. **`/proc` must be (re-)mounted *after* `pivot_root`**, not before — mounting it under the old root wastes the work; it needs to land inside the new root.
7. **The seccomp filter must be the *last* thing installed before the final exec.** It's irreversible and inherited by everything forked/exec'd afterward — install it too early and it constrains the isolation setup code itself, which needs a much broader syscall set (mount, unshare, pivot_root, cgroup writes) than the entrypoint ever should.

### 1.4 Failure policy

Setup failures are fatal and loud — there is no degraded/partial-isolation mode. If any step fails, the process reports why and terminates. The *real* fate of the entrypoint (clean exit vs. killed by an uncaught signal) must be observable at the top level — an implementation must not launder every outcome into a generic "it exited" without preserving whether that was a real exit or a kill.

### 1.5 Explicitly out of scope (still language-independent — these are product decisions)

- No OCI/image format — the root filesystem content is provisioned externally, by hand, once. The program never fetches or manages images.
- No user namespace / rootless operation. Real root and `CAP_SYS_ADMIN` are required.
- No multi-container orchestration — one manager, one container, no config surface to change that.
- No devtmpfs/tmpfs inside the container root — only whatever device nodes were hand-created during provisioning exist.

---

## Part 2 — The Rust implementation

### 2.1 Dependency: `nix` only

One direct dependency, `nix` (features: `sched`, `process`, `mount`, `fs`), providing safe(r) wrappers over `unshare`, `mount`, `pivot_root`, `fork`, `waitpid`, `memfd_create`, `fcntl`. `nix` has no seccomp/`prctl` support at all, so that piece goes through `nix::libc` (`nix`'s re-export of its own `libc` dependency) directly — deliberately, rather than pulling in a dedicated seccomp crate, to keep the "raw kernel primitives, no framework" positioning intact and avoid a second dependency (and its own version-compatibility surface) for one narrow need.

### 2.2 Why the double-fork works safely in Rust

FerroVault's actual control flow does real work — cgroup writes, `unshare`, mounts, `pivot_root`, building and installing a seccomp-BPF program — *between* two `fork()` calls and the final `execve`. This is safe here specifically because **a plain Rust binary that never spawns its own threads is genuinely single-threaded at the OS level**, and none of FerroVault's own code spawns threads. A freshly forked child in this situation only ever had one thread to begin with, so there's no risk of inheriting half-duplicated runtime state or locks held by threads that no longer exist post-fork. This assumption is silent and easy to take for granted in Rust — it is the single biggest thing that does **not** carry over to Go (see Part 3).

### 2.3 Process architecture

```
main()
 └─ provision_identity()        # /dev/urandom → sealed memfd, before any fork
 └─ setup_cgroup()               # creates cgroup, returns a CgroupGuard
 └─ fork() #1
     ├─ [parent] waitpid, propagate real exit status, drop CgroupGuard
     └─ [child]  setup_namespaces_and_spawn()
                   ├─ self-assign to cgroup (race-free, before unshare)
                   ├─ unshare(NEWPID|NEWNS|NEWIPC|NEWNET)
                   ├─ mount("/", MS_PRIVATE|MS_REC)
                   └─ fork() #2                       # required for CLONE_NEWPID to take effect
                       ├─ [parent] waitpid, propagate real exit/signal status
                       └─ [child]  execute_container_payload()   # this is PID 1
                                     ├─ pivot_to_rootfs()
                                     ├─ mount("/proc", ...)
                                     ├─ read identity from memfd, print hex
                                     ├─ install_seccomp_filter()  # last step before exec
                                     └─ execvp("/bin/sh")
```

### 2.4 Error-handling convention

Two deliberate tiers, split exactly at the first `fork()`:
- **Pre-fork setup** (`provision_identity`, most of `setup_cgroup`): `.expect()` — panics. There's no meaningful way to continue without an identity or a cgroup, so failing loudly and immediately is correct.
- **Post-fork code** (everything in `setup_namespaces_and_spawn` and after): explicit `match` on `Result`, `eprintln!`, `std::process::exit(1)`. Not panics — this is namespace/mount/exec code where a manual, labeled diagnostic reads better than a generic panic message.

This tiering is a Rust-idiom choice for expressing the language-independent policy in §1.4 ("fail loud, no soft degradation") — the *policy* is what a port must preserve, not the specific `.expect()`/`match` split.

### 2.5 RAII-guarded cleanup, and its sharp edge

`CgroupGuard` is a `#[must_use]` unit struct whose `Drop` impl removes the cgroup directory; `setup_cgroup` returns one instead of `()`. Binding it to a name guarantees cleanup runs even if a panic unwinds past where cleanup used to be called explicitly.

The sharp edge, found during development: `std::process::exit()` **skips destructors entirely**, same as a raw `_exit(2)`. The fork-failure error path originally leaked the cgroup for exactly this reason — `Drop` doesn't save you from an explicit early exit, only from *unwinding*. The fix explicitly `drop()`s the guard before that specific `exit(1)`. This is a real, general Rust trap (RAII plus `process::exit` don't mix the way people expect), not FerroVault-specific — and it has a direct Go analogue (§3.6).

### 2.6 Exit-status propagation

The process between the manager and the real PID-1 container process originally always called `exit(0)` once its child died, *regardless of whether that child exited cleanly or was killed by a signal* — silently violating §1.4. Fixed by matching on the real `WaitStatus`: propagate the exact exit code on a clean exit, or re-raise the identical signal on itself (`libc::raise`) on a signal death, so the signal is faithfully observable two process levels up. This bug was specifically what made an early seccomp kill invisible during development — worth knowing before a port re-derives the same debugging session.

### 2.7 Seccomp filter construction

No crate wraps BPF program construction, so it's built by hand in `seccomp.rs`: a `Vec<libc::sock_filter>` checking the syscall-table architecture first (rejects the classic 32-bit-ABI confusion attack on x86-64), then the syscall number against `ALLOWED_SYSCALLS`, ending in `SECCOMP_RET_KILL_PROCESS` as the *default* and `SECCOMP_RET_ALLOW` reached only via an explicit jump from a match.

**A real bug shipped here and was caught before merging, worth inheriting the lesson from directly**: the first version placed `RET_ALLOW` immediately after the syscall checks. A *non-match* falls through to "whatever instruction comes next" exactly the same way a *match*'s jump would land there — so with `RET_ALLOW` in that position, a non-match landed on ALLOW by pure positional accident. The filter allowed every syscall regardless of the allowlist, while still reporting itself as "installed and active." Caught with a standalone unprivileged reproduction, not by unit tests alone — the original test suite verified match-jump correctness but never asserted where the *fallthrough* path lands, which is the one property that actually matters for a default-deny filter. Fixed by making `RET_KILL_PROCESS` the fallthrough target with matches explicitly jumping past it, and adding a test that specifically walks the fallthrough path. **Any port must port this exact test, not just the filter logic** — the underlying BPF footgun is identical regardless of language.

### 2.8 The allowlist itself is empirical, not designed

56 syscalls, derived from three rounds of `strace -f` against the *exact* BusyBox binary used in the container's rootfs, not reasoned about from first principles:
1. A piped, non-interactive shell session running the same commands `test.sh` exercises.
2. The same session under a **real pty** — which turned up 6 more syscalls (`getcwd`/`geteuid`/`getpgid`/`nanosleep`/`poll`/`setpgid`) that only appear during interactive job-control setup and never show up on piped stdin. A filter built from only the piped trace passed automated testing while silently killing the shell the moment a human ran it interactively.
3. Manual discovery that `chdir` was still missing — `cd` is a shell *builtin* that calls `chdir()` directly in the shell's own process rather than forking a child, so it's invisible to any trace that never runs `cd`, and unlike an external command's syscall violation (which only kills the forked child), it killed the shell itself.

The methodology, not just the resulting list, is the thing to carry into a port: piped and interactive sessions genuinely exercise different syscalls, and builtins vs. forked externals fail differently when something's missing.

### 2.9 Testing

- **15 unit tests** (`cargo test`, no privileges needed): pure-logic pieces only — cgroup value formatting, hex encoding, and specifically the BPF jump-offset arithmetic (6 tests, including the fallthrough-to-kill property from §2.7). Anything that touches real `mount`/`unshare`/cgroups isn't unit-testable at all; it's covered instead by:
- **`test.sh`** (repo root, executable): a black-box integration test that runs the *actual* privileged binary inside a privileged container, feeding it commands over a FIFO and asserting on real kernel-observable state (`/proc/1/status`'s `Seccomp:` field, `/proc/net/dev`, actual cgroup file contents, etc.). This half of the test story is language-agnostic by construction — it drives a binary and reads `/proc`, and ports over to a Go build with no changes beyond the binary path.

---

## Part 3 — Porting to Go: what changes and why

Go is a completely legitimate, well-precedented choice for this — it's the dominant language in this exact space (Docker, containerd, runc, most of the OCI ecosystem). Everything FerroVault touches at the syscall level is reachable from Go. But one property Rust gets for free does not carry over, and it forces a real architectural difference, not just a syntax translation.

### 3.1 The central issue: Go's runtime is never single-threaded

Even a trivial Go binary runs the scheduler, garbage collector, and `sysmon` as real OS threads from startup. `fork()` only duplicates the *calling* thread into the child — every other runtime thread simply vanishes, along with any locks they were holding at the moment of the fork. Running ordinary Go code (which may allocate, which may need the GC, which may want to schedule a goroutine) in a post-fork, pre-exec child is unsafe in a way it structurally is not in single-threaded Rust (§2.2).

This is not a theoretical concern for this specific project — it's precisely why `runc` doesn't do a raw fork-then-work-then-exec chain. It **re-execs itself** (`/proc/self/exe`), typically triggered by a hidden subcommand or a sentinel environment variable, so that all the "do interesting things before the real entrypoint runs" logic happens inside a **freshly exec'd process** with a clean, fully-initialized runtime — not inside a raw post-fork child.

**A Go port needs the same pattern.** Concretely: use `os/exec` with `SysProcAttr{Cloneflags: ...}` to get the initial namespace creation (this much Go's stdlib supports directly and is the idiomatic, safe way to combine `clone`/`unshare` with an atomic exec), but push the cgroup-self-assign / `pivot_root` / seccomp-install / identity-read logic into a re-exec'd stage of the *same binary*, detected via an argv[0] convention or an env var, rather than trying to run it inline between a manual `fork()` and `exec()`. The final `execve` into `/bin/sh` can then use `syscall.Exec` directly (safe in Go, since nothing needs to survive past it except the fd table).

This is a real restructuring, not a reskin — plan for it up front rather than discovering it mid-port.

### 3.2 Syscall access: `golang.org/x/sys/unix`

Not stdlib, but the closest Go equivalent to `nix` in spirit — maintained by the Go team, the de facto standard for exactly this kind of code. Provides `unix.Unshare`, `unix.Mount`, `unix.PivotRoot`, and friends. Treat it the same way `nix` is treated here: the one dependency that's fine to take because it's a thin, well-trusted syscall wrapper, not a framework.

### 3.3 Things to verify before assuming they exist, not guess

Every one of these should be checked against current Go documentation/source before writing code that depends on it — the exact discipline this Rust implementation used repeatedly (docs.rs checks, real `strace` traces, standalone unprivileged reproductions) rather than working from memory, which is how the original BPF ordering bug and an earlier wrong download URL both got caught before shipping:
- Does `x/sys/unix` expose `memfd_create` and the seal-related `fcntl`/`F_ADD_SEALS` constants directly, or do they need raw syscall numbers?
- Does it expose `sock_filter`/`sock_fprog`-equivalent structs for hand-building a BPF program the same way `libc::sock_filter` did, or does the port need to define the struct layout manually?
- Exact `SysProcAttr` field support for the namespace flags actually needed (`CLONE_NEWPID`/`NEWNS`/`NEWIPC`/`NEWNET`) on whatever Go version the port targets — this has changed across Go versions.

### 3.4 The seccomp allowlist needs re-tracing, not just re-typing

The 56 syscall numbers themselves are a kernel/architecture property, not a Rust property, and mostly transfer directly. But **re-trace it against the actual Go-built binary**, don't assume the same list is complete. Two reasons: first, whatever shell/rootfs the port uses should be traced the same way (§2.8's piped-vs-pty distinction applies identically); second, confirm the re-exec'd init stage's own Go-runtime startup syscalls all happen *before* the filter installs (§1.3 rule 7 — as long as that ordering holds, the Go runtime's own scheduler/GC syscalls are irrelevant to the allowlist, since they never run under the filter — but this is exactly the kind of ordering assumption worth confirming empirically rather than trusting by inspection).

### 3.5 Error handling shifts from two-tier to one-tier

Go has no `panic`/`.expect()` split the way Rust does (§2.4) — idiomatic Go is `if err != nil { return err }` uniformly. The language-independent policy (§1.4: fail loud, no degradation) is best expressed in Go as every setup function returning `error`, with the top level doing `if err != nil { fmt.Fprintln(os.Stderr, ...); os.Exit(1) }` at each step. This actually maps cleanly onto Rust's *post-fork* convention already (§2.4) — the pre-fork "just panic" tier doesn't have as natural a Go equivalent, and collapsing to one uniform convention there is a legitimate simplification, not a loss.

### 3.6 No RAII — the cleanup footgun has a direct Go twin

Go has no `Drop`/destructors. The closest tool is `defer`, but **`os.Exit()` skips deferred functions**, exactly the way Rust's `process::exit()` skips `Drop` (§2.5). This is the same bug class, not a different one: any Go port needs the identical discipline the Rust version had to learn the hard way — explicitly run cleanup before any `os.Exit()` call on an error path; don't assume `defer` alone covers it, especially on the fork-failure-style paths where the process is about to terminate abnormally.

### 3.7 Testing story ports over almost unchanged

Go's built-in `testing` package is a direct analogue for §2.9's unit-test half — the BPF construction logic, syscall list, and any other pure logic get `_test.go` files the same way they got `#[cfg(test)] mod tests` here. `test.sh` needs essentially no changes beyond the binary path — it was already black-box, driving a compiled binary and reading `/proc`, which is language-agnostic by construction.

### 3.8 Dependency-footprint goal

The Rust version has exactly one dependency. A faithful port should hold the same line: `golang.org/x/sys` only. Specifically avoid pulling in a cgo-bound `libseccomp` binding (reintroduces a C dependency the Rust version deliberately avoided) or any existing container-runtime framework — hand-rolling the BPF filter the way `seccomp.rs` does is more code, but it's the thing that makes "built from raw primitives, not a framework" a true statement about the port too, not just the original.
