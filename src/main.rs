use nix::fcntl::{fcntl, FcntlArg, SealFlag};
use nix::libc;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, execvp, fork, lseek, pivot_root, read, write, ForkResult, Whence};
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::io::AsRawFd;

const CGROUP_PATH: &str = "/sys/fs/cgroup/ferrovault";
const ROOTFS_PATH: &str = "/workspace/rootfs";

/// AUDIT_ARCH_X86_64 = EM_X86_64 (0x3E) | __AUDIT_ARCH_64BIT (0x8000_0000) |
/// __AUDIT_ARCH_LE (0x4000_0000). Not exposed by `libc`; value verified
/// against servo/gaol's seccomp.rs, a working reference implementation.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

// Offsets into the kernel's `struct seccomp_data { int nr; __u32 arch; ... }`
// — frozen seccomp ABI, not exposed by `libc`. Verified against the same
// reference implementation.
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

/// Syscalls the container's entrypoint (`/bin/sh` and whatever it execs) is
/// allowed to make. Derived empirically, not guessed. Two `strace -f`
/// traces of the exact BusyBox build used in `./rootfs/` — first the same
/// command sequence test.sh and README's walkthrough use, fed over a plain
/// pipe (echo, ls, touch, cat, ps, grep, a piped command); then the same
/// shell run under a real pty, which turned up 6 more syscalls
/// (getcwd/geteuid/getpgid/nanosleep/poll/setpgid) that only show up during
/// interactive job-control setup and never appear on piped, non-tty stdin —
/// plus `chdir`, found afterward: `cd` is an ash *builtin* that calls
/// chdir() directly in the shell's own process rather than forking a child,
/// so unlike an external command (e.g. a disallowed `mkdir`, which only
/// kills the forked child and leaves the shell running), running `cd`
/// without this killed the shell itself. Anything not on this list kills
/// the calling process — see install_seccomp_filter().
const ALLOWED_SYSCALLS: &[i64] = &[
    libc::SYS_access,
    libc::SYS_arch_prctl,
    libc::SYS_brk,
    libc::SYS_chdir,
    libc::SYS_close,
    libc::SYS_dup2,
    libc::SYS_execve,
    libc::SYS_exit_group,
    libc::SYS_fcntl,
    libc::SYS_fork,
    libc::SYS_fstat,
    libc::SYS_futex,
    libc::SYS_getcwd,
    libc::SYS_getdents64,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getpgid,
    libc::SYS_getpid,
    libc::SYS_getppid,
    libc::SYS_getrandom,
    libc::SYS_gettid,
    libc::SYS_getuid,
    libc::SYS_ioctl,
    libc::SYS_lseek,
    libc::SYS_lstat,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_nanosleep,
    libc::SYS_newfstatat,
    libc::SYS_open,
    libc::SYS_openat,
    libc::SYS_pipe,
    libc::SYS_poll,
    libc::SYS_pread64,
    libc::SYS_prlimit64,
    libc::SYS_read,
    libc::SYS_readlink,
    libc::SYS_rseq,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sendfile,
    libc::SYS_set_robust_list,
    libc::SYS_set_tid_address,
    libc::SYS_setgid,
    libc::SYS_setpgid,
    libc::SYS_setuid,
    libc::SYS_stat,
    libc::SYS_sysinfo,
    libc::SYS_uname,
    libc::SYS_unlinkat,
    libc::SYS_utimensat,
    libc::SYS_wait4,
    libc::SYS_write,
    libc::SYS_writev,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CgroupLimits {
    memory_max_bytes: u64,
    cpu_quota_us: u64,
    cpu_period_us: u64,
    pids_max: u32,
}

impl Default for CgroupLimits {
    fn default() -> Self {
        Self {
            memory_max_bytes: 256 * 1024 * 1024, // 256 MB
            cpu_quota_us: 50_000,                 // 50% of one CPU
            cpu_period_us: 100_000,               // per 100 ms window
            pids_max: 32,
        }
    }
}

impl CgroupLimits {
    /// (cgroup control-file name, value to write) pairs for this limit set.
    /// Pure data shaping — no I/O. `setup_cgroup` performs the actual writes.
    fn cgroup_writes(&self) -> [(&'static str, String); 3] {
        [
            ("memory.max", self.memory_max_bytes.to_string()),
            (
                "cpu.max",
                format!("{} {}", self.cpu_quota_us, self.cpu_period_us),
            ),
            ("pids.max", self.pids_max.to_string()),
        ]
    }
}

fn main() {
    println!("=== FerroVault Manager Starting ===");

    let identity_fd = provision_identity();
    std::env::set_var("FERROVAULT_IDENTITY_FD", identity_fd.as_raw_fd().to_string());

    let cgroup_guard = setup_cgroup(&CgroupLimits::default());

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            println!("Manager: Spawned container process PID {}", child);
            match waitpid(child, None) {
                Ok(status) => println!("Manager: Container exited with status: {:?}", status),
                Err(e) => eprintln!("Manager: waitpid error: {}", e),
            }
            // cgroup_guard drops here, removing the cgroup directory.
        }
        Ok(ForkResult::Child) => {
            // cgroup_guard's Drop never runs in this process: every path out
            // of setup_namespaces_and_spawn() ends in process::exit() or
            // execvp(), both of which skip destructors — intentional, since
            // only the manager (parent) should ever remove the cgroup.
            setup_namespaces_and_spawn();
        }
        Err(e) => {
            eprintln!("Manager: fork failed: {}", e);
            // process::exit() skips destructors too, so without this the
            // cgroup directory created above would leak on this path.
            drop(cgroup_guard);
            std::process::exit(1);
        }
    }
}

/// Owns the manager's membership of the FerroVault cgroup. Its `Drop` impl
/// is the only thing that removes `CGROUP_PATH` — binding this to a named
/// variable guarantees cleanup runs even if a panic unwinds past the point
/// where cleanup used to be called explicitly.
#[must_use = "dropping this immediately removes the cgroup directory"]
struct CgroupGuard;

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        cleanup_cgroup();
    }
}

fn setup_cgroup(limits: &CgroupLimits) -> CgroupGuard {
    // Enable controllers in the parent cgroup so child cgroups can use them.
    // Best-effort: inside a container the root cgroup may restrict this.
    if let Err(e) = fs::write(
        "/sys/fs/cgroup/cgroup.subtree_control",
        "+memory +cpu +pids",
    ) {
        eprintln!("Manager: cgroup.subtree_control (best-effort): {}", e);
    }

    fs::create_dir_all(CGROUP_PATH).expect("create cgroup directory");

    for (file, value) in limits.cgroup_writes() {
        match fs::write(format!("{}/{}", CGROUP_PATH, file), &value) {
            Ok(_) => println!("Manager:   {} = {}", file, value),
            Err(e) => eprintln!("Manager:   {} (skipped): {}", file, e),
        }
    }

    println!("Manager: Cgroup ready at {}.", CGROUP_PATH);

    CgroupGuard
}

fn cleanup_cgroup() {
    // The directory can only be removed once all processes have left the cgroup.
    // By the time we reach this, waitpid has returned so the container is gone.
    if let Err(e) = fs::remove_dir(CGROUP_PATH) {
        eprintln!("Manager: cgroup cleanup: {}", e);
    } else {
        println!("Manager: Cgroup removed.");
    }
}

fn provision_identity() -> OwnedFd {
    // Generate 32 random bytes directly from the kernel entropy pool
    let mut identity = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .expect("open /dev/urandom")
        .read_exact(&mut identity)
        .expect("read urandom");

    // Anonymous in-RAM file. MFD_ALLOW_SEALING enables F_ADD_SEALS below.
    // No MFD_CLOEXEC: the fd must survive execvp so the container inherits it.
    let fd = memfd_create(c"ferrovault-identity", MemFdCreateFlag::MFD_ALLOW_SEALING)
        .expect("memfd_create failed");

    write(&fd, &identity).expect("write identity to memfd");

    // Seek back to 0 — file description offset is shared across forks,
    // so the grandchild reads from the start without needing its own seek.
    lseek(fd.as_raw_fd(), 0, Whence::SeekSet).expect("lseek memfd");

    // Freeze content and size, then lock the seal set itself so no further
    // seals (or unsealings) are possible.
    fcntl(
        fd.as_raw_fd(),
        FcntlArg::F_ADD_SEALS(
            SealFlag::F_SEAL_SEAL
                | SealFlag::F_SEAL_WRITE
                | SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_GROW,
        ),
    )
    .expect("seal memfd failed");

    println!(
        "Manager: Identity provisioned — 32 bytes sealed in memfd (fd={}).",
        fd.as_raw_fd()
    );

    fd
}

fn setup_namespaces_and_spawn() {
    // Self-assign to the cgroup before any further forking so the grandchild
    // inherits it at fork time. Doing this in the parent after fork() is a
    // race — the grandchild may already exist before the write lands.
    let my_pid = nix::unistd::getpid();
    if let Err(e) = fs::write(
        format!("{}/cgroup.procs", CGROUP_PATH),
        my_pid.to_string(),
    ) {
        eprintln!("Container: cgroup self-assign failed: {}", e);
        std::process::exit(1);
    }
    println!("Container: Assigned to cgroup (PID {}).", my_pid);

    // NEWNS and NEWIPC take effect immediately for the calling process.
    // NEWPID creates the namespace but does NOT move the caller into it —
    // only the next forked child enters it as PID 1.
    let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWIPC;

    if let Err(e) = unshare(flags) {
        eprintln!("Container: unshare failed: {}", e);
        std::process::exit(1);
    }

    // Sever mount propagation from the host. The new mount namespace inherits
    // the host's MS_SHARED root by default, so any mount we do would propagate
    // back and corrupt the host's /proc. MS_PRIVATE | MS_REC cuts that link.
    if let Err(e) = mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    ) {
        eprintln!("Container: failed to make mounts private: {}", e);
        std::process::exit(1);
    }

    println!("Container: Namespaces created. Forking into new PID namespace...");

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Propagate the real PID-1 process's fate instead of always
            // exiting 0 — otherwise the manager's own waitpid sees a clean
            // Exited(_, 0) no matter what actually happened to the
            // container (e.g. a seccomp SIGSYS kill goes completely
            // unreported, as it did during development of the seccomp
            // filter above).
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, code)) => std::process::exit(code),
                Ok(WaitStatus::Signaled(_, signal, _)) => {
                    // Re-raise the same signal on ourselves. No signal
                    // handlers are installed anywhere in this program, so
                    // dispositions are still all default — this terminates
                    // us the same way, and the manager's own waitpid sees a
                    // Signaled status instead of a misleading Exited(_, 0).
                    unsafe { libc::raise(signal as i32) };
                    // Only reached if raise() somehow didn't terminate us.
                    std::process::exit(128 + signal as i32);
                }
                Ok(status) => {
                    eprintln!("Namespace-init: unexpected wait status: {:?}", status);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Namespace-init: waitpid error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Ok(ForkResult::Child) => {
            execute_container_payload();
        }
        Err(e) => {
            eprintln!("Namespace-init: second fork failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn pivot_to_rootfs() {
    // pivot_root(2) requires the new root to be a mount point distinct from
    // its parent. Bind-mounting the rootfs onto itself satisfies that
    // without needing a real second filesystem or partition.
    if let Err(e) = mount(
        Some(ROOTFS_PATH),
        ROOTFS_PATH,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    ) {
        eprintln!("Container: failed to bind-mount rootfs: {}", e);
        std::process::exit(1);
    }

    // put_old must be a directory under the new root. Created fresh each
    // run and removed below — nothing persists between runs.
    let put_old = format!("{}/.oldroot", ROOTFS_PATH);
    if let Err(e) = fs::create_dir_all(&put_old) {
        eprintln!("Container: failed to create pivot_root put_old dir: {}", e);
        std::process::exit(1);
    }

    if let Err(e) = chdir(ROOTFS_PATH) {
        eprintln!("Container: chdir into rootfs failed: {}", e);
        std::process::exit(1);
    }

    // put_old is given relative to the new root (our new cwd).
    if let Err(e) = pivot_root(".", ".oldroot") {
        eprintln!("Container: pivot_root failed: {}", e);
        std::process::exit(1);
    }

    if let Err(e) = chdir("/") {
        eprintln!("Container: chdir to new / failed: {}", e);
        std::process::exit(1);
    }

    // Lazily detach the old root — it vanishes from this namespace immediately.
    if let Err(e) = umount2("/.oldroot", MntFlags::MNT_DETACH) {
        eprintln!("Container: failed to unmount old root: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = fs::remove_dir("/.oldroot") {
        eprintln!("Container: failed to remove old root mountpoint: {}", e);
        std::process::exit(1);
    }

    // Lock the new root read-only now that nothing references the old one.
    // Remounting is a required second, separate mount(2) call — MS_BIND
    // ignores MS_RDONLY when set on the same call that creates the bind.
    // Doing this last (after the .oldroot cleanup above) matters: if the
    // root were already read-only, rmdir("/.oldroot") would fail.
    if let Err(e) = mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
        None::<&str>,
    ) {
        eprintln!("Container: failed to remount rootfs read-only: {}", e);
        std::process::exit(1);
    }

    println!(
        "Container: pivoted into isolated rootfs at {} (now read-only).",
        ROOTFS_PATH
    );
}

/// Builds the seccomp-BPF program enforcing `ALLOWED_SYSCALLS`. Two checks
/// run in order: the syscall table's architecture (rejects the classic
/// 32-bit-ABI confusion attack on x86_64), then the syscall number itself
/// against the allowlist. Anything that falls through both is killed.
fn build_seccomp_filter() -> Vec<libc::sock_filter> {
    let ld_word_abs = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let jmp_jeq_k = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let ret_k = (libc::BPF_RET | libc::BPF_K) as u16;

    // Indices 0-3 are fixed regardless of allowlist size, so the arch check's
    // jt (skip 1 instruction: the kill that follows it, landing on load_nr)
    // can be hardcoded here.
    let mut program = vec![
        libc::sock_filter {
            code: ld_word_abs,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_ARCH_OFFSET,
        },
        libc::sock_filter {
            code: jmp_jeq_k,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH_X86_64,
        },
        libc::sock_filter {
            code: ret_k,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_KILL_PROCESS,
        },
        libc::sock_filter {
            code: ld_word_abs,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        },
    ];

    // One BPF_JEQ per allowed syscall. RET_KILL_PROCESS sits immediately
    // after the last check — that's the fallthrough target when nothing
    // matches (every check's jf: 0 just falls to the next instruction, and
    // "next" after the last check is this kill). A match must instead jump
    // *past* it to RET_ALLOW: for the check at index i (of n total), that's
    // n - i instructions to skip (n - i - 1 remaining checks, plus the kill
    // instruction itself).
    //
    // Getting this backwards — e.g. putting RET_ALLOW right after the
    // checks instead of RET_KILL_PROCESS — silently makes the filter allow
    // everything: a non-match would fall through onto RET_ALLOW by the same
    // positional accident, since fallthrough only depends on what
    // instruction comes next, not on whether anything actually matched.
    // (Caught exactly this bug empirically before it shipped — see the
    // seccomp_filter_no_match_falls_through_to_kill test below.)
    let n = ALLOWED_SYSCALLS.len();
    for (i, &syscall_nr) in ALLOWED_SYSCALLS.iter().enumerate() {
        program.push(libc::sock_filter {
            code: jmp_jeq_k,
            jt: (n - i) as u8,
            jf: 0,
            k: syscall_nr as u32,
        });
    }

    program.push(libc::sock_filter {
        code: ret_k,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_KILL_PROCESS,
    });
    program.push(libc::sock_filter {
        code: ret_k,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    });

    program
}

/// Installs the seccomp filter for this process and everything it execs or
/// forks from here on — irreversible, and deliberately the last thing done
/// before execvp so it only constrains the untrusted entrypoint, not
/// FerroVault's own setup code (which needs a much broader syscall set).
fn install_seccomp_filter() {
    // Not strictly required since the container runs as real root, but
    // cheap, standard defense-in-depth, and doesn't conflict with anything
    // in ALLOWED_SYSCALLS.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        eprintln!(
            "Container: prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    let program = build_seccomp_filter();
    let fprog = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_ptr() as *mut libc::sock_filter,
    };

    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &fprog) } != 0 {
        eprintln!(
            "Container: prctl(PR_SET_SECCOMP) failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    println!(
        "Container: seccomp filter installed — {} syscalls allowed, everything else kills the process.",
        ALLOWED_SYSCALLS.len()
    );
}

fn execute_container_payload() {
    println!("Container: Entered new PID namespace. I am PID 1.");

    pivot_to_rootfs();

    // Overmount /proc with a fresh procfs scoped to this PID namespace.
    // MS_NOSUID/NODEV/NOEXEC are the standard hardening flags for procfs —
    // prevents setuid escalation and device/exec abuse through /proc paths.
    if let Err(e) = mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    ) {
        eprintln!("Container: failed to mount procfs: {}", e);
        std::process::exit(1);
    }

    println!("Container: /proc mounted. Only this namespace's processes are visible.");

    // Recover the fd number the manager stored before forking
    let fd_num: i32 = std::env::var("FERROVAULT_IDENTITY_FD")
        .expect("FERROVAULT_IDENTITY_FD not set")
        .parse()
        .expect("invalid fd number");

    let mut identity = [0u8; 32];
    read(fd_num, &mut identity).expect("read identity from memfd");

    // Print as hex — proves the sealed identity was received intact
    println!("Container: Identity received — 0x{}", to_hex(&identity));

    // Last step before exec: everything from here on (the entrypoint and
    // anything it forks) is confined to ALLOWED_SYSCALLS.
    install_seccomp_filter();

    // fd intentionally left open: sh inherits it, verifiable via
    // `ls -la /proc/1/fd` inside the container
    let command = CString::new("/bin/sh").unwrap();
    let args = [CString::new("/bin/sh").unwrap()];

    let e = execvp(&command, &args).unwrap_err();
    eprintln!("Container: execvp failed: {}", e);
    std::process::exit(1);
}

/// Lowercase, zero-padded hex encoding, e.g. `[0x02, 0xff]` -> "02ff".
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cgroup_limits_match_documented_values() {
        let d = CgroupLimits::default();
        assert_eq!(d.memory_max_bytes, 256 * 1024 * 1024);
        assert_eq!(d.cpu_quota_us, 50_000);
        assert_eq!(d.cpu_period_us, 100_000);
        assert_eq!(d.pids_max, 32);
    }

    #[test]
    fn cgroup_writes_has_expected_files_and_order() {
        let writes = CgroupLimits::default().cgroup_writes();
        let names: Vec<&str> = writes.iter().map(|(f, _)| *f).collect();
        assert_eq!(names, ["memory.max", "cpu.max", "pids.max"]);
    }

    #[test]
    fn cpu_max_formats_quota_and_period_space_separated() {
        let limits = CgroupLimits {
            cpu_quota_us: 50_000,
            cpu_period_us: 100_000,
            ..CgroupLimits::default()
        };
        let (_, value) = &limits.cgroup_writes()[1];
        assert_eq!(value, "50000 100000");
    }

    #[test]
    fn memory_max_and_pids_max_stringify_plainly() {
        let limits = CgroupLimits {
            memory_max_bytes: 268_435_456,
            pids_max: 32,
            ..CgroupLimits::default()
        };
        let writes = limits.cgroup_writes();
        assert_eq!(writes[0].1, "268435456");
        assert_eq!(writes[2].1, "32");
    }

    #[test]
    fn to_hex_empty_slice_is_empty_string() {
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn to_hex_zero_pads_single_digit_bytes() {
        assert_eq!(to_hex(&[0x00]), "00");
        assert_eq!(to_hex(&[0x02]), "02");
    }

    #[test]
    fn to_hex_is_lowercase() {
        assert_eq!(to_hex(&[0xab, 0xcd, 0xef]), "abcdef");
    }

    #[test]
    fn to_hex_32_byte_identity_has_expected_length_and_content() {
        let identity: [u8; 32] = std::array::from_fn(|i| i as u8);
        let hex = to_hex(&identity);
        assert_eq!(hex.len(), 64);
        assert_eq!(&hex[0..6], "000102");
        assert_eq!(&hex[hex.len() - 6..], "1d1e1f");
    }

    // Fixed prefix before the per-syscall checks: load_arch, check_arch,
    // kill_wrong_arch, load_nr. Mirrors build_seccomp_filter()'s own layout —
    // if that layout changes, these indices must move with it.
    const PREFIX_LEN: usize = 4;

    #[test]
    fn seccomp_filter_length_matches_prefix_plus_allowlist_plus_two_returns() {
        let program = build_seccomp_filter();
        assert_eq!(program.len(), PREFIX_LEN + ALLOWED_SYSCALLS.len() + 2);
    }

    // The layout after the fixed prefix is: n syscall checks, then
    // RET_KILL_PROCESS (the fallthrough/default target), then RET_ALLOW
    // (reached only via an explicit jump from a matching check).
    fn kill_index() -> usize {
        PREFIX_LEN + ALLOWED_SYSCALLS.len()
    }
    fn allow_index() -> usize {
        kill_index() + 1
    }

    #[test]
    fn seccomp_filter_no_match_falls_through_every_check_to_kill_process() {
        // The single most important property of a default-deny filter: if a
        // syscall doesn't match any check, where do you actually land? Not
        // "does a match jump correctly" (checked below) — this simulates
        // the pure fallthrough path (every jf: 0, i.e. no match anywhere)
        // starting from the first check, exactly as the kernel's BPF
        // interpreter would for an unlisted syscall number.
        //
        // This is the test that would have caught the real bug shipped
        // here: RET_ALLOW placed immediately after the last check made
        // fallthrough land on ALLOW by coincidence, making the filter
        // permit every syscall regardless of the allowlist. Confirmed with
        // a live, unprivileged, forked reproduction outside this test suite
        // before fixing it — this test encodes that same property so it
        // can't regress silently.
        let program = build_seccomp_filter();
        let mut pc = PREFIX_LEN;
        while program[pc].jf == 0 && pc < kill_index() {
            pc += 1;
        }
        assert_eq!(
            pc,
            kill_index(),
            "falling through every check should land on RET_KILL_PROCESS, not somewhere else"
        );
        assert_eq!(program[kill_index()].k, libc::SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn seccomp_filter_last_syscall_check_jumps_past_kill_to_allow() {
        let program = build_seccomp_filter();
        let last_check = program[kill_index() - 1];
        // jt: 1 means "match -> skip the very next instruction (the kill)
        // and land on the one after it" — which must be RET_ALLOW.
        assert_eq!(last_check.jt, 1);
        assert_eq!(last_check.jf, 0);
    }

    #[test]
    fn seccomp_filter_first_syscall_check_jumps_past_every_other_check_and_kill() {
        let program = build_seccomp_filter();
        let first_check = program[PREFIX_LEN];
        assert_eq!(first_check.jt, ALLOWED_SYSCALLS.len() as u8);
    }

    #[test]
    fn seccomp_filter_every_syscall_check_lands_on_ret_allow_when_matched() {
        let program = build_seccomp_filter();
        for (i, check_index) in (PREFIX_LEN..kill_index()).enumerate() {
            let check = program[check_index];
            let landing_index = check_index + 1 + check.jt as usize;
            assert_eq!(
                landing_index,
                allow_index(),
                "check for syscall #{i} (nr={}) lands on index {landing_index}, expected RET_ALLOW at {}",
                ALLOWED_SYSCALLS[i],
                allow_index()
            );
        }
    }

    #[test]
    fn seccomp_filter_ends_with_kill_process_then_allow() {
        let program = build_seccomp_filter();
        assert_eq!(program[kill_index()].k, libc::SECCOMP_RET_KILL_PROCESS);
        assert_eq!(program[allow_index()].k, libc::SECCOMP_RET_ALLOW);
    }

    #[test]
    fn seccomp_filter_checks_cover_every_allowed_syscall_in_order() {
        let program = build_seccomp_filter();
        let checked: Vec<i64> = program[PREFIX_LEN..PREFIX_LEN + ALLOWED_SYSCALLS.len()]
            .iter()
            .map(|f| f.k as i64)
            .collect();
        assert_eq!(checked, ALLOWED_SYSCALLS);
    }
}
