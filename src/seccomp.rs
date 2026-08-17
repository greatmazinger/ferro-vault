//! Seccomp-BPF syscall allowlist confining the container's entrypoint.
//!
//! `install_seccomp_filter` is called as the last step before `execvp` in
//! `execute_container_payload` (see `main.rs`) — deliberately scoped to the
//! untrusted entrypoint only, not FerroVault's own privileged setup code,
//! which needs a much broader syscall set (mount, unshare, pivot_root,
//! cgroup writes — none of which are in `ALLOWED_SYSCALLS`).

use nix::libc;

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
/// the calling process — see `install_seccomp_filter`.
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
    // seccomp_filter_no_match_falls_through_every_check_to_kill_process test
    // below.)
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
pub(crate) fn install_seccomp_filter() {
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

#[cfg(test)]
mod tests {
    use super::*;

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
