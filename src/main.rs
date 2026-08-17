use nix::fcntl::{fcntl, FcntlArg, SealFlag};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::wait::waitpid;
use nix::unistd::{chdir, execvp, fork, lseek, pivot_root, read, write, ForkResult, Whence};
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::io::AsRawFd;

const CGROUP_PATH: &str = "/sys/fs/cgroup/ferrovault";
const ROOTFS_PATH: &str = "/workspace/rootfs";

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
            match waitpid(child, None) {
                Ok(_) => std::process::exit(0),
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
}
