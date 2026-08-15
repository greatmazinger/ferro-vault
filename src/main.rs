use nix::fcntl::{fcntl, FcntlArg, SealFlag};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::wait::waitpid;
use nix::unistd::{chdir, execvp, fork, lseek, pivot_root, read, write, ForkResult, Whence};
use std::ffi::{CStr, CString};
use std::fs;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::io::AsRawFd;

const CGROUP_PATH: &str = "/sys/fs/cgroup/ferrovault";
const ROOTFS_PATH: &str = "/workspace/rootfs";

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

fn main() {
    println!("=== FerroVault Manager Starting ===");

    let identity_fd = provision_identity();
    std::env::set_var("FERROVAULT_IDENTITY_FD", identity_fd.as_raw_fd().to_string());

    setup_cgroup(&CgroupLimits::default());

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            println!("Manager: Spawned container process PID {}", child);
            match waitpid(child, None) {
                Ok(status) => println!("Manager: Container exited with status: {:?}", status),
                Err(e) => eprintln!("Manager: waitpid error: {}", e),
            }
            cleanup_cgroup();
        }
        Ok(ForkResult::Child) => {
            setup_namespaces_and_spawn();
        }
        Err(e) => {
            eprintln!("Manager: fork failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn setup_cgroup(limits: &CgroupLimits) {
    // Enable controllers in the parent cgroup so child cgroups can use them.
    // Best-effort: inside a container the root cgroup may restrict this.
    if let Err(e) = fs::write(
        "/sys/fs/cgroup/cgroup.subtree_control",
        "+memory +cpu +pids",
    ) {
        eprintln!("Manager: cgroup.subtree_control (best-effort): {}", e);
    }

    fs::create_dir_all(CGROUP_PATH).expect("create cgroup directory");

    let writes: &[(&str, String)] = &[
        ("memory.max", limits.memory_max_bytes.to_string()),
        (
            "cpu.max",
            format!("{} {}", limits.cpu_quota_us, limits.cpu_period_us),
        ),
        ("pids.max", limits.pids_max.to_string()),
    ];

    for (file, value) in writes {
        match fs::write(format!("{}/{}", CGROUP_PATH, file), value) {
            Ok(_) => println!("Manager:   {} = {}", file, value),
            Err(e) => eprintln!("Manager:   {} (skipped): {}", file, e),
        }
    }

    println!("Manager: Cgroup ready at {}.", CGROUP_PATH);
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
    let fd = memfd_create(
        CStr::from_bytes_with_nul(b"ferrovault-identity\0").unwrap(),
        MemFdCreateFlag::MFD_ALLOW_SEALING,
    )
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
    print!("Container: Identity received — 0x");
    for byte in &identity {
        print!("{:02x}", byte);
    }
    println!();

    // fd intentionally left open: sh inherits it, verifiable via
    // `ls -la /proc/1/fd` inside the container
    let command = CString::new("/bin/sh").unwrap();
    let args = [CString::new("/bin/sh").unwrap()];

    let e = execvp(&command, &args).unwrap_err();
    eprintln!("Container: execvp failed: {}", e);
    std::process::exit(1);
}
