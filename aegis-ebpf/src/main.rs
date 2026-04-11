use std::{
    convert::TryFrom as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use aegis_ebpf_common::{MemoryEvent, MemorySyscall, TASK_COMM_LEN};
use anyhow::Context as _;
use aya::{
    Btf, EbpfLoader, Endianness,
    maps::{HashMap, RingBuf},
    programs::TracePoint,
};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let btf = match load_btf().await {
        Ok(btf) => btf,
        Err(err) => {
            eprintln!("BTF not found locally and BTFHub download failed: {err}");
            eprintln!("Try: apt install linux-image-$(uname -r)-dbgsym");
            std::process::exit(1);
        }
    };

    let mut ebpf_loader = EbpfLoader::new();
    if let Some(btf) = btf.as_ref() {
        ebpf_loader.btf(Some(btf));
    }
    let mut ebpf = ebpf_loader.load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/aegis-ebpf"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    attach_syscall_tracepoint(&mut ebpf, "sys_enter_mmap", "sys_enter_mmap")?;
    attach_syscall_tracepoint(&mut ebpf, "sys_enter_mprotect", "sys_enter_mprotect")?;
    attach_syscall_tracepoint(
        &mut ebpf,
        "sys_enter_memfd_create",
        "sys_enter_memfd_create",
    )?;
    attach_syscall_tracepoint(&mut ebpf, "sys_enter_ptrace", "sys_enter_ptrace")?;
    attach_syscall_tracepoint(&mut ebpf, "sys_exit_mmap", "sys_exit_mmap")?;
    attach_syscall_tracepoint(&mut ebpf, "sys_exit_mprotect", "sys_exit_mprotect")?;
    attach_syscall_tracepoint(&mut ebpf, "sys_exit_memfd_create", "sys_exit_memfd_create")?;
    attach_syscall_tracepoint(&mut ebpf, "sys_exit_ptrace", "sys_exit_ptrace")?;

    populate_blocklist(&mut ebpf)?;

    let ring_buf = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .context("eBPF map EVENTS not found")?,
    )?;
    let mut ring_buf =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);
    println!("Listening for memory syscall tracepoints. Press Ctrl-C to stop.");
    loop {
        tokio::select! {
            _ = &mut ctrl_c => break,
            readiness = ring_buf.readable_mut() => {
                let mut guard = readiness?;
                while let Some(item) = guard.get_inner_mut().next() {
                    if let Some(event) = MemoryEvent::from_bytes(item.as_ref()) {
                        print_memory_event(event);
                    } else {
                        warn!("received malformed ring buffer sample with {} bytes", item.len());
                    }
                }
                guard.clear_ready();
            }
        }
    }

    println!("Exiting...");

    Ok(())
}

fn populate_blocklist(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let mut blocklist = HashMap::<_, u32, u8>::try_from(
        ebpf.map_mut("BLOCKLIST")
            .context("eBPF map BLOCKLIST not found")?,
    )?;

    // Block common system processes that generate noise.
    // NOTE: Keep this minimal and deterministic for now; dynamic /proc discovery can be added later.
    let blocked_tgids = [1_u32, 2_u32];
    for tgid in blocked_tgids {
        blocklist.insert(tgid, 1u8, 0)?;
    }

    let rate_limited_count = HashMap::<_, u32, u64>::try_from(
        ebpf.map("RATE_LIMITED_COUNT")
            .context("eBPF map RATE_LIMITED_COUNT not found")?,
    )?;
    let dropped = rate_limited_count.get(&0, 0).unwrap_or(0);
    println!(
        "Kernel filter blocklist initialized ({} TGIDs). rate_limited_drops={}",
        blocked_tgids.len(),
        dropped
    );

    Ok(())
}

fn attach_syscall_tracepoint(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    tracepoint_name: &str,
) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .with_context(|| format!("eBPF program {program_name} not found"))?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", tracepoint_name)?;
    Ok(())
}

fn print_memory_event(event: MemoryEvent) {
    let syscall = event
        .syscall_kind()
        .map(|kind| kind.as_str())
        .unwrap_or("unknown");
    let comm = parse_comm(&event.comm);

    match event.syscall_kind() {
        Some(MemorySyscall::Mmap) => {
            println!(
                "[{}] tgid={} pid={} comm={} mmap(addr=0x{:x}, len={}, prot=0x{:x}, flags=0x{:x}, fd={}, offset={})",
                event.timestamp_ns,
                event.tgid,
                event.pid,
                comm,
                event.args[0],
                event.args[1],
                event.args[2],
                event.args[3],
                event.args[4] as i64,
                event.args[5]
            );
        }
        Some(MemorySyscall::Mprotect) => {
            println!(
                "[{}] tgid={} pid={} comm={} mprotect(addr=0x{:x}, len={}, prot=0x{:x})",
                event.timestamp_ns,
                event.tgid,
                event.pid,
                comm,
                event.args[0],
                event.args[1],
                event.args[2]
            );
        }
        Some(MemorySyscall::MemfdCreate) => {
            println!(
                "[{}] tgid={} pid={} comm={} memfd_create(name_ptr=0x{:x}, flags=0x{:x})",
                event.timestamp_ns, event.tgid, event.pid, comm, event.args[0], event.args[1]
            );
        }
        Some(MemorySyscall::Ptrace) => {
            println!(
                "[{}] tgid={} pid={} comm={} ptrace(request=0x{:x}, target_pid={}, addr=0x{:x}, data=0x{:x})",
                event.timestamp_ns,
                event.tgid,
                event.pid,
                comm,
                event.args[0],
                event.args[1],
                event.args[2],
                event.args[3]
            );
        }
        None => {
            println!(
                "[{}] tgid={} pid={} comm={} syscall={} args={:?}",
                event.timestamp_ns, event.tgid, event.pid, comm, syscall, event.args
            );
        }
    }
}

fn parse_comm(comm: &[u8; TASK_COMM_LEN]) -> String {
    let len = comm.iter().position(|&b| b == 0).unwrap_or(TASK_COMM_LEN);
    String::from_utf8_lossy(&comm[..len]).into_owned()
}

async fn load_btf() -> Result<Option<Btf>, anyhow::Error> {
    let local_btf_path = Path::new("/sys/kernel/btf/vmlinux");
    if fs::File::open(local_btf_path).is_ok() {
        return Ok(None);
    }

    let kernel_release = uname_release().context("failed to detect kernel release via uname -r")?;
    let (distro, version) = distro_and_version().context("failed to detect distro/version")?;
    let arch = btfhub_arch();
    let patch = kernel_release
        .split('-')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("unexpected kernel release format: {kernel_release}"))?;

    let url = format!(
        "https://github.com/aquasecurity/btfhub-archive/raw/main/{distro}/{version}/{arch}/5.4.0-{patch}-generic.btf.tar.xz"
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client for BTFHub download")?;
    let archive_bytes = client
        .get(&url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .context(format!("failed to download BTF archive from {url}"))?
        .bytes()
        .context("failed to read downloaded BTF archive bytes")?;

    let temp_dir = tempfile::tempdir().context("failed to create temporary directory")?;
    let archive_path = temp_dir.path().join("btfhub.btf.tar.xz");
    fs::write(&archive_path, &archive_bytes).context("failed to persist downloaded BTF archive")?;

    let status = Command::new("tar")
        .arg("-xJf")
        .arg(&archive_path)
        .arg("-C")
        .arg(temp_dir.path())
        .status()
        .context("failed to extract downloaded BTF archive with tar")?;
    if !status.success() {
        return Err(anyhow::anyhow!("tar extraction failed with status {status}"));
    }

    let btf_file = find_btf_file(temp_dir.path())
        .context("failed to locate .btf file in extracted BTFHub archive")?;
    let btf_bytes = fs::read(&btf_file).context("failed to read extracted .btf file")?;
    let btf =
        Btf::parse(&btf_bytes, Endianness::default()).context("failed to parse downloaded BTF")?;
    Ok(Some(btf))
}

fn uname_release() -> anyhow::Result<String> {
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .context("running uname -r failed")?;
    if !output.status.success() {
        return Err(anyhow::anyhow!("uname -r returned non-zero status"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn distro_and_version() -> anyhow::Result<(String, String)> {
    let content = fs::read_to_string("/etc/os-release").context("reading /etc/os-release failed")?;
    let id = parse_os_release_field(&content, "ID")
        .ok_or_else(|| anyhow::anyhow!("ID not found in /etc/os-release"))?;
    let version = parse_os_release_field(&content, "VERSION_ID")
        .ok_or_else(|| anyhow::anyhow!("VERSION_ID not found in /etc/os-release"))?;
    Ok((id, version))
}

fn parse_os_release_field(content: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    let value = content
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))?
        .trim()
        .trim_matches('"')
        .to_owned();
    Some(value)
}

fn btfhub_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => other,
    }
}

fn find_btf_file(root: &Path) -> anyhow::Result<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).context("failed to read extracted archive directory")? {
            let entry = entry.context("failed to access extracted archive entry")?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) == Some("btf") {
                return Ok(path);
            }
        }
    }
    Err(anyhow::anyhow!("no .btf file found"))
}
