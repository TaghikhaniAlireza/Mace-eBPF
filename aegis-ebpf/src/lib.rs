use std::{
    convert::TryFrom as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use aegis_ebpf_common::MemoryEvent;
use anyhow::Context as _;
use aya::{
    Btf, Ebpf, EbpfLoader, Endianness,
    maps::{HashMap, RingBuf},
    programs::TracePoint,
};
use log::{debug, warn};
use tokio::sync::mpsc;

pub struct SensorConfig {
    pub blocklist_pids: Vec<u32>,
    pub channel_capacity: usize,
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            blocklist_pids: vec![],
            channel_capacity: 1024,
        }
    }
}

pub async fn start_sensor(config: SensorConfig) -> anyhow::Result<mpsc::Receiver<MemoryEvent>> {
    bump_memlock_rlimit();

    let mut ebpf = load_ebpf().await?;
    init_ebpf_logger(&mut ebpf);

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

    populate_blocklist(&mut ebpf, &config.blocklist_pids)?;

    let ring_buf = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .context("eBPF map EVENTS not found")?,
    )?;
    let mut ring_buf =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let (tx, rx) = mpsc::channel(config.channel_capacity.max(1));
    tokio::task::spawn(async move {
        let _ebpf = ebpf;
        loop {
            let mut guard = match ring_buf.readable_mut().await {
                Ok(guard) => guard,
                Err(_) => break,
            };

            while let Some(item) = guard.get_inner_mut().next() {
                if let Some(event) = MemoryEvent::from_bytes(item.as_ref()) {
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
            guard.clear_ready();
        }
    });

    Ok(rx)
}

fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

fn init_ebpf_logger(ebpf: &mut Ebpf) {
    match aya_log::EbpfLogger::init(ebpf) {
        Err(e) => warn!("failed to initialize eBPF logger: {e}"),
        Ok(logger) => {
            if let Ok(mut logger) =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)
            {
                tokio::task::spawn(async move {
                    loop {
                        let mut guard = logger.readable_mut().await.unwrap();
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
        }
    }
}

fn attach_syscall_tracepoint(
    ebpf: &mut Ebpf,
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

fn populate_blocklist(ebpf: &mut Ebpf, blocklist_pids: &[u32]) -> anyhow::Result<()> {
    let mut blocklist = HashMap::<_, u32, u8>::try_from(
        ebpf.map_mut("BLOCKLIST")
            .context("eBPF map BLOCKLIST not found")?,
    )?;
    for &tgid in blocklist_pids {
        blocklist.insert(tgid, 1u8, 0)?;
    }
    Ok(())
}

async fn load_ebpf() -> anyhow::Result<Ebpf> {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aegis-ebpf"));
    if let Some(btf) = load_btf().await? {
        let mut loader = EbpfLoader::new();
        loader.btf(Some(&btf));
        return loader.load(bytes).context("failed to load eBPF with fallback BTF");
    }
    Ebpf::load(bytes).context("failed to load eBPF program bytes")
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
    let btf = Btf::parse_file(&btf_file, Endianness::default())
        .context("failed to parse downloaded BTF")?;
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
