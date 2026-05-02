#![allow(clippy::collapsible_if, clippy::manual_clamp)]

use std::{
    convert::TryFrom as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Once},
    time::Duration,
};

use parking_lot::Mutex;

pub mod alert;
pub mod audit;
pub mod cmdline_context;
pub mod engine_stage;
pub mod enrichment;
pub mod execve_wire;
pub mod ffi;
pub mod kernel_health;
pub mod logging;
pub mod observability;
pub mod passwd;
pub mod pipeline;
pub mod proc_cmdline;
pub mod proto;
pub mod rules;
pub mod state;

pub use alert::{Alert, AlertCallback, StandardizedEvent, StandardizedEventCallback};
use anyhow::Context as _;
use aya::{
    Btf, Ebpf, EbpfLoader, Endianness,
    maps::{HashMap, RingBuf},
    programs::TracePoint,
};
pub use enrichment::{ContextEnricher, NoopEnricher, PodMetadata};
pub use ffi::event_callback::{
    JsonCallback, mace_register_event_callback, mace_unregister_event_callback,
};
use log::{debug, warn};
pub use logging::MaceLogLevel;
use mace_ebpf_common::MemoryEvent;
use tracing_subscriber::{EnvFilter, prelude::*};

static FFI_LOG_ONCE: Once = Once::new();

/// When loaded as `libmace_ebpf.so`, nothing runs `main()` — install a `tracing` subscriber once so
/// **`RUST_LOG`** applies to `tracing::*` macros (rule engine, pipeline). Also bridges the `log`
/// crate via **`tracing-log`** (`log::info!`, etc.).
pub(crate) fn init_logging_for_ffi() {
    FFI_LOG_ONCE.call_once(|| {
        let _ = tracing_log::LogTracer::init();
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            // sensible default when `RUST_LOG` is unset (embedded Go/Python callers)
            EnvFilter::new("info")
        });
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .try_init();
        logging::apply_env_log_level();
    });
}
pub use pipeline::{
    EnrichedEvent, PipelineError, PipelineHandle, config::PipelineConfig, start_pipeline,
};
pub use state::{ProcessState, StateTracker};
use tokio::sync::mpsc;

pub struct SensorConfig {
    pub allowlist_pids: Vec<u32>,
    pub channel_capacity: usize,
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            allowlist_pids: vec![],
            // Large ring-buffer records + syscall bursts: avoid starving the enrichment task.
            channel_capacity: 8192,
        }
    }
}

pub async fn start_sensor(
    config: SensorConfig,
) -> anyhow::Result<(mpsc::Receiver<MemoryEvent>, Arc<Mutex<Ebpf>>)> {
    bump_memlock_rlimit();

    let mut ebpf = load_ebpf().await?;
    init_ebpf_logger(&mut ebpf);

    // Hooks needed for exec argv, open paths, and ptrace — failure here means the sensor cannot run.
    const REQUIRED_SYSCALL_TRACEPOINTS: &[(&str, &str)] = &[
        ("sys_enter_execve", "sys_enter_execve"),
        ("sys_exit_execve", "sys_exit_execve"),
        ("sys_enter_execveat", "sys_enter_execveat"),
        ("sys_exit_execveat", "sys_exit_execveat"),
        ("sys_enter_openat", "sys_enter_openat"),
        ("sys_exit_openat", "sys_exit_openat"),
        ("sys_enter_ptrace", "sys_enter_ptrace"),
        ("sys_exit_ptrace", "sys_exit_ptrace"),
    ];

    // Memory syscall hooks — optional so we still emit execve/openat/ptrace events if the kernel
    // rejects one of these (EINVAL/EPERM varies by distro, lockdown, or missing tracepoint).
    const OPTIONAL_SYSCALL_TRACEPOINTS: &[(&str, &str)] = &[
        ("sys_enter_mmap", "sys_enter_mmap"),
        ("sys_exit_mmap", "sys_exit_mmap"),
        ("sys_enter_mprotect", "sys_enter_mprotect"),
        ("sys_exit_mprotect", "sys_exit_mprotect"),
        ("sys_enter_memfd_create", "sys_enter_memfd_create"),
        ("sys_exit_memfd_create", "sys_exit_memfd_create"),
    ];

    for &(program_name, tracepoint_name) in REQUIRED_SYSCALL_TRACEPOINTS {
        attach_syscall_tracepoint(&mut ebpf, program_name, tracepoint_name)?;
    }
    for &(program_name, tracepoint_name) in OPTIONAL_SYSCALL_TRACEPOINTS {
        if let Err(e) = attach_syscall_tracepoint(&mut ebpf, program_name, tracepoint_name) {
            mace_log!(
                Info,
                "optional syscall tracepoint not attached program={} tracepoint={}: {:#}",
                program_name,
                tracepoint_name,
                e
            );
        }
    }

    populate_allowlist(&mut ebpf, &config.allowlist_pids)?;

    let ebpf = Arc::new(Mutex::new(ebpf));

    let ring_buf = {
        let mut g = ebpf.lock();
        RingBuf::try_from(g.take_map("EVENTS").context("eBPF map EVENTS not found")?)?
    };
    let mut ring_buf =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let ebpf_stats = Arc::clone(&ebpf);
    tokio::task::spawn(async move {
        let _keep_alive = ebpf_stats;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let mut g = _keep_alive.lock();
            kernel_health::refresh_kernel_stats_from_ebpf(&mut g);
        }
    });

    let (tx, rx) = mpsc::channel(config.channel_capacity.max(1));
    let ebpf_ring = Arc::clone(&ebpf);
    tokio::task::spawn(async move {
        let _keep_alive = ebpf_ring;
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

    Ok((rx, ebpf))
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
        .with_context(|| format!("eBPF program `{program_name}` not found in loaded object"))?
        .try_into()
        .with_context(|| format!("program `{program_name}` is not a tracepoint"))?;
    program
        .load()
        .with_context(|| format!("failed to load eBPF program `{program_name}`"))?;
    program
        .attach("syscalls", tracepoint_name)
        .with_context(|| {
            format!("failed to attach `{program_name}` to tracepoint `syscalls/{tracepoint_name}`")
        })?;
    Ok(())
}

fn populate_allowlist(ebpf: &mut Ebpf, allowlist_pids: &[u32]) -> anyhow::Result<()> {
    let mut allowlist = HashMap::<_, u32, u8>::try_from(
        ebpf.map_mut("ALLOWLIST")
            .context("eBPF map ALLOWLIST not found")?,
    )?;
    for &tgid in allowlist_pids {
        allowlist.insert(tgid, 1u8, 0)?;
    }
    Ok(())
}

async fn load_ebpf() -> anyhow::Result<Ebpf> {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/mace-ebpf"));
    if let Some(btf) = load_btf().await? {
        let mut loader = EbpfLoader::new();
        loader.btf(Some(&btf));
        return loader
            .load(bytes)
            .context("failed to load eBPF with fallback BTF");
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
        return Err(anyhow::anyhow!(
            "tar extraction failed with status {status}"
        ));
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
    let content =
        fs::read_to_string("/etc/os-release").context("reading /etc/os-release failed")?;
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

// Maps host `ARCH` strings (e.g. `std::env::consts::ARCH`) to BTFHub archive directory names.
// Pure helper so tests can pass arbitrary `arch` without changing the process environment.
fn btfhub_arch_for(arch: &str) -> &str {
    match arch {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => other,
    }
}

fn btfhub_arch() -> &'static str {
    btfhub_arch_for(std::env::consts::ARCH)
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

#[cfg(test)]
mod tests {
    use super::{btfhub_arch_for, parse_os_release_field};

    // --- parse_os_release_field ---

    /// Validates that `ID=` is parsed from a typical `/etc/os-release` fragment.
    #[test]
    fn parse_os_release_field_id_ubuntu() {
        let content = "ID=ubuntu\nVERSION_ID=\"22.04\"\n";
        assert_eq!(
            parse_os_release_field(content, "ID").as_deref(),
            Some("ubuntu")
        );
    }

    /// Validates that quoted `VERSION_ID` values are unquoted in the result.
    #[test]
    fn parse_os_release_field_version_id_quoted() {
        let content = "ID=ubuntu\nVERSION_ID=\"22.04\"\n";
        assert_eq!(
            parse_os_release_field(content, "VERSION_ID").as_deref(),
            Some("22.04")
        );
    }

    /// Validates that a missing key returns `None`.
    #[test]
    fn parse_os_release_field_missing_returns_none() {
        let content = "ID=ubuntu\n";
        assert!(parse_os_release_field(content, "VERSION_ID").is_none());
    }

    /// Validates that empty input yields `None` for any field.
    #[test]
    fn parse_os_release_field_empty_content() {
        assert!(parse_os_release_field("", "ID").is_none());
    }

    /// Validates that lines without `KEY=` are ignored and do not satisfy the lookup.
    #[test]
    fn parse_os_release_field_malformed_line_no_equals() {
        let content = "not_a_key_value_line\nalso_no_equals\n";
        assert!(parse_os_release_field(content, "ID").is_none());
    }

    /// Validates that a malformed line is skipped and a later valid line still matches.
    #[test]
    fn parse_os_release_field_skips_malformed_then_finds_key() {
        let content = "garbage\nID=debian\n";
        assert_eq!(
            parse_os_release_field(content, "ID").as_deref(),
            Some("debian")
        );
    }

    /// Validates that the first matching line wins when the key appears only once at the start.
    #[test]
    fn parse_os_release_field_key_at_start() {
        let content = "ID=alpha\nFOO=bar\n";
        assert_eq!(
            parse_os_release_field(content, "ID").as_deref(),
            Some("alpha")
        );
    }

    /// Validates parsing when the target field is in the middle of the file.
    #[test]
    fn parse_os_release_field_key_in_middle() {
        let content = "A=1\nID=middle\nB=2\n";
        assert_eq!(
            parse_os_release_field(content, "ID").as_deref(),
            Some("middle")
        );
    }

    /// Validates parsing when the target field is the last line.
    #[test]
    fn parse_os_release_field_key_at_end() {
        let content = "A=1\nB=2\nID=last\n";
        assert_eq!(
            parse_os_release_field(content, "ID").as_deref(),
            Some("last")
        );
    }

    // --- btfhub_arch_for (testable without mocking env) ---

    /// Validates that `x86_64` maps to the BTFHub directory name `x86_64`.
    #[test]
    fn btfhub_arch_for_x86_64() {
        assert_eq!(btfhub_arch_for("x86_64"), "x86_64");
    }

    /// Validates that `aarch64` maps to BTFHub's `arm64` layout.
    #[test]
    fn btfhub_arch_for_aarch64() {
        assert_eq!(btfhub_arch_for("aarch64"), "arm64");
    }

    /// Validates that unknown architecture strings pass through unchanged.
    #[test]
    fn btfhub_arch_for_unknown_passthrough() {
        assert_eq!(btfhub_arch_for("riscv64gc"), "riscv64gc");
    }

    /// Validates that `btfhub_arch()` matches `btfhub_arch_for` for the current host.
    #[test]
    fn btfhub_arch_matches_env_consts() {
        assert_eq!(
            super::btfhub_arch(),
            btfhub_arch_for(std::env::consts::ARCH)
        );
    }
}
