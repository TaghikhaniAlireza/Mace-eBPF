//! Loads the pre-built `mace-ebpf` ELF and attaches all syscall tracepoints.
//! Used by Vagrant / CI matrix jobs to validate CO-RE + verifier on many kernels without rebuilding BPF.
//!
//! Modes:
//!   default     — load, attach, verify EVENTS map, exit (programs unload on drop).
//!   `--daemon`  — same, then sleep forever so BPF stays attached (for stress suites; stop with SIGTERM).

use std::{env, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use aya::{
    EbpfLoader, VerifierLogLevel,
    maps::RingBuf,
    programs::{Program, trace_point::TracePointLinkId},
};

/// Same pairing as `mace_ebpf::start_sensor`.
const SYSCALL_TRACEPOINTS: &[(&str, &str)] = &[
    ("sys_enter_mmap", "sys_enter_mmap"),
    ("sys_enter_mprotect", "sys_enter_mprotect"),
    ("sys_enter_memfd_create", "sys_enter_memfd_create"),
    ("sys_enter_ptrace", "sys_enter_ptrace"),
    ("sys_enter_execve", "sys_enter_execve"),
    ("sys_enter_openat", "sys_enter_openat"),
    ("sys_exit_mmap", "sys_exit_mmap"),
    ("sys_exit_mprotect", "sys_exit_mprotect"),
    ("sys_exit_memfd_create", "sys_exit_memfd_create"),
    ("sys_exit_ptrace", "sys_exit_ptrace"),
    ("sys_exit_execve", "sys_exit_execve"),
    ("sys_exit_openat", "sys_exit_openat"),
];

extern "C" fn handle_sigterm(_sig: libc::c_int) {
    // Test harness: exit immediately on SIGTERM/SIGINT so the parent script can reap us.
    unsafe {
        libc::_exit(0);
    }
}

fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
}

fn parse_args() -> (bool, PathBuf) {
    let mut daemon = false;
    let mut path_arg: Option<PathBuf> = None;
    for a in env::args().skip(1) {
        if a == "--daemon" {
            daemon = true;
            continue;
        }
        if !a.starts_with('-') {
            path_arg = Some(PathBuf::from(a));
        }
    }
    let path = if let Some(p) = path_arg {
        p
    } else if let Ok(p) = env::var("MACE_EBPF_OBJECT") {
        PathBuf::from(p)
    } else {
        PathBuf::new()
    };
    (daemon, path)
}

fn resolve_object_path(path: PathBuf) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        anyhow::bail!(
            "usage: mace-ebpf-loader [--daemon] [PATH_TO_MACE_EBPF]\n\
             or set MACE_EBPF_OBJECT to the pre-built ELF (bpfel-unknown-none output)."
        );
    }
    if path.is_file() {
        return Ok(path);
    }
    anyhow::bail!("eBPF object path {} is not a file", path.display())
}

fn load_and_attach(path: &PathBuf) -> Result<(aya::Ebpf, Vec<TracePointLinkId>)> {
    let mut ebpf = EbpfLoader::new()
        .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
        .load_file(path)
        .with_context(|| format!("EbpfLoader::load_file({})", path.display()))?;

    let mut links: Vec<TracePointLinkId> = Vec::new();

    for &(program_name, tracepoint_name) in SYSCALL_TRACEPOINTS {
        let program = ebpf
            .program_mut(program_name)
            .with_context(|| format!("missing program `{program_name}`"))?;
        let Program::TracePoint(tp) = program else {
            anyhow::bail!("`{program_name}` is not a TracePoint");
        };
        tp.load()
            .with_context(|| format!("BPF_PROG_LOAD failed for `{program_name}`"))?;
        let link = tp
            .attach("syscalls", tracepoint_name)
            .with_context(|| format!("attach `{program_name}` -> syscalls/{tracepoint_name}"))?;
        links.push(link);
    }

    let _ring = RingBuf::try_from(ebpf.map_mut("EVENTS").context("EVENTS map missing")?)
        .context("EVENTS is not a BPF_MAP_TYPE_RINGBUF")?;

    Ok((ebpf, links))
}

fn main() -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        euid == 0,
        "must run as root (CAP_BPF required for BPF_PROG_LOAD)"
    );

    bump_memlock_rlimit();

    let (daemon, path_arg) = parse_args();
    let path = resolve_object_path(path_arg)?;
    eprintln!("mace-ebpf-loader: loading {}", path.display());

    let (ebpf, _links) = load_and_attach(&path)?;

    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    eprintln!(
        "mace-ebpf-loader: OK — loaded object and attached {} tracepoints (kernel {}).",
        SYSCALL_TRACEPOINTS.len(),
        release
    );

    if daemon {
        eprintln!(
            "mace-ebpf-loader: --daemon holding BPF until SIGTERM (pid {}).",
            std::process::id()
        );
        unsafe {
            let h = handle_sigterm as *const () as libc::sighandler_t;
            libc::signal(libc::SIGTERM, h);
            libc::signal(libc::SIGINT, h);
        }
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    drop(ebpf);
    Ok(())
}
