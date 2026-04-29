//! Shared helpers for eBPF integration tests (`verifier_load_test`, `tracepoint_attach_test`, …).

use std::path::PathBuf;

pub fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
}

pub fn assert_running_as_root() {
    let euid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))?
                .split_whitespace()
                .nth(1)?
                .parse::<u32>()
                .ok()
        });
    assert_eq!(
        euid,
        Some(0),
        "eBPF integration tests must run as root (CAP_BPF). \
         When using sudo, pass through PATH, RUSTUP_HOME, and CARGO_HOME, then for example:\n\
         cargo test --test <name> -p mace-ebpf -- --ignored"
    );
}

fn collect_ebpf_object_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(explicit) = std::env::var("MACE_EBPF_OBJECT") {
        paths.push(PathBuf::from(explicit));
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let workspace_root = manifest_dir.parent().map(PathBuf::from);
    let target_roots = {
        let mut roots = Vec::new();
        if let Some(ref ws) = workspace_root {
            roots.push(ws.join("target"));
        }
        if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
            roots.push(PathBuf::from(td));
        }
        roots
    };

    for target in &target_roots {
        paths.push(target.join("bpfel-unknown-none/release/mace-ebpf"));
        paths.push(target.join("bpfel-unknown-none/debug/mace-ebpf"));
    }

    for target in &target_roots {
        for profile in ["debug", "release"] {
            let build_dir = target.join(profile).join("build");
            if let Ok(entries) = std::fs::read_dir(&build_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if !name.starts_with("mace-ebpf-") {
                        continue;
                    }
                    let out = entry.path().join("out");
                    paths.push(out.join("mace-ebpf"));
                    paths.push(out.join(
                        "aya-build/target/mace-ebpf-ebpf/bpfel-unknown-none/release/mace-ebpf",
                    ));
                }
            }
        }
    }

    paths
}

pub fn resolve_ebpf_object_path() -> PathBuf {
    let mut candidates: Vec<PathBuf> = collect_ebpf_object_paths()
        .into_iter()
        .filter(|p| p.is_file())
        .collect();

    if candidates.is_empty() {
        let tried = collect_ebpf_object_paths()
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join("\n  ");

        panic!(
            "compiled eBPF object `mace-ebpf` not found. Checked:\n  {tried}\n\n\
             Build the BPF target first, for example from the workspace root:\n\
               cargo build -p mace-ebpf\n\n\
             Or set MACE_EBPF_OBJECT to an explicit path (used by Vagrant / kernel matrix).\n\n\
             (The `mace-ebpf` crate's build.rs compiles `mace-ebpf-ebpf` for `bpfel-unknown-none`.)"
        );
    }

    candidates.sort_by_key(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });

    candidates.pop().expect("non-empty after is_file filter")
}
