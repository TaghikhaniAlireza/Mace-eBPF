//! Loads the compiled eBPF object and runs `BPF_PROG_LOAD` for each **tracepoint** program so the
//! kernel verifier must accept them. (The linked object may also contain non-tracepoint symbols
//! such as `aegis_ebpf`; those are skipped because they are not valid `BPF_PROG_TYPE_TRACEPOINT`
//! loads.)
//!
//! Requires **root** (or CAP_BPF) and a prior **eBPF build**.
//!
//! The test is marked `#[ignore]` because many CI / microVM kernels (for example Firecracker)
//! reject `BPF_PROG_LOAD` for tracepoints with `EINVAL` before the verifier runs. On a normal
//! Linux workstation or server with BPF enabled, run:
//!
//! `sudo env PATH="$PATH" RUSTUP_HOME="$RUSTUP_HOME" CARGO_HOME="$CARGO_HOME" cargo test --test verifier_load_test -p aegis-ebpf -- --ignored`

mod common;

use aya::{EbpfLoader, VerifierLogLevel, programs::Program};

/// Must match `#[tracepoint(...)]` entry points in `aegis-ebpf-ebpf`.
const EXPECTED_TRACEPOINTS: &[&str] = &[
    "sys_enter_mmap",
    "sys_enter_mprotect",
    "sys_enter_memfd_create",
    "sys_enter_ptrace",
    "sys_enter_execve",
    "sys_exit_mmap",
    "sys_exit_mprotect",
    "sys_exit_memfd_create",
    "sys_exit_ptrace",
    "sys_exit_execve",
];

#[test]
#[ignore = "needs root + full BPF tracepoint support; run with --ignored on a capable kernel"]
fn test_load_ebpf_program() {
    common::assert_running_as_root();
    common::bump_memlock_rlimit();

    let path = common::resolve_ebpf_object_path();
    let mut ebpf = EbpfLoader::new()
        .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
        .load_file(&path)
        .unwrap_or_else(|e| {
            panic!(
                "failed to parse/load eBPF object from {}: {e}",
                path.display()
            )
        });

    let mut tracepoint_names: Vec<&str> = ebpf
        .programs()
        .filter_map(|(name, p)| matches!(p, Program::TracePoint(_)).then_some(name))
        .collect();
    tracepoint_names.sort();

    assert!(
        !tracepoint_names.is_empty(),
        "no tracepoint programs found in {}; check aegis-ebpf-ebpf exports #[tracepoint] progs",
        path.display()
    );

    for expected in EXPECTED_TRACEPOINTS {
        assert!(
            tracepoint_names.contains(expected),
            "expected tracepoint `{expected}` missing from object; found: {tracepoint_names:?}"
        );
    }

    assert_eq!(
        tracepoint_names.len(),
        EXPECTED_TRACEPOINTS.len(),
        "tracepoint set mismatch: expected exactly {:?}, found {:?}",
        EXPECTED_TRACEPOINTS,
        tracepoint_names
    );

    for name in EXPECTED_TRACEPOINTS {
        let program = ebpf
            .program_mut(name)
            .unwrap_or_else(|| panic!("program `{name}` missing after enumeration"));
        let Program::TracePoint(tp) = program else {
            panic!("program `{name}` is not a TracePoint");
        };
        if let Err(e) = tp.load() {
            panic!("kernel verifier rejected tracepoint `{name}`: {e}");
        }
    }
}
