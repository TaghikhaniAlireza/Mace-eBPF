//! Attaches syscall tracepoints, triggers `mprotect` with `PROT_EXEC`, and reads a `MemoryEvent`
//! from the kernel `EVENTS` ring buffer.
//!
//! Requires **root** and full BPF / tracepoint support. Marked `#[ignore]` like Phase 2.1 so
//! `cargo test` succeeds on restricted kernels (e.g. Firecracker). On a capable host:
//!
//! `sudo env PATH="$PATH" RUSTUP_HOME="$RUSTUP_HOME" CARGO_HOME="$CARGO_HOME" cargo test --test tracepoint_attach_test -p aegis-ebpf -- --ignored`
//!
//! The test sleeps briefly after `mmap` so `mprotect` is not dropped by the eBPF program’s shared
//! mmap/mprotect rate limiter (see `RATE_LIMIT_INTERVAL_NS` in `aegis-ebpf-ebpf`).

mod common;

use std::time::{Duration, Instant};

use aegis_ebpf_common::{EventType, MemoryEvent};
use aya::{
    EbpfLoader, VerifierLogLevel,
    maps::RingBuf,
    programs::{Program, trace_point::TracePointLinkId},
};

/// `(program_name, tracepoint_name)` — same pairing as `start_sensor` in `aegis-ebpf` lib.
const SYSCALL_TRACEPOINTS: &[(&str, &str)] = &[
    ("sys_enter_mmap", "sys_enter_mmap"),
    ("sys_enter_mprotect", "sys_enter_mprotect"),
    ("sys_enter_memfd_create", "sys_enter_memfd_create"),
    ("sys_enter_ptrace", "sys_enter_ptrace"),
    ("sys_exit_mmap", "sys_exit_mmap"),
    ("sys_exit_mprotect", "sys_exit_mprotect"),
    ("sys_exit_memfd_create", "sys_exit_memfd_create"),
    ("sys_exit_ptrace", "sys_exit_ptrace"),
];

#[test]
#[ignore = "needs root + full BPF tracepoint + ringbuf; run with --ignored on a capable kernel"]
fn test_tracepoint_attach_and_mprotect_event() {
    common::assert_running_as_root();
    common::bump_memlock_rlimit();

    let path = common::resolve_ebpf_object_path();
    let mut ebpf = EbpfLoader::new()
        .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
        .load_file(&path)
        .unwrap_or_else(|e| panic!("failed to load eBPF object from {}: {e}", path.display()));

    let mut _links: Vec<TracePointLinkId> = Vec::new();

    for &(program_name, tracepoint_name) in SYSCALL_TRACEPOINTS {
        let program = ebpf
            .program_mut(program_name)
            .unwrap_or_else(|| panic!("missing program `{program_name}`"));
        let Program::TracePoint(tp) = program else {
            panic!("`{program_name}` is not a TracePoint");
        };
        tp.load()
            .unwrap_or_else(|e| panic!("load `{program_name}`: {e}"));
        let link = tp.attach("syscalls", tracepoint_name).unwrap_or_else(|e| {
            panic!("attach `{program_name}` -> syscalls/{tracepoint_name}: {e}")
        });
        _links.push(link);
    }

    let mut ring = RingBuf::try_from(
        ebpf.map_mut("EVENTS")
            .expect("EVENTS ring buffer map missing from object"),
    )
    .expect("EVENTS map is not a BPF_MAP_TYPE_RINGBUF");

    let my_tgid = std::process::id();

    let prot_rw = libc::PROT_READ | libc::PROT_WRITE;
    let prot_rwx = prot_rw | libc::PROT_EXEC;
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            prot_rw,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(
        page,
        libc::MAP_FAILED,
        "mmap(MAP_ANONYMOUS) failed: {}",
        std::io::Error::last_os_error()
    );

    // `sys_enter_mmap` and `sys_enter_mprotect` share the same per-TGID rate limit in the eBPF
    // program (`RATE_LIMIT_INTERVAL_NS` = 100 ms). A mmap immediately before mprotect would
    // suppress the mprotect enter path and no `MprotectWX` event would be emitted.
    std::thread::sleep(Duration::from_millis(110));

    unsafe {
        let rc = libc::mprotect(page, 4096, prot_rwx);
        assert_eq!(rc, 0, "mprotect: {}", std::io::Error::last_os_error());
    }

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut matched: Option<MemoryEvent> = None;

    while Instant::now() < deadline && matched.is_none() {
        while let Some(item) = ring.next() {
            if let Some(ev) = MemoryEvent::from_bytes(item.as_ref())
                && ev.tgid == my_tgid
                && ev.event_type == EventType::MprotectWX
            {
                matched = Some(ev);
                break;
            }
        }

        if matched.is_none() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    unsafe {
        libc::munmap(page, 4096);
    }

    let ev = matched.expect(
        "no MprotectWX MemoryEvent for this process within timeout; \
         check tracepoints attached and ring buffer map EVENTS",
    );
    assert_eq!(ev.tgid, my_tgid);
    assert_eq!(
        ev.pid, my_tgid,
        "single-threaded test: pid should match tgid"
    );
    assert_eq!(ev.event_type, EventType::MprotectWX);
    assert!(
        ev.addr != 0 || ev.len != 0,
        "expected non-zero mprotect addr/len"
    );
}
