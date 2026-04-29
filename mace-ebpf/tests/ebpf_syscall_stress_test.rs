//! Real kernel `mprotect` storm with concurrent ring-buffer draining.
//!
//! Loads the same syscall tracepoints as [`tracepoint_attach_test`](mod@tracepoint_attach_test),
//! triggers many `mprotect` transitions to `PROT_READ | PROT_WRITE | PROT_EXEC` (reverted to
//! `PROT_READ` each iteration), and counts [`EventType::MprotectWX`] samples from the `EVENTS`
//! ring buffer for this process group.
//!
//! **Rate limiting in eBPF:** `sys_enter_mprotect` / `sys_enter_mmap` are limited to one stored
//! pending event per TGID per 100 ms (see `RATE_LIMIT_INTERVAL_NS` in the eBPF program). Under a
//! tight loop, most syscalls are intentionally suppressed in-kernel; the test still validates that
//! the kernel-to-userspace path stays responsive (no hang) and reports implied drop rate vs
//! syscall count.
//!
//! Requires **root** and full BPF / tracepoint support. Marked `#[ignore]` so `cargo test`
//! succeeds on restricted kernels (e.g. Firecracker). On a capable host:
//!
//! ```text
//! sudo env PATH="$PATH" RUSTUP_HOME="$RUSTUP_HOME" CARGO_HOME="$CARGO_HOME" \
//!   cargo test --test ebpf_syscall_stress_test -p mace-ebpf -- --ignored --nocapture
//! ```

mod common;

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use aya::{
    EbpfLoader, VerifierLogLevel,
    maps::RingBuf,
    programs::{Program, trace_point::TracePointLinkId},
};
use mace_ebpf_common::{EventType, MemoryEvent};

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

/// Iterations per worker thread (`mprotect` RWX then revert per iteration).
const MPROTECT_ITERATIONS_PER_THREAD: u32 = 50_000;
/// Worker threads hammering `mprotect` concurrently (same page per thread, own `mmap`).
const STRESS_THREAD_COUNT: usize = 4;
/// Wall-clock budget so the test cannot spin forever if the ring buffer misbehaves.
const TEST_DEADLINE: Duration = Duration::from_secs(120);
/// After workers finish, keep draining briefly so lagging samples are counted.
const POST_DRAIN: Duration = Duration::from_millis(500);

fn mmap_page() -> *mut libc::c_void {
    let prot_rw = libc::PROT_READ | libc::PROT_WRITE;
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
    page
}

fn mprotect_storm_loop(page: *mut libc::c_void, iterations: u32) -> u64 {
    let prot_rw = libc::PROT_READ | libc::PROT_WRITE;
    let prot_rwx = prot_rw | libc::PROT_EXEC;
    let mut ok: u64 = 0;
    for _ in 0..iterations {
        unsafe {
            if libc::mprotect(page, 4096, prot_rwx) == 0 && libc::mprotect(page, 4096, prot_rw) == 0
            {
                ok += 1;
            }
        }
    }
    ok
}

#[test]
#[ignore = "needs root + full BPF tracepoint + ringbuf; run with --ignored on a capable kernel"]
fn test_ebpf_ringbuf_under_mprotect_storm() {
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
    let syscall_ok_total = AtomicU64::new(0);
    let matched_events = AtomicU64::new(0);

    let test_start = Instant::now();

    std::thread::scope(|s| {
        for _ in 0..STRESS_THREAD_COUNT {
            s.spawn(|| {
                let page = mmap_page();
                let n = mprotect_storm_loop(page, MPROTECT_ITERATIONS_PER_THREAD);
                syscall_ok_total.fetch_add(n, Ordering::Relaxed);
                unsafe {
                    libc::munmap(page, 4096);
                }
            });
        }

        let deadline = Instant::now() + TEST_DEADLINE;
        while Instant::now() < deadline {
            let workers_done = syscall_ok_total.load(Ordering::Relaxed)
                >= u64::from(MPROTECT_ITERATIONS_PER_THREAD) * STRESS_THREAD_COUNT as u64;

            while let Some(item) = ring.next() {
                if let Some(ev) = MemoryEvent::from_bytes(item.as_ref())
                    && ev.tgid == my_tgid
                    && ev.event_type == EventType::MprotectWX
                {
                    matched_events.fetch_add(1, Ordering::Relaxed);
                }
            }

            if workers_done && Instant::now() > test_start + POST_DRAIN {
                break;
            }
            std::thread::sleep(Duration::from_micros(50));
        }
    });

    let elapsed = test_start.elapsed();
    let syscalls = syscall_ok_total.load(Ordering::Relaxed);
    let received = matched_events.load(Ordering::Relaxed);

    eprintln!(
        "[ebpf_syscall_stress] threads={} iterations/thread={} elapsed={:.2?} syscalls_ok={} ringbuf_mprotect_wx={}",
        STRESS_THREAD_COUNT, MPROTECT_ITERATIONS_PER_THREAD, elapsed, syscalls, received
    );

    if syscalls > 0 {
        let drop_pct = (1.0_f64 - (received as f64 / syscalls as f64)) * 100.0_f64;
        eprintln!(
            "[ebpf_syscall_stress] implied_drop_vs_successful_syscalls={:.4}% (kernel rate-limit + ringbuf reserve failures reduce observable events)",
            drop_pct.clamp(0.0, 100.0)
        );
    }

    assert!(
        elapsed < TEST_DEADLINE,
        "test exceeded wall-clock budget ({TEST_DEADLINE:?}); possible hang"
    );
    assert!(
        syscalls > 0,
        "expected at least one successful mprotect pair; last OS error: {:?}",
        std::io::Error::last_os_error()
    );
    assert!(
        received > 0,
        "expected at least one MprotectWX ring-buffer event for this process; \
         check tracepoints and EVENTS map"
    );

    // Under extreme load the 256 KiB ring buffer can drop; do not fail the build on drops.
    if received < syscalls {
        eprintln!(
            "[ebpf_syscall_stress] note: received ({received}) < successful syscalls ({syscalls}); \
             eBPF rate limiting and/or ring buffer backpressure"
        );
    }
}
