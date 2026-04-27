#![no_std]
#![no_main]

use aegis_ebpf_common::{
    EXECVE_ARG_MAX_LEN, EXECVE_ARGC_CAPTURE, EXECVE_ARGV_BLOB_LEN, KernelMemoryEvent,
    MemorySyscall, OPENAT_PATH_MAX_LEN, RING_PAYLOAD_BLOB_LEN, RING_SAMPLE_LAYOUT_VERSION,
    RingBufferSample, SYSCALL_ARG_COUNT, TASK_COMM_LEN,
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{LruHashMap, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;

const RINGBUF_SIZE_BYTES: u32 = 256 * 1024;
const PENDING_SYSCALLS_MAX_ENTRIES: u32 = 10_240;
const PROT_EXEC: u64 = 0x4;
const ALLOWLIST_MAX_ENTRIES: u32 = 1_024;
const RATE_LIMIT_MAX_ENTRIES: u32 = 10_240;
const RATE_LIMIT_INTERVAL_NS: u64 = 100_000_000; // 100ms per PID

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_SIZE_BYTES, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingEvent {
    kernel: KernelMemoryEvent,
    /// Union of execve argv slots and openat path (only one syscall populates per pending entry).
    payload_blob: [u8; RING_PAYLOAD_BLOB_LEN],
}

#[allow(non_upper_case_globals)]
#[map]
static pending_syscalls: LruHashMap<u64, PendingEvent> =
    LruHashMap::with_max_entries(PENDING_SYSCALLS_MAX_ENTRIES, 0);

#[map]
static ALLOWLIST: LruHashMap<u32, u8> = LruHashMap::with_max_entries(ALLOWLIST_MAX_ENTRIES, 0);

#[map]
static RATE_LIMIT_LAST_TS: LruHashMap<u32, u64> =
    LruHashMap::with_max_entries(RATE_LIMIT_MAX_ENTRIES, 0);

#[map]
static RATE_LIMITED_COUNT: LruHashMap<u32, u64> =
    LruHashMap::with_max_entries(RATE_LIMIT_MAX_ENTRIES, 0);

fn should_rate_limit(syscall: MemorySyscall) -> bool {
    // Rate-limit mmap→mprotect storms only at mmap; do not suppress standalone mprotect RWX (SIM_A_RWX).
    syscall == MemorySyscall::Mmap
}

fn read_syscall_args(ctx: &TracePointContext) -> [u64; SYSCALL_ARG_COUNT] {
    [
        unsafe { ctx.read_at::<u64>(16).unwrap_or(0) },
        unsafe { ctx.read_at::<u64>(24).unwrap_or(0) },
        unsafe { ctx.read_at::<u64>(32).unwrap_or(0) },
        unsafe { ctx.read_at::<u64>(40).unwrap_or(0) },
        unsafe { ctx.read_at::<u64>(48).unwrap_or(0) },
        unsafe { ctx.read_at::<u64>(56).unwrap_or(0) },
    ]
}

fn capture_openat_path(path_ptr: u64, out: &mut [u8]) {
    if path_ptr == 0 || out.len() < OPENAT_PATH_MAX_LEN {
        return;
    }
    let _ = unsafe {
        bpf_probe_read_user_str_bytes(path_ptr as *const u8, &mut out[..OPENAT_PATH_MAX_LEN])
    };
}

fn capture_execve_argv(argv_ptr: u64, out_blob: &mut [u8]) {
    if argv_ptr == 0 || out_blob.len() < EXECVE_ARGV_BLOB_LEN {
        return;
    }
    let argv = argv_ptr as *const u64;
    for i in 0..EXECVE_ARGC_CAPTURE {
        let arg_user_ptr = match unsafe { bpf_probe_read_user(argv.add(i)) } {
            Ok(p) => p,
            Err(_) => break,
        };
        if arg_user_ptr == 0 {
            break;
        }
        let slot_off = i * EXECVE_ARG_MAX_LEN;
        let slot = &mut out_blob[slot_off..slot_off + EXECVE_ARG_MAX_LEN];
        let _ = unsafe { bpf_probe_read_user_str_bytes(arg_user_ptr as *const u8, slot) };
    }
}

fn store_pending_event(ctx: &TracePointContext, syscall: MemorySyscall) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    if unsafe { ALLOWLIST.get(&tgid) }.is_some() {
        return 0;
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };
    if should_rate_limit(syscall) {
        let last_ts = unsafe { RATE_LIMIT_LAST_TS.get(&tgid).copied().unwrap_or(0) };

        if now_ns.saturating_sub(last_ts) < RATE_LIMIT_INTERVAL_NS {
            let prev = unsafe { RATE_LIMITED_COUNT.get(&tgid).copied().unwrap_or(0) };
            let next = prev.saturating_add(1);
            let _ = RATE_LIMITED_COUNT.insert(&tgid, &next, 0);
            return 0;
        }

        let _ = RATE_LIMIT_LAST_TS.insert(&tgid, &now_ns, 0);
    }

    let comm = bpf_get_current_comm().unwrap_or([0; TASK_COMM_LEN]);
    let args = read_syscall_args(ctx);
    // Build `PendingEvent` in place: separate temp `[u8; N]` arrays plus a full `PendingEvent`
    // exceed the ~512 B BPF stack limit when LLVM keeps both alive across helper calls.
    let mut pending = PendingEvent {
        kernel: KernelMemoryEvent {
            timestamp_ns: now_ns,
            pid: pid_tgid as u32,
            tgid,
            syscall: syscall as u32,
            args,
            comm,
        },
        payload_blob: [0u8; RING_PAYLOAD_BLOB_LEN],
    };
    if syscall == MemorySyscall::Execve {
        capture_execve_argv(args[1], &mut pending.payload_blob[..EXECVE_ARGV_BLOB_LEN]);
    } else if syscall == MemorySyscall::Openat {
        capture_openat_path(args[1], &mut pending.payload_blob[..OPENAT_PATH_MAX_LEN]);
    }

    if let Err(err) = pending_syscalls.insert(pid_tgid, pending, 0) {
        warn!(ctx, "pending syscall insert failed: {}", err);
        return 1;
    }

    0
}

fn emit_pending_event_on_success(ctx: &TracePointContext, syscall: MemorySyscall) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = unsafe { ctx.read_at::<i64>(16).unwrap_or(-1) };
    let pending = unsafe { pending_syscalls.get(&pid_tgid).copied() };
    let Some(mut pending) = pending else { return 0 };

    // Ptrace / openat: emit on exit even when the syscall fails (e.g. EPERM) so user-space rules
    // can detect attach attempts and sensitive-path opens.
    let always_emit = matches!(
        syscall,
        MemorySyscall::Ptrace | MemorySyscall::Openat | MemorySyscall::Execve
    );

    if ret < 0 && !always_emit {
        let _ = pending_syscalls.remove(&pid_tgid);
        return 0;
    }

    if syscall == MemorySyscall::Mprotect && (pending.kernel.args[2] & PROT_EXEC) == 0 {
        let _ = pending_syscalls.remove(&pid_tgid);
        return 0;
    }

    pending.kernel.syscall = syscall as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let sample = RingBufferSample {
        kernel: pending.kernel,
        syscall_ret: ret,
        uid,
        _reserved: 0,
        layout_version: RING_SAMPLE_LAYOUT_VERSION,
        payload_blob: pending.payload_blob,
    };
    if let Some(mut entry) = EVENTS.reserve::<RingBufferSample>(0) {
        entry.write(sample);
        entry.submit(0);
    } else {
        warn!(ctx, "ring buffer reserve failed");
    }

    let _ = pending_syscalls.remove(&pid_tgid);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_mmap")]
pub fn sys_enter_mmap(ctx: TracePointContext) -> u32 {
    store_pending_event(&ctx, MemorySyscall::Mmap)
}

#[tracepoint(category = "syscalls", name = "sys_enter_mprotect")]
pub fn sys_enter_mprotect(ctx: TracePointContext) -> u32 {
    store_pending_event(&ctx, MemorySyscall::Mprotect)
}

#[tracepoint(category = "syscalls", name = "sys_enter_memfd_create")]
pub fn sys_enter_memfd_create(ctx: TracePointContext) -> u32 {
    store_pending_event(&ctx, MemorySyscall::MemfdCreate)
}

#[tracepoint(category = "syscalls", name = "sys_enter_ptrace")]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    store_pending_event(&ctx, MemorySyscall::Ptrace)
}

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    store_pending_event(&ctx, MemorySyscall::Execve)
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    store_pending_event(&ctx, MemorySyscall::Openat)
}

#[tracepoint(category = "syscalls", name = "sys_exit_mmap")]
pub fn sys_exit_mmap(ctx: TracePointContext) -> u32 {
    emit_pending_event_on_success(&ctx, MemorySyscall::Mmap)
}

#[tracepoint(category = "syscalls", name = "sys_exit_mprotect")]
pub fn sys_exit_mprotect(ctx: TracePointContext) -> u32 {
    emit_pending_event_on_success(&ctx, MemorySyscall::Mprotect)
}

#[tracepoint(category = "syscalls", name = "sys_exit_memfd_create")]
pub fn sys_exit_memfd_create(ctx: TracePointContext) -> u32 {
    emit_pending_event_on_success(&ctx, MemorySyscall::MemfdCreate)
}

#[tracepoint(category = "syscalls", name = "sys_exit_ptrace")]
pub fn sys_exit_ptrace(ctx: TracePointContext) -> u32 {
    emit_pending_event_on_success(&ctx, MemorySyscall::Ptrace)
}

#[tracepoint(category = "syscalls", name = "sys_exit_execve")]
pub fn sys_exit_execve(ctx: TracePointContext) -> u32 {
    emit_pending_event_on_success(&ctx, MemorySyscall::Execve)
}

#[tracepoint(category = "syscalls", name = "sys_exit_openat")]
pub fn sys_exit_openat(ctx: TracePointContext) -> u32 {
    emit_pending_event_on_success(&ctx, MemorySyscall::Openat)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
