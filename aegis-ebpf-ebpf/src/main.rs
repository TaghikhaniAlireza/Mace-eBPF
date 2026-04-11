#![no_std]
#![no_main]

use aegis_ebpf_common::{MemoryEvent, MemorySyscall, SYSCALL_ARG_COUNT, TASK_COMM_LEN};
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;

const RINGBUF_SIZE_BYTES: u32 = 256 * 1024;
const BLOCKLIST_MAX_ENTRIES: u32 = 1024;
const RATE_LIMIT_TS_MAX_ENTRIES: u32 = 4096;
const RATE_LIMIT_NS: u64 = 1_000_000;
const PENDING_SYSCALLS_MAX_ENTRIES: u32 = 10_240;
const PROT_EXEC: u64 = 0x4;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_SIZE_BYTES, 0);

#[allow(non_upper_case_globals)]
#[map]
static pending_syscalls: LruHashMap<u64, MemoryEvent> =
    LruHashMap::with_max_entries(PENDING_SYSCALLS_MAX_ENTRIES, 0);

#[unsafe(no_mangle)]
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(BLOCKLIST_MAX_ENTRIES, 0);

#[unsafe(no_mangle)]
#[map]
static RATE_LIMIT_LAST_TS: HashMap<u32, u64> =
    HashMap::with_max_entries(RATE_LIMIT_TS_MAX_ENTRIES, 0);

#[unsafe(no_mangle)]
#[map]
static RATE_LIMITED_COUNT: Array<u64> = Array::with_max_entries(1, 0);

#[inline(always)]
fn read_syscall_args(ctx: &TracePointContext) -> [u64; SYSCALL_ARG_COUNT] {
    [
        // SAFETY: tracepoint context memory is kernel-provided; read_at performs helper-based probing.
        unsafe { ctx.read_at::<u64>(16).unwrap_or(0) },
        // SAFETY: tracepoint context memory is kernel-provided; read_at performs helper-based probing.
        unsafe { ctx.read_at::<u64>(24).unwrap_or(0) },
        // SAFETY: tracepoint context memory is kernel-provided; read_at performs helper-based probing.
        unsafe { ctx.read_at::<u64>(32).unwrap_or(0) },
        // SAFETY: tracepoint context memory is kernel-provided; read_at performs helper-based probing.
        unsafe { ctx.read_at::<u64>(40).unwrap_or(0) },
        // SAFETY: tracepoint context memory is kernel-provided; read_at performs helper-based probing.
        unsafe { ctx.read_at::<u64>(48).unwrap_or(0) },
        // SAFETY: tracepoint context memory is kernel-provided; read_at performs helper-based probing.
        unsafe { ctx.read_at::<u64>(56).unwrap_or(0) },
    ]
}

#[inline(always)]
fn store_pending_event(ctx: &TracePointContext, syscall: MemorySyscall) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    if unsafe { core::hint::black_box(BLOCKLIST.get(&tgid)).is_some() } {
        return 0;
    }

    // SAFETY: helper reads kernel monotonic time and has no pointer inputs.
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(&last_ts) = unsafe { core::hint::black_box(RATE_LIMIT_LAST_TS.get(&tgid)) } {
        if now.saturating_sub(last_ts) < RATE_LIMIT_NS {
            if let Some(counter_ptr) = RATE_LIMITED_COUNT.get_ptr_mut(0) {
                // SAFETY: get_ptr_mut returns a valid in-map pointer for index 0 while this program runs.
                unsafe {
                    *counter_ptr = (*counter_ptr).saturating_add(1);
                }
            }
            return 0;
        }
    }
    let _ = RATE_LIMIT_LAST_TS.insert(tgid, now, 0);

    let comm = bpf_get_current_comm().unwrap_or([0; TASK_COMM_LEN]);

    let event = MemoryEvent {
        timestamp_ns: now,
        pid: pid_tgid as u32,
        tgid,
        syscall: syscall as u32,
        args: read_syscall_args(ctx),
        comm,
    };

    if let Err(err) = pending_syscalls.insert(pid_tgid, event, 0) {
        warn!(ctx, "pending syscall insert failed: {}", err);
        return 1;
    }

    0
}

#[inline(always)]
fn emit_pending_event_on_success(ctx: &TracePointContext, syscall: MemorySyscall) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    // SAFETY: tracepoint context memory is kernel-provided; read_at performs helper-based probing.
    let ret = unsafe { ctx.read_at::<i64>(16).unwrap_or(-1) };

    // SAFETY: We immediately copy the looked-up value and never keep a borrowed reference around.
    let event = unsafe { pending_syscalls.get(&pid_tgid).copied() };
    let Some(event) = event else {
        return 0;
    };

    if ret < 0 {
        let _ = pending_syscalls.remove(&pid_tgid);
        return 0;
    }

    if syscall == MemorySyscall::Mprotect && (event.args[2] & PROT_EXEC) == 0 {
        let _ = pending_syscalls.remove(&pid_tgid);
        return 0;
    }

    if let Some(mut entry) = EVENTS.reserve::<MemoryEvent>(0) {
        entry.write(event);
        entry.submit(0);
    } else {
        warn!(ctx, "ring buffer reserve failed");
    }

    let _ = pending_syscalls.remove(&pid_tgid);
    0
}

#[tracepoint]
pub fn sys_enter_mmap(ctx: TracePointContext) -> u32 {
    store_pending_event(&ctx, MemorySyscall::Mmap)
}

#[tracepoint]
pub fn sys_enter_mprotect(ctx: TracePointContext) -> u32 {
    store_pending_event(&ctx, MemorySyscall::Mprotect)
}

#[tracepoint]
pub fn sys_enter_memfd_create(ctx: TracePointContext) -> u32 {
    store_pending_event(&ctx, MemorySyscall::MemfdCreate)
}

#[tracepoint]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    store_pending_event(&ctx, MemorySyscall::Ptrace)
}

#[tracepoint]
pub fn sys_exit_mmap(ctx: TracePointContext) -> u32 {
    emit_pending_event_on_success(&ctx, MemorySyscall::Mmap)
}

#[tracepoint]
pub fn sys_exit_mprotect(ctx: TracePointContext) -> u32 {
    emit_pending_event_on_success(&ctx, MemorySyscall::Mprotect)
}

#[tracepoint]
pub fn sys_exit_memfd_create(ctx: TracePointContext) -> u32 {
    emit_pending_event_on_success(&ctx, MemorySyscall::MemfdCreate)
}

#[tracepoint]
pub fn sys_exit_ptrace(ctx: TracePointContext) -> u32 {
    emit_pending_event_on_success(&ctx, MemorySyscall::Ptrace)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
