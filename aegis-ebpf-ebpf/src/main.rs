#![no_std]
#![no_main]

use aegis_ebpf_common::{MemoryEvent, MemorySyscall, SYSCALL_ARG_COUNT, TASK_COMM_LEN};
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{LruHashMap, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;

const RINGBUF_SIZE_BYTES: u32 = 256 * 1024;
const SYSCALL_ARGS_OFFSET: usize = 16;
const PENDING_SYSCALLS_MAX_ENTRIES: u32 = 10_240;
const PROT_EXEC: u64 = 0x4;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_SIZE_BYTES, 0);

#[allow(non_upper_case_globals)]
#[map]
static pending_syscalls: LruHashMap<u64, MemoryEvent> =
    LruHashMap::with_max_entries(PENDING_SYSCALLS_MAX_ENTRIES, 0);

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
pub fn sys_exit_ptrace(ctx: TracePointContext) -> u32 {
    emit_pending_event_on_success(&ctx, MemorySyscall::Ptrace)
}

#[inline(always)]
fn store_pending_event(ctx: &TracePointContext, syscall: MemorySyscall) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let comm = bpf_get_current_comm().unwrap_or([0; TASK_COMM_LEN]);

    let event = MemoryEvent {
        // SAFETY: helper reads kernel monotonic time and has no pointer inputs.
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        syscall: syscall as u32,
        args: read_syscall_args(ctx),
        comm,
    };

    if let Err(err) = pending_syscalls.insert(pid_tgid, event, 0) {
        warn!(ctx, "pending syscall insert failed: {}", err);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
