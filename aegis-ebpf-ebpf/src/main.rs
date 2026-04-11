#![no_std]
#![no_main]

use aegis_ebpf_common::{MemoryEvent, MemorySyscall, SYSCALL_ARG_COUNT, TASK_COMM_LEN};
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;

const RINGBUF_SIZE_BYTES: u32 = 256 * 1024;
const SYSCALL_ARGS_OFFSET: usize = 16;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_SIZE_BYTES, 0);
}

#[tracepoint]
pub fn sys_enter_mprotect(ctx: TracePointContext) -> u32 {
}

#[tracepoint]
pub fn sys_enter_memfd_create(ctx: TracePointContext) -> u32 {
}

#[tracepoint]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
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
    0
}

#[inline(always)]
fn read_syscall_args(ctx: &TracePointContext) -> [u64; SYSCALL_ARG_COUNT] {
    [
        read_syscall_arg(ctx, 0),
        read_syscall_arg(ctx, 1),
        read_syscall_arg(ctx, 2),
        read_syscall_arg(ctx, 3),
        read_syscall_arg(ctx, 4),
        read_syscall_arg(ctx, 5),
    ]
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
