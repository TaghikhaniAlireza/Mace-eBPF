#![no_std]
#![no_main]

use aegis_ebpf_common::{
    EXECVE_SCRATCH_LEN, KernelMemoryEvent, MemorySyscall, OPENAT_PATH_MAX_LEN,
    RING_PAYLOAD_BLOB_LEN, RING_SAMPLE_LAYOUT_VERSION, RingBufferSample, SYSCALL_ARG_COUNT,
    TASK_COMM_LEN,
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;

const RINGBUF_SIZE_BYTES: u32 = 512 * 1024;
const PENDING_SYSCALLS_MAX_ENTRIES: u32 = 10_240;
const PROT_EXEC: u64 = 0x4;
const ALLOWLIST_MAX_ENTRIES: u32 = 1_024;
const RATE_LIMIT_MAX_ENTRIES: u32 = 10_240;
const RATE_LIMIT_INTERVAL_NS: u64 = 100_000_000; // 100ms per PID

/// Per-CPU scratch for execve argv join and zeroed payloads for other syscalls (no large stack vars).
#[repr(C)]
struct ScratchBuf {
    buf: [u8; RING_PAYLOAD_BLOB_LEN],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_SIZE_BYTES, 0);

/// Single per-CPU buffer: execve stores `argv[0]` only (v10); openat stores pathname prefix.
#[map]
static SCRATCH_ARGV: PerCpuArray<ScratchBuf> = PerCpuArray::with_max_entries(1, 0);

/// Assemble [`RingBufferSample`] here (map-backed) so emit avoids ~4 KiB BPF stack temporaries.
#[map]
static RING_SAMPLE_OUT: PerCpuArray<RingBufferSample> = PerCpuArray::with_max_entries(1, 0);

#[allow(non_upper_case_globals)]
#[map]
static pending_syscalls: LruHashMap<u64, KernelMemoryEvent> =
    LruHashMap::with_max_entries(PENDING_SYSCALLS_MAX_ENTRIES, 0);

#[allow(non_upper_case_globals)]
#[map]
static pending_payload: LruHashMap<u64, [u8; RING_PAYLOAD_BLOB_LEN]> =
    LruHashMap::with_max_entries(PENDING_SYSCALLS_MAX_ENTRIES, 0);

#[map]
static ALLOWLIST: LruHashMap<u32, u8> = LruHashMap::with_max_entries(ALLOWLIST_MAX_ENTRIES, 0);

#[map]
static RATE_LIMIT_LAST_TS: LruHashMap<u32, u64> =
    LruHashMap::with_max_entries(RATE_LIMIT_MAX_ENTRIES, 0);

#[map]
static RATE_LIMITED_COUNT: LruHashMap<u32, u64> =
    LruHashMap::with_max_entries(RATE_LIMIT_MAX_ENTRIES, 0);

static ZERO_PAYLOAD: [u8; RING_PAYLOAD_BLOB_LEN] = [0u8; RING_PAYLOAD_BLOB_LEN];

/// Single memset-style clear (typically one BPF helper path) — avoids 1k+ scalar stores from `fill`
/// or naive loops that LLVM unrolls for map-backed buffers.
#[inline(always)]
fn zero_scratch_buf(scratch: &mut ScratchBuf) {
    unsafe {
        core::ptr::write_bytes(scratch.buf.as_mut_ptr(), 0u8, EXECVE_SCRATCH_LEN);
    }
}

#[inline(always)]
fn zero_payload_blob(out: &mut [u8; RING_PAYLOAD_BLOB_LEN]) {
    unsafe {
        core::ptr::write_bytes(out.as_mut_ptr(), 0u8, RING_PAYLOAD_BLOB_LEN);
    }
}

fn should_rate_limit(syscall: MemorySyscall) -> bool {
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

/// Snapshot **`argv[0]` only** (executable path) into scratch at offset 0.
///
/// Joining multiple argv strings in-kernel caused `copy_nonoverlapping` + loops that pushed
/// `sys_enter_execve` past the verifier's 1M instruction limit on strict kernels.
fn capture_execve_argv_into_scratch(argv_ptr: u64) -> usize {
    let Some(scratch_ptr) = SCRATCH_ARGV.get_ptr_mut(0) else {
        return 0;
    };
    let scratch = unsafe { &mut *scratch_ptr };
    zero_scratch_buf(scratch);

    if argv_ptr == 0 {
        return 0;
    }

    let argv0 = match unsafe { bpf_probe_read_user(argv_ptr as *const u64) } {
        Ok(p) => p,
        Err(_) => return 0,
    };
    if argv0 == 0 {
        return 0;
    }

    match unsafe {
        bpf_probe_read_user_str_bytes(argv0 as *const u8, &mut scratch.buf[..EXECVE_SCRATCH_LEN])
    } {
        Ok(b) => b.len(),
        Err(_) => 0,
    }
}

fn capture_openat_path_into_scratch(path_ptr: u64) {
    let Some(ptr) = SCRATCH_ARGV.get_ptr_mut(0) else {
        return;
    };
    let scratch = unsafe { &mut *ptr };
    zero_scratch_buf(scratch);
    if path_ptr == 0 {
        return;
    }
    let _ = unsafe {
        bpf_probe_read_user_str_bytes(
            path_ptr as *const u8,
            &mut scratch.buf[..OPENAT_PATH_MAX_LEN],
        )
    };
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

    if syscall == MemorySyscall::Execve {
        let _len = capture_execve_argv_into_scratch(args[1]);
    } else if syscall == MemorySyscall::Openat {
        capture_openat_path_into_scratch(args[1]);
    } else if let Some(ptr) = SCRATCH_ARGV.get_ptr_mut(0) {
        zero_scratch_buf(unsafe { &mut *ptr });
    }

    let kernel = KernelMemoryEvent {
        timestamp_ns: now_ns,
        pid: pid_tgid as u32,
        tgid,
        syscall: syscall as u32,
        args,
        comm,
    };

    if let Err(err) = pending_syscalls.insert(pid_tgid, &kernel, 0) {
        warn!(ctx, "pending syscall insert failed: {}", err);
        return 1;
    }

    let payload_ref = SCRATCH_ARGV.get(0).map(|s| &s.buf).unwrap_or(&ZERO_PAYLOAD);
    if let Err(err) = pending_payload.insert(pid_tgid, payload_ref, 0) {
        let _ = pending_syscalls.remove(&pid_tgid);
        warn!(ctx, "pending payload insert failed: {}", err);
        return 1;
    }

    0
}

fn emit_pending_event_on_success(ctx: &TracePointContext, syscall: MemorySyscall) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = unsafe { ctx.read_at::<i64>(16).unwrap_or(-1) };
    let pending = unsafe { pending_syscalls.get(&pid_tgid).copied() };
    let Some(mut kernel) = pending else {
        return 0;
    };

    let always_emit = matches!(
        syscall,
        MemorySyscall::Ptrace | MemorySyscall::Openat | MemorySyscall::Execve
    );

    if ret < 0 && !always_emit {
        let _ = pending_syscalls.remove(&pid_tgid);
        let _ = pending_payload.remove(&pid_tgid);
        return 0;
    }

    if syscall == MemorySyscall::Mprotect && (kernel.args[2] & PROT_EXEC) == 0 {
        let _ = pending_syscalls.remove(&pid_tgid);
        let _ = pending_payload.remove(&pid_tgid);
        return 0;
    }

    kernel.syscall = syscall as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let Some(out_ptr) = RING_SAMPLE_OUT.get_ptr_mut(0) else {
        let _ = pending_syscalls.remove(&pid_tgid);
        let _ = pending_payload.remove(&pid_tgid);
        return 0;
    };

    // Member-wise write: never `payload_blob: *src` (that copies ~4 KiB onto the BPF stack).
    unsafe {
        let out = &mut *out_ptr;
        out.kernel = kernel;
        out.syscall_ret = ret;
        out.uid = uid;
        out._reserved = 0;
        out.layout_version = RING_SAMPLE_LAYOUT_VERSION;
        if let Some(p) = pending_payload.get(&pid_tgid) {
            out.payload_blob.copy_from_slice(p);
        } else {
            zero_payload_blob(&mut out.payload_blob);
        }
    }

    let wire_len = core::mem::size_of::<RingBufferSample>();
    let wire = unsafe { core::slice::from_raw_parts(out_ptr.cast::<u8>(), wire_len) };
    if EVENTS.output::<[u8]>(wire, 0).is_err() {
        warn!(ctx, "ring buffer output failed");
    }

    let _ = pending_syscalls.remove(&pid_tgid);
    let _ = pending_payload.remove(&pid_tgid);
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
