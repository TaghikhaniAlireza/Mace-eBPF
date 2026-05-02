#![no_std]
#![no_main]

#[cfg(not(feature = "execve_no_user_argv"))]
use aya_ebpf::helpers::bpf_probe_read_user;
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
#[cfg(not(feature = "execve_no_user_argv"))]
use mace_ebpf_common::{EXECVE_ARG_BLOB_LEN, EXECVE_MAX_ARGS_IN_BPF, EXECVE_WIRE_HEADER_LEN};
use mace_ebpf_common::{
    EXECVE_PER_ARG_READ_MAX, ExecveWireHeader, KernelMemoryEvent, MemorySyscall,
    OPENAT_PATH_MAX_LEN, RING_PAYLOAD_BLOB_LEN, RING_SAMPLE_LAYOUT_VERSION, RingBufferSample,
    SYSCALL_ARG_COUNT, TASK_COMM_LEN,
};

const RINGBUF_SIZE_BYTES: u32 = 512 * 1024;
const PENDING_SYSCALLS_MAX_ENTRIES: u32 = 10_240;
const PROT_EXEC: u64 = 0x4;
const ALLOWLIST_MAX_ENTRIES: u32 = 1_024;
const RATE_LIMIT_MAX_ENTRIES: u32 = 10_240;
const RATE_LIMIT_INTERVAL_NS: u64 = 100_000_000; // 100ms per PID

/// Global kernel-side counters (single `BPF_ARRAY` of 4 u64 slots; userspace reads via `Array`).
/// 0: ringbuf output failures; 1: pending-map insert failures; 2: allowlist hits; 3: mmap rate-limit hits.
#[map]
static KERNEL_STATS: Array<u64> = Array::with_max_entries(4, 0);

#[inline(always)]
fn bump_kernel_stat(idx: u32) {
    if let Some(ptr) = KERNEL_STATS.get_ptr_mut(idx) {
        unsafe {
            *ptr = (*ptr).saturating_add(1);
        }
    }
}

#[inline(always)]
fn ringbuf_output_sample(ctx: &TracePointContext, wire: &[u8]) {
    if EVENTS.output::<[u8]>(wire, 0).is_err() {
        bump_kernel_stat(0);
        warn!(ctx, "ring buffer output failed");
    }
}

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

/// Per-CPU temp for one `bpf_probe_read_user_str_bytes` argv read (must not live on BPF stack).
#[repr(C)]
struct ArgReadTemp {
    buf: [u8; EXECVE_PER_ARG_READ_MAX],
}

#[map]
static EXECV_ARG_READ_TEMP: PerCpuArray<ArgReadTemp> = PerCpuArray::with_max_entries(1, 0);

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
        core::ptr::write_bytes(scratch.buf.as_mut_ptr(), 0u8, RING_PAYLOAD_BLOB_LEN);
    }
}

#[inline(always)]
fn zero_payload_blob(out: &mut [u8; RING_PAYLOAD_BLOB_LEN]) {
    unsafe {
        core::ptr::write_bytes(out.as_mut_ptr(), 0u8, RING_PAYLOAD_BLOB_LEN);
    }
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

/// Pack argv into `scratch.buf`: v11 wire = [`ExecveWireHeader`] + NUL-separated strings (bounded).
fn capture_execve_argv_into_scratch(ctx: &TracePointContext, argv_ptr: u64) -> u32 {
    #[cfg(feature = "execve_no_user_argv")]
    {
        let _ = (ctx, argv_ptr);
        let Some(scratch_ptr) = SCRATCH_ARGV.get_ptr_mut(0) else {
            return 0;
        };
        let scratch = unsafe { &mut *scratch_ptr };
        zero_scratch_buf(scratch);
        let pid_tgid = bpf_get_current_pid_tgid();
        let pid = pid_tgid as u32;
        let hdr = ExecveWireHeader {
            pid,
            args_count: 0,
            args_len: 0,
            is_truncated: 1,
        };
        unsafe {
            core::ptr::write_unaligned(scratch.buf.as_mut_ptr().cast(), hdr);
        }
        return 0;
    }

    #[cfg(not(feature = "execve_no_user_argv"))]
    let Some(scratch_ptr) = SCRATCH_ARGV.get_ptr_mut(0) else {
        return 0;
    };
    #[cfg(not(feature = "execve_no_user_argv"))]
    let scratch = unsafe { &mut *scratch_ptr };
    #[cfg(not(feature = "execve_no_user_argv"))]
    zero_scratch_buf(scratch);

    #[cfg(not(feature = "execve_no_user_argv"))]
    let Some(temp_ptr) = EXECV_ARG_READ_TEMP.get_ptr_mut(0) else {
        return 0;
    };
    #[cfg(not(feature = "execve_no_user_argv"))]
    let temp = unsafe { &mut *temp_ptr };
    #[cfg(not(feature = "execve_no_user_argv"))]
    unsafe {
        // Clear the full map value so any bytes past `read_cap` stay deterministic.
        core::ptr::write_bytes(temp.buf.as_mut_ptr(), 0u8, EXECVE_PER_ARG_READ_MAX);
    }

    #[cfg(not(feature = "execve_no_user_argv"))]
    if argv_ptr == 0 {
        return 0;
    }

    #[cfg(not(feature = "execve_no_user_argv"))]
    let pid_tgid = bpf_get_current_pid_tgid();
    #[cfg(not(feature = "execve_no_user_argv"))]
    let pid = pid_tgid as u32;

    #[cfg(not(feature = "execve_no_user_argv"))]
    let payload_base = EXECVE_WIRE_HEADER_LEN;

    #[cfg(not(feature = "execve_no_user_argv"))]
    {
        let payload_cap = EXECVE_ARG_BLOB_LEN;
        let mut write_off: usize = 0;
        let mut args_seen: u32 = 0;
        let mut truncated: u32 = 0;

        let mut i: u32 = 0;
        while i < EXECVE_MAX_ARGS_IN_BPF {
            // Keep loop bounds opaque to LLVM so the eBPF backend does not fully unroll 15× body
            // (verifier instruction explosion).
            let _ = core::hint::black_box(EXECVE_MAX_ARGS_IN_BPF);
            #[cfg(feature = "execve_argv0_only")]
            if i > 0 {
                break;
            }

            let entry_off = (i as usize).saturating_mul(core::mem::size_of::<u64>());
            let user_arg_ptr = match unsafe {
                bpf_probe_read_user::<u64>((argv_ptr as usize + entry_off) as *const u64)
            } {
                Ok(p) => p,
                Err(_) => {
                    truncated = 1;
                    break;
                }
            };

            if user_arg_ptr == 0 {
                break;
            }

            // Reserve one byte in `temp` so the kernel helper can always write a trailing NUL after
            // a maximally long user string (127 content bytes + NUL for a 128-byte buffer).
            // Passing the full `EXECVE_PER_ARG_READ_MAX`-byte slice would NUL-terminate one past the end.
            let read_cap = EXECVE_PER_ARG_READ_MAX.saturating_sub(1);
            let n = match unsafe {
                bpf_probe_read_user_str_bytes(user_arg_ptr as *const u8, &mut temp.buf[..read_cap])
            } {
                Ok(b) => b.len(),
                Err(_) => {
                    truncated = 1;
                    break;
                }
            };

            if n == 0 {
                args_seen = args_seen.saturating_add(1);
                i = i.saturating_add(1);
                continue;
            }

            // `bpf_probe_read_user_str_bytes` returns the string **without** the NUL; the helper
            // wrote the terminator into `temp.buf[n]` within `read_cap` bytes.
            let need = n.saturating_add(1);
            if write_off.saturating_add(need) > payload_cap {
                truncated = 1;
                break;
            }

            let dst_start = payload_base.saturating_add(write_off);
            if dst_start.saturating_add(need) > scratch.buf.len() {
                truncated = 1;
                break;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    temp.buf.as_ptr(),
                    scratch.buf.as_mut_ptr().add(dst_start),
                    need,
                );
            }
            write_off = write_off.saturating_add(need);
            args_seen = args_seen.saturating_add(1);
            i = i.saturating_add(1);
            if i >= EXECVE_MAX_ARGS_IN_BPF {
                break;
            }
        }

        let hdr = ExecveWireHeader {
            pid,
            args_count: args_seen,
            args_len: write_off as u32,
            is_truncated: truncated,
        };
        unsafe {
            core::ptr::write_unaligned(scratch.buf.as_mut_ptr().cast(), hdr);
        }

        if truncated == 1 && args_seen == 0 && write_off == 0 {
            warn!(ctx, "execve argv capture truncated before first arg");
        }

        args_seen
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
    // Same NUL-terminator rule as execve argv: helper needs one spare byte in the destination.
    let read_cap = OPENAT_PATH_MAX_LEN.saturating_sub(1);
    let _ = unsafe {
        bpf_probe_read_user_str_bytes(path_ptr as *const u8, &mut scratch.buf[..read_cap])
    };
}

fn clear_scratch_payload() {
    if let Some(ptr) = SCRATCH_ARGV.get_ptr_mut(0) {
        zero_scratch_buf(unsafe { &mut *ptr });
    }
}

/// Per-syscall `sys_enter_*` bodies must **not** share a helper that passes large structs or many
/// registers — `bpf-linker` rejects BPF-to-BPF calls with stack arguments. Duplicate the small
/// pending-map insert tail in each `store_pending_event_for_*` instead.

#[inline(never)]
fn store_pending_event_for_mmap(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    if unsafe { ALLOWLIST.get(&tgid) }.is_some() {
        bump_kernel_stat(2);
        return 0;
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let last_ts = unsafe { RATE_LIMIT_LAST_TS.get(&tgid).copied().unwrap_or(0) };

    if now_ns.saturating_sub(last_ts) < RATE_LIMIT_INTERVAL_NS {
        let prev = unsafe { RATE_LIMITED_COUNT.get(&tgid).copied().unwrap_or(0) };
        let next = prev.saturating_add(1);
        let _ = RATE_LIMITED_COUNT.insert(&tgid, &next, 0);
        bump_kernel_stat(3);
        return 0;
    }

    let _ = RATE_LIMIT_LAST_TS.insert(&tgid, &now_ns, 0);

    let comm = bpf_get_current_comm().unwrap_or([0; TASK_COMM_LEN]);
    let args = read_syscall_args(ctx);
    clear_scratch_payload();

    let kernel = KernelMemoryEvent {
        timestamp_ns: now_ns,
        pid: pid_tgid as u32,
        tgid,
        syscall: MemorySyscall::Mmap as u32,
        args,
        comm,
    };

    if let Err(err) = pending_syscalls.insert(pid_tgid, &kernel, 0) {
        warn!(ctx, "pending syscall insert failed: {}", err);
        bump_kernel_stat(1);
        return 1;
    }

    let payload_ref = SCRATCH_ARGV.get(0).map(|s| &s.buf).unwrap_or(&ZERO_PAYLOAD);
    if let Err(err) = pending_payload.insert(pid_tgid, payload_ref, 0) {
        let _ = pending_syscalls.remove(&pid_tgid);
        warn!(ctx, "pending payload insert failed: {}", err);
        bump_kernel_stat(1);
        return 1;
    }

    0
}

#[inline(never)]
fn store_pending_event_for_execve(ctx: &TracePointContext) -> u32 {
    store_pending_exec_family(ctx, MemorySyscall::Execve, 1)
}

#[inline(never)]
fn store_pending_event_for_execveat(ctx: &TracePointContext) -> u32 {
    store_pending_exec_family(ctx, MemorySyscall::Execveat, 2)
}

#[inline(never)]
fn store_pending_exec_family(
    ctx: &TracePointContext,
    kind: MemorySyscall,
    argv_arg_idx: usize,
) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    if unsafe { ALLOWLIST.get(&tgid) }.is_some() {
        bump_kernel_stat(2);
        return 0;
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let comm = bpf_get_current_comm().unwrap_or([0; TASK_COMM_LEN]);
    let args = read_syscall_args(ctx);
    let argv_ptr = args.get(argv_arg_idx).copied().unwrap_or(0);
    let _n = capture_execve_argv_into_scratch(ctx, argv_ptr);

    let kernel = KernelMemoryEvent {
        timestamp_ns: now_ns,
        pid: pid_tgid as u32,
        tgid,
        syscall: kind as u32,
        args,
        comm,
    };

    if let Err(err) = pending_syscalls.insert(pid_tgid, &kernel, 0) {
        warn!(ctx, "pending syscall insert failed: {}", err);
        bump_kernel_stat(1);
        return 1;
    }

    let payload_ref = SCRATCH_ARGV.get(0).map(|s| &s.buf).unwrap_or(&ZERO_PAYLOAD);
    if let Err(err) = pending_payload.insert(pid_tgid, payload_ref, 0) {
        let _ = pending_syscalls.remove(&pid_tgid);
        warn!(ctx, "pending payload insert failed: {}", err);
        bump_kernel_stat(1);
        return 1;
    }

    0
}

#[inline(never)]
fn store_pending_event_for_openat(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    if unsafe { ALLOWLIST.get(&tgid) }.is_some() {
        bump_kernel_stat(2);
        return 0;
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let comm = bpf_get_current_comm().unwrap_or([0; TASK_COMM_LEN]);
    let args = read_syscall_args(ctx);
    capture_openat_path_into_scratch(args[1]);

    let kernel = KernelMemoryEvent {
        timestamp_ns: now_ns,
        pid: pid_tgid as u32,
        tgid,
        syscall: MemorySyscall::Openat as u32,
        args,
        comm,
    };

    if let Err(err) = pending_syscalls.insert(pid_tgid, &kernel, 0) {
        warn!(ctx, "pending syscall insert failed: {}", err);
        bump_kernel_stat(1);
        return 1;
    }

    let payload_ref = SCRATCH_ARGV.get(0).map(|s| &s.buf).unwrap_or(&ZERO_PAYLOAD);
    if let Err(err) = pending_payload.insert(pid_tgid, payload_ref, 0) {
        let _ = pending_syscalls.remove(&pid_tgid);
        warn!(ctx, "pending payload insert failed: {}", err);
        bump_kernel_stat(1);
        return 1;
    }

    0
}

#[inline(never)]
fn store_pending_event_for_mprotect(ctx: &TracePointContext) -> u32 {
    store_pending_enter_clear(ctx, MemorySyscall::Mprotect)
}

#[inline(never)]
fn store_pending_event_for_memfd_create(ctx: &TracePointContext) -> u32 {
    store_pending_enter_clear(ctx, MemorySyscall::MemfdCreate)
}

#[inline(never)]
fn store_pending_event_for_ptrace(ctx: &TracePointContext) -> u32 {
    store_pending_enter_clear(ctx, MemorySyscall::Ptrace)
}

#[inline(never)]
fn store_pending_enter_clear(ctx: &TracePointContext, syscall: MemorySyscall) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    if unsafe { ALLOWLIST.get(&tgid) }.is_some() {
        bump_kernel_stat(2);
        return 0;
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let comm = bpf_get_current_comm().unwrap_or([0; TASK_COMM_LEN]);
    let args = read_syscall_args(ctx);
    clear_scratch_payload();

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
        bump_kernel_stat(1);
        return 1;
    }

    let payload_ref = SCRATCH_ARGV.get(0).map(|s| &s.buf).unwrap_or(&ZERO_PAYLOAD);
    if let Err(err) = pending_payload.insert(pid_tgid, payload_ref, 0) {
        let _ = pending_syscalls.remove(&pid_tgid);
        warn!(ctx, "pending payload insert failed: {}", err);
        bump_kernel_stat(1);
        return 1;
    }

    0
}

#[inline(never)]
fn emit_exit_mmap(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = unsafe { ctx.read_at::<i64>(16).unwrap_or(-1) };
    let pending = unsafe { pending_syscalls.get(&pid_tgid).copied() };
    let Some(mut kernel) = pending else {
        return 0;
    };

    if ret < 0 {
        let _ = pending_syscalls.remove(&pid_tgid);
        let _ = pending_payload.remove(&pid_tgid);
        return 0;
    }

    kernel.syscall = MemorySyscall::Mmap as u32;

    let uid = bpf_get_current_uid_gid() as u32;
    let Some(out_ptr) = RING_SAMPLE_OUT.get_ptr_mut(0) else {
        let _ = pending_syscalls.remove(&pid_tgid);
        let _ = pending_payload.remove(&pid_tgid);
        return 0;
    };
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
    ringbuf_output_sample(ctx, wire);
    let _ = pending_syscalls.remove(&pid_tgid);
    let _ = pending_payload.remove(&pid_tgid);
    0
}

#[inline(never)]
fn emit_exit_mprotect(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = unsafe { ctx.read_at::<i64>(16).unwrap_or(-1) };
    let pending = unsafe { pending_syscalls.get(&pid_tgid).copied() };
    let Some(mut kernel) = pending else {
        return 0;
    };

    if ret < 0 {
        let _ = pending_syscalls.remove(&pid_tgid);
        let _ = pending_payload.remove(&pid_tgid);
        return 0;
    }

    if (kernel.args[2] & PROT_EXEC) == 0 {
        let _ = pending_syscalls.remove(&pid_tgid);
        let _ = pending_payload.remove(&pid_tgid);
        return 0;
    }

    kernel.syscall = MemorySyscall::Mprotect as u32;

    let uid = bpf_get_current_uid_gid() as u32;
    let Some(out_ptr) = RING_SAMPLE_OUT.get_ptr_mut(0) else {
        let _ = pending_syscalls.remove(&pid_tgid);
        let _ = pending_payload.remove(&pid_tgid);
        return 0;
    };
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
    ringbuf_output_sample(ctx, wire);
    let _ = pending_syscalls.remove(&pid_tgid);
    let _ = pending_payload.remove(&pid_tgid);
    0
}

#[inline(never)]
fn emit_exit_memfd_create(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = unsafe { ctx.read_at::<i64>(16).unwrap_or(-1) };
    let pending = unsafe { pending_syscalls.get(&pid_tgid).copied() };
    let Some(mut kernel) = pending else {
        return 0;
    };

    if ret < 0 {
        let _ = pending_syscalls.remove(&pid_tgid);
        let _ = pending_payload.remove(&pid_tgid);
        return 0;
    }

    kernel.syscall = MemorySyscall::MemfdCreate as u32;

    let uid = bpf_get_current_uid_gid() as u32;
    let Some(out_ptr) = RING_SAMPLE_OUT.get_ptr_mut(0) else {
        let _ = pending_syscalls.remove(&pid_tgid);
        let _ = pending_payload.remove(&pid_tgid);
        return 0;
    };
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
    ringbuf_output_sample(ctx, wire);
    let _ = pending_syscalls.remove(&pid_tgid);
    let _ = pending_payload.remove(&pid_tgid);
    0
}

#[inline(never)]
fn emit_exit_ptrace(ctx: &TracePointContext) -> u32 {
    emit_exit_always_kind(ctx, MemorySyscall::Ptrace)
}

#[inline(never)]
fn emit_exit_execve(ctx: &TracePointContext) -> u32 {
    emit_exit_exec_family(ctx, MemorySyscall::Execve)
}

#[inline(never)]
fn emit_exit_execveat(ctx: &TracePointContext) -> u32 {
    emit_exit_exec_family(ctx, MemorySyscall::Execveat)
}

#[inline(never)]
fn emit_exit_exec_family(ctx: &TracePointContext, kind: MemorySyscall) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = unsafe { ctx.read_at::<i64>(16).unwrap_or(-1) };
    let pending = unsafe { pending_syscalls.get(&pid_tgid).copied() };
    let Some(mut kernel) = pending else {
        return 0;
    };

    if kernel.syscall != kind as u32 {
        return 0;
    }

    kernel.syscall = kind as u32;

    let uid = bpf_get_current_uid_gid() as u32;
    let Some(out_ptr) = RING_SAMPLE_OUT.get_ptr_mut(0) else {
        let _ = pending_syscalls.remove(&pid_tgid);
        let _ = pending_payload.remove(&pid_tgid);
        return 0;
    };
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
    ringbuf_output_sample(ctx, wire);
    let _ = pending_syscalls.remove(&pid_tgid);
    let _ = pending_payload.remove(&pid_tgid);
    0
}

#[inline(never)]
fn emit_exit_openat(ctx_inner: &TracePointContext) -> u32 {
    emit_exit_always_kind(ctx_inner, MemorySyscall::Openat)
}

#[inline(never)]
fn emit_exit_always_kind(ctx: &TracePointContext, syscall: MemorySyscall) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = unsafe { ctx.read_at::<i64>(16).unwrap_or(-1) };
    let pending = unsafe { pending_syscalls.get(&pid_tgid).copied() };
    let Some(mut kernel) = pending else {
        return 0;
    };

    kernel.syscall = syscall as u32;

    let uid = bpf_get_current_uid_gid() as u32;
    let Some(out_ptr) = RING_SAMPLE_OUT.get_ptr_mut(0) else {
        let _ = pending_syscalls.remove(&pid_tgid);
        let _ = pending_payload.remove(&pid_tgid);
        return 0;
    };
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
    ringbuf_output_sample(ctx, wire);
    let _ = pending_syscalls.remove(&pid_tgid);
    let _ = pending_payload.remove(&pid_tgid);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_mmap")]
pub fn sys_enter_mmap(ctx: TracePointContext) -> u32 {
    store_pending_event_for_mmap(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_enter_mprotect")]
pub fn sys_enter_mprotect(ctx: TracePointContext) -> u32 {
    store_pending_event_for_mprotect(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_enter_memfd_create")]
pub fn sys_enter_memfd_create(ctx: TracePointContext) -> u32 {
    store_pending_event_for_memfd_create(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_enter_ptrace")]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    store_pending_event_for_ptrace(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    store_pending_event_for_execve(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_enter_execveat")]
pub fn sys_enter_execveat(ctx: TracePointContext) -> u32 {
    store_pending_event_for_execveat(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    store_pending_event_for_openat(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_exit_mmap")]
pub fn sys_exit_mmap(ctx: TracePointContext) -> u32 {
    emit_exit_mmap(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_exit_mprotect")]
pub fn sys_exit_mprotect(ctx: TracePointContext) -> u32 {
    emit_exit_mprotect(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_exit_memfd_create")]
pub fn sys_exit_memfd_create(ctx: TracePointContext) -> u32 {
    emit_exit_memfd_create(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_exit_ptrace")]
pub fn sys_exit_ptrace(ctx: TracePointContext) -> u32 {
    emit_exit_ptrace(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_exit_execve")]
pub fn sys_exit_execve(ctx: TracePointContext) -> u32 {
    emit_exit_execve(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_exit_execveat")]
pub fn sys_exit_execveat(ctx: TracePointContext) -> u32 {
    emit_exit_execveat(&ctx)
}

#[tracepoint(category = "syscalls", name = "sys_exit_openat")]
pub fn sys_exit_openat(ctx: TracePointContext) -> u32 {
    emit_exit_openat(&ctx)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
