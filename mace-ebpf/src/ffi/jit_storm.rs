//! High-throughput stress helpers for FFI consumers (Phase 4.1 “JIT storm”).

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use super::{
    arena::{ArenaError, EventArena},
    handle::{MaceArenaHandle, MaceErrorCode},
    types::RawMemoryEvent,
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct JitStormStats {
    /// Number of events the producer attempted to commit (`count` argument).
    pub requested: u64,
    /// Successful `try_push` completions.
    pub pushed: u64,
    /// Successful `try_pop` completions.
    pub popped: u64,
    /// Times `try_push` returned `Full` before retrying (backpressure / contention signal).
    pub full_retries: u64,
}

fn mock_event(seq: u32) -> RawMemoryEvent {
    RawMemoryEvent {
        timestamp_ns: u64::from(seq),
        tgid: seq,
        pid: seq.wrapping_add(1),
        syscall_id: 1,
        _pad0: 0,
        args: [u64::from(seq); 6],
        cgroup_id: u64::from(seq),
        comm: [0; 16],
        uid: 0,
        _pad_uid: 0,
        syscall_ret: 0,
        execve_cmdline: [0; crate::ffi::types::RAW_EXECVE_CMDLINE_LEN],
    }
}

/// Run a scoped producer/consumer pair that moves `count` events through `handle`'s arena as fast
/// as possible (SPSC). The arena must outlive this call; `handle` must be a valid
/// `mace_arena_new` pointer and is **not** consumed.
///
/// # Safety
/// `handle` must be a live arena handle. `out_stats` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_simulate_jit_storm(
    handle: *mut MaceArenaHandle,
    count: u32,
    out_stats: *mut JitStormStats,
) -> i32 {
    if handle.is_null() || out_stats.is_null() {
        return MaceErrorCode::NullPointer as i32;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: same opaque-pointer layout as `MaceArenaHandle::from_arc` / `as_ref` in `handle.rs`.
        let arena: &EventArena = unsafe { &*(handle as *const EventArena) };
        let requested = u64::from(count);
        let pushed = AtomicU64::new(0);
        let popped = AtomicU64::new(0);
        let full_retries = AtomicU64::new(0);

        thread::scope(|s| {
            s.spawn(|| {
                for i in 0..count {
                    let ev = mock_event(i);
                    loop {
                        match arena.try_push(ev) {
                            Ok(_) => {
                                pushed.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            Err(ArenaError::Full) => {
                                full_retries.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            });

            s.spawn(|| {
                while popped.load(Ordering::Acquire) < requested {
                    if arena.try_pop().is_some() {
                        popped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        });

        unsafe {
            out_stats.write(JitStormStats {
                requested,
                pushed: pushed.load(Ordering::Relaxed),
                popped: popped.load(Ordering::Relaxed),
                full_retries: full_retries.load(Ordering::Relaxed),
            });
        }

        MaceErrorCode::Success as i32
    }));

    match result {
        Ok(code) => code,
        Err(_) => MaceErrorCode::Panic as i32,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{super::handle::MaceArenaHandle, *};

    #[test]
    fn jit_storm_roundtrip_10k() {
        let arena = EventArena::new(4096);
        let raw = Arc::into_raw(arena) as *mut MaceArenaHandle;
        let mut stats = JitStormStats::default();
        let rc = unsafe { mace_simulate_jit_storm(raw, 10_000, &mut stats) };
        assert_eq!(rc, MaceErrorCode::Success as i32);
        assert_eq!(stats.requested, 10_000);
        assert_eq!(stats.pushed, 10_000);
        assert_eq!(stats.popped, 10_000);
        let _ = unsafe { Arc::from_raw(raw as *const EventArena) };
    }
}
