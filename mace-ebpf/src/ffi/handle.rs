use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

use super::{
    arena::{ArenaError, EventArena},
    types::RawMemoryEvent,
};

/// Opaque handle to an EventArena.
/// C code receives this as a void* pointer.
/// Must be freed with mace_arena_free().
#[repr(C)]
pub struct MaceArenaHandle {
    _private: [u8; 0],
}

impl MaceArenaHandle {
    fn from_arc(arena: Arc<EventArena>) -> *mut Self {
        Arc::into_raw(arena) as *mut MaceArenaHandle
    }

    unsafe fn to_arc(handle: *mut Self) -> Arc<EventArena> {
        // SAFETY: caller guarantees `handle` was produced by `from_arc` and has
        // not already been consumed by another `to_arc` call.
        unsafe { Arc::from_raw(handle as *const EventArena) }
    }

    unsafe fn as_ref(handle: *const Self) -> Option<&'static EventArena> {
        if handle.is_null() {
            None
        } else {
            // SAFETY: caller guarantees pointer validity and lifetime while the
            // handle is alive; this function only creates a shared reference.
            Some(unsafe { &*(handle as *const EventArena) })
        }
    }
}

/// Error codes returned by FFI functions.
/// Negative values indicate errors, 0 indicates success.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaceErrorCode {
    Success = 0,
    NullPointer = -1,
    ArenaFull = -2,
    ArenaEmpty = -3,
    Panic = -4,
    InitFailed = -5,
}

impl From<ArenaError> for MaceErrorCode {
    fn from(err: ArenaError) -> Self {
        match err {
            ArenaError::Full => MaceErrorCode::ArenaFull,
        }
    }
}

/// Create a new event arena with the specified capacity.
/// Capacity must be a power of two.
///
/// Returns a non-null handle on success, or null on panic.
///
/// # Safety
/// The returned handle must be freed with mace_arena_free().
#[unsafe(no_mangle)]
pub extern "C" fn mace_arena_new(capacity: usize) -> *mut MaceArenaHandle {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let arena = EventArena::new(capacity);
        MaceArenaHandle::from_arc(arena)
    }));

    match result {
        Ok(handle) => handle,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free an arena handle created by mace_arena_new().
///
/// # Safety
/// - handle must be a valid pointer returned by mace_arena_new()
/// - handle must not be used after this call
/// - handle must not be freed more than once
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_arena_free(handle: *mut MaceArenaHandle) {
    if handle.is_null() {
        return;
    }

    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: `handle` is expected to be allocated by `mace_arena_new`
        // and consumed exactly once by this destructor.
        let _arena = MaceArenaHandle::to_arc(handle);
    }));
}

/// Push an event into the arena.
///
/// Returns:
/// - MaceErrorCode::Success (0) on success
/// - MaceErrorCode::NullPointer if handle or event is null
/// - MaceErrorCode::ArenaFull if buffer is full
/// - MaceErrorCode::Panic if a panic occurred
///
/// # Safety
/// - handle must be a valid pointer returned by mace_arena_new()
/// - event must point to a valid RawMemoryEvent
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_arena_push(
    handle: *mut MaceArenaHandle,
    event: *const RawMemoryEvent,
) -> MaceErrorCode {
    if handle.is_null() || event.is_null() {
        return MaceErrorCode::NullPointer;
    }

    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: null checks above guarantee both pointers are non-null; the
        // caller guarantees they point to valid objects for reads.
        let arena = MaceArenaHandle::as_ref(handle).expect("checked non-null");
        let event_copy = *event;
        arena.try_push(event_copy)
    }));

    match result {
        Ok(Ok(_)) => MaceErrorCode::Success,
        Ok(Err(e)) => e.into(),
        Err(_) => MaceErrorCode::Panic,
    }
}

/// Pop an event from the arena.
///
/// Returns:
/// - MaceErrorCode::Success (0) if an event was written to out_event
/// - MaceErrorCode::NullPointer if handle or out_event is null
/// - MaceErrorCode::ArenaEmpty if buffer is empty
/// - MaceErrorCode::Panic if a panic occurred
///
/// # Safety
/// - handle must be a valid pointer returned by mace_arena_new()
/// - out_event must point to a valid RawMemoryEvent buffer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_arena_pop(
    handle: *mut MaceArenaHandle,
    out_event: *mut RawMemoryEvent,
) -> MaceErrorCode {
    if handle.is_null() || out_event.is_null() {
        return MaceErrorCode::NullPointer;
    }

    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: pointers are checked for null above; caller guarantees handle
        // validity and that out_event points to writable memory.
        let arena = MaceArenaHandle::as_ref(handle).expect("checked non-null");
        match arena.try_pop() {
            Some(event) => {
                std::ptr::write(out_event, event);
                Ok(())
            }
            None => Err(MaceErrorCode::ArenaEmpty),
        }
    }));

    match result {
        Ok(Ok(())) => MaceErrorCode::Success,
        Ok(Err(e)) => e,
        Err(_) => MaceErrorCode::Panic,
    }
}

/// Try to push an event into the arena.
///
/// C-friendly alias for `mace_arena_push`.
///
/// # Safety
/// - handle must be a valid pointer returned by mace_arena_new()
/// - event must point to a valid RawMemoryEvent
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_arena_try_push(
    handle: *mut MaceArenaHandle,
    event: *const RawMemoryEvent,
) -> i32 {
    // SAFETY: this function forwards the exact same FFI contract.
    unsafe { mace_arena_push(handle, event) as i32 }
}

/// Try to pop an event from the arena.
///
/// C-friendly alias for `mace_arena_pop`.
///
/// # Safety
/// - handle must be a valid pointer returned by mace_arena_new()
/// - out_event must point to a valid RawMemoryEvent buffer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_arena_try_pop(
    handle: *mut MaceArenaHandle,
    out_event: *mut RawMemoryEvent,
) -> i32 {
    // SAFETY: this function forwards the exact same FFI contract.
    unsafe { mace_arena_pop(handle, out_event) as i32 }
}

/// Get the number of events currently in the arena.
/// Returns 0 if handle is null or a panic occurs.
///
/// # Safety
/// - handle must be either null or a valid pointer returned by mace_arena_new()
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_arena_len(handle: *const MaceArenaHandle) -> usize {
    if handle.is_null() {
        return 0;
    }

    catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: non-null handle checked above; caller guarantees handle validity.
        MaceArenaHandle::as_ref(handle)
            .expect("checked non-null")
            .len()
    }))
    .unwrap_or(0)
}

/// Get the total capacity of the arena.
/// Returns 0 if handle is null or a panic occurs.
///
/// # Safety
/// - handle must be either null or a valid pointer returned by mace_arena_new()
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_arena_capacity(handle: *const MaceArenaHandle) -> usize {
    if handle.is_null() {
        return 0;
    }

    catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: non-null handle checked above; caller guarantees handle validity.
        MaceArenaHandle::as_ref(handle)
            .expect("checked non-null")
            .capacity()
    }))
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(tgid: u32) -> RawMemoryEvent {
        RawMemoryEvent {
            timestamp_ns: u64::from(tgid),
            tgid,
            pid: tgid,
            syscall_id: 1,
            _pad0: 0,
            args: [u64::from(tgid); 6],
            cgroup_id: u64::from(tgid),
            comm: [0; 16],
            uid: 0,
            _pad_uid: 0,
            syscall_ret: 0,
            execve_cmdline: [0; crate::ffi::types::RAW_EXECVE_CMDLINE_LEN],
        }
    }

    #[test]
    fn test_handle_new_and_free() {
        let handle = mace_arena_new(16);
        assert!(!handle.is_null());
        assert_eq!(unsafe { mace_arena_capacity(handle) }, 16);
        unsafe { mace_arena_free(handle) };
    }

    #[test]
    fn test_handle_new_invalid_capacity_returns_null() {
        let handle = mace_arena_new(7);
        assert!(handle.is_null());
    }

    #[test]
    fn test_handle_push_pop_roundtrip() {
        let handle = mace_arena_new(4);
        assert!(!handle.is_null());

        let event = sample_event(5678);
        let push_code = unsafe { mace_arena_push(handle, &event) };
        assert_eq!(push_code, MaceErrorCode::Success);
        assert_eq!(unsafe { mace_arena_len(handle) }, 1);

        let mut out_event = sample_event(0);
        let pop_code = unsafe { mace_arena_pop(handle, &mut out_event) };
        assert_eq!(pop_code, MaceErrorCode::Success);
        assert_eq!(out_event.tgid, 5678);

        unsafe { mace_arena_free(handle) };
    }

    #[test]
    fn test_handle_push_null_handle() {
        let event = sample_event(1);
        let code = unsafe { mace_arena_push(std::ptr::null_mut(), &event) };
        assert_eq!(code, MaceErrorCode::NullPointer);
    }

    #[test]
    fn test_handle_push_null_event() {
        let handle = mace_arena_new(4);
        assert!(!handle.is_null());

        let code = unsafe { mace_arena_push(handle, std::ptr::null()) };
        assert_eq!(code, MaceErrorCode::NullPointer);

        unsafe { mace_arena_free(handle) };
    }

    #[test]
    fn test_handle_pop_null_handle() {
        let mut out_event = sample_event(0);
        let code = unsafe { mace_arena_pop(std::ptr::null_mut(), &mut out_event) };
        assert_eq!(code, MaceErrorCode::NullPointer);
    }

    #[test]
    fn test_handle_pop_null_output() {
        let handle = mace_arena_new(4);
        assert!(!handle.is_null());

        let code = unsafe { mace_arena_pop(handle, std::ptr::null_mut()) };
        assert_eq!(code, MaceErrorCode::NullPointer);

        unsafe { mace_arena_free(handle) };
    }

    #[test]
    fn test_handle_pop_empty_arena() {
        let handle = mace_arena_new(4);
        assert!(!handle.is_null());

        let mut out_event = sample_event(0);
        let code = unsafe { mace_arena_pop(handle, &mut out_event) };
        assert_eq!(code, MaceErrorCode::ArenaEmpty);

        unsafe { mace_arena_free(handle) };
    }

    #[test]
    fn test_handle_push_until_full() {
        let handle = mace_arena_new(4);
        assert!(!handle.is_null());

        assert_eq!(
            unsafe { mace_arena_push(handle, &sample_event(1)) },
            MaceErrorCode::Success
        );
        assert_eq!(
            unsafe { mace_arena_push(handle, &sample_event(2)) },
            MaceErrorCode::Success
        );
        assert_eq!(
            unsafe { mace_arena_push(handle, &sample_event(3)) },
            MaceErrorCode::Success
        );
        assert_eq!(
            unsafe { mace_arena_push(handle, &sample_event(4)) },
            MaceErrorCode::ArenaFull
        );

        unsafe { mace_arena_free(handle) };
    }

    #[test]
    fn test_handle_free_null_is_safe() {
        unsafe { mace_arena_free(std::ptr::null_mut()) };
    }

    #[test]
    fn test_handle_len_and_capacity_null_safe() {
        assert_eq!(unsafe { mace_arena_len(std::ptr::null()) }, 0);
        assert_eq!(unsafe { mace_arena_capacity(std::ptr::null()) }, 0);
    }
}
