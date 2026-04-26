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
/// Must be freed with aegis_arena_free().
#[repr(C)]
pub struct AegisArenaHandle {
    _private: [u8; 0],
}

impl AegisArenaHandle {
    fn from_arc(arena: Arc<EventArena>) -> *mut Self {
        Arc::into_raw(arena) as *mut AegisArenaHandle
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
pub enum AegisErrorCode {
    Success = 0,
    NullPointer = -1,
    ArenaFull = -2,
    ArenaEmpty = -3,
    Panic = -4,
    InitFailed = -5,
}

impl From<ArenaError> for AegisErrorCode {
    fn from(err: ArenaError) -> Self {
        match err {
            ArenaError::Full => AegisErrorCode::ArenaFull,
        }
    }
}

/// Create a new event arena with the specified capacity.
/// Capacity must be a power of two.
///
/// Returns a non-null handle on success, or null on panic.
///
/// # Safety
/// The returned handle must be freed with aegis_arena_free().
#[unsafe(no_mangle)]
pub extern "C" fn aegis_arena_new(capacity: usize) -> *mut AegisArenaHandle {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let arena = EventArena::new(capacity);
        AegisArenaHandle::from_arc(arena)
    }));

    match result {
        Ok(handle) => handle,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free an arena handle created by aegis_arena_new().
///
/// # Safety
/// - handle must be a valid pointer returned by aegis_arena_new()
/// - handle must not be used after this call
/// - handle must not be freed more than once
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_arena_free(handle: *mut AegisArenaHandle) {
    if handle.is_null() {
        return;
    }

    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: `handle` is expected to be allocated by `aegis_arena_new`
        // and consumed exactly once by this destructor.
        let _arena = AegisArenaHandle::to_arc(handle);
    }));
}

/// Push an event into the arena.
///
/// Returns:
/// - AegisErrorCode::Success (0) on success
/// - AegisErrorCode::NullPointer if handle or event is null
/// - AegisErrorCode::ArenaFull if buffer is full
/// - AegisErrorCode::Panic if a panic occurred
///
/// # Safety
/// - handle must be a valid pointer returned by aegis_arena_new()
/// - event must point to a valid RawMemoryEvent
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_arena_push(
    handle: *mut AegisArenaHandle,
    event: *const RawMemoryEvent,
) -> AegisErrorCode {
    if handle.is_null() || event.is_null() {
        return AegisErrorCode::NullPointer;
    }

    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: null checks above guarantee both pointers are non-null; the
        // caller guarantees they point to valid objects for reads.
        let arena = AegisArenaHandle::as_ref(handle).expect("checked non-null");
        let event_copy = *event;
        arena.try_push(event_copy)
    }));

    match result {
        Ok(Ok(_)) => AegisErrorCode::Success,
        Ok(Err(e)) => e.into(),
        Err(_) => AegisErrorCode::Panic,
    }
}

/// Pop an event from the arena.
///
/// Returns:
/// - AegisErrorCode::Success (0) if an event was written to out_event
/// - AegisErrorCode::NullPointer if handle or out_event is null
/// - AegisErrorCode::ArenaEmpty if buffer is empty
/// - AegisErrorCode::Panic if a panic occurred
///
/// # Safety
/// - handle must be a valid pointer returned by aegis_arena_new()
/// - out_event must point to a valid RawMemoryEvent buffer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_arena_pop(
    handle: *mut AegisArenaHandle,
    out_event: *mut RawMemoryEvent,
) -> AegisErrorCode {
    if handle.is_null() || out_event.is_null() {
        return AegisErrorCode::NullPointer;
    }

    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: pointers are checked for null above; caller guarantees handle
        // validity and that out_event points to writable memory.
        let arena = AegisArenaHandle::as_ref(handle).expect("checked non-null");
        match arena.try_pop() {
            Some(event) => {
                std::ptr::write(out_event, event);
                Ok(())
            }
            None => Err(AegisErrorCode::ArenaEmpty),
        }
    }));

    match result {
        Ok(Ok(())) => AegisErrorCode::Success,
        Ok(Err(e)) => e,
        Err(_) => AegisErrorCode::Panic,
    }
}

/// Try to push an event into the arena.
///
/// C-friendly alias for `aegis_arena_push`.
///
/// # Safety
/// - handle must be a valid pointer returned by aegis_arena_new()
/// - event must point to a valid RawMemoryEvent
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_arena_try_push(
    handle: *mut AegisArenaHandle,
    event: *const RawMemoryEvent,
) -> i32 {
    // SAFETY: this function forwards the exact same FFI contract.
    unsafe { aegis_arena_push(handle, event) as i32 }
}

/// Try to pop an event from the arena.
///
/// C-friendly alias for `aegis_arena_pop`.
///
/// # Safety
/// - handle must be a valid pointer returned by aegis_arena_new()
/// - out_event must point to a valid RawMemoryEvent buffer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_arena_try_pop(
    handle: *mut AegisArenaHandle,
    out_event: *mut RawMemoryEvent,
) -> i32 {
    // SAFETY: this function forwards the exact same FFI contract.
    unsafe { aegis_arena_pop(handle, out_event) as i32 }
}

/// Get the number of events currently in the arena.
/// Returns 0 if handle is null or a panic occurs.
///
/// # Safety
/// - handle must be either null or a valid pointer returned by aegis_arena_new()
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_arena_len(handle: *const AegisArenaHandle) -> usize {
    if handle.is_null() {
        return 0;
    }

    catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: non-null handle checked above; caller guarantees handle validity.
        AegisArenaHandle::as_ref(handle)
            .expect("checked non-null")
            .len()
    }))
    .unwrap_or(0)
}

/// Get the total capacity of the arena.
/// Returns 0 if handle is null or a panic occurs.
///
/// # Safety
/// - handle must be either null or a valid pointer returned by aegis_arena_new()
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_arena_capacity(handle: *const AegisArenaHandle) -> usize {
    if handle.is_null() {
        return 0;
    }

    catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: non-null handle checked above; caller guarantees handle validity.
        AegisArenaHandle::as_ref(handle)
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
        }
    }

    #[test]
    fn test_handle_new_and_free() {
        let handle = aegis_arena_new(16);
        assert!(!handle.is_null());
        assert_eq!(unsafe { aegis_arena_capacity(handle) }, 16);
        unsafe { aegis_arena_free(handle) };
    }

    #[test]
    fn test_handle_new_invalid_capacity_returns_null() {
        let handle = aegis_arena_new(7);
        assert!(handle.is_null());
    }

    #[test]
    fn test_handle_push_pop_roundtrip() {
        let handle = aegis_arena_new(4);
        assert!(!handle.is_null());

        let event = sample_event(5678);
        let push_code = unsafe { aegis_arena_push(handle, &event) };
        assert_eq!(push_code, AegisErrorCode::Success);
        assert_eq!(unsafe { aegis_arena_len(handle) }, 1);

        let mut out_event = sample_event(0);
        let pop_code = unsafe { aegis_arena_pop(handle, &mut out_event) };
        assert_eq!(pop_code, AegisErrorCode::Success);
        assert_eq!(out_event.tgid, 5678);

        unsafe { aegis_arena_free(handle) };
    }

    #[test]
    fn test_handle_push_null_handle() {
        let event = sample_event(1);
        let code = unsafe { aegis_arena_push(std::ptr::null_mut(), &event) };
        assert_eq!(code, AegisErrorCode::NullPointer);
    }

    #[test]
    fn test_handle_push_null_event() {
        let handle = aegis_arena_new(4);
        assert!(!handle.is_null());

        let code = unsafe { aegis_arena_push(handle, std::ptr::null()) };
        assert_eq!(code, AegisErrorCode::NullPointer);

        unsafe { aegis_arena_free(handle) };
    }

    #[test]
    fn test_handle_pop_null_handle() {
        let mut out_event = sample_event(0);
        let code = unsafe { aegis_arena_pop(std::ptr::null_mut(), &mut out_event) };
        assert_eq!(code, AegisErrorCode::NullPointer);
    }

    #[test]
    fn test_handle_pop_null_output() {
        let handle = aegis_arena_new(4);
        assert!(!handle.is_null());

        let code = unsafe { aegis_arena_pop(handle, std::ptr::null_mut()) };
        assert_eq!(code, AegisErrorCode::NullPointer);

        unsafe { aegis_arena_free(handle) };
    }

    #[test]
    fn test_handle_pop_empty_arena() {
        let handle = aegis_arena_new(4);
        assert!(!handle.is_null());

        let mut out_event = sample_event(0);
        let code = unsafe { aegis_arena_pop(handle, &mut out_event) };
        assert_eq!(code, AegisErrorCode::ArenaEmpty);

        unsafe { aegis_arena_free(handle) };
    }

    #[test]
    fn test_handle_push_until_full() {
        let handle = aegis_arena_new(4);
        assert!(!handle.is_null());

        assert_eq!(
            unsafe { aegis_arena_push(handle, &sample_event(1)) },
            AegisErrorCode::Success
        );
        assert_eq!(
            unsafe { aegis_arena_push(handle, &sample_event(2)) },
            AegisErrorCode::Success
        );
        assert_eq!(
            unsafe { aegis_arena_push(handle, &sample_event(3)) },
            AegisErrorCode::Success
        );
        assert_eq!(
            unsafe { aegis_arena_push(handle, &sample_event(4)) },
            AegisErrorCode::ArenaFull
        );

        unsafe { aegis_arena_free(handle) };
    }

    #[test]
    fn test_handle_free_null_is_safe() {
        unsafe { aegis_arena_free(std::ptr::null_mut()) };
    }

    #[test]
    fn test_handle_len_and_capacity_null_safe() {
        assert_eq!(unsafe { aegis_arena_len(std::ptr::null()) }, 0);
        assert_eq!(unsafe { aegis_arena_capacity(std::ptr::null()) }, 0);
    }
}
