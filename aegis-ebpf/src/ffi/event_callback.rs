//! C-compatible registration for standardized JSON event lines (Phase 2 — FFI exporter).

use std::{
    ffi::{CString, c_char},
    sync::RwLock,
};

use futures::FutureExt;

/// C callback invoked with a NUL-terminated UTF-8 JSON payload.
/// **Contract:** The pointer is valid only for the duration of the call; copy the string before returning.
pub type JsonCallback = extern "C" fn(*const c_char);

static GLOBAL_JSON_CALLBACK: RwLock<Option<JsonCallback>> = RwLock::new(None);

/// Register the global JSON sink used by [`crate::pipeline::start_pipeline`] when
/// `PipelineConfig::on_standardized_event` is unset.
///
/// # Safety
/// `cb` must be a valid `extern "C"` function pointer. The callback must be thread-safe and must
/// not call back into this library in a way that deadlocks on `GLOBAL_JSON_CALLBACK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn register_event_callback(cb: JsonCallback) {
    if let Ok(mut w) = GLOBAL_JSON_CALLBACK.write() {
        *w = Some(cb);
    }
}

/// Clear the global JSON callback (C callers should use this instead of passing NULL).
#[unsafe(no_mangle)]
pub extern "C" fn unregister_event_callback() {
    if let Ok(mut w) = GLOBAL_JSON_CALLBACK.write() {
        *w = None;
    }
}

pub(crate) fn invoke_registered_json_callback(json: &str) {
    let cb = match GLOBAL_JSON_CALLBACK.read() {
        Ok(g) => *g,
        Err(_) => return,
    };
    let Some(cb) = cb else {
        return;
    };
    let Ok(cstr) = CString::new(json) else {
        return;
    };
    cb(cstr.as_ptr());
}

/// `true` if a C callback is registered (for merging into [`crate::pipeline::PipelineConfig`]).
pub(crate) fn is_json_callback_registered() -> bool {
    GLOBAL_JSON_CALLBACK
        .read()
        .ok()
        .is_some_and(|g| g.is_some())
}

/// Bridge used by [`crate::start_pipeline`] when no Rust `on_standardized_event` hook is set.
pub(crate) fn pipeline_json_callback_bridge() -> crate::StandardizedEventCallback {
    std::sync::Arc::new(|json: String| {
        async move {
            invoke_registered_json_callback(&json);
        }
        .boxed()
    })
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::CStr,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use serial_test::serial;

    use super::*;

    static SEEN: AtomicUsize = AtomicUsize::new(0);
    static LAST: Mutex<Option<String>> = Mutex::new(None);

    extern "C" fn test_cb(ptr: *const c_char) {
        SEEN.fetch_add(1, Ordering::SeqCst);
        if ptr.is_null() {
            return;
        }
        let s = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        if let Ok(mut w) = LAST.lock() {
            *w = Some(s);
        }
    }

    #[test]
    #[serial(event_callback_global)]
    fn register_invokes_json() {
        SEEN.store(0, Ordering::SeqCst);
        *LAST.lock().unwrap() = None;

        unsafe {
            register_event_callback(test_cb);
        }
        invoke_registered_json_callback(r#"{"matched_rules":["X"]}"#);
        assert_eq!(SEEN.load(Ordering::SeqCst), 1);
        assert_eq!(
            LAST.lock().unwrap().as_deref(),
            Some(r#"{"matched_rules":["X"]}"#)
        );

        unregister_event_callback();
        invoke_registered_json_callback("ignored");
        assert_eq!(SEEN.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[serial(event_callback_global)]
    fn stress_json_callback_roundtrip() {
        SEEN.store(0, Ordering::SeqCst);
        unsafe {
            register_event_callback(test_cb);
        }
        let payload = r#"{"matched_rules":["STRESS"],"timestamp":1}"#;
        for _ in 0..50_000 {
            invoke_registered_json_callback(payload);
        }
        assert_eq!(SEEN.load(Ordering::SeqCst), 50_000);
        unregister_event_callback();
        invoke_registered_json_callback("ignored");
        assert_eq!(SEEN.load(Ordering::SeqCst), 50_000);
    }
}
