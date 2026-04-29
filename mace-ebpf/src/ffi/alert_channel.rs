use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

use futures::FutureExt;
use prost::Message;
use tokio::sync::mpsc;
use tracing::warn;
use uuid::Uuid;

use super::handle::MaceErrorCode;
use crate::{
    alert::{Alert as RustAlert, AlertCallback},
    observability::metrics::record_alert_fired,
    proto::{Alert as ProtoAlert, AlertBatch, Severity as ProtoSeverity},
    rules::Severity as RustSeverity,
};

/// A channel for delivering alerts to FFI consumers.
///
/// Alerts are converted to protobuf and buffered in a bounded channel.
/// C consumers can poll for alerts without blocking the rule engine.
pub struct AlertChannel {
    tx: mpsc::Sender<ProtoAlert>,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<ProtoAlert>>>,
}

impl AlertChannel {
    /// Create a new alert channel with the specified buffer capacity.
    ///
    /// If the buffer fills up, new alerts will be dropped by `try_send`.
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            tx,
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
        }
    }

    /// Send an alert to the channel.
    pub async fn send(&self, alert: RustAlert) -> Result<(), mpsc::error::SendError<ProtoAlert>> {
        let rule_id = alert.rule_id.clone();
        let proto_alert = convert_alert_to_proto(alert);
        self.tx.send(proto_alert).await?;
        record_alert_fired(&rule_id);
        Ok(())
    }

    /// Enqueue a raw protobuf alert (for FFI test harnesses). Uses the same `try_send` path as production.
    #[allow(clippy::result_large_err)]
    pub fn inject_test_proto(
        &self,
        alert: ProtoAlert,
    ) -> Result<(), mpsc::error::TrySendError<ProtoAlert>> {
        self.tx.try_send(alert)
    }

    /// Try to send an alert without blocking.
    ///
    /// Returns Ok(()) if sent, Err if full or closed.
    #[allow(clippy::result_large_err)]
    pub fn try_send(&self, alert: RustAlert) -> Result<(), mpsc::error::TrySendError<ProtoAlert>> {
        let rule_id = alert.rule_id.clone();
        let proto_alert = convert_alert_to_proto(alert);
        match self.tx.try_send(proto_alert) {
            Ok(()) => {
                record_alert_fired(&rule_id);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Receive the next alert (async, blocking).
    pub async fn recv(&self) -> Option<ProtoAlert> {
        self.rx.lock().await.recv().await
    }

    /// Try to receive an alert without blocking.
    pub fn try_recv(&self) -> Option<ProtoAlert> {
        self.rx.try_lock().ok()?.try_recv().ok()
    }

    /// Try to receive up to `max_items` alerts without blocking.
    pub fn try_recv_batch(&self, max_items: usize) -> Vec<ProtoAlert> {
        let Ok(mut rx) = self.rx.try_lock() else {
            return Vec::new();
        };

        let mut out = Vec::with_capacity(max_items);
        for _ in 0..max_items {
            match rx.try_recv() {
                Ok(alert) => out.push(alert),
                Err(_) => break,
            }
        }
        out
    }

    /// Get a sender handle for this channel.
    pub fn sender(&self) -> mpsc::Sender<ProtoAlert> {
        self.tx.clone()
    }

    /// Build a callback that forwards pipeline alerts into this channel.
    pub fn callback(&self) -> AlertCallback {
        callback_from_sender(self.sender())
    }
}

/// Build an alert callback from a protobuf sender.
///
/// The callback is non-blocking (`try_send`) to avoid stalling rule evaluation.
pub fn callback_from_sender(sender: mpsc::Sender<ProtoAlert>) -> AlertCallback {
    Arc::new(move |alert: RustAlert| {
        let sender = sender.clone();
        async move {
            let proto_alert = convert_alert_to_proto(alert);
            if let Err(err) = sender.try_send(proto_alert) {
                warn!("failed to enqueue ffi alert: {err}");
            }
        }
        .boxed()
    })
}

/// Convert Rust alerts into protobuf alerts.
pub fn convert_alert_to_proto(alert: RustAlert) -> ProtoAlert {
    let RustAlert {
        rule_id,
        rule_name,
        severity,
        timestamp_ns,
        tgid,
        pid,
        comm,
        syscall_id,
        matched_flags,
        namespace,
        pod_name,
    } = alert;

    let severity = match severity {
        RustSeverity::Low => ProtoSeverity::Low,
        RustSeverity::Medium => ProtoSeverity::Medium,
        RustSeverity::High => ProtoSeverity::High,
        RustSeverity::Critical => ProtoSeverity::Critical,
    };

    let message = format!("Rule {rule_id} matched for process {comm}");
    let context_json = serde_json::json!({
        "rule_id": rule_id,
        "pid": pid,
        "syscall_id": syscall_id,
        "matched_flags": matched_flags,
        "namespace": namespace,
        "pod_name": pod_name
    })
    .to_string();

    ProtoAlert {
        alert_id: Uuid::new_v4().to_string(),
        rule_name,
        severity: severity as i32,
        message,
        tgid,
        process_name: comm,
        timestamp_ns,
        context_json,
    }
}

/// Encode a batch of protobuf alerts.
pub fn encode_alert_batch(alerts: Vec<ProtoAlert>) -> Vec<u8> {
    AlertBatch { alerts }.encode_to_vec()
}

/// Opaque handle to an AlertChannel.
#[repr(C)]
pub struct MaceAlertChannelHandle {
    _private: [u8; 0],
}

impl MaceAlertChannelHandle {
    fn from_arc(channel: Arc<AlertChannel>) -> *mut Self {
        Arc::into_raw(channel) as *mut MaceAlertChannelHandle
    }

    unsafe fn to_arc(handle: *mut Self) -> Arc<AlertChannel> {
        // SAFETY: caller guarantees `handle` came from `from_arc` and is consumed once.
        unsafe { Arc::from_raw(handle as *const AlertChannel) }
    }

    unsafe fn as_ref(handle: *const Self) -> Option<&'static AlertChannel> {
        if handle.is_null() {
            None
        } else {
            // SAFETY: caller guarantees pointer validity while handle is alive.
            Some(unsafe { &*(handle as *const AlertChannel) })
        }
    }
}

/// Create a new alert channel with the specified capacity.
///
/// Returns a non-null handle on success, or null on panic.
///
/// # Safety
/// The returned handle must be freed with mace_alert_channel_free().
#[unsafe(no_mangle)]
pub extern "C" fn mace_alert_channel_new(capacity: usize) -> *mut MaceAlertChannelHandle {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let channel = AlertChannel::new(capacity);
        MaceAlertChannelHandle::from_arc(Arc::new(channel))
    }));

    match result {
        Ok(handle) => handle,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free an alert channel handle.
///
/// # Safety
/// - handle must be a valid pointer returned by mace_alert_channel_new()
/// - handle must not be used after this call
/// - handle must not be freed more than once
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_alert_channel_free(handle: *mut MaceAlertChannelHandle) {
    if handle.is_null() {
        return;
    }

    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: `handle` is expected to be allocated by `mace_alert_channel_new`
        // and consumed exactly once by this destructor.
        let _channel = MaceAlertChannelHandle::to_arc(handle);
    }));
}

/// Try to receive an alert from the channel (non-blocking).
///
/// Returns:
/// - Positive integer: number of bytes written to out_buffer
/// - 0: no alert available
/// - Negative required size: output buffer is too small
/// - MaceErrorCode::NullPointer if handle or out_buffer is null
/// - MaceErrorCode::Panic if a panic occurred
///
/// # Safety
/// - handle must be a valid pointer returned by mace_alert_channel_new()
/// - out_buffer must point to a buffer of at least buffer_size bytes
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_alert_channel_try_recv(
    handle: *mut MaceAlertChannelHandle,
    out_buffer: *mut u8,
    buffer_size: usize,
) -> i32 {
    if handle.is_null() || out_buffer.is_null() {
        return MaceErrorCode::NullPointer as i32;
    }

    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: pointers are checked for null above; caller guarantees validity.
        let channel = MaceAlertChannelHandle::as_ref(handle).expect("checked non-null");
        match channel.try_recv() {
            Some(alert) => {
                let bytes = alert.encode_to_vec();
                if bytes.len() > i32::MAX as usize {
                    return MaceErrorCode::Panic as i32;
                }
                if bytes.len() > buffer_size {
                    return -(bytes.len() as i32);
                }

                // SAFETY: caller guarantees `out_buffer` points to at least `buffer_size`
                // bytes, and we only copy `bytes.len()` where `bytes.len() <= buffer_size`.
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buffer, bytes.len());
                bytes.len() as i32
            }
            None => 0,
        }
    }));

    match result {
        Ok(size) => size,
        Err(_) => MaceErrorCode::Panic as i32,
    }
}

/// Compatibility alias for older C API naming.
///
/// # Safety
/// - same requirements as `mace_alert_channel_try_recv`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_alert_channel_recv(
    handle: *mut MaceAlertChannelHandle,
    out_buffer: *mut u8,
    buffer_size: usize,
) -> i32 {
    // SAFETY: forwards directly to the canonical implementation.
    unsafe { mace_alert_channel_try_recv(handle, out_buffer, buffer_size) }
}

/// Push a fixed, maximal-field [`ProtoAlert`] into the channel for cross-language integrity tests.
///
/// Intended for Go/Python harnesses (not production): exercises protobuf serialization and the
/// same `try_recv` path as real alerts. Returns `MaceErrorCode` as `i32`.
///
/// # Safety
/// `handle` must be a valid pointer returned by `mace_alert_channel_new` and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_alert_channel_feed_test_alert(
    handle: *mut MaceAlertChannelHandle,
) -> i32 {
    if handle.is_null() {
        return MaceErrorCode::NullPointer as i32;
    }

    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        let channel = MaceAlertChannelHandle::as_ref(handle).expect("checked non-null");

        let big = "Z".repeat(16_384);
        let ctx = serde_json::json!({
            "n": i64::MAX,
            "nested": { "s": "inner", "arr": [1, 2, 3] },
            "big": big,
        })
        .to_string();

        let alert = ProtoAlert {
            alert_id: "edgecase-alert-id-12345".to_string(),
            rule_name: "rule-integrity-αβ".to_string(),
            severity: ProtoSeverity::Critical as i32,
            message: "msg-\n\t\"escaped\"".to_string(),
            tgid: u32::MAX,
            process_name: "procname-no-nul-padding".to_string(),
            timestamp_ns: u64::MAX,
            context_json: ctx,
        };

        match channel.inject_test_proto(alert) {
            Ok(()) => MaceErrorCode::Success as i32,
            Err(_) => MaceErrorCode::Panic as i32,
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => MaceErrorCode::Panic as i32,
    }
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::*;

    fn sample_alert(rule_name: &str, severity: RustSeverity, tgid: u32) -> RustAlert {
        RustAlert {
            rule_id: format!("{rule_name}-id"),
            rule_name: rule_name.to_string(),
            severity,
            timestamp_ns: 1000,
            tgid,
            pid: tgid + 1,
            comm: "test_proc".to_string(),
            syscall_id: 9,
            matched_flags: 0x4,
            namespace: Some("default".to_string()),
            pod_name: Some("test-pod".to_string()),
        }
    }

    #[tokio::test]
    async fn test_alert_channel_send_recv() {
        let channel = AlertChannel::new(10);
        let alert = sample_alert("test_rule", RustSeverity::High, 1234);

        channel.send(alert).await.expect("send should succeed");

        let received = channel.recv().await.expect("alert should be received");
        assert_eq!(received.rule_name, "test_rule");
        assert_eq!(received.severity, ProtoSeverity::High as i32);
        assert_eq!(received.tgid, 1234);
    }

    #[tokio::test]
    async fn test_alert_channel_try_send() {
        let channel = AlertChannel::new(1);
        let alert1 = sample_alert("rule1", RustSeverity::Medium, 100);
        let alert2 = sample_alert("rule2", RustSeverity::Low, 200);

        channel.try_send(alert1).expect("first send should work");
        assert!(channel.try_send(alert2).is_err());
    }

    #[test]
    fn test_convert_alert_to_proto() {
        let rust_alert = sample_alert("suspicious_access", RustSeverity::Critical, 5678);
        let proto_alert = convert_alert_to_proto(rust_alert);

        assert_eq!(proto_alert.rule_name, "suspicious_access");
        assert_eq!(proto_alert.severity, ProtoSeverity::Critical as i32);
        assert_eq!(proto_alert.tgid, 5678);
        assert_eq!(proto_alert.process_name, "test_proc");
        assert_eq!(proto_alert.timestamp_ns, 1000);
        assert!(proto_alert.context_json.contains("test-pod"));
        assert!(!proto_alert.alert_id.is_empty());
    }

    #[test]
    fn test_ffi_alert_channel_new_and_free() {
        let handle = mace_alert_channel_new(10);
        assert!(!handle.is_null());
        unsafe { mace_alert_channel_free(handle) };
    }

    #[test]
    fn test_ffi_alert_channel_try_recv_empty() {
        let handle = mace_alert_channel_new(10);
        let mut buffer = vec![0u8; 1024];

        let result =
            unsafe { mace_alert_channel_try_recv(handle, buffer.as_mut_ptr(), buffer.len()) };

        assert_eq!(result, 0);
        unsafe { mace_alert_channel_free(handle) };
    }

    #[test]
    fn test_ffi_alert_channel_null_handle() {
        let mut buffer = vec![0u8; 1024];

        let result = unsafe {
            mace_alert_channel_try_recv(std::ptr::null_mut(), buffer.as_mut_ptr(), buffer.len())
        };

        assert_eq!(result, MaceErrorCode::NullPointer as i32);
    }

    #[test]
    fn test_ffi_alert_channel_null_buffer() {
        let handle = mace_alert_channel_new(10);

        let result = unsafe { mace_alert_channel_try_recv(handle, std::ptr::null_mut(), 1024) };

        assert_eq!(result, MaceErrorCode::NullPointer as i32);
        unsafe { mace_alert_channel_free(handle) };
    }

    #[test]
    fn test_ffi_feed_test_alert_roundtrip() {
        let handle = mace_alert_channel_new(4);
        assert!(!handle.is_null());
        let st = unsafe { mace_alert_channel_feed_test_alert(handle) };
        assert_eq!(st, MaceErrorCode::Success as i32);

        let mut buf = vec![0u8; 512 * 1024];
        let n = unsafe { mace_alert_channel_try_recv(handle, buf.as_mut_ptr(), buf.len()) };
        assert!(n > 0, "expected payload, got {n}");
        let got = ProtoAlert::decode(&buf[..n as usize]).expect("decode");
        assert_eq!(got.alert_id, "edgecase-alert-id-12345");
        assert_eq!(got.tgid, u32::MAX);
        assert_eq!(got.timestamp_ns, u64::MAX);
        assert_eq!(got.process_name, "procname-no-nul-padding");
        assert!(!got.context_json.is_empty());
        unsafe { mace_alert_channel_free(handle) };
    }
}
