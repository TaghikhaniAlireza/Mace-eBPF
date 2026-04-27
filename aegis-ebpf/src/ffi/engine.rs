//! Embedded engine control for Go/Python: Tokio runtime + eBPF sensor + pipeline in a background thread.

use std::{
    ffi::{CStr, c_char},
    sync::Mutex,
    thread::JoinHandle,
};

use tokio::sync::oneshot;

use crate::{NoopEnricher, PipelineConfig, SensorConfig, pipeline::PipelineHandle, start_pipeline};

static ENGINE_YAML: Mutex<Option<String>> = Mutex::new(None);
static SHUTDOWN_TX: Mutex<Option<oneshot::Sender<()>>> = Mutex::new(None);
static ENGINE_THREAD: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

fn take_engine_thread() -> Option<JoinHandle<()>> {
    ENGINE_THREAD.lock().ok()?.take()
}

fn set_engine_thread(j: JoinHandle<()>) {
    if let Ok(mut g) = ENGINE_THREAD.lock() {
        *g = Some(j);
    }
}

fn stop_engine_inner() {
    if let Ok(mut g) = SHUTDOWN_TX.lock() {
        if let Some(tx) = g.take() {
            let _ = tx.send(());
        }
    }
    if let Some(j) = take_engine_thread() {
        let _ = j.join();
    }
}

/// Initialize global engine state: stops any previous run, clears staged YAML.
#[unsafe(no_mangle)]
pub extern "C" fn aegis_engine_init() -> i32 {
    crate::init_logging_for_ffi();
    stop_engine_inner();
    if let Ok(mut g) = ENGINE_YAML.lock() {
        *g = None;
    }
    super::handle::AegisErrorCode::Success as i32
}

/// Load rule YAML from a NUL-terminated UTF-8 string (not written to disk). Must be called before
/// `aegis_start_pipeline` (or call `aegis_start_pipeline` again after stop to change rules).
///
/// # Safety
/// `yaml` must be a valid pointer to a NUL-terminated C string for the lifetime of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_load_rules(yaml: *const c_char) -> i32 {
    if yaml.is_null() {
        return super::handle::AegisErrorCode::NullPointer as i32;
    }
    let s = match unsafe { CStr::from_ptr(yaml) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return super::handle::AegisErrorCode::InitFailed as i32,
    };
    if let Err(e) = crate::rules::loader::RuleSet::from_yaml_str(&s) {
        tracing::error!("aegis_load_rules: invalid yaml: {e}");
        return super::handle::AegisErrorCode::InitFailed as i32;
    }
    if let Ok(mut g) = ENGINE_YAML.lock() {
        *g = Some(s);
    }
    super::handle::AegisErrorCode::Success as i32
}

/// Start the sensor + pipeline on a dedicated thread with its own Tokio runtime.
/// Requires prior `aegis_load_rules`. Uses `register_event_callback` when set (`start_pipeline` wires it).
#[unsafe(no_mangle)]
pub extern "C" fn aegis_start_pipeline() -> i32 {
    if ENGINE_THREAD.lock().ok().is_some_and(|g| g.is_some()) {
        return super::handle::AegisErrorCode::InitFailed as i32;
    }
    let yaml = match ENGINE_YAML.lock().ok().and_then(|g| g.clone()) {
        Some(y) => y,
        None => return super::handle::AegisErrorCode::InitFailed as i32,
    };

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    if let Ok(mut g) = SHUTDOWN_TX.lock() {
        *g = Some(shutdown_tx);
    }

    let join = std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!("aegis_start_pipeline: runtime: {e}");
                return;
            }
        };

        rt.block_on(async move {
            let handle: PipelineHandle = match start_pipeline(
                SensorConfig::default(),
                PipelineConfig {
                    rules_inline_yaml: Some(yaml),
                    ..PipelineConfig::default()
                },
                std::sync::Arc::new(NoopEnricher),
            )
            .await
            {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("aegis_start_pipeline: {e}");
                    return;
                }
            };

            tracing::info!(
                "aegis: eBPF sensor and rule pipeline started (set RUST_LOG=debug for verbose logs)"
            );

            let _ = shutdown_rx.await;
            handle.shutdown().await;
        });
    });

    set_engine_thread(join);
    super::handle::AegisErrorCode::Success as i32
}

/// Signal the engine thread to stop and join it.
#[unsafe(no_mangle)]
pub extern "C" fn aegis_stop_pipeline() -> i32 {
    stop_engine_inner();
    super::handle::AegisErrorCode::Success as i32
}
