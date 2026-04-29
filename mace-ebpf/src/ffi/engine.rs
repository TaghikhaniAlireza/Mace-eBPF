//! Embedded engine control for Go/Python: Tokio runtime + eBPF sensor + pipeline in a background thread.

use std::{
    ffi::{CStr, c_char},
    path::PathBuf,
    sync::Mutex,
    thread::JoinHandle,
};

use tokio::sync::oneshot;

use crate::{NoopEnricher, PipelineConfig, SensorConfig, pipeline::PipelineHandle, start_pipeline};

static ENGINE_YAML: Mutex<Option<String>> = Mutex::new(None);
/// When set, `mace_start_pipeline` uses [`PipelineConfig::rules_path`] (hot-reload via [`crate::rules::watcher::RuleWatcher`]).
static ENGINE_RULES_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
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
pub extern "C" fn mace_engine_init() -> i32 {
    crate::init_logging_for_ffi();
    stop_engine_inner();
    if let Ok(mut g) = ENGINE_YAML.lock() {
        *g = None;
    }
    if let Ok(mut g) = ENGINE_RULES_PATH.lock() {
        *g = None;
    }
    super::handle::MaceErrorCode::Success as i32
}

/// Load rule YAML from a NUL-terminated UTF-8 string (not written to disk). Must be called before
/// `mace_start_pipeline` (or call `mace_start_pipeline` again after stop to change rules).
///
/// # Safety
/// `yaml` must be a valid pointer to a NUL-terminated C string for the lifetime of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_load_rules(yaml: *const c_char) -> i32 {
    if yaml.is_null() {
        return super::handle::MaceErrorCode::NullPointer as i32;
    }
    let s = match unsafe { CStr::from_ptr(yaml) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return super::handle::MaceErrorCode::InitFailed as i32,
    };
    if let Err(e) = crate::rules::loader::RuleSet::from_yaml_str(&s) {
        tracing::error!("mace_load_rules: invalid yaml: {e}");
        return super::handle::MaceErrorCode::InitFailed as i32;
    }
    if let Ok(mut g) = ENGINE_RULES_PATH.lock() {
        *g = None;
    }
    if let Ok(mut g) = ENGINE_YAML.lock() {
        *g = Some(s);
    }
    super::handle::MaceErrorCode::Success as i32
}

/// Load rules from a filesystem path (YAML file). Enables hot-reload when the file changes.
/// Mutually exclusive with `mace_load_rules` for the next `mace_start_pipeline` call.
///
/// # Safety
/// `path_utf8` must be a valid pointer to a NUL-terminated UTF-8 path string for the lifetime of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_load_rules_file(path_utf8: *const c_char) -> i32 {
    if path_utf8.is_null() {
        return super::handle::MaceErrorCode::NullPointer as i32;
    }
    let p = match unsafe { CStr::from_ptr(path_utf8) }.to_str() {
        Ok(s) => PathBuf::from(s),
        Err(_) => return super::handle::MaceErrorCode::InitFailed as i32,
    };
    if let Err(e) = crate::rules::loader::RuleSet::from_file(&p) {
        tracing::error!(
            "mace_load_rules_file: invalid rules file {}: {e}",
            p.display()
        );
        return super::handle::MaceErrorCode::InitFailed as i32;
    }
    if let Ok(mut g) = ENGINE_YAML.lock() {
        *g = None;
    }
    if let Ok(mut g) = ENGINE_RULES_PATH.lock() {
        *g = Some(p);
    }
    super::handle::MaceErrorCode::Success as i32
}

/// Start the sensor + pipeline on a dedicated thread with its own Tokio runtime.
/// Requires prior `mace_load_rules` **or** `mace_load_rules_file`. Uses `mace_register_event_callback` when set (`start_pipeline` wires it).
#[unsafe(no_mangle)]
pub extern "C" fn mace_start_pipeline() -> i32 {
    if ENGINE_THREAD.lock().ok().is_some_and(|g| g.is_some()) {
        return super::handle::MaceErrorCode::InitFailed as i32;
    }
    let rules_path = ENGINE_RULES_PATH.lock().ok().and_then(|g| g.clone());
    let inline_yaml = ENGINE_YAML.lock().ok().and_then(|g| g.clone());

    let pipeline_rules = match (&rules_path, &inline_yaml) {
        (Some(path), None) => PipelineConfig {
            rules_path: Some(path.clone()),
            rules_inline_yaml: None,
            ..PipelineConfig::default()
        },
        (None, Some(yaml)) => PipelineConfig {
            rules_path: None,
            rules_inline_yaml: Some(yaml.clone()),
            ..PipelineConfig::default()
        },
        _ => return super::handle::MaceErrorCode::InitFailed as i32,
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
                tracing::error!("mace_start_pipeline: runtime: {e}");
                return;
            }
        };

        rt.block_on(async move {
            let handle: PipelineHandle = match start_pipeline(
                SensorConfig::default(),
                pipeline_rules,
                std::sync::Arc::new(NoopEnricher),
            )
            .await
            {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("mace_start_pipeline: {e:#}");
                    return;
                }
            };

            tracing::info!(
                "mace: eBPF sensor and rule pipeline started (set RUST_LOG=debug for verbose logs)"
            );

            let _ = shutdown_rx.await;
            handle.shutdown().await;
        });
    });

    set_engine_thread(join);
    super::handle::MaceErrorCode::Success as i32
}

/// Signal the engine thread to stop and join it.
#[unsafe(no_mangle)]
pub extern "C" fn mace_stop_pipeline() -> i32 {
    stop_engine_inner();
    super::handle::MaceErrorCode::Success as i32
}

/// Set the minimum **Mace** log severity for core diagnostics (`[Mace][LEVEL] …` on stderr).
///
/// `level` must be `0` = TRACE, `1` = INFO, `2` = SUPPRESSED, `3` = EVENT, `4` = ALERT.
/// Invalid values return [`MaceErrorCode::InitFailed`]. Thread-safe; may be called before
/// `mace_engine_init` or at any time while the library is loaded.
#[unsafe(no_mangle)]
pub extern "C" fn mace_set_log_level(level: i32) -> i32 {
    if !(0..=4).contains(&level) {
        return super::handle::MaceErrorCode::InitFailed as i32;
    }
    if let Some(lvl) = crate::MaceLogLevel::from_u8(level as u8) {
        crate::logging::set_filter_floor(lvl);
    }
    super::handle::MaceErrorCode::Success as i32
}
