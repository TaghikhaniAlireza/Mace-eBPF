//! Embedded engine control for Go/Python: Tokio runtime + eBPF sensor + pipeline in a background thread.

use std::{
    ffi::{CStr, c_char},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
};

use aya::{
    Ebpf,
    maps::{Array, HashMap},
};
use serde::Serialize;
use tokio::sync::oneshot;

use crate::{NoopEnricher, PipelineConfig, SensorConfig, audit, start_pipeline};

static ENGINE_YAML: Mutex<Option<String>> = Mutex::new(None);
/// When set, `mace_start_pipeline` uses [`PipelineConfig::rules_path`] (hot-reload via [`crate::rules::watcher::RuleWatcher`]).
static ENGINE_RULES_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
static SHUTDOWN_TX: Mutex<Option<oneshot::Sender<()>>> = Mutex::new(None);
static ENGINE_THREAD: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);
/// Live `Ebpf` while the sensor thread runs (for health / allowlist updates).
static ENGINE_EBPF: Mutex<Option<Arc<Mutex<Ebpf>>>> = Mutex::new(None);
static ENGINE_RUNNING: AtomicBool = AtomicBool::new(false);
static ENGINE_PARTITION_COUNT: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn engine_rule_path() -> Option<PathBuf> {
    ENGINE_RULES_PATH.lock().ok().and_then(|g| g.clone())
}

pub(crate) fn engine_rule_inline_yaml() -> Option<String> {
    ENGINE_YAML.lock().ok().and_then(|g| g.clone())
}

pub(crate) fn engine_pipeline_running() -> bool {
    ENGINE_RUNNING.load(Ordering::Acquire)
}

pub(crate) fn engine_partition_count() -> usize {
    ENGINE_PARTITION_COUNT.load(Ordering::Acquire)
}

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
    ENGINE_RUNNING.store(false, Ordering::Release);
    if let Ok(mut g) = ENGINE_EBPF.lock() {
        *g = None;
    }
}

fn audit_detail_path(p: &Path) -> String {
    format!("path={}", p.display())
}

fn audit_detail_yaml_preview(s: &str) -> String {
    let n = s.len().min(120);
    format!("yaml_chars={} preview={:?}", s.len(), &s[..n])
}

/// Initialize global engine state: stops any previous run, clears staged YAML.
#[unsafe(no_mangle)]
pub extern "C" fn mace_engine_init() -> i32 {
    crate::init_logging_for_ffi();
    audit::init_from_env();
    stop_engine_inner();
    if let Ok(mut g) = ENGINE_YAML.lock() {
        *g = None;
    }
    if let Ok(mut g) = ENGINE_RULES_PATH.lock() {
        *g = None;
    }
    crate::engine_stage::clear_staged_rule_count();
    audit::record(
        "engine_init",
        "cleared staged rules and stopped prior thread",
        true,
    );
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
        Err(_) => {
            audit::record("load_rules", "invalid utf-8 in yaml pointer", false);
            return super::handle::MaceErrorCode::InitFailed as i32;
        }
    };
    let set = match crate::rules::loader::RuleSet::from_yaml_str(&s) {
        Ok(set) => set,
        Err(e) => {
            tracing::error!("mace_load_rules: invalid yaml: {e}");
            audit::record("load_rules", &format!("parse_error={e}"), false);
            return super::handle::MaceErrorCode::InitFailed as i32;
        }
    };
    crate::engine_stage::record_staged_rule_count(set.rules.len());
    if let Ok(mut g) = ENGINE_RULES_PATH.lock() {
        *g = None;
    }
    if let Ok(mut g) = ENGINE_YAML.lock() {
        *g = Some(s.clone());
    }
    audit::record("load_rules", &audit_detail_yaml_preview(&s), true);
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
        Err(_) => {
            audit::record("load_rules_file", "invalid utf-8 path", false);
            return super::handle::MaceErrorCode::InitFailed as i32;
        }
    };
    let set = match crate::rules::loader::RuleSet::from_file(&p) {
        Ok(set) => set,
        Err(e) => {
            tracing::error!(
                "mace_load_rules_file: invalid rules file {}: {e}",
                p.display()
            );
            audit::record(
                "load_rules_file",
                &format!("{} error={e}", audit_detail_path(&p)),
                false,
            );
            return super::handle::MaceErrorCode::InitFailed as i32;
        }
    };
    crate::engine_stage::record_staged_rule_count(set.rules.len());
    if let Ok(mut g) = ENGINE_YAML.lock() {
        *g = None;
    }
    if let Ok(mut g) = ENGINE_RULES_PATH.lock() {
        *g = Some(p.clone());
    }
    audit::record("load_rules_file", &audit_detail_path(&p), true);
    super::handle::MaceErrorCode::Success as i32
}

/// Add a TGID to the kernel `ALLOWLIST` map (suppresses syscall capture for that thread group).
/// Requires a running pipeline. Audit-logged.
#[unsafe(no_mangle)]
pub extern "C" fn mace_allowlist_add_tgid(tgid: u32) -> i32 {
    let arc = match ENGINE_EBPF.lock().ok().and_then(|g| g.clone()) {
        Some(a) => a,
        None => {
            audit::record(
                "allowlist_add_tgid",
                "engine not running (start pipeline first)",
                false,
            );
            return super::handle::MaceErrorCode::InitFailed as i32;
        }
    };
    let mut ebpf = match arc.lock() {
        Ok(g) => g,
        Err(_) => return super::handle::MaceErrorCode::InitFailed as i32,
    };
    let map_fd = match ebpf.map_mut("ALLOWLIST") {
        Some(m) => m,
        None => {
            tracing::error!("mace_allowlist_add_tgid: ALLOWLIST map missing");
            audit::record("allowlist_add_tgid", "ALLOWLIST map missing", false);
            return super::handle::MaceErrorCode::InitFailed as i32;
        }
    };
    let mut allow = match HashMap::<_, u32, u8>::try_from(map_fd) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("mace_allowlist_add_tgid: {e}");
            audit::record(
                "allowlist_add_tgid",
                &format!("tgid={tgid} wrap_error={e}"),
                false,
            );
            return super::handle::MaceErrorCode::InitFailed as i32;
        }
    };
    if let Err(e) = allow.insert(tgid, 1u8, 0) {
        tracing::error!("mace_allowlist_add_tgid: insert: {e}");
        audit::record(
            "allowlist_add_tgid",
            &format!("tgid={tgid} insert_error={e}"),
            false,
        );
        return super::handle::MaceErrorCode::InitFailed as i32;
    }
    audit::record(
        "allowlist_add_tgid",
        &format!("tgid={tgid} (kernel ALLOWLIST)"),
        true,
    );
    super::handle::MaceErrorCode::Success as i32
}

/// Start the sensor + pipeline on a dedicated thread with its own Tokio runtime.
/// Requires prior `mace_load_rules` **or** `mace_load_rules_file`. Uses `mace_register_event_callback` when set (`start_pipeline` wires it).
#[unsafe(no_mangle)]
pub extern "C" fn mace_start_pipeline() -> i32 {
    if ENGINE_THREAD.lock().ok().is_some_and(|g| g.is_some()) {
        audit::record("start_pipeline", "already running", false);
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
        _ => {
            audit::record(
                "start_pipeline",
                "no rules staged (load_rules first)",
                false,
            );
            return super::handle::MaceErrorCode::InitFailed as i32;
        }
    };
    let part = pipeline_rules.partition_count;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    if let Ok(mut g) = SHUTDOWN_TX.lock() {
        *g = Some(shutdown_tx);
    }

    let join =
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("mace_start_pipeline: runtime: {e}");
                    audit::record(
                        "start_pipeline",
                        &format!("tokio runtime error: {e}"),
                        false,
                    );
                    return;
                }
            };

            rt.block_on(async move {
            let (handle, ebpf) = match start_pipeline(
                SensorConfig::default(),
                pipeline_rules,
                Arc::new(NoopEnricher),
            )
            .await
            {
                Ok(x) => x,
                Err(e) => {
                    tracing::error!("mace_start_pipeline: {e:#}");
                    audit::record("start_pipeline", &format!("error={e:#}"), false);
                    return;
                }
            };

            if let Ok(mut g) = ENGINE_EBPF.lock() {
                *g = Some(Arc::clone(&ebpf));
            }
            ENGINE_PARTITION_COUNT.store(part, Ordering::Release);
            ENGINE_RUNNING.store(true, Ordering::Release);
            audit::record("start_pipeline", "sensor and pipeline started", true);

            tracing::info!(
                "mace: eBPF sensor and rule pipeline started (set RUST_LOG=debug for verbose logs)"
            );

            let _ = shutdown_rx.await;
            handle.shutdown().await;
            ENGINE_RUNNING.store(false, Ordering::Release);
            if let Ok(mut g) = ENGINE_EBPF.lock() {
                *g = None;
            }
            audit::record("stop_pipeline", "shutdown complete (from engine thread)", true);
        });
        });

    set_engine_thread(join);
    super::handle::MaceErrorCode::Success as i32
}

/// Signal the engine thread to stop and join it.
#[unsafe(no_mangle)]
pub extern "C" fn mace_stop_pipeline() -> i32 {
    audit::record("stop_pipeline", "shutdown requested", true);
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
        audit::record("set_log_level", &format!("invalid level={level}"), false);
        return super::handle::MaceErrorCode::InitFailed as i32;
    }
    if let Some(lvl) = crate::MaceLogLevel::from_u8(level as u8) {
        crate::logging::set_filter_floor(lvl);
    }
    audit::record("set_log_level", &format!("level={level}"), true);
    super::handle::MaceErrorCode::Success as i32
}

#[derive(Serialize)]
struct HealthJson {
    pipeline_running: bool,
    rule_source: &'static str,
    rule_count: usize,
    staged_rule_count: usize,
    partition_count: usize,
    ringbuf_capacity_bytes: u64,
    maps_memory_bytes_estimated: u64,
    kernel_stats_ringbuf_fails: u64,
    kernel_stats_lru_fails: u64,
    kernel_stats_allowlist_hits: u64,
    kernel_stats_rate_limit_hits: u64,
}

fn rule_count_for_health() -> (usize, usize) {
    let staged = crate::engine_stage::staged_rule_count();
    let parsed = rule_count_parse_fallback();
    let effective = if staged > 0 { staged } else { parsed };
    (effective, staged)
}

fn rule_count_parse_fallback() -> usize {
    if let Some(p) = engine_rule_path() {
        if let Ok(set) = crate::rules::loader::RuleSet::from_file(&p) {
            return set.rules.len();
        }
    }
    if let Some(y) = engine_rule_inline_yaml() {
        if let Ok(set) = crate::rules::loader::RuleSet::from_yaml_str(&y) {
            return set.rules.len();
        }
    }
    0
}

/// Number of rules last staged successfully for the embedded engine (O(1); no disk read).
#[unsafe(no_mangle)]
pub extern "C" fn mace_engine_staged_rule_count() -> u64 {
    crate::engine_stage::staged_rule_count() as u64
}

fn rule_source_str() -> &'static str {
    if engine_rule_path().is_some() {
        "file"
    } else if engine_rule_inline_yaml().is_some() {
        "inline"
    } else {
        "none"
    }
}

fn read_kernel_stats(ebpf: &mut Ebpf) -> [u64; 4] {
    let Ok(arr) = Array::<_, u64>::try_from(
        ebpf.map_mut("KERNEL_STATS")
            .expect("KERNEL_STATS map present when sensor loaded"),
    ) else {
        return [0; 4];
    };
    let mut out = [0u64; 4];
    for i in 0u32..4 {
        if let Ok(v) = arr.get(&i, 0) {
            out[i as usize] = v;
        }
    }
    out
}

fn estimated_map_bytes() -> u64 {
    const RINGBUF: u64 = 512 * 1024;
    const PENDING_APPROX: u64 = 10240 * (8 + 256);
    const LRU_OTHER: u64 = 256 * 1024;
    RINGBUF + PENDING_APPROX * 2 + LRU_OTHER
}

/// Write a compact JSON health document into `out` (NUL-terminated if space allows).
///
/// # Safety
/// `out` must point to `out_len` writable bytes when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mace_engine_health_json(out: *mut c_char, out_len: usize) -> i32 {
    if out.is_null() || out_len == 0 {
        return super::handle::MaceErrorCode::NullPointer as i32;
    }
    let stats = match ENGINE_EBPF.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(arc) => match arc.lock() {
                Ok(mut e) => read_kernel_stats(&mut e),
                Err(_) => [0; 4],
            },
            None => [0; 4],
        },
        Err(_) => [0; 4],
    };

    let (rule_count, staged_rule_count) = rule_count_for_health();

    let h = HealthJson {
        pipeline_running: engine_pipeline_running(),
        rule_source: rule_source_str(),
        rule_count,
        staged_rule_count,
        partition_count: engine_partition_count(),
        ringbuf_capacity_bytes: 512 * 1024,
        maps_memory_bytes_estimated: estimated_map_bytes(),
        kernel_stats_ringbuf_fails: stats[0],
        kernel_stats_lru_fails: stats[1],
        kernel_stats_allowlist_hits: stats[2],
        kernel_stats_rate_limit_hits: stats[3],
    };
    let json = match serde_json::to_string(&h) {
        Ok(s) => s,
        Err(_) => return super::handle::MaceErrorCode::InitFailed as i32,
    };
    let need = json.len() + 1;
    if need > out_len {
        return -(need as i32);
    }
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), out.cast(), json.len());
        *out.add(json.len()) = 0;
    }
    super::handle::MaceErrorCode::Success as i32
}
