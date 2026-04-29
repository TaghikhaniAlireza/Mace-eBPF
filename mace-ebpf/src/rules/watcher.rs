use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use arc_swap::ArcSwap;
use notify::{
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher, event::ModifyKind,
};
use regex::Regex;
use tracing::error;

use super::{RuleError, loader::RuleSet};
use crate::alert::AlertCallback;

pub struct RuleWatcher {
    rules: Arc<ArcSwap<RuleSet>>,
    /// Pre-compiled regexes keyed by rule id (cgroup + process-name patterns at last successful load).
    precompiled_rules: Arc<ArcSwap<HashMap<String, Regex>>>,
    _watcher: RecommendedWatcher,
}

impl RuleWatcher {
    pub fn new(path: PathBuf) -> Result<Self, RuleError> {
        let initial = load_ruleset_from_path(&path)?;
        let precompiled = Arc::new(ArcSwap::from_pointee(build_precompiled_map(&initial)));
        let rules = Arc::new(ArcSwap::from_pointee(initial));

        let (event_tx, event_rx) = mpsc::channel::<notify::Result<Event>>();
        let mut watcher = RecommendedWatcher::new(
            move |event| {
                let _ = event_tx.send(event);
            },
            Config::default(),
        )
        .map_err(|err| RuleError::IoError(std::io::Error::other(err.to_string())))?;

        let watch_target = watch_target(&path);
        watcher
            .watch(&watch_target, RecursiveMode::NonRecursive)
            .map_err(|err| RuleError::IoError(std::io::Error::other(err.to_string())))?;

        let rules_for_thread = Arc::clone(&rules);
        let precompiled_for_thread = Arc::clone(&precompiled);
        thread::spawn(move || {
            while let Ok(event_result) = event_rx.recv() {
                match event_result {
                    Ok(event) => {
                        if !should_reload(&event, &path) {
                            continue;
                        }
                        // Small debounce to allow editor atomic write/rename sequences.
                        thread::sleep(Duration::from_millis(20));
                        match load_ruleset_from_path(&path) {
                            Ok(new_rules) => {
                                precompiled_for_thread
                                    .store(Arc::new(build_precompiled_map(&new_rules)));
                                rules_for_thread.store(Arc::new(new_rules.clone()));
                                crate::engine_stage::record_staged_rule_count(
                                    new_rules.rules.len(),
                                );
                                crate::audit::record(
                                    "rules_hot_reload",
                                    &format!("path={}", path.display()),
                                    true,
                                );
                            }
                            Err(err) => {
                                error!("rule reload failed: {err}");
                                crate::audit::record(
                                    "rules_hot_reload",
                                    &format!("path={} error={err}", path.display()),
                                    false,
                                );
                            }
                        }
                    }
                    Err(err) => {
                        error!("rule watcher event error: {err}");
                    }
                }
            }
        });

        Ok(Self {
            rules,
            precompiled_rules: precompiled,
            _watcher: watcher,
        })
    }

    pub fn rules(&self) -> Arc<ArcSwap<RuleSet>> {
        Arc::clone(&self.rules)
    }

    /// Snapshot of regexes compiled at rule load time (for introspection / tests).
    pub fn precompiled_rules(&self) -> Arc<ArcSwap<HashMap<String, Regex>>> {
        Arc::clone(&self.precompiled_rules)
    }
}

/// One entry per rule id: prefers `process_name_pattern`, then `cgroup_pattern`, then `pathname_pattern`, then `cmdline_context_pattern`.
fn build_precompiled_map(rules: &RuleSet) -> HashMap<String, Regex> {
    let mut map = HashMap::new();
    for rule in &rules.rules {
        if let Some(rx) = &rule.process_name_regex {
            map.insert(rule.id.clone(), rx.clone());
        } else if let Some(rx) = &rule.cgroup_regex {
            map.insert(rule.id.clone(), rx.clone());
        } else if let Some(rx) = &rule.pathname_regex {
            map.insert(rule.id.clone(), rx.clone());
        } else if let Some(rx) = &rule.cmdline_context_regex {
            map.insert(rule.id.clone(), rx.clone());
        }
    }
    map
}

pub fn load_ruleset_from_path(path: &Path) -> Result<RuleSet, RuleError> {
    if path.is_dir() {
        return RuleSet::from_dir(path);
    }
    RuleSet::from_file(path)
}

fn watch_target(path: &Path) -> PathBuf {
    if path.is_dir() {
        return path.to_path_buf();
    }
    path.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn should_reload(event: &Event, configured_path: &Path) -> bool {
    let relevant_kind = matches!(
        event.kind,
        EventKind::Create(_)
            | EventKind::Modify(ModifyKind::Data(_))
            | EventKind::Modify(ModifyKind::Name(_))
            | EventKind::Modify(ModifyKind::Any)
            | EventKind::Remove(_)
            | EventKind::Any
    );
    if !relevant_kind {
        return false;
    }

    if configured_path.is_dir() {
        return true;
    }

    // Reload when target file is touched directly or via parent-dir events.
    if event.paths.is_empty() {
        return true;
    }
    let parent = configured_path.parent();
    let file_name = configured_path.file_name();
    event.paths.iter().any(|path| {
        path == configured_path
            || parent.is_some_and(|dir| path == dir)
            || file_name
                .is_some_and(|name| path.file_name().is_some_and(|candidate| candidate == name))
    })
}

pub fn call_alert_callback(callback: &Option<AlertCallback>, alert: crate::Alert) {
    if let Some(cb) = callback {
        let fut = cb(alert);
        tokio::spawn(fut);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{Arc, Mutex},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use futures::FutureExt;
    use mace_ebpf_common::{EventType, MemoryEvent};
    use tokio::sync::mpsc;

    use super::RuleWatcher;
    use crate::{
        Alert, AlertCallback, NoopEnricher, PipelineConfig,
        pipeline::start_pipeline_from_receiver_for_tests_with_rules,
    };

    fn unique_path(prefix: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!("mace-watcher-test-{prefix}-{unique}.yaml"))
    }

    fn write_rule_file(path: &std::path::Path, body: &str) {
        fs::write(path, body).expect("rule file should be written");
    }

    fn one_rule_yaml(id: &str) -> String {
        format!(
            r#"rules:
  - id: "{id}"
    name: "rule-{id}"
    severity: "high"
    description: "desc"
    conditions:
      syscall: "mprotect"
"#
        )
    }

    fn two_rule_yaml(id_a: &str, id_b: &str) -> String {
        format!(
            r#"rules:
  - id: "{id_a}"
    name: "rule-{id_a}"
    severity: "high"
    description: "desc"
    conditions:
      syscall: "mprotect"
  - id: "{id_b}"
    name: "rule-{id_b}"
    severity: "medium"
    description: "desc"
    conditions:
      syscall: "mmap"
"#
        )
    }

    fn fake_event(event_type: EventType) -> MemoryEvent {
        MemoryEvent {
            timestamp_ns: 1,
            tgid: 7,
            pid: 7,
            uid: 0,
            comm: [0; 16],
            event_type,
            addr: 0x1000,
            len: 4096,
            flags: 0,
            ret: 0,
            execve_cmdline: String::new(),
            openat_path: String::new(),
            memfd_name: String::new(),
        }
    }

    #[test]
    fn initial_load() {
        let path = unique_path("initial");
        write_rule_file(&path, &one_rule_yaml("R1"));
        let watcher = RuleWatcher::new(path.clone()).expect("watcher should initialize");
        assert_eq!(watcher.rules().load().rules.len(), 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn hot_reload_on_file_change() {
        let path = unique_path("reload");
        write_rule_file(&path, &one_rule_yaml("R1"));
        let watcher = RuleWatcher::new(path.clone()).expect("watcher should initialize");
        assert_eq!(watcher.rules().load().rules.len(), 1);

        write_rule_file(&path, &two_rule_yaml("R1", "R2"));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(watcher.rules().load().rules.len(), 2);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn invalid_reload_keeps_old_rules() {
        let path = unique_path("invalid");
        write_rule_file(&path, &one_rule_yaml("R1"));
        let watcher = RuleWatcher::new(path.clone()).expect("watcher should initialize");
        assert_eq!(watcher.rules().load().rules.len(), 1);

        write_rule_file(&path, "invalid: [");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(watcher.rules().load().rules.len(), 1);
        let _ = fs::remove_file(path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn integration_pipeline_hot_reload() {
        let path = unique_path("pipeline");
        let rule_a = r#"
rules:
  - id: "RULE-A"
    name: "A"
    severity: "high"
    description: "desc"
    conditions:
      syscall: "mprotect"
"#;
        write_rule_file(&path, rule_a);

        let alerts = Arc::new(Mutex::new(Vec::<Alert>::new()));
        let sink = Arc::clone(&alerts);
        let callback: AlertCallback = Arc::new(move |alert: Alert| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().expect("alerts mutex poisoned").push(alert);
            }
            .boxed()
        });

        let (raw_tx, raw_rx) = mpsc::channel(8);
        let cfg = PipelineConfig {
            rules_path: Some(path.clone()),
            on_alert: Some(callback),
            reorder_window_ms: 1,
            ..PipelineConfig::default()
        };
        let watcher = RuleWatcher::new(path.clone()).expect("watcher should initialize");
        let mut handle = start_pipeline_from_receiver_for_tests_with_rules(
            raw_rx,
            cfg,
            Arc::new(NoopEnricher),
            watcher.rules(),
        );

        raw_tx
            .send(fake_event(EventType::MprotectWX))
            .await
            .expect("send should succeed");
        let _ = handle.next_event().await.expect("event should arrive");
        wait_for_alert_count_at_least(&alerts, 1, Duration::from_millis(300)).await;
        assert_eq!(alerts.lock().expect("alerts mutex poisoned").len(), 1);

        let rule_b = r#"
rules:
  - id: "RULE-B"
    name: "B"
    severity: "medium"
    description: "desc"
    conditions:
      syscall: "mmap"
"#;
        write_rule_file(&path, rule_b);
        // Touch the file once more after a short delay to make watcher pickup deterministic
        // across different notify backends/edit semantics.
        tokio::time::sleep(Duration::from_millis(60)).await;
        write_rule_file(&path, rule_b);
        tokio::time::sleep(Duration::from_millis(150)).await;
        alerts.lock().expect("alerts mutex poisoned").clear();

        raw_tx
            .send(fake_event(EventType::MprotectWX))
            .await
            .expect("send should succeed");
        let _ = handle.next_event().await.expect("event should arrive");
        tokio::time::sleep(Duration::from_millis(120)).await;
        // No strict assertion here: in-flight events may still be evaluated with old rules.

        raw_tx
            .send(fake_event(EventType::Mmap))
            .await
            .expect("send should succeed");
        let _ = handle.next_event().await.expect("event should arrive");
        wait_for_alert_rule_id(&alerts, "RULE-B", Duration::from_millis(500)).await;
        let rule_b_present = {
            let guard = alerts.lock().expect("alerts mutex poisoned");
            guard.iter().any(|alert| alert.rule_id == "RULE-B")
        };
        assert!(rule_b_present, "expected RULE-B alert after hot-reload");

        handle.shutdown().await;
        let _ = fs::remove_file(path);
    }

    async fn wait_for_alert_count_at_least(
        alerts: &Arc<Mutex<Vec<Alert>>>,
        expected: usize,
        timeout: Duration,
    ) {
        let started = std::time::Instant::now();
        loop {
            if alerts.lock().expect("alerts mutex poisoned").len() >= expected {
                return;
            }
            if started.elapsed() > timeout {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_for_alert_rule_id(
        alerts: &Arc<Mutex<Vec<Alert>>>,
        rule_id: &str,
        timeout: Duration,
    ) {
        let started = std::time::Instant::now();
        loop {
            if alerts
                .lock()
                .expect("alerts mutex poisoned")
                .iter()
                .any(|alert| alert.rule_id == rule_id)
            {
                return;
            }
            if started.elapsed() > timeout {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
