use std::sync::Arc;

use aegis_ebpf_common::EventType;
use futures::future::BoxFuture;
use serde::Serialize;

use crate::{
    EnrichedEvent,
    rules::{Rule, Severity},
};

#[derive(Debug, Clone)]
pub struct Alert {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub timestamp_ns: u64,
    pub tgid: u32,
    pub pid: u32,
    pub comm: String,
    pub syscall_id: i64,
    pub matched_flags: u64,
    pub namespace: Option<String>,
    pub pod_name: Option<String>,
}

pub type AlertCallback = Arc<dyn Fn(Alert) -> BoxFuture<'static, ()> + Send + Sync>;

/// JSON line emitted once per event after rule evaluation (see [`crate::pipeline::StandardizedEvent`]).
pub type StandardizedEventCallback = Arc<dyn Fn(String) -> BoxFuture<'static, ()> + Send + Sync>;

/// JSON-serializable view of a syscall observation plus matched rule ids.
#[derive(Serialize, Debug, Clone, Eq, PartialEq)]
pub struct StandardizedEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub process_name: String,
    pub syscall_name: String,
    pub arguments: Vec<String>,
    pub matched_rules: Vec<String>,
}

fn syscall_name_for_event(event_type: EventType) -> &'static str {
    match event_type {
        EventType::Mmap => "mmap",
        EventType::MprotectWX => "mprotect",
        EventType::MemfdCreate => "memfd_create",
        EventType::Ptrace => "ptrace",
    }
}

fn format_syscall_arguments(ev: &aegis_ebpf_common::MemoryEvent) -> Vec<String> {
    vec![
        format!("addr=0x{:x}", ev.addr),
        format!("len=0x{:x}", ev.len),
        format!("flags=0x{:x}", ev.flags),
    ]
}

fn comm_string(comm: &[u8; aegis_ebpf_common::TASK_COMM_LEN]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

/// Build [`StandardizedEvent`] from an enriched event and matched rule ids (stable JSON output).
pub fn build_standardized_event(
    ev: &EnrichedEvent,
    matched_rule_ids: &[String],
) -> StandardizedEvent {
    StandardizedEvent {
        timestamp: ev.inner.timestamp_ns,
        pid: ev.inner.pid,
        process_name: comm_string(&ev.inner.comm),
        syscall_name: syscall_name_for_event(ev.inner.event_type).to_string(),
        arguments: format_syscall_arguments(&ev.inner),
        matched_rules: matched_rule_ids.to_vec(),
    }
}

/// Convenience: build from matched [`Rule`] references.
pub fn build_standardized_event_from_rules(
    ev: &EnrichedEvent,
    matched: &[&Rule],
) -> StandardizedEvent {
    let ids: Vec<String> = matched.iter().map(|r| r.id.clone()).collect();
    build_standardized_event(ev, &ids)
}

impl Alert {
    pub fn from_rule_and_event(rule: &Rule, event: &EnrichedEvent) -> Self {
        Self {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            severity: rule.severity,
            timestamp_ns: event.inner.timestamp_ns,
            tgid: event.inner.tgid,
            pid: event.inner.pid,
            comm: String::from_utf8_lossy(&event.inner.comm)
                .trim_matches('\0')
                .to_string(),
            syscall_id: event.inner.event_type as i64,
            matched_flags: event.inner.flags,
            namespace: event.metadata.as_ref().map(|meta| meta.namespace.clone()),
            pod_name: event.metadata.as_ref().map(|meta| meta.pod_name.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    use aegis_ebpf_common::{EventType, MemoryEvent};
    use futures::FutureExt;
    use tokio::sync::mpsc;

    use crate::{
        NoopEnricher, PipelineConfig,
        alert::{Alert, AlertCallback},
        pipeline::start_pipeline_from_receiver_for_tests,
        rules::Severity,
    };

    fn unique_yaml_path(prefix: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!("aegis-alert-test-{prefix}-{unique}.yaml"))
    }

    fn fake_event(event_type: EventType, flags: u64) -> MemoryEvent {
        MemoryEvent {
            timestamp_ns: 7,
            tgid: 42,
            pid: 24,
            comm: *b"unit-test\0\0\0\0\0\0\0",
            event_type,
            addr: 0x1000,
            len: 4096,
            flags,
            ret: 0,
        }
    }

    fn callback_sink() -> (Arc<Mutex<Vec<Alert>>>, AlertCallback) {
        let alerts = Arc::new(Mutex::new(Vec::<Alert>::new()));
        let sink = Arc::clone(&alerts);
        let callback: AlertCallback = Arc::new(move |alert: Alert| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().expect("alert sink mutex poisoned").push(alert);
            }
            .boxed()
        });
        (alerts, callback)
    }

    async fn run_single_event_through_pipeline(
        yaml: &str,
        event: MemoryEvent,
        on_alert: Option<AlertCallback>,
    ) {
        let path = unique_yaml_path("single");
        fs::write(&path, yaml).expect("rule file should be written");

        let (raw_tx, raw_rx) = mpsc::channel(8);
        let cfg = PipelineConfig {
            rules_path: Some(path.clone()),
            on_alert,
            reorder_window_ms: 1,
            ..PipelineConfig::default()
        };
        let mut handle =
            start_pipeline_from_receiver_for_tests(raw_rx, cfg, Arc::new(NoopEnricher))
                .expect("pipeline should start");

        raw_tx.send(event).await.expect("send should succeed");
        let _ = handle.next_event().await.expect("event should arrive");
        handle.shutdown().await;
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn callback_called_on_rule_match() {
        let yaml = r#"
rules:
  - id: "MEM-A1"
    name: "match"
    severity: "high"
    description: "desc"
    conditions:
      syscall: "mprotect"
      flags_contains: ["PROT_EXEC"]
"#;
        let (alerts, callback) = callback_sink();
        run_single_event_through_pipeline(
            yaml,
            fake_event(EventType::MprotectWX, crate::rules::PROT_EXEC),
            Some(callback),
        )
        .await;

        let alerts = alerts.lock().expect("alert sink mutex poisoned");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "MEM-A1");
    }

    #[tokio::test]
    async fn callback_not_called_when_no_match() {
        let yaml = r#"
rules:
  - id: "MEM-A2"
    name: "match"
    severity: "medium"
    description: "desc"
    conditions:
      syscall: "mprotect"
      flags_contains: ["PROT_EXEC"]
"#;
        let (alerts, callback) = callback_sink();
        run_single_event_through_pipeline(yaml, fake_event(EventType::Mmap, 0), Some(callback))
            .await;

        let alerts = alerts.lock().expect("alert sink mutex poisoned");
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn callback_called_once_per_matched_rule() {
        let yaml = r#"
rules:
  - id: "MEM-A3-1"
    name: "match-one"
    severity: "high"
    description: "desc"
    conditions:
      syscall: "mprotect"
  - id: "MEM-A3-2"
    name: "match-two"
    severity: "critical"
    description: "desc"
    conditions:
      flags_contains: ["PROT_EXEC"]
"#;
        let (alerts, callback) = callback_sink();
        run_single_event_through_pipeline(
            yaml,
            fake_event(EventType::MprotectWX, crate::rules::PROT_EXEC),
            Some(callback),
        )
        .await;

        let alerts = alerts.lock().expect("alert sink mutex poisoned");
        assert_eq!(alerts.len(), 2);
        let ids: Vec<&str> = alerts.iter().map(|alert| alert.rule_id.as_str()).collect();
        assert!(ids.contains(&"MEM-A3-1"));
        assert!(ids.contains(&"MEM-A3-2"));
    }

    #[tokio::test]
    async fn no_callback_pipeline_still_works() {
        let yaml = r#"
rules:
  - id: "MEM-A4"
    name: "match"
    severity: "low"
    description: "desc"
    conditions:
      syscall: "mmap"
"#;
        run_single_event_through_pipeline(yaml, fake_event(EventType::Mmap, 0), None).await;
    }

    #[tokio::test]
    async fn alert_fields_populated_correctly() {
        let yaml = r#"
rules:
  - id: "MEM-A5"
    name: "field-check"
    severity: "critical"
    description: "desc"
    conditions:
      syscall: "mmap"
"#;
        let (alerts, callback) = callback_sink();
        run_single_event_through_pipeline(yaml, fake_event(EventType::Mmap, 0x123), Some(callback))
            .await;

        let alerts = alerts.lock().expect("alert sink mutex poisoned");
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.tgid, 42);
        assert_eq!(alert.rule_id, "MEM-A5");
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.pid, 24);
        assert_eq!(alert.matched_flags, 0x123);
    }
}
