pub mod loader;

use std::{error::Error, fmt};

use aegis_ebpf_common::EventType;
use regex::Regex;
use serde::Deserialize;

use crate::pipeline::EnrichedEvent;

pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;
pub const MAP_ANONYMOUS: u64 = 0x20;

#[derive(Clone, Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
    pub conditions: Conditions,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Conditions {
    pub syscall: Option<String>,
    #[serde(default)]
    pub flags_contains: Vec<String>,
    #[serde(default)]
    pub flags_excludes: Vec<String>,
    pub min_size: Option<u64>,
    pub cgroup_pattern: Option<String>,
}

#[derive(Debug)]
pub enum RuleError {
    IoError(std::io::Error),
    ParseError(serde_yaml::Error),
    InvalidCondition(String),
}

impl Rule {
    pub fn matches(&self, event: &EnrichedEvent) -> bool {
        if let Some(expected) = self.conditions.syscall.as_deref()
            && !expected.eq_ignore_ascii_case(event_syscall_name(event))
        {
            return false;
        }

        let flags = event.inner.flags;
        if !self
            .conditions
            .flags_contains
            .iter()
            .all(|name| is_flag_present(flags, name))
        {
            return false;
        }

        if self
            .conditions
            .flags_excludes
            .iter()
            .any(|name| is_flag_present(flags, name))
        {
            return false;
        }

        if let Some(min_size) = self.conditions.min_size
            && event.inner.len < min_size
        {
            return false;
        }

        if let Some(pattern) = self.conditions.cgroup_pattern.as_deref() {
            let Some(path) = event_cgroup_path(event) else {
                return false;
            };
            let Ok(regex) = Regex::new(pattern) else {
                return false;
            };
            if !regex.is_match(&path) {
                return false;
            }
        }

        true
    }
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoError(err) => write!(f, "rule I/O error: {err}"),
            Self::ParseError(err) => write!(f, "rule parse error: {err}"),
            Self::InvalidCondition(msg) => write!(f, "invalid rule condition: {msg}"),
        }
    }
}

impl Error for RuleError {}

impl From<std::io::Error> for RuleError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

impl From<serde_yaml::Error> for RuleError {
    fn from(value: serde_yaml::Error) -> Self {
        Self::ParseError(value)
    }
}

pub(crate) fn validate_rule(rule: &Rule) -> Result<(), RuleError> {
    if rule.id.trim().is_empty() {
        return Err(RuleError::InvalidCondition("rule id cannot be empty".into()));
    }
    if rule.name.trim().is_empty() {
        return Err(RuleError::InvalidCondition("rule name cannot be empty".into()));
    }

    if let Some(syscall) = rule.conditions.syscall.as_deref()
        && !is_supported_syscall(syscall)
    {
        return Err(RuleError::InvalidCondition(format!(
            "unsupported syscall condition: {syscall}"
        )));
    }

    for flag in &rule.conditions.flags_contains {
        validate_flag_name(flag)?;
    }
    for flag in &rule.conditions.flags_excludes {
        validate_flag_name(flag)?;
    }
    if let Some(pattern) = rule.conditions.cgroup_pattern.as_deref() {
        Regex::new(pattern).map_err(|err| {
            RuleError::InvalidCondition(format!("invalid cgroup_pattern regex '{pattern}': {err}"))
        })?;
    }
    Ok(())
}

fn validate_flag_name(name: &str) -> Result<(), RuleError> {
    if flag_bit(name).is_none() && !name.eq_ignore_ascii_case("MAP_FILE") {
        return Err(RuleError::InvalidCondition(format!(
            "unsupported flag name: {name}"
        )));
    }
    Ok(())
}

fn event_syscall_name(event: &EnrichedEvent) -> &'static str {
    match event.inner.event_type {
        EventType::Mmap => "mmap",
        EventType::MprotectWX => "mprotect",
        EventType::MemfdCreate => "memfd_create",
        EventType::Ptrace => "ptrace",
    }
}

fn is_supported_syscall(syscall: &str) -> bool {
    matches!(
        syscall.to_ascii_lowercase().as_str(),
        "mmap" | "mprotect" | "memfd_create" | "ptrace"
    )
}

fn event_cgroup_path(event: &EnrichedEvent) -> Option<String> {
    event
        .metadata
        .as_ref()
        .map(|meta| format!("/kubepods/{}/{}", meta.namespace, meta.pod_name))
}

fn is_flag_present(flags: u64, name: &str) -> bool {
    if name.eq_ignore_ascii_case("MAP_FILE") {
        // MAP_FILE is represented as "not MAP_ANONYMOUS" in Linux.
        return (flags & MAP_ANONYMOUS) == 0;
    }

    let Some(bit) = flag_bit(name) else {
        return false;
    };
    (flags & bit) != 0
}

fn flag_bit(name: &str) -> Option<u64> {
    match name.to_ascii_uppercase().as_str() {
        "PROT_READ" => Some(PROT_READ),
        "PROT_WRITE" => Some(PROT_WRITE),
        "PROT_EXEC" => Some(PROT_EXEC),
        "MAP_ANONYMOUS" => Some(MAP_ANONYMOUS),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    use aegis_ebpf_common::{EventType, MemoryEvent};
    use tokio::sync::mpsc;
    use tracing_subscriber::fmt::MakeWriter;

    use super::{loader::RuleSet, *};
    use crate::{pipeline, NoopEnricher, PipelineConfig};

    fn fake_enriched_event(event_type: EventType, flags: u64, len: u64) -> crate::EnrichedEvent {
        crate::EnrichedEvent {
            inner: MemoryEvent {
                timestamp_ns: 1,
                tgid: 42,
                pid: 42,
                comm: [0; 16],
                event_type,
                addr: 0x1000,
                len,
                flags,
                ret: 0,
            },
            metadata: None,
        }
    }

    #[test]
    fn rule_parsing_from_yaml() {
        let yaml = r#"
rules:
  - id: "MEM-001"
    name: "Example"
    severity: "high"
    description: "desc"
    conditions:
      syscall: "mprotect"
"#;
        let set = RuleSet::from_yaml_str(yaml).expect("yaml should parse");
        assert_eq!(set.rules.len(), 1);
        let rule = &set.rules[0];
        assert_eq!(rule.id, "MEM-001");
        assert_eq!(rule.name, "Example");
        assert_eq!(rule.severity, Severity::High);
    }

    #[test]
    fn syscall_exact_match() {
        let rule = Rule {
            id: "R1".into(),
            name: "syscall".into(),
            severity: Severity::Low,
            description: "desc".into(),
            conditions: Conditions {
                syscall: Some("mprotect".into()),
                ..Default::default()
            },
        };
        let mprotect_event = fake_enriched_event(EventType::MprotectWX, 0, 4096);
        let mmap_event = fake_enriched_event(EventType::Mmap, 0, 4096);
        assert!(rule.matches(&mprotect_event));
        assert!(!rule.matches(&mmap_event));
    }

    #[test]
    fn flags_contains_logic() {
        let rule = Rule {
            id: "R2".into(),
            name: "flags_contains".into(),
            severity: Severity::Medium,
            description: "desc".into(),
            conditions: Conditions {
                flags_contains: vec!["PROT_EXEC".into(), "PROT_WRITE".into()],
                ..Default::default()
            },
        };

        let match_event = fake_enriched_event(
            EventType::MprotectWX,
            PROT_EXEC | PROT_WRITE | PROT_READ,
            4096,
        );
        let missing_event = fake_enriched_event(EventType::MprotectWX, PROT_EXEC, 4096);
        assert!(rule.matches(&match_event));
        assert!(!rule.matches(&missing_event));
    }

    #[test]
    fn flags_excludes_logic() {
        let rule = Rule {
            id: "R3".into(),
            name: "flags_excludes".into(),
            severity: Severity::Medium,
            description: "desc".into(),
            conditions: Conditions {
                flags_excludes: vec!["MAP_FILE".into()],
                ..Default::default()
            },
        };

        let anonymous = fake_enriched_event(EventType::Mmap, MAP_ANONYMOUS | PROT_EXEC, 4096);
        let file_backed = fake_enriched_event(EventType::Mmap, PROT_EXEC, 4096);
        assert!(rule.matches(&anonymous));
        assert!(!rule.matches(&file_backed));
    }

    #[test]
    fn multiple_rules_evaluation() {
        let set = RuleSet {
            rules: vec![
                Rule {
                    id: "R1".into(),
                    name: "mmap".into(),
                    severity: Severity::Low,
                    description: "desc".into(),
                    conditions: Conditions {
                        syscall: Some("mmap".into()),
                        ..Default::default()
                    },
                },
                Rule {
                    id: "R2".into(),
                    name: "mprotect".into(),
                    severity: Severity::Low,
                    description: "desc".into(),
                    conditions: Conditions {
                        syscall: Some("mprotect".into()),
                        ..Default::default()
                    },
                },
                Rule {
                    id: "R3".into(),
                    name: "contains exec".into(),
                    severity: Severity::Low,
                    description: "desc".into(),
                    conditions: Conditions {
                        flags_contains: vec!["PROT_EXEC".into()],
                        ..Default::default()
                    },
                },
            ],
        };

        let event = fake_enriched_event(EventType::Mmap, PROT_EXEC, 4096);
        let matches = set.evaluate(&event);
        let ids: Vec<&str> = matches.iter().map(|rule| rule.id.as_str()).collect();
        assert_eq!(ids, vec!["R1", "R3"]);
    }

    #[test]
    fn empty_rule_set() {
        let set = RuleSet::default();
        let event = fake_enriched_event(EventType::Mmap, PROT_EXEC, 4096);
        assert!(set.evaluate(&event).is_empty());
    }

    #[derive(Clone)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for LogBuffer {
        type Writer = LogBufferWriter;

        fn make_writer(&'a self) -> Self::Writer {
            LogBufferWriter(Arc::clone(&self.0))
        }
    }

    struct LogBufferWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for LogBufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("log buffer mutex poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn integration_rule_match_logs_and_passthroughs() {
        let yaml = r#"
rules:
  - id: "MEM-T1"
    name: "Executable mprotect"
    severity: "high"
    description: "desc"
    conditions:
      syscall: "mprotect"
      flags_contains: ["PROT_EXEC"]
"#;
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("aegis-rule-test-{unique}.yaml"));
        fs::write(&path, yaml).expect("rule file should be written");

        let logs = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(LogBuffer(Arc::clone(&logs)))
            .with_max_level(tracing::Level::WARN)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (raw_tx, raw_rx) = mpsc::channel(8);
        let config = PipelineConfig {
            reorder_window_ms: 1,
            rules_path: Some(path.clone()),
            ..PipelineConfig::default()
        };
        let mut handle = pipeline::start_pipeline_from_receiver_for_tests(
            raw_rx,
            config,
            Arc::new(NoopEnricher),
        )
        .expect("pipeline should start");

        raw_tx
            .send(MemoryEvent {
                timestamp_ns: 1,
                tgid: 77,
                pid: 77,
                comm: [0; 16],
                event_type: EventType::MprotectWX,
                addr: 0x1000,
                len: 4096,
                flags: PROT_EXEC,
                ret: 0,
            })
            .await
            .expect("send should succeed");

        let event = handle.next_event().await.expect("event should arrive");
        assert_eq!(event.inner.tgid, 77);

        handle.shutdown().await;
        let _ = fs::remove_file(path);

        let logs = String::from_utf8(
            logs.lock()
                .expect("log buffer mutex poisoned")
                .clone(),
        )
        .expect("logs should be valid utf-8");
        assert!(
            logs.contains("Rule match detected"),
            "expected rule-match warning in logs"
        );
        assert!(logs.contains("MEM-T1"), "expected matched rule id in logs");
    }
}
