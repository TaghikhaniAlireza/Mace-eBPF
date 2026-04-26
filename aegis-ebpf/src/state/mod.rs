use std::collections::{HashMap, HashSet};

use aegis_ebpf_common::EventType;

use crate::pipeline::EnrichedEvent;

const NS_PER_MS: u64 = 1_000_000;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessState {
    pub tgid: u32,
    pub first_seen: u64,
    pub last_seen: u64,
    pub event_count: usize,
    pub syscall_counts: HashMap<i64, usize>,
    pub total_rwx_bytes: u64,
    pub mprotect_exec_count: usize,
    pub unique_addresses: HashSet<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct StateTracker {
    states: HashMap<u32, ProcessState>,
    window_ms: u64,
}

impl StateTracker {
    pub fn new(window_ms: u64) -> Self {
        Self {
            states: HashMap::new(),
            window_ms,
        }
    }

    pub fn update(&mut self, event: &EnrichedEvent) {
        let tgid = event.inner.tgid;
        let timestamp_ns = event.inner.timestamp_ns;

        let state = self.states.entry(tgid).or_insert_with(|| ProcessState {
            tgid,
            first_seen: timestamp_ns,
            last_seen: timestamp_ns,
            event_count: 0,
            syscall_counts: HashMap::new(),
            total_rwx_bytes: 0,
            mprotect_exec_count: 0,
            unique_addresses: HashSet::new(),
        });

        state.last_seen = timestamp_ns;
        state.event_count += 1;

        let syscall_id = event.inner.event_type as i64;
        *state.syscall_counts.entry(syscall_id).or_insert(0) += 1;

        if is_rwx_mapping(event.inner.flags) {
            state.total_rwx_bytes = state.total_rwx_bytes.saturating_add(event.inner.len);
        }
        if matches!(event.inner.event_type, EventType::MprotectWX)
            && (event.inner.flags & PROT_EXEC) != 0
        {
            state.mprotect_exec_count += 1;
        }

        state.unique_addresses.insert(event.inner.addr);
    }

    pub fn get(&self, tgid: u32) -> Option<&ProcessState> {
        self.states.get(&tgid)
    }

    pub fn expire_old(&mut self, now_ns: u64) {
        let ttl_ns = self.window_ms.saturating_mul(NS_PER_MS);
        self.states
            .retain(|_, state| now_ns.saturating_sub(state.last_seen) <= ttl_ns);
    }
}

fn is_rwx_mapping(flags: u64) -> bool {
    (flags & PROT_EXEC) != 0 && (flags & PROT_WRITE) != 0
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use aegis_ebpf_common::{EventType, MemoryEvent};
    use arc_swap::ArcSwap;
    use futures::FutureExt;
    use tokio::sync::mpsc;

    use super::StateTracker;
    use crate::{
        Alert, AlertCallback, EnrichedEvent, NoopEnricher, PipelineConfig,
        pipeline::start_pipeline_from_receiver_for_tests_with_rules,
        rules::{Conditions, Rule, Severity, StatefulConditions, loader::RuleSet},
    };

    fn fake_enriched_event(
        timestamp_ns: u64,
        tgid: u32,
        event_type: EventType,
        flags: u64,
        len: u64,
        addr: u64,
    ) -> EnrichedEvent {
        EnrichedEvent {
            inner: MemoryEvent {
                timestamp_ns,
                tgid,
                pid: tgid,
                comm: [0; 16],
                event_type,
                addr,
                len,
                flags,
                ret: 0,
            },
            metadata: None,
        }
    }

    #[test]
    fn state_creation_and_update() {
        let mut tracker = StateTracker::new(1_000);
        tracker.update(&fake_enriched_event(
            10,
            42,
            EventType::Mmap,
            0,
            4096,
            0x1000,
        ));
        tracker.update(&fake_enriched_event(
            20,
            42,
            EventType::MprotectWX,
            super::PROT_EXEC,
            4096,
            0x2000,
        ));
        tracker.update(&fake_enriched_event(
            30,
            42,
            EventType::Ptrace,
            0,
            0,
            0x3000,
        ));

        let state = tracker.get(42).expect("state should exist");
        assert_eq!(state.event_count, 3);
        assert_eq!(state.last_seen, 30);
    }

    #[test]
    fn syscall_counting() {
        let mut tracker = StateTracker::new(1_000);
        tracker.update(&fake_enriched_event(1, 7, EventType::MprotectWX, 0, 1, 0x1));
        tracker.update(&fake_enriched_event(2, 7, EventType::MprotectWX, 0, 1, 0x2));
        tracker.update(&fake_enriched_event(
            3,
            7,
            EventType::MemfdCreate,
            0,
            1,
            0x3,
        ));

        let state = tracker.get(7).expect("state should exist");
        assert_eq!(state.syscall_counts[&(EventType::MprotectWX as i64)], 2);
        assert_eq!(state.syscall_counts[&(EventType::MemfdCreate as i64)], 1);
    }

    #[test]
    fn expiration() {
        let mut tracker = StateTracker::new(100);
        tracker.update(&fake_enriched_event(
            0,
            100,
            EventType::Mmap,
            0,
            4096,
            0x1000,
        ));
        tracker.expire_old(200_000_000);
        assert!(tracker.get(100).is_none());
    }

    #[test]
    fn stateful_rule_matching() {
        let mut tracker = StateTracker::new(10_000);
        let set = RuleSet {
            rules: vec![Rule {
                id: "STATE-1".to_string(),
                name: "mprotect threshold".to_string(),
                severity: Severity::High,
                description: "desc".to_string(),
                conditions: Conditions {
                    syscall: Some("mprotect".to_string()),
                    flags_contains: vec!["PROT_EXEC".to_string()],
                    ..Default::default()
                },
                stateful: Some(StatefulConditions {
                    min_event_count: None,
                    min_mprotect_exec_count: Some(3),
                    min_rwx_bytes: None,
                }),
                cgroup_regex: None,
                process_name_regex: None,
                pathname_regex: None,
            }],
        };

        for n in 1..=3 {
            let event = fake_enriched_event(
                n,
                77,
                EventType::MprotectWX,
                super::PROT_EXEC,
                4096,
                0x1000 + n,
            );
            tracker.update(&event);
            tracker.expire_old(event.inner.timestamp_ns);
            let state = tracker.get(77);
            let matched = set.evaluate(&event, state);
            if n < 3 {
                assert!(matched.is_empty());
            } else {
                assert_eq!(matched.len(), 1);
                assert_eq!(matched[0].id, "STATE-1");
            }
        }
    }

    #[test]
    fn stateful_rule_non_matching_event() {
        let mut tracker = StateTracker::new(10_000);
        let set = RuleSet {
            rules: vec![Rule {
                id: "STATE-2".to_string(),
                name: "min events".to_string(),
                severity: Severity::Medium,
                description: "desc".to_string(),
                conditions: Conditions::default(),
                stateful: Some(StatefulConditions {
                    min_event_count: Some(5),
                    min_mprotect_exec_count: None,
                    min_rwx_bytes: None,
                }),
                cgroup_regex: None,
                process_name_regex: None,
                pathname_regex: None,
            }],
        };

        for ts in 1..=4 {
            let event = fake_enriched_event(ts, 100, EventType::Mmap, 0, 4096, 0x2000 + ts);
            tracker.update(&event);
        }

        let other = fake_enriched_event(5, 200, EventType::Mmap, 0, 4096, 0x9999);
        tracker.update(&other);
        let state = tracker.get(200);
        let matches = set.evaluate(&other, state);
        assert!(matches.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn integration_stateful_threshold_triggers_callback() {
        let rule_set = RuleSet {
            rules: vec![Rule {
                id: "STATE-PIPE-1".to_string(),
                name: "3x mprotect exec".to_string(),
                severity: Severity::High,
                description: "desc".to_string(),
                conditions: Conditions {
                    syscall: Some("mprotect".to_string()),
                    flags_contains: vec!["PROT_EXEC".to_string()],
                    ..Default::default()
                },
                stateful: Some(StatefulConditions {
                    min_event_count: None,
                    min_mprotect_exec_count: Some(3),
                    min_rwx_bytes: None,
                }),
                cgroup_regex: None,
                process_name_regex: None,
                pathname_regex: None,
            }],
        };

        let alerts = Arc::new(Mutex::new(Vec::<Alert>::new()));
        let sink = Arc::clone(&alerts);
        let callback: AlertCallback = Arc::new(move |alert: Alert| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().expect("alerts mutex poisoned").push(alert);
            }
            .boxed()
        });

        let (raw_tx, raw_rx) = mpsc::channel(16);
        let config = PipelineConfig {
            reorder_window_ms: 1,
            on_alert: Some(callback),
            state_window_ms: 60_000,
            ..PipelineConfig::default()
        };
        let rules = Arc::new(ArcSwap::from_pointee(rule_set));
        let mut handle = start_pipeline_from_receiver_for_tests_with_rules(
            raw_rx,
            config,
            Arc::new(NoopEnricher),
            rules,
        );

        for ts in 1..=3 {
            raw_tx
                .send(MemoryEvent {
                    timestamp_ns: ts,
                    tgid: 500,
                    pid: 500,
                    comm: [0; 16],
                    event_type: EventType::MprotectWX,
                    addr: 0x1000 + ts,
                    len: 4096,
                    flags: super::PROT_EXEC,
                    ret: 0,
                })
                .await
                .expect("send should succeed");
            let _ = handle.next_event().await.expect("event should arrive");
        }

        wait_for_alerts(&alerts, 1).await;
        let (len, first_rule) = {
            let guard = alerts.lock().expect("alerts mutex poisoned");
            (guard.len(), guard.first().map(|a| a.rule_id.clone()))
        };
        assert_eq!(len, 1);
        assert_eq!(first_rule.as_deref(), Some("STATE-PIPE-1"));

        handle.shutdown().await;
    }

    async fn wait_for_alerts(alerts: &Arc<Mutex<Vec<Alert>>>, expected: usize) {
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_millis(300) {
            if alerts.lock().expect("alerts mutex poisoned").len() >= expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
