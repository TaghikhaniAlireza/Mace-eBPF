//! Criterion benchmarks for rule evaluation and state tracker hot paths.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use mace_ebpf::{EnrichedEvent, rules::loader::RuleSet, state::StateTracker};
use mace_ebpf_common::{EventType, MemoryEvent};

fn yaml_rules(n: usize) -> String {
    let mut s = String::from("rules:\n");
    for i in 0..n {
        s.push_str(&format!(
            r#"  - id: "RULE_{i}"
    name: "bench"
    severity: "medium"
    description: "d"
    conditions:
      syscall: "mmap"

"#
        ));
    }
    s
}

fn sample_memory_event(seed: u32, event_type: EventType) -> MemoryEvent {
    MemoryEvent {
        timestamp_ns: u64::from(seed),
        tgid: seed,
        pid: seed,
        uid: 1000,
        comm: [b't'; 16],
        event_type,
        addr: 0x7fff_0000_0000 + u64::from(seed),
        len: 4096,
        flags: 0x7,
        ret: 0,
        execve_cmdline: String::new(),
        openat_path: String::new(),
        memfd_name: String::new(),
    }
}

fn sample_enriched(inner: MemoryEvent) -> EnrichedEvent {
    EnrichedEvent {
        inner,
        metadata: None,
        cmdline_context: Some("/bin/demo arg".to_string()),
        username: Some("user".to_string()),
    }
}

fn rule_set_evaluate(c: &mut Criterion) {
    let yaml = yaml_rules(256);
    let rules = RuleSet::from_yaml_str(&yaml).expect("valid bench yaml");
    let ev = sample_enriched(sample_memory_event(1, EventType::Mmap));
    let state = StateTracker::new(60_000);

    let mut group = c.benchmark_group("rule_engine");
    group.sample_size(30);
    group.bench_function("evaluate_256_rules_mmap", |b| {
        b.iter(|| {
            black_box(rules.evaluate(black_box(&ev), black_box(state.get(ev.inner.tgid))));
        });
    });
    group.finish();
}

fn state_tracker_update(c: &mut Criterion) {
    let mut tracker = StateTracker::new(60_000);
    let mut seq = 0u64;
    let mut group = c.benchmark_group("state_tracker");
    group.sample_size(30);
    group.bench_function("update_same_tgid", |b| {
        b.iter(|| {
            seq = seq.wrapping_add(1);
            let ev = sample_enriched(sample_memory_event(42, EventType::Mmap));
            let mut inner = ev.inner.clone();
            inner.timestamp_ns = seq;
            let ev = sample_enriched(inner);
            tracker.update(black_box(&ev));
            black_box(tracker.get(42));
        });
    });
    group.finish();
}

criterion_group!(benches, rule_set_evaluate, state_tracker_update);
criterion_main!(benches);
