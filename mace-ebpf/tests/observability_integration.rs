#![cfg(feature = "prometheus")]

use std::{thread, time::Duration};

use mace_ebpf::{
    ffi::{arena::EventArena, types::RawMemoryEvent},
    observability::{
        metrics::EVENTS_INGESTED_TOTAL,
        prometheus::{PrometheusConfig, start_prometheus_http},
    },
};

#[test]
fn prometheus_scrape_contains_arena_metrics() {
    let addr: std::net::SocketAddr = "127.0.0.1:19092".parse().expect("valid address");
    start_prometheus_http(PrometheusConfig { listen_addr: addr }).expect("prometheus http");

    let arena = EventArena::new(64);
    for i in 0..10 {
        let ev = RawMemoryEvent {
            timestamp_ns: i * 1000,
            tgid: 1234,
            pid: 5678,
            syscall_id: 1,
            _pad0: 0,
            args: [0x7fff_0000_0000 + i, 4096, 0, 0, 0, 0],
            cgroup_id: 1234,
            comm: [0; 16],
            uid: 0,
            _pad_uid: 0,
            syscall_ret: 0,
            execve_cmdline: [0; mace_ebpf::ffi::types::RAW_EXECVE_CMDLINE_LEN],
        };
        arena.try_push(ev).expect("push");
    }

    thread::sleep(Duration::from_millis(300));

    let body = reqwest::blocking::get(format!("http://{addr}/metrics"))
        .expect("GET /metrics")
        .text()
        .expect("body");

    assert!(
        body.contains(EVENTS_INGESTED_TOTAL),
        "expected metric name in scrape output"
    );

    let mut total: Option<u64> = None;
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with(EVENTS_INGESTED_TOTAL) && !line.contains("_bucket") {
            let mut parts = line.split_whitespace();
            let _name = parts.next();
            if let Some(v) = parts.next()
                && let Ok(n) = v.parse::<u64>()
            {
                total = Some(n);
                break;
            }
        }
    }

    assert!(
        total.unwrap_or(0) >= 10,
        "expected ingest counter >= 10, got {:?}",
        total
    );
}
