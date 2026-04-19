# Aegis eBPF observability stack

Docker Compose stack for **Prometheus**, **Grafana**, and **Jaeger** (OTLP).

## Prerequisites

1. Build the SDK and run your process with observability enabled, exposing Prometheus on the host:

   ```bash
   cargo build -p aegis-ebpf --features observability
   ```

   Call `aegis_ebpf::observability::prometheus::start_prometheus_http(...)` from your binary (default scrape URL: `http://127.0.0.1:9090/metrics`).

2. Start the stack from this directory:

   ```bash
   docker compose up -d
   ```

## Endpoints

| Service    | URL                         |
|-----------|------------------------------|
| Grafana   | http://localhost:3000 (admin/admin) |
| Prometheus| http://localhost:9091        |
| Jaeger UI | http://localhost:16686       |
| OTLP gRPC | localhost:4317             |

Prometheus scrapes the host SDK at `host.docker.internal:9090` (Linux uses `extra_hosts: host-gateway`).

## OTLP traces

With `--features otel`, initialize via `observability::otel::OtelExporter::start(OtelConfig { endpoint: "http://localhost:4317".into(), .. })` before processing events.

## Metrics names

- `aegis_events_ingested_total` — arena pushes + pipeline raw ingests
- `aegis_events_dropped_total` — arena full
- `aegis_alerts_fired_total{rule_id}` — FFI alert channel enqueue
- `aegis_pipeline_latency_ns` — partition worker evaluation latency
- `aegis_reorder_buffer_size` — reorder heap depth
- `aegis_worker_queue_depth{worker_id}` — per-partition queue backlog
