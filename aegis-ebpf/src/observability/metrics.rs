//! Metric definitions using the `metrics` facade (no-op unless a recorder is installed).

#[cfg(any(feature = "prometheus", feature = "otel"))]
macro_rules! record_metric {
    (counter: $name:expr) => {
        ::metrics::counter!($name).increment(1);
    };
    (counter: $name:expr, $($labels:tt)+) => {
        ::metrics::counter!($name, $($labels)+).increment(1);
    };
    (gauge: $name:expr, $value:expr) => {
        ::metrics::gauge!($name).set($value as f64);
    };
    (gauge: $name:expr, $value:expr, $($labels:tt)+) => {
        ::metrics::gauge!($name, $($labels)+).set($value as f64);
    };
    (histogram: $name:expr, $value:expr) => {
        ::metrics::histogram!($name).record($value as f64);
    };
    (histogram: $name:expr, $value:expr, $($labels:tt)+) => {
        ::metrics::histogram!($name, $($labels)+).record($value as f64);
    };
}

#[cfg(not(any(feature = "prometheus", feature = "otel")))]
macro_rules! record_metric {
    ($($_tt:tt)*) => {};
}

#[allow(unused_imports)]
pub(crate) use record_metric;

pub const EVENTS_INGESTED_TOTAL: &str = "aegis_events_ingested_total";
pub const EVENTS_DROPPED_TOTAL: &str = "aegis_events_dropped_total";
pub const ALERTS_FIRED_TOTAL: &str = "aegis_alerts_fired_total";
pub const PIPELINE_LATENCY_NS: &str = "aegis_pipeline_latency_ns";
pub const REORDER_BUFFER_SIZE: &str = "aegis_reorder_buffer_size";
pub const WORKER_QUEUE_DEPTH: &str = "aegis_worker_queue_depth";

#[inline]
pub fn record_event_ingested() {
    record_metric!(counter: EVENTS_INGESTED_TOTAL);
}

#[inline]
pub fn record_event_dropped() {
    record_metric!(counter: EVENTS_DROPPED_TOTAL);
}

#[inline]
pub fn record_alert_fired(rule_id: &str) {
    record_metric!(counter: ALERTS_FIRED_TOTAL, "rule_id" => rule_id.to_string());
}

#[inline]
pub fn record_pipeline_latency(latency_ns: u64) {
    record_metric!(histogram: PIPELINE_LATENCY_NS, latency_ns);
}

#[inline]
pub fn update_reorder_buffer_size(size: usize) {
    record_metric!(gauge: REORDER_BUFFER_SIZE, size);
}

#[inline]
pub fn update_worker_queue_depth(worker_id: usize, depth: usize) {
    record_metric!(
        gauge: WORKER_QUEUE_DEPTH,
        depth,
        "worker_id" => worker_id.to_string()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_helpers_compile() {
        record_event_ingested();
        record_event_dropped();
        record_alert_fired("test_rule");
        record_pipeline_latency(1000);
        update_reorder_buffer_size(42);
        update_worker_queue_depth(0, 10);
    }
}
