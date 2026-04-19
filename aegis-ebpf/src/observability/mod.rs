//! Optional Prometheus metrics and OpenTelemetry tracing.

pub mod metrics;

#[cfg(feature = "prometheus")]
pub mod prometheus;

#[cfg(feature = "otel")]
pub mod otel;
