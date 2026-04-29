//! OpenTelemetry OTLP tracing (gRPC).

use std::time::Duration;

use opentelemetry::{
    KeyValue, global,
    global::BoxedSpan,
    trace::{Span, SpanKind, Status, Tracer},
};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    trace::{Sampler, SdkTracerProvider},
};

/// OTLP/gRPC endpoint (default Jaeger all-in-one: `http://localhost:4317`).
#[derive(Debug, Clone)]
pub struct OtelConfig {
    pub endpoint: String,
    pub service_name: String,
    pub sample_ratio: f64,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:4317".to_string(),
            service_name: "mace-ebpf".to_string(),
            sample_ratio: 1.0,
        }
    }
}

/// Holds the SDK tracer provider so shutdown can flush OTLP.
pub struct OtelExporter {
    provider: SdkTracerProvider,
}

impl OtelExporter {
    /// Build OTLP exporter, batch processor, and install as global tracer provider.
    pub fn start(config: OtelConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(config.endpoint.clone())
            .with_timeout(Duration::from_secs(5))
            .build()?;

        let resource = Resource::builder()
            .with_attributes([
                KeyValue::new("service.name", config.service_name.clone()),
                KeyValue::new(
                    "service.version",
                    option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"),
                ),
            ])
            .build();

        let sampler = if config.sample_ratio >= 1.0 {
            Sampler::AlwaysOn
        } else if config.sample_ratio <= 0.0 {
            Sampler::AlwaysOff
        } else {
            Sampler::TraceIdRatioBased(config.sample_ratio)
        };

        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_sampler(sampler)
            .with_resource(resource)
            .build();

        global::set_tracer_provider(provider.clone());

        Ok(Self { provider })
    }

    /// Span for one pipeline event on a partition worker (`event_pipeline`).
    pub fn create_pipeline_span(tgid: u32, syscall_id: u32, worker_id: usize) -> BoxedSpan {
        let tracer = global::tracer("mace-pipeline");
        let mut builder = tracer.span_builder("event_pipeline");
        builder.span_kind = Some(SpanKind::Internal);
        builder.attributes = Some(vec![
            KeyValue::new("tgid", i64::from(tgid)),
            KeyValue::new("syscall_id", i64::from(syscall_id)),
            KeyValue::new("worker_id", i64::try_from(worker_id).unwrap_or(-1)),
        ]);
        tracer.build(builder)
    }

    pub fn record_rule_match(span: &mut BoxedSpan, rule_id: &str, matched: bool) {
        span.set_attribute(KeyValue::new("rule_id", rule_id.to_string()));
        span.set_attribute(KeyValue::new("rule_matched", matched));
        if matched {
            span.set_status(Status::Ok);
        }
    }

    pub fn shutdown(self) {
        let _ = self.provider.shutdown();
    }
}
