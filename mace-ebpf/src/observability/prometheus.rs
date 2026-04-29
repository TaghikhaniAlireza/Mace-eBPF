//! Prometheus HTTP scrape endpoint via `metrics-exporter-prometheus`.

use std::net::SocketAddr;

use metrics_exporter_prometheus::PrometheusBuilder;

/// HTTP listener address for the `/metrics` scrape endpoint.
#[derive(Debug, Clone)]
pub struct PrometheusConfig {
    pub listen_addr: SocketAddr,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9090".parse().expect("static address is valid"),
        }
    }
}

/// Installs the global metrics recorder and spawns the HTTP listener.
///
/// Returns an error if a recorder is already installed or the HTTP server fails to start.
pub fn start_prometheus_http(
    config: PrometheusConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    PrometheusBuilder::new()
        .with_http_listener(config.listen_addr)
        .install()?;
    Ok(())
}
