use async_trait::async_trait;

#[cfg(feature = "kubernetes")]
pub mod kubernetes;
#[cfg(feature = "kubernetes")]
pub use kubernetes::KubernetesEnricher;

pub struct PodMetadata {
    pub pod_name: String,
    pub namespace: String,
    pub node_name: String,
}

#[async_trait]
pub trait ContextEnricher: Send + Sync {
    async fn enrich(&self, cgroup_id: u64) -> Option<PodMetadata>;
}

pub struct NoopEnricher;

#[async_trait]
impl ContextEnricher for NoopEnricher {
    async fn enrich(&self, _cgroup_id: u64) -> Option<PodMetadata> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{ContextEnricher, NoopEnricher};

    #[tokio::test]
    async fn noop_enricher_returns_none() {
        let enricher = NoopEnricher;
        assert!(enricher.enrich(0).await.is_none());
    }
}
