#![cfg(feature = "kubernetes")]

/*
Manual testing in a real Kubernetes environment:
1) Configure Kubernetes auth:
   - Use local kubeconfig: export KUBECONFIG=/path/to/kubeconfig
   - Or run in-cluster where ServiceAccount credentials are mounted.
2) Build and run the sensor with Kubernetes support:
   - cargo run --features kubernetes --release
3) Trigger a memory event in a pod and verify enrichment output includes pod metadata:
   - Expected enrichment contains pod name, namespace, and node name.
   - Example expected shape: Some(PodMetadata { pod_name: "...", namespace: "...", node_name: "..." })
*/

use std::{future::Future, time::Duration};

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client, api::ListParams};
use moka::sync::Cache;

use crate::{ContextEnricher, PodMetadata};

const CACHE_MAX_CAPACITY: u64 = 10_000;
const CACHE_TTL_SECONDS: u64 = 60;

pub struct KubernetesEnricher {
    client: Client,
    cache: Cache<u64, PodMetadata>,
}

async fn enrich_with_cache<F, Fut>(
    cache: &Cache<u64, PodMetadata>,
    cgroup_id: u64,
    lookup: F,
) -> Option<PodMetadata>
where
    F: FnOnce(u64) -> Fut,
    Fut: Future<Output = Option<PodMetadata>>,
{
    if let Some(metadata) = cache.get(&cgroup_id) {
        return Some(metadata);
    }

    let metadata = lookup(cgroup_id).await?;
    cache.insert(cgroup_id, metadata.clone());
    Some(metadata)
}

impl KubernetesEnricher {
    pub async fn new() -> Option<Self> {
        let client = Client::try_default().await.ok()?;
        let cache = Cache::builder()
            .max_capacity(CACHE_MAX_CAPACITY)
            .time_to_live(Duration::from_secs(CACHE_TTL_SECONDS))
            .build();
        Some(Self { client, cache })
    }

    async fn lookup_pod_metadata(&self, cgroup_id: u64) -> Option<PodMetadata> {
        let pods: Api<Pod> = Api::all(self.client.clone());
        let pod_list = pods.list(&ListParams::default()).await.ok()?;
        let cgroup_hex = format!("{cgroup_id:x}");

        for pod in pod_list.items {
            let matches = pod
                .status
                .as_ref()
                .and_then(|status| status.container_statuses.as_ref())
                .into_iter()
                .flatten()
                .filter_map(|container| container.container_id.as_deref())
                .any(|container_id| container_id.contains(&cgroup_hex));

            if !matches {
                continue;
            }

            return Some(PodMetadata {
                pod_name: pod.metadata.name.unwrap_or_default(),
                namespace: pod.metadata.namespace.unwrap_or_default(),
                node_name: pod
                    .spec
                    .as_ref()
                    .and_then(|spec| spec.node_name.clone())
                    .unwrap_or_default(),
            });
        }

        None
    }
}

#[async_trait]
impl ContextEnricher for KubernetesEnricher {
    async fn enrich(&self, cgroup_id: u64) -> Option<PodMetadata> {
        enrich_with_cache(&self.cache, cgroup_id, |id| self.lookup_pod_metadata(id)).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use moka::sync::Cache;

    use super::{KubernetesEnricher, enrich_with_cache};
    use crate::{ContextEnricher, PodMetadata};

    fn assert_context_enricher<T: ContextEnricher>() {}

    #[test]
    fn kubernetes_enricher_implements_context_enricher() {
        assert_context_enricher::<KubernetesEnricher>();
    }

    #[tokio::test]
    async fn cache_miss_triggers_lookup_and_populates_cache() {
        let cache = Cache::new(100);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_lookup = Arc::clone(&calls);
        let expected = PodMetadata {
            pod_name: "miss-pod".to_string(),
            namespace: "default".to_string(),
            node_name: "node-a".to_string(),
        };
        let expected_for_lookup = expected.clone();
        let enriched = enrich_with_cache(&cache, 42, move |_| {
            let calls = Arc::clone(&calls_for_lookup);
            let expected = expected_for_lookup.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Some(expected)
            }
        })
        .await;

        assert_eq!(enriched, Some(expected.clone()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache.get(&42), Some(expected));
    }

    #[tokio::test]
    async fn cache_hit_returns_without_requerying() {
        let cache = Cache::new(100);
        let expected = PodMetadata {
            pod_name: "hit-pod".to_string(),
            namespace: "kube-system".to_string(),
            node_name: "node-b".to_string(),
        };
        cache.insert(42, expected.clone());

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_lookup = Arc::clone(&calls);
        let enriched = enrich_with_cache(&cache, 42, move |_| {
            let calls = Arc::clone(&calls_for_lookup);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                None
            }
        })
        .await;

        assert_eq!(enriched, Some(expected));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    struct MockEnricher;

    #[async_trait]
    impl ContextEnricher for MockEnricher {
        async fn enrich(&self, cgroup_id: u64) -> Option<PodMetadata> {
            if cgroup_id == 42 {
                return Some(PodMetadata {
                    pod_name: "demo-pod".to_string(),
                    namespace: "default".to_string(),
                    node_name: "node-a".to_string(),
                });
            }
            None
        }
    }

    #[tokio::test]
    async fn mock_enricher_returns_expected_values() {
        let enricher = MockEnricher;
        let enriched = enricher.enrich(42).await;
        assert!(enriched.is_some());
        let metadata = enriched.expect("metadata should be present for cgroup id 42");
        assert_eq!(metadata.pod_name, "demo-pod");
        assert_eq!(metadata.namespace, "default");
        assert_eq!(metadata.node_name, "node-a");

        assert!(enricher.enrich(99).await.is_none());
    }
}
