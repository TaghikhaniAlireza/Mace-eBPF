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

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    Api, Client,
    api::ListParams,
};

use crate::{ContextEnricher, PodMetadata};

pub struct KubernetesEnricher {
    client: Client,
}

impl KubernetesEnricher {
    pub async fn new() -> Option<Self> {
        let client = Client::try_default().await.ok()?;
        Some(Self { client })
    }
}

#[async_trait]
impl ContextEnricher for KubernetesEnricher {
    async fn enrich(&self, cgroup_id: u64) -> Option<PodMetadata> {
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

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use crate::{ContextEnricher, PodMetadata};

    use super::KubernetesEnricher;

    fn assert_context_enricher<T: ContextEnricher>() {}

    #[test]
    fn kubernetes_enricher_implements_context_enricher() {
        assert_context_enricher::<KubernetesEnricher>();
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
