use std::{
    cmp::{Ordering, Reverse},
    collections::BinaryHeap,
    sync::Arc,
    time::{Duration, Instant},
};

use aegis_ebpf_common::MemoryEvent;
use log::warn;
use tokio::sync::{mpsc, oneshot};

use crate::{ContextEnricher, PodMetadata, SensorConfig, start_sensor};

pub mod config;

const HEAP_CAPACITY_LIMIT: usize = 1024;

#[derive(Clone, Debug)]
pub struct EnrichedEvent {
    pub inner: MemoryEvent,
    pub metadata: Option<PodMetadata>,
}

impl Ord for EnrichedEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.timestamp_ns.cmp(&other.inner.timestamp_ns)
    }
}

impl PartialOrd for EnrichedEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for EnrichedEvent {
    fn eq(&self, other: &Self) -> bool {
        self.inner.timestamp_ns == other.inner.timestamp_ns
    }
}

impl Eq for EnrichedEvent {}

pub struct PipelineHandle {
    ordered_rx: mpsc::Receiver<EnrichedEvent>,
    shutdown_tx: oneshot::Sender<()>,
}

pub async fn start_pipeline(
    sensor_config: SensorConfig,
    pipeline_config: config::PipelineConfig,
    enricher: Arc<dyn ContextEnricher>,
) -> anyhow::Result<PipelineHandle> {
    let raw_rx = start_sensor(sensor_config).await?;
    Ok(spawn_pipeline_from_raw(
        raw_rx,
        pipeline_config,
        enricher,
    ))
}

fn spawn_pipeline_from_raw(
    raw_rx: mpsc::Receiver<MemoryEvent>,
    pipeline_config: config::PipelineConfig,
    enricher: Arc<dyn ContextEnricher>,
) -> PipelineHandle {
    let channel_buffer_size = pipeline_config.channel_buffer_size.max(1);
    let (enriched_tx, enriched_rx) = mpsc::channel(channel_buffer_size);
    let (ordered_tx, ordered_rx) = mpsc::channel(channel_buffer_size);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(run_enrichment_worker(raw_rx, enriched_tx, enricher, shutdown_rx));
    tokio::spawn(run_reorder_task(
        enriched_rx,
        ordered_tx,
        pipeline_config.reorder_window_ms,
        pipeline_config.reorder_heap_capacity.max(1),
    ));

    PipelineHandle {
        ordered_rx,
        shutdown_tx,
    }
}

async fn run_enrichment_worker(
    mut raw_rx: mpsc::Receiver<MemoryEvent>,
    enriched_tx: mpsc::Sender<EnrichedEvent>,
    enricher: Arc<dyn ContextEnricher>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let mut shutdown_requested = false;
    loop {
        if shutdown_requested {
            match raw_rx.try_recv() {
                Ok(event) => {
                    if send_enriched_event(event, &enriched_tx, enricher.as_ref())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => return,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return,
            }
            continue;
        }

        tokio::select! {
            maybe_event = raw_rx.recv() => {
                let Some(event) = maybe_event else { return };
                if send_enriched_event(event, &enriched_tx, enricher.as_ref()).await.is_err() {
                    return;
                }
            }
            _ = &mut shutdown_rx => {
                shutdown_requested = true;
            }
        }
    }
}

async fn send_enriched_event(
    event: MemoryEvent,
    enriched_tx: &mpsc::Sender<EnrichedEvent>,
    enricher: &dyn ContextEnricher,
) -> Result<(), ()> {
    // cgroup_id is not yet present in MemoryEvent in this workspace,
    // so use tgid as the current enrichment key placeholder.
    let cgroup_id = u64::from(event.tgid);
    let metadata = match enricher.enrich(cgroup_id).await {
        Some(metadata) => Some(metadata),
        None => {
            warn!("context enrichment returned no metadata for cgroup_id={cgroup_id}");
            None
        }
    };

    let enriched = EnrichedEvent {
        inner: event,
        metadata,
    };
    enriched_tx.send(enriched).await.map_err(|_| ())
}

async fn run_reorder_task(
    mut enriched_rx: mpsc::Receiver<EnrichedEvent>,
    ordered_tx: mpsc::Sender<EnrichedEvent>,
    reorder_window_ms: u64,
    reorder_heap_capacity: usize,
) {
    let mut heap: BinaryHeap<Reverse<EnrichedEvent>> = BinaryHeap::new();
    let mut deadline: Option<Instant> = None;
    let effective_capacity = reorder_heap_capacity.min(HEAP_CAPACITY_LIMIT).max(1);

    loop {
        if let Some(deadline_at) = deadline {
            let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline_at));
            tokio::pin!(sleep);

            tokio::select! {
                maybe_event = enriched_rx.recv() => {
                    match maybe_event {
                        Some(event) => {
                            heap.push(Reverse(event));
                            if heap.len() >= effective_capacity {
                                if flush_heap(&mut heap, &ordered_tx).await.is_err() {
                                    return;
                                }
                                deadline = None;
                            }
                        }
                        None => {
                            let _ = flush_heap(&mut heap, &ordered_tx).await;
                            return;
                        }
                    }
                }
                _ = &mut sleep => {
                    if flush_heap(&mut heap, &ordered_tx).await.is_err() {
                        return;
                    }
                    deadline = None;
                }
            }
        } else {
            match enriched_rx.recv().await {
                Some(event) => {
                    heap.push(Reverse(event));
                    deadline = Some(Instant::now() + Duration::from_millis(reorder_window_ms));
                    if heap.len() >= effective_capacity {
                        if flush_heap(&mut heap, &ordered_tx).await.is_err() {
                            return;
                        }
                        deadline = None;
                    }
                }
                None => {
                    let _ = flush_heap(&mut heap, &ordered_tx).await;
                    return;
                }
            }
        }
    }
}

async fn flush_heap(
    heap: &mut BinaryHeap<Reverse<EnrichedEvent>>,
    ordered_tx: &mpsc::Sender<EnrichedEvent>,
) -> Result<(), ()> {
    while let Some(Reverse(event)) = heap.pop() {
        if ordered_tx.send(event).await.is_err() {
            return Err(());
        }
    }
    Ok(())
}

impl PipelineHandle {
    pub async fn next_event(&mut self) -> Option<EnrichedEvent> {
        self.ordered_rx.recv().await
    }

    pub async fn shutdown(self) {
        drop(self.shutdown_tx);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use tokio::sync::mpsc;

    use super::{EnrichedEvent, PipelineHandle, config, spawn_pipeline_from_raw};
    use crate::{ContextEnricher, NoopEnricher, PodMetadata};
    use aegis_ebpf_common::{EventType, MemoryEvent};

    fn fake_event(timestamp_ns: u64, tgid: u32, pid: u32) -> MemoryEvent {
        MemoryEvent {
            timestamp_ns,
            tgid,
            pid,
            comm: [0; 16],
            event_type: EventType::Mmap,
            addr: 0x1000,
            len: 4096,
            flags: 0,
            ret: 0,
        }
    }

    fn spawn_test_pipeline(
        enricher: Arc<dyn ContextEnricher>,
    ) -> (mpsc::Sender<MemoryEvent>, PipelineHandle) {
        let (raw_tx, raw_rx) = mpsc::channel(128);
        let handle = spawn_pipeline_from_raw(raw_rx, config::PipelineConfig::default(), enricher);
        (raw_tx, handle)
    }

    #[tokio::test]
    async fn happy_path_noop_enricher_preserves_fields() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        let input = fake_event(123, 456, 789);
        raw_tx.send(input).await.expect("send should succeed");

        let output = handle.next_event().await.expect("event should arrive");
        assert!(output.metadata.is_none());
        assert_eq!(output.inner.timestamp_ns, 123);
        assert_eq!(output.inner.tgid, 456);
    }

    struct AlwaysMetadataEnricher;

    #[async_trait]
    impl ContextEnricher for AlwaysMetadataEnricher {
        async fn enrich(&self, _cgroup_id: u64) -> Option<PodMetadata> {
            Some(PodMetadata {
                pod_name: "test-pod".to_string(),
                namespace: "default".to_string(),
                node_name: "node-1".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn enrichment_populates_metadata() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(AlwaysMetadataEnricher));
        raw_tx
            .send(fake_event(1, 2, 3))
            .await
            .expect("send should succeed");

        let output = handle.next_event().await.expect("event should arrive");
        let metadata = output.metadata.expect("metadata should be present");
        assert_eq!(metadata.pod_name, "test-pod");
        assert_eq!(metadata.namespace, "default");
        assert_eq!(metadata.node_name, "node-1");
    }

    struct AlwaysNoneEnricher;

    #[async_trait]
    impl ContextEnricher for AlwaysNoneEnricher {
        async fn enrich(&self, _cgroup_id: u64) -> Option<PodMetadata> {
            None
        }
    }

    #[tokio::test]
    async fn enrichment_failure_is_non_fatal() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(AlwaysNoneEnricher));
        for idx in 0..3 {
            raw_tx
                .send(fake_event(100 + idx, 200 + idx as u32, 300 + idx as u32))
                .await
                .expect("send should succeed");
        }

        let mut received = Vec::<EnrichedEvent>::new();
        for _ in 0..3 {
            received.push(handle.next_event().await.expect("event should arrive"));
        }
        assert_eq!(received.len(), 3);
        assert!(received.iter().all(|event| event.metadata.is_none()));

        let pending = tokio::time::timeout(Duration::from_millis(50), handle.next_event()).await;
        assert!(pending.is_err(), "channel should stay open without immediate close");
    }

    #[tokio::test]
    async fn shutdown_drains_inflight_events() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        for idx in 0..50u64 {
            raw_tx
                .send(fake_event(1_000 + idx, 42, 42))
                .await
                .expect("send should succeed");
        }

        // Extract the ordered receiver so we can continue draining after shutdown consumes the handle.
        let (_dummy_tx, dummy_rx) = mpsc::channel(1);
        let mut rx = std::mem::replace(&mut handle.ordered_rx, dummy_rx);
        handle.shutdown().await;

        let mut count = 0usize;
        while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            count += 1;
        }

        assert_eq!(count, 50);
    }

    #[tokio::test]
    async fn reorder_in_order_passthrough() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        for ts in [100, 200, 300, 400, 500] {
            raw_tx
                .send(fake_event(ts, ts as u32, ts as u32))
                .await
                .expect("send should succeed");
        }

        tokio::time::sleep(Duration::from_millis(config::PipelineConfig::default().reorder_window_ms + 10)).await;

        let mut out = Vec::new();
        for _ in 0..5 {
            let event = handle.next_event().await.expect("event should arrive");
            out.push(event.inner.timestamp_ns);
        }
        assert_eq!(out, vec![100, 200, 300, 400, 500]);
    }

    #[tokio::test]
    async fn reorder_out_of_order_events() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        for ts in [300, 100, 500, 200, 400] {
            raw_tx
                .send(fake_event(ts, ts as u32, ts as u32))
                .await
                .expect("send should succeed");
        }

        tokio::time::sleep(Duration::from_millis(config::PipelineConfig::default().reorder_window_ms + 10)).await;

        let mut out = Vec::new();
        for _ in 0..5 {
            let event = handle.next_event().await.expect("event should arrive");
            out.push(event.inner.timestamp_ns);
        }
        assert_eq!(out, vec![100, 200, 300, 400, 500]);
    }

    #[tokio::test]
    async fn reorder_capacity_flush_without_timer() {
        let (raw_tx, raw_rx) = mpsc::channel(128);
        let config = config::PipelineConfig {
            reorder_heap_capacity: 4,
            ..config::PipelineConfig::default()
        };
        let mut handle = spawn_pipeline_from_raw(raw_rx, config, Arc::new(NoopEnricher));

        for ts in [40, 10, 30, 20] {
            raw_tx
                .send(fake_event(ts, ts as u32, ts as u32))
                .await
                .expect("send should succeed");
        }

        let mut out = Vec::new();
        for _ in 0..4 {
            let event = handle.next_event().await.expect("event should arrive");
            out.push(event.inner.timestamp_ns);
        }
        assert_eq!(out, vec![10, 20, 30, 40]);
    }

    #[tokio::test]
    async fn reorder_shutdown_flushes_remaining_events() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        for ts in [30, 10, 20] {
            raw_tx
                .send(fake_event(ts, ts as u32, ts as u32))
                .await
                .expect("send should succeed");
        }

        let (_dummy_tx, dummy_rx) = mpsc::channel(1);
        let mut rx = std::mem::replace(&mut handle.ordered_rx, dummy_rx);
        handle.shutdown().await;

        let mut out = Vec::new();
        while let Ok(Some(event)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            out.push(event.inner.timestamp_ns);
            if out.len() == 3 {
                break;
            }
        }

        assert_eq!(out, vec![10, 20, 30]);
    }
}
