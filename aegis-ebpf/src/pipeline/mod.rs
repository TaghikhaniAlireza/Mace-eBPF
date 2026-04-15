use std::{
    cmp::{Ordering, Reverse},
    collections::BinaryHeap,
    sync::Arc,
    time::{Duration, Instant},
};

use aegis_ebpf_common::MemoryEvent;
use log::warn;
use tokio::sync::{mpsc, oneshot};

use crate::{start_sensor, ContextEnricher, PodMetadata, SensorConfig};

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
    assert!(
        pipeline_config.partition_count.is_power_of_two(),
        "partition_count must be a power of 2"
    );

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
    assert!(
        pipeline_config.partition_count.is_power_of_two(),
        "partition_count must be a power of 2"
    );

    let channel_buffer_size = pipeline_config.channel_buffer_size.max(1);
    let (enriched_tx, enriched_rx) = mpsc::channel(channel_buffer_size);
    let (ordered_tx, ordered_rx) = mpsc::channel(channel_buffer_size);
    let (final_tx, final_rx) = mpsc::channel(channel_buffer_size);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    tokio::spawn(run_enrichment_worker(raw_rx, enriched_tx, enricher, shutdown_rx));
    tokio::spawn(run_reorder_task(
        enriched_rx,
        ordered_tx,
        pipeline_config.reorder_window_ms,
        pipeline_config.reorder_heap_capacity.max(1),
    ));
    tokio::spawn(run_partition_router(
        ordered_rx,
        final_tx,
        pipeline_config.partition_count,
        channel_buffer_size,
    ));

    PipelineHandle {
        ordered_rx: final_rx,
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

fn route_partition_index(tgid: u32, partition_count: usize) -> usize {
    (tgid as usize) % partition_count.max(1)
}

async fn run_partition_worker(
    mut rx: mpsc::Receiver<EnrichedEvent>,
    merge_tx: mpsc::Sender<EnrichedEvent>,
) {
    while let Some(event) = rx.recv().await {
        if merge_tx.send(event).await.is_err() {
            return;
        }
    }
}

async fn run_partition_router(
    mut ordered_rx: mpsc::Receiver<EnrichedEvent>,
    final_tx: mpsc::Sender<EnrichedEvent>,
    partition_count: usize,
    partition_buffer_size: usize,
) {
    let mut partition_txs = Vec::with_capacity(partition_count);
    let mut worker_handles = Vec::with_capacity(partition_count);

    for _ in 0..partition_count {
        let (partition_tx, partition_rx) = mpsc::channel(partition_buffer_size.max(1));
        partition_txs.push(partition_tx);
        worker_handles.push(tokio::spawn(run_partition_worker(
            partition_rx,
            final_tx.clone(),
        )));
    }
    drop(final_tx);

    while let Some(event) = ordered_rx.recv().await {
        let idx = route_partition_index(event.inner.tgid, partition_count);
        if partition_txs[idx].send(event).await.is_err() {
            warn!("partition worker channel closed for index={idx}");
        }
    }

    drop(partition_txs);
    for handle in worker_handles {
        let _ = handle.await;
    }
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
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use aegis_ebpf_common::{EventType, MemoryEvent};
    use async_trait::async_trait;
    use tokio::sync::mpsc;

    use super::{config, route_partition_index, spawn_pipeline_from_raw, EnrichedEvent, PipelineHandle};
    use crate::{ContextEnricher, NoopEnricher, PodMetadata};

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

    fn spawn_test_pipeline_with_config(
        enricher: Arc<dyn ContextEnricher>,
        cfg: config::PipelineConfig,
    ) -> (mpsc::Sender<MemoryEvent>, PipelineHandle) {
        let (raw_tx, raw_rx) = mpsc::channel(128);
        let handle = spawn_pipeline_from_raw(raw_rx, cfg, enricher);
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
    async fn in_order_passthrough() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        for ts in [100, 200, 300, 400, 500] {
            raw_tx
                .send(fake_event(ts, 7, 7))
                .await
                .expect("send should succeed");
        }

        tokio::time::sleep(Duration::from_millis(
            config::PipelineConfig::default().reorder_window_ms + 10,
        ))
        .await;

        let mut out = Vec::new();
        for _ in 0..5 {
            let event = handle.next_event().await.expect("event should arrive");
            out.push(event.inner.timestamp_ns);
        }
        assert_eq!(out, vec![100, 200, 300, 400, 500]);
    }

    #[tokio::test]
    async fn out_of_order_reordering() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        for ts in [300, 100, 500, 200, 400] {
            raw_tx
                .send(fake_event(ts, 7, 7))
                .await
                .expect("send should succeed");
        }

        tokio::time::sleep(Duration::from_millis(
            config::PipelineConfig::default().reorder_window_ms + 10,
        ))
        .await;

        let mut out = Vec::new();
        for _ in 0..5 {
            let event = handle.next_event().await.expect("event should arrive");
            out.push(event.inner.timestamp_ns);
        }
        assert_eq!(out, vec![100, 200, 300, 400, 500]);
    }

    #[tokio::test]
    async fn capacity_flush_no_sleep_needed() {
        let config = config::PipelineConfig {
            reorder_heap_capacity: 4,
            ..config::PipelineConfig::default()
        };
        let (raw_tx, mut handle) = spawn_test_pipeline_with_config(Arc::new(NoopEnricher), config);

        for ts in [40, 10, 30, 20] {
            raw_tx
                .send(fake_event(ts, 11, 11))
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
    async fn shutdown_flushes_remaining_events() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        for ts in [30, 10, 20] {
            raw_tx
                .send(fake_event(ts, 12, 12))
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

    #[test]
    fn same_tgid_maps_to_same_partition() {
        let partition_count = 4usize;
        let expected = 42usize % partition_count;
        for _ in 0..100 {
            assert_eq!(route_partition_index(42, partition_count), expected);
        }
    }

    #[test]
    fn different_tgids_distribute_across_partitions() {
        let partition_count = 4usize;
        let tgids = [0u32, 1, 2, 3, 4, 5, 6, 7];
        let mapped: Vec<usize> = tgids
            .iter()
            .map(|tgid| route_partition_index(*tgid, partition_count))
            .collect();
        assert_eq!(mapped, vec![0, 1, 2, 3, 0, 1, 2, 3]);
        assert_eq!(mapped[0], mapped[4]);
    }

    #[tokio::test]
    async fn end_to_end_ordering_within_tgid() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        for ts in [50, 10, 90, 30, 70, 20, 60, 40, 80, 100] {
            raw_tx
                .send(fake_event(ts, 99, 99))
                .await
                .expect("send should succeed");
        }

        tokio::time::sleep(Duration::from_millis(
            config::PipelineConfig::default().reorder_window_ms + 10,
        ))
        .await;

        let mut out = Vec::new();
        for _ in 0..10 {
            let event = handle.next_event().await.expect("event should arrive");
            if event.inner.tgid == 99 {
                out.push(event.inner.timestamp_ns);
            }
        }

        assert_eq!(out.len(), 10);
        assert!(out.windows(2).all(|w| w[0] <= w[1]));
    }

    #[tokio::test]
    async fn events_from_different_tgids_all_arrive() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        for (ts, tgid) in [(100u64, 1u32), (200, 2), (300, 3), (400, 4)] {
            raw_tx
                .send(fake_event(ts, tgid, tgid))
                .await
                .expect("send should succeed");
        }

        tokio::time::sleep(Duration::from_millis(
            config::PipelineConfig::default().reorder_window_ms + 10,
        ))
        .await;

        let mut counts = HashMap::new();
        for _ in 0..4 {
            let event = handle.next_event().await.expect("event should arrive");
            *counts.entry(event.inner.tgid).or_insert(0usize) += 1;
        }
        assert_eq!(counts.get(&1), Some(&1));
        assert_eq!(counts.get(&2), Some(&1));
        assert_eq!(counts.get(&3), Some(&1));
        assert_eq!(counts.get(&4), Some(&1));
    }

    #[tokio::test]
    async fn shutdown_with_events_inflight_across_partitions() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        for (ts, tgid) in [
            (110u64, 1u32),
            (120, 1),
            (210, 2),
            (220, 2),
            (310, 3),
            (320, 3),
            (410, 4),
            (420, 4),
        ] {
            raw_tx
                .send(fake_event(ts, tgid, tgid))
                .await
                .expect("send should succeed");
        }

        let (_dummy_tx, dummy_rx) = mpsc::channel(1);
        let mut rx = std::mem::replace(&mut handle.ordered_rx, dummy_rx);
        handle.shutdown().await;

        let mut counts: HashMap<u32, usize> = HashMap::new();
        while let Ok(Some(event)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            *counts.entry(event.inner.tgid).or_insert(0usize) += 1;
            if counts.values().sum::<usize>() == 8 {
                break;
            }
        }

        assert_eq!(counts.values().sum::<usize>(), 8);
        assert_eq!(counts.get(&1), Some(&2));
        assert_eq!(counts.get(&2), Some(&2));
        assert_eq!(counts.get(&3), Some(&2));
        assert_eq!(counts.get(&4), Some(&2));
    }
}
