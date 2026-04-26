use std::path::PathBuf;

use crate::{AlertCallback, StandardizedEventCallback};

#[derive(Clone)]
pub struct PipelineConfig {
    pub channel_buffer_size: usize,
    pub reorder_window_ms: u64,
    pub reorder_heap_capacity: usize,
    pub partition_count: usize,
    pub state_window_ms: u64,
    pub rules_path: Option<PathBuf>,
    pub on_alert: Option<AlertCallback>,
    /// Called after rule evaluation with `serde_json` of [`crate::StandardizedEvent`] (empty `matched_rules` if none).
    pub on_standardized_event: Option<StandardizedEventCallback>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            channel_buffer_size: 4096,
            reorder_window_ms: 50,
            reorder_heap_capacity: 1024,
            partition_count: 4,
            state_window_ms: 60_000,
            rules_path: None,
            on_alert: None,
            on_standardized_event: None,
        }
    }
}
