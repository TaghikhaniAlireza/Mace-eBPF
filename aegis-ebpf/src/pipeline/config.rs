use std::path::PathBuf;

use crate::AlertCallback;

#[derive(Clone, Debug)]
pub struct PipelineConfig {
    pub channel_buffer_size: usize,
    pub reorder_window_ms: u64,
    pub reorder_heap_capacity: usize,
    pub partition_count: usize,
    pub rules_path: Option<PathBuf>,
    pub on_alert: Option<AlertCallback>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            channel_buffer_size: 4096,
            reorder_window_ms: 50,
            reorder_heap_capacity: 1024,
            partition_count: 4,
            rules_path: None,
            on_alert: None,
        }
    }
}
