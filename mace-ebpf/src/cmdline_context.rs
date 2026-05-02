//! Per-TGID last execve argv snapshot for attributing later syscalls (mmap, openat, …).

use std::collections::HashMap;

use mace_ebpf_common::{EventType, MemoryEvent};

use crate::proc_cmdline::read_proc_cmdline_joined;

/// Retain execve cmdline text per thread group for `ttl_ns` (wall time via event timestamps).
#[derive(Debug)]
pub struct CmdlineContextTracker {
    map: HashMap<u32, (String, u64)>,
    ttl_ns: u64,
}

impl CmdlineContextTracker {
    pub fn new(ttl_ns: u64) -> Self {
        Self {
            map: HashMap::new(),
            ttl_ns: ttl_ns.max(1),
        }
    }

    /// Update state from `event` and return the **context string** to attach to this observation
    /// (usually the latest non-empty execve line for this TGID, including the current execve).
    pub fn observe(&mut self, event: &MemoryEvent) -> Option<String> {
        let tgid = event.tgid;
        let ts = event.timestamp_ns;

        self.prune(ts);

        if matches!(event.event_type, EventType::Execve | EventType::Execveat) {
            if !event.execve_cmdline.is_empty() {
                self.map.insert(tgid, (event.execve_cmdline.clone(), ts));
                return Some(event.execve_cmdline.clone());
            }
            // eBPF argv empty (e.g. `execve_no_user_argv` build): seed context from `/proc` so
            // rules and JSON `cmdline` match the same haystack as `rule_cmdline_haystack`.
            if let Some(fallback) = read_proc_cmdline_joined(tgid) {
                self.map.insert(tgid, (fallback.clone(), ts));
                return Some(fallback);
            }
        }

        self.map
            .get(&tgid)
            .filter(|(_, last_ts)| ts.saturating_sub(*last_ts) <= self.ttl_ns)
            .map(|(s, _)| s.clone())
    }

    fn prune(&mut self, now_ns: u64) {
        self.map
            .retain(|_, (_, last)| now_ns.saturating_sub(*last) <= self.ttl_ns);
    }
}
