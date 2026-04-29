//! Staged rule count for the embedded engine (updated when rules are validated/loaded for the next
//! `mace_start_pipeline`, and when the rule watcher hot-reloads). Read via [`staged_rule_count`] and
//! [`mace_engine_staged_rule_count`](crate::ffi::engine::...) without re-parsing YAML from disk.

use std::sync::atomic::{AtomicUsize, Ordering};

static STAGED_RULE_COUNT: AtomicUsize = AtomicUsize::new(0);

#[inline]
pub fn record_staged_rule_count(n: usize) {
    STAGED_RULE_COUNT.store(n, Ordering::Release);
}

#[inline]
pub fn clear_staged_rule_count() {
    STAGED_RULE_COUNT.store(0, Ordering::Release);
}

#[inline]
pub fn staged_rule_count() -> usize {
    STAGED_RULE_COUNT.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_count_roundtrip() {
        clear_staged_rule_count();
        assert_eq!(staged_rule_count(), 0);
        record_staged_rule_count(42);
        assert_eq!(staged_rule_count(), 42);
        clear_staged_rule_count();
    }
}
