use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use super::types::RawMemoryEvent;
use crate::observability::metrics::{record_event_dropped, record_event_ingested};

#[derive(Debug)]
pub struct EventArena {
    buffer: Box<[RawMemoryEvent]>,
    capacity: usize,
    write_index: AtomicUsize,
    read_index: AtomicUsize,
}

impl EventArena {
    /// Create a new arena with `capacity` slots.
    /// Each slot holds one RawMemoryEvent.
    pub fn new(capacity: usize) -> Arc<Self> {
        assert!(
            capacity > 0 && capacity.is_power_of_two(),
            "capacity must be a power of two"
        );

        let buffer = vec![
            RawMemoryEvent {
                timestamp_ns: 0,
                tgid: 0,
                pid: 0,
                syscall_id: 0,
                _pad0: 0,
                args: [0; 6],
                cgroup_id: 0,
                comm: [0; 16],
            };
            capacity
        ]
        .into_boxed_slice();

        Arc::new(Self {
            buffer,
            capacity,
            write_index: AtomicUsize::new(0),
            read_index: AtomicUsize::new(0),
        })
    }

    /// Try to write an event into the next available slot.
    pub fn try_push(&self, event: RawMemoryEvent) -> Result<usize, ArenaError> {
        let write = self.write_index.load(Ordering::Acquire);
        let read = self.read_index.load(Ordering::Acquire);

        let next_write = (write + 1) % self.capacity;
        if next_write == read {
            record_event_dropped();
            return Err(ArenaError::Full);
        }

        // SAFETY: `write` is always within bounds because it is maintained modulo
        // `capacity`, and we only write when the ring is not full (`next_write != read`),
        // which guarantees this slot is not currently owned by the consumer.
        unsafe {
            let slot = self.buffer.as_ptr().add(write) as *mut RawMemoryEvent;
            std::ptr::write(slot, event);
        }

        self.write_index.store(next_write, Ordering::Release);
        record_event_ingested();
        Ok(write)
    }

    /// Try to read the next event from the buffer.
    pub fn try_pop(&self) -> Option<RawMemoryEvent> {
        let read = self.read_index.load(Ordering::Acquire);
        let write = self.write_index.load(Ordering::Acquire);

        if read == write {
            return None;
        }

        // SAFETY: `read` is always within bounds because it is maintained modulo
        // `capacity`, and `read != write` guarantees this slot contains a produced event.
        let event = unsafe {
            let slot = self.buffer.as_ptr().add(read);
            std::ptr::read(slot)
        };

        let next_read = (read + 1) % self.capacity;
        self.read_index.store(next_read, Ordering::Release);
        Some(event)
    }

    /// Returns the number of events currently in the buffer.
    pub fn len(&self) -> usize {
        let write = self.write_index.load(Ordering::Acquire);
        let read = self.read_index.load(Ordering::Acquire);

        if write >= read {
            write - read
        } else {
            self.capacity - read + write
        }
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the total capacity of the buffer.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

// SAFETY: all shared mutable state is coordinated via atomic indices; event
// slots contain `RawMemoryEvent` (plain Copy data, no interior pointers).
unsafe impl Send for EventArena {}
// SAFETY: concurrent access follows SPSC index discipline with atomics and does
// not expose unsynchronized mutable references.
unsafe impl Sync for EventArena {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArenaError {
    Full,
}

impl std::fmt::Display for ArenaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArenaError::Full => write!(f, "arena buffer is full"),
        }
    }
}

impl std::error::Error for ArenaError {}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::*;

    fn event_with_tgid(tgid: u32) -> RawMemoryEvent {
        RawMemoryEvent {
            timestamp_ns: u64::from(tgid),
            tgid,
            pid: tgid,
            syscall_id: 1,
            _pad0: 0,
            args: [u64::from(tgid); 6],
            cgroup_id: u64::from(tgid),
            comm: [0; 16],
        }
    }

    #[test]
    fn test_arena_new() {
        let arena = EventArena::new(16);
        assert_eq!(arena.capacity(), 16);
        assert!(arena.is_empty());
        assert_eq!(arena.len(), 0);
    }

    #[test]
    fn test_arena_push_pop_single() {
        let arena = EventArena::new(4);
        let event = event_with_tgid(1234);

        let slot = arena.try_push(event).expect("push should succeed");
        assert_eq!(slot, 0);
        assert_eq!(arena.len(), 1);

        let popped = arena.try_pop().expect("pop should return event");
        assert_eq!(popped.tgid, 1234);
        assert!(arena.is_empty());
    }

    #[test]
    fn test_arena_push_until_full() {
        let arena = EventArena::new(4);

        assert!(arena.try_push(event_with_tgid(1)).is_ok());
        assert!(arena.try_push(event_with_tgid(2)).is_ok());
        assert!(arena.try_push(event_with_tgid(3)).is_ok());

        let err = arena
            .try_push(event_with_tgid(4))
            .expect_err("fourth push should hit full condition");
        assert_eq!(err, ArenaError::Full);
        assert_eq!(arena.len(), 3);
    }

    #[test]
    fn test_arena_pop_empty() {
        let arena = EventArena::new(4);
        assert_eq!(arena.try_pop(), None);
    }

    #[test]
    fn test_arena_wraparound() {
        let arena = EventArena::new(4);

        arena
            .try_push(event_with_tgid(100))
            .expect("push should succeed");
        arena
            .try_push(event_with_tgid(200))
            .expect("push should succeed");

        assert_eq!(arena.try_pop().expect("event should exist").tgid, 100);
        assert_eq!(arena.try_pop().expect("event should exist").tgid, 200);

        arena
            .try_push(event_with_tgid(300))
            .expect("push should succeed");
        arena
            .try_push(event_with_tgid(400))
            .expect("push should succeed");

        assert_eq!(arena.try_pop().expect("event should exist").tgid, 300);
        assert_eq!(arena.try_pop().expect("event should exist").tgid, 400);
        assert!(arena.is_empty());
    }

    #[test]
    fn test_arena_concurrent_push_pop() {
        let arena = EventArena::new(64);
        let writer_arena = Arc::clone(&arena);
        let reader_arena = Arc::clone(&arena);

        let writer = thread::spawn(move || {
            for tgid in 0u32..1000 {
                let event = event_with_tgid(tgid);
                loop {
                    if writer_arena.try_push(event).is_ok() {
                        break;
                    }
                    thread::sleep(Duration::from_micros(10));
                }
            }
        });

        let reader = thread::spawn(move || {
            let mut collected = Vec::with_capacity(1000);
            while collected.len() < 1000 {
                if let Some(event) = reader_arena.try_pop() {
                    collected.push(event);
                } else {
                    thread::yield_now();
                }
            }
            collected
        });

        writer.join().expect("writer thread should complete");
        let events = reader.join().expect("reader thread should complete");
        assert_eq!(events.len(), 1000);
        for (idx, event) in events.iter().enumerate() {
            assert_eq!(event.tgid as usize, idx);
        }
    }

    #[test]
    fn test_arena_len_calculation() {
        let arena = EventArena::new(8);

        arena
            .try_push(event_with_tgid(1))
            .expect("push should succeed");
        arena
            .try_push(event_with_tgid(2))
            .expect("push should succeed");
        arena
            .try_push(event_with_tgid(3))
            .expect("push should succeed");
        assert_eq!(arena.len(), 3);

        let _ = arena.try_pop();
        assert_eq!(arena.len(), 2);

        arena
            .try_push(event_with_tgid(4))
            .expect("push should succeed");
        arena
            .try_push(event_with_tgid(5))
            .expect("push should succeed");
        assert_eq!(arena.len(), 4);
    }

    #[test]
    fn test_arena_capacity_must_be_power_of_two() {
        let panic = std::panic::catch_unwind(|| EventArena::new(7));
        assert!(panic.is_err(), "new(7) should panic");

        let payload = panic.expect_err("panic payload should exist");
        let panic_msg = if let Some(msg) = payload.downcast_ref::<&str>() {
            *msg
        } else if let Some(msg) = payload.downcast_ref::<String>() {
            msg.as_str()
        } else {
            ""
        };
        assert!(
            panic_msg.contains("power of two"),
            "panic message should mention power-of-two capacity"
        );
    }
}
