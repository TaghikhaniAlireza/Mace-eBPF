//! Criterion benchmarks for `EventArena` (SPSC ring buffer): single-threaded O(1) paths and
//! concurrent producer/consumer throughput.

use std::{sync::Arc, thread};

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use mace_ebpf::ffi::{
    arena::{ArenaError, EventArena},
    types::RawMemoryEvent,
};

const LARGE_CAP: usize = 262_144;

fn sample_event(seed: u32) -> RawMemoryEvent {
    RawMemoryEvent {
        timestamp_ns: u64::from(seed),
        tgid: seed,
        pid: seed,
        syscall_id: 1,
        _pad0: 0,
        args: [u64::from(seed); 6],
        cgroup_id: u64::from(seed),
        comm: [0; 16],
        uid: 0,
        _pad_uid: 0,
        syscall_ret: 0,
        execve_cmdline: [0; mace_ebpf::ffi::types::RAW_EXECVE_CMDLINE_LEN],
    }
}

fn single_thread_push_pop(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_thread_push_pop");

    group.bench_function("try_push_non_full", |b| {
        let arena = EventArena::new(LARGE_CAP);
        let event = sample_event(1);
        b.iter(|| {
            black_box(arena.try_push(event).expect("arena must stay non-full"));
            black_box(arena.try_pop());
        });
    });

    group.bench_function("try_push_full_arena", |b| {
        let cap = 256usize;
        let arena = EventArena::new(cap);
        let event = sample_event(42);
        // Ring holds at most `capacity - 1` events.
        for i in 0..(cap - 1) {
            arena.try_push(sample_event(i as u32)).unwrap();
        }
        assert_eq!(arena.try_push(event).unwrap_err(), ArenaError::Full);
        b.iter(|| {
            black_box(arena.try_push(event).unwrap_err());
        });
    });

    group.bench_function("try_pop_non_empty", |b| {
        let arena = EventArena::new(64);
        let event = sample_event(7);
        arena.try_push(event).unwrap();
        b.iter(|| {
            black_box(arena.try_pop().expect("slot must be occupied"));
            black_box(arena.try_push(event).unwrap());
        });
    });

    group.bench_function("try_pop_empty", |b| {
        let arena = EventArena::new(16);
        b.iter(|| black_box(arena.try_pop()));
    });

    group.finish();
}

const CONCURRENT_ITERS: u64 = 10_000;

fn concurrent_push_pop(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_push_pop");
    group.throughput(Throughput::Elements(CONCURRENT_ITERS));
    group.sample_size(30);

    group.bench_function("spsc_scope_10k_roundtrip", |b| {
        b.iter(|| {
            let arena = EventArena::new(1024);
            let a = Arc::clone(&arena);
            let b_arc = Arc::clone(&arena);
            thread::scope(|s| {
                s.spawn(move || {
                    for i in 0..CONCURRENT_ITERS {
                        let ev = sample_event(i as u32);
                        loop {
                            if a.try_push(ev).is_ok() {
                                break;
                            }
                            thread::yield_now();
                        }
                    }
                });
                s.spawn(move || {
                    for _ in 0..CONCURRENT_ITERS {
                        loop {
                            if let Some(ev) = b_arc.try_pop() {
                                black_box(ev);
                                break;
                            }
                            thread::yield_now();
                        }
                    }
                });
            });
        });
    });

    group.finish();
}

criterion_group!(benches, single_thread_push_pop, concurrent_push_pop);
criterion_main!(benches);
