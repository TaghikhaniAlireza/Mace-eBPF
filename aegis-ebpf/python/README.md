# Aegis Python Bindings

Python bindings for the Aegis-eBPF SDK using `ctypes` against `libaegis_ebpf`.

## Prerequisites

Build the Rust shared library from the **workspace root** (the `.so` is at `target/debug/`):

```bash
cargo build -p aegis-ebpf
```

## Installation

```bash
pip install -e aegis-ebpf/python/
```

## Usage

```python
from aegis import Arena, AlertChannel, raw_memory_event

with Arena(1024) as arena:
    ev = raw_memory_event(
        timestamp_ns=123,
        tgid=42,
        pid=42,
        syscall_id=1,
        args=(0x1000, 64, 0, 0, 0, 0),
        cgroup_id=0,
        comm=b"demo",
    )
    arena.push(ev)
    popped = arena.pop()

with AlertChannel(256) as ch:
    alert = ch.try_recv()
```

## Regenerating protobuf

```bash
protoc --python_out=aegis-ebpf/python/aegis/proto \
  --proto_path=aegis-ebpf/proto \
  aegis-ebpf/proto/alert.proto
```

## Testing

```bash
pip install pytest
python -m pytest aegis-ebpf/python/tests/ -v
```

The package resolves `libaegis_ebpf.so` (or `.dylib` on macOS) under the workspace `target/debug/` directory.
