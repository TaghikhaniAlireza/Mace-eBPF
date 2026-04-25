# Aegis-eBPF Go Bindings

Go bindings for the Aegis-eBPF SDK: cgo over `libaegis_ebpf`, arena event polling, and protobuf alert decoding.

## Prerequisites

- **Rust**: build the shared library from the **workspace root** (the `target/` directory lives next to `aegis-ebpf/`, not inside it):

  ```bash
  cargo build -p aegis-ebpf
  ```

  This produces `target/debug/libaegis_ebpf.so` (Linux) or `libaegis_ebpf.dylib` (macOS).

- **Go** 1.21+

## Installation / test

```bash
cd aegis-ebpf/pkg/aegis
go test -v ./...
```

Or use the helper (sets `LD_LIBRARY_PATH` to the workspace `target/debug`):

```bash
cargo build -p aegis-ebpf
./aegis-ebpf/pkg/aegis/run_go_tests.sh
```

The cgo linker uses `-L../../../target/debug` relative to this package directory.

### Low-level handles (GC / cgo stress)

- **`Arena`** (`arena_handle.go`) — `NewArena`, `TryPush` / `TryPop`, explicit **`Close()`**; `sync.Once` ensures **`aegis_arena_free`** runs once even if **`Close`** races a **`SetFinalizer`** cleanup.
- **`AlertChannelHandle`** (`alert_handle.go`) — same pattern for **`aegis_alert_channel_*`** without background goroutines.

## Usage

```go
package main

import (
	"fmt"

	"github.com/aegis-ebpf/sdk/pkg/aegis"
)

func main() {
	cfg := aegis.DefaultConfig()
	sensor, err := aegis.NewSensor(cfg)
	if err != nil {
		panic(err)
	}
	defer sensor.Close()

	for ev := range sensor.Events() {
		fmt.Printf("event tgid=%d syscall=%d\n", ev.TGID, ev.SyscallID)
	}
}
```

## Generated code

`aegisproto/` contains Go types generated from `proto/alert.proto`. Regenerate after changing the proto:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.32.0
protoc -I ../../proto --go_out=aegisproto --go_opt=paths=source_relative ../../proto/alert.proto
```

## Features

- **Opaque FFI handles** — arena + alert channel created in Rust, freed on `Close`
- **Finalizer** — `Sensor` registers `runtime.SetFinalizer` as a safety net if `Close` is omitted
- **Channels** — `Events()` and `Alerts()` for idiomatic consumption
- **Protobuf alerts** — `aegis_alert_channel_try_recv` payloads decoded with `google.golang.org/protobuf`

## Testing

```bash
go test -v ./...
go test -race -v ./...
```
