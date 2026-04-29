# Go bindings (`mace-ebpf/pkg/mace`)

This Go module wraps the Rust **`mace-ebpf`** crate via **cgo**, linking **`libmace_ebpf.a`** by default (debug build). Use **`-tags mace_static_release`** after **`cargo build --release -p mace-ebpf`** so the linker picks **`target/release/libmace_ebpf.a`**.

## Quick test

From the **repository root** (so `target/debug/libmace_ebpf.a` exists):

```bash
cd mace-ebpf/pkg/mace
CGO_ENABLED=1 go test -race -v ./...
```

Or run **`./mace-ebpf/pkg/mace/run_go_tests.sh`** from the repo root.

## What is here

- **Arena / raw events** — `Arena`, `Event`, `TryPush` / `TryPop` against the Rust SPSC ring.
- **Alert channel** — bounded protobuf alert delivery (`AlertChannel`, `TryRecvNonBlocking`, …).
- **Sensor** — higher-level polling loop combining arena + alerts (`Sensor`, `DefaultConfig`).
- **Protobuf integrity** — `FeedTestAlert()` calls Rust **`mace_alert_channel_feed_test_alert`** to enqueue a maximal-field `maceproto.Alert`; see **`alert_integrity_test.go`** (`TestProtobufAlertIntegrity`).

## Minimal usage

```go
package main

import (
	"log"
	"time"

	"github.com/mace-ebpf/sdk/pkg/mace"
)

func main() {
	cfg := mace.DefaultConfig()
	sensor, err := mace.NewSensor(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer sensor.Close()

	// Push events, drain channels, etc. — see example_test.go
	_ = time.Second
}
```

## Regenerating protobuf (Go)

`maceproto/` contains Go types generated from `proto/alert.proto`. Regenerate after changing the proto:

```bash
cd mace-ebpf/pkg/mace
mkdir -p maceproto
protoc -I ../../proto --go_out=maceproto --go_opt=paths=source_relative ../../proto/alert.proto
```

Requires **`protoc`** and **`protoc-gen-go`** on your **`PATH`**.
