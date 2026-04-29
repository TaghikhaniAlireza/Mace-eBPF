package mace

/*
#include "mace.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"google.golang.org/protobuf/proto"

	"github.com/mace-ebpf/sdk/pkg/mace/maceproto"
)

// Config configures polling and channel buffer sizes for Sensor.
type Config struct {
	// ArenaCapacity must be a power of two (required by the Rust ring buffer).
	ArenaCapacity int
	// AlertChannelCapacity is the Rust-side bounded alert queue depth.
	AlertChannelCapacity int
	// PollInterval controls how often the arena and alert channel are polled.
	PollInterval time.Duration
}

// DefaultConfig returns defaults aligned with the Rust SDK examples.
func DefaultConfig() Config {
	return Config{
		ArenaCapacity:        1024,
		AlertChannelCapacity: 256,
		PollInterval:         10 * time.Millisecond,
	}
}

// Sensor owns FFI arena and alert-channel handles and exposes Go channels.
type Sensor struct {
	mu sync.Mutex

	arena        *C.MaceArenaHandle
	alertChannel *C.MaceAlertChannelHandle

	events chan Event
	alerts chan Alert

	stopCh chan struct{}
	wg     sync.WaitGroup

	closed    bool
	closeOnce sync.Once
}

// NewSensor constructs arena + alert channel handles and starts poll loops.
func NewSensor(cfg Config) (*Sensor, error) {
	if cfg.ArenaCapacity <= 0 || (cfg.ArenaCapacity&(cfg.ArenaCapacity-1)) != 0 {
		return nil, fmt.Errorf("mace: ArenaCapacity must be a positive power of two, got %d", cfg.ArenaCapacity)
	}
	if cfg.AlertChannelCapacity == 0 {
		return nil, fmt.Errorf("mace: AlertChannelCapacity must be > 0")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultConfig().PollInterval
	}

	arena := C.mace_arena_new(C.size_t(cfg.ArenaCapacity))
	if arena == nil {
		return nil, fmt.Errorf("mace: mace_arena_new failed")
	}

	alertCh := C.mace_alert_channel_new(C.size_t(cfg.AlertChannelCapacity))
	if alertCh == nil {
		C.mace_arena_free(arena)
		return nil, fmt.Errorf("mace: mace_alert_channel_new failed")
	}

	s := &Sensor{
		arena:        arena,
		alertChannel: alertCh,
		events:       make(chan Event, 128),
		alerts:       make(chan Alert, 128),
		stopCh:       make(chan struct{}),
	}

	ensureFinalizer(s)

	s.wg.Add(2)
	go s.pollEvents(cfg.PollInterval)
	go s.pollAlerts(cfg.PollInterval)

	return s, nil
}

// Events returns a receive-only channel of memory events from the arena.
func (s *Sensor) Events() <-chan Event {
	return s.events
}

// Alerts returns decoded protobuf alerts received from the FFI channel.
func (s *Sensor) Alerts() <-chan Alert {
	return s.alerts
}

// PushEvent pushes a RawMemoryEvent into the arena (tests and bridged producers).
func (s *Sensor) PushEvent(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.arena == nil {
		return ErrClosed
	}
	ce := e.toCEvent()
	code := C.mace_arena_try_push(s.arena, &ce)
	return errFromArenaCode(code)
}

// Close stops pollers, frees C handles, and closes the Go channels.
func (s *Sensor) Close() error {
	s.closeOnce.Do(func() {
		clearFinalizer(s)

		close(s.stopCh)
		s.wg.Wait()

		s.mu.Lock()
		if s.arena != nil {
			C.mace_arena_free(s.arena)
			s.arena = nil
		}
		if s.alertChannel != nil {
			C.mace_alert_channel_free(s.alertChannel)
			s.alertChannel = nil
		}
		s.closed = true
		s.mu.Unlock()

		close(s.events)
		close(s.alerts)
	})
	return nil
}

func (s *Sensor) closeInternal() error {
	return s.Close()
}

func (s *Sensor) pollEvents(interval time.Duration) {
	defer s.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.drainArenaTick()
		}
	}
}

func (s *Sensor) drainArenaTick() {
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		var ce C.RawMemoryEvent
		code := C.mace_arena_try_pop(s.arena, &ce)
		switch ErrorCode(code) {
		case ArenaEmpty:
			return
		case Success:
			ev := fromCEvent(&ce)
			select {
			case s.events <- ev:
			case <-s.stopCh:
				return
			}
		default:
			return
		}
	}
}

func (s *Sensor) pollAlerts(interval time.Duration) {
	defer s.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	buf := make([]byte, 4096)

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.recvAlertsTick(&buf)
		}
	}
}

func (s *Sensor) recvAlertsTick(buf *[]byte) {
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		if len(*buf) == 0 {
			*buf = make([]byte, 4096)
		}
		n, need, err := recvAlertResult(C.mace_alert_channel_try_recv(
			s.alertChannel,
			(*C.uint8_t)(unsafe.Pointer(&(*buf)[0])),
			C.size_t(len(*buf)),
		))
		if err != nil {
			return
		}
		if need > len(*buf) {
			*buf = make([]byte, need)
			continue
		}
		if n == 0 {
			return
		}

		data := (*buf)[:n]
		var pb maceproto.Alert
		if err := proto.Unmarshal(data, &pb); err != nil {
			return
		}
		alert := alertFromProto(&pb)

		select {
		case s.alerts <- alert:
		case <-s.stopCh:
			return
		}
	}
}
