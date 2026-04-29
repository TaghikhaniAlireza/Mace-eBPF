package mace

/*
#include "mace.h"
*/
import "C"

// Syscall identifiers matching the Rust/kernel bridge (MemorySyscall).
const (
	SyscallMmap        uint32 = 1
	SyscallMprotect    uint32 = 2
	SyscallMemfdCreate uint32 = 3
	SyscallPtrace      uint32 = 4
)

// Event mirrors C.RawMemoryEvent / the Rust FFI layout.
type Event struct {
	TimestampNs   uint64
	TGID          uint32
	PID           uint32
	SyscallID     uint32
	Args          [6]uint64
	CgroupID      uint64
	Comm          [16]byte
	UID           uint32
	SyscallRet    int64
	ExecveCmdline string
}

// CommString returns the command name as a NUL-terminated Go string.
func (e *Event) CommString() string {
	n := 0
	for n < len(e.Comm) && e.Comm[n] != 0 {
		n++
	}
	return string(e.Comm[:n])
}

func fromCEvent(ce *C.RawMemoryEvent) Event {
	var args [6]uint64
	for i := range args {
		args[i] = uint64(ce.args[i])
	}
	var comm [16]byte
	for i := 0; i < 16; i++ {
		comm[i] = byte(ce.comm[i])
	}
	cmd := execveCmdlineFromC(ce)
	return Event{
		TimestampNs:   uint64(ce.timestamp_ns),
		TGID:          uint32(ce.tgid),
		PID:           uint32(ce.pid),
		SyscallID:     uint32(ce.syscall_id),
		Args:          args,
		CgroupID:      uint64(ce.cgroup_id),
		Comm:          comm,
		UID:           uint32(ce.uid),
		SyscallRet:    int64(ce.syscall_ret),
		ExecveCmdline: cmd,
	}
}

func (e *Event) toCEvent() C.RawMemoryEvent {
	var ce C.RawMemoryEvent
	ce.timestamp_ns = C.uint64_t(e.TimestampNs)
	ce.tgid = C.uint32_t(e.TGID)
	ce.pid = C.uint32_t(e.PID)
	ce.syscall_id = C.uint32_t(e.SyscallID)
	ce._pad0 = 0
	for i := range e.Args {
		ce.args[i] = C.uint64_t(e.Args[i])
	}
	ce.cgroup_id = C.uint64_t(e.CgroupID)
	for i := 0; i < 16; i++ {
		ce.comm[i] = C.uint8_t(e.Comm[i])
	}
	ce.uid = C.uint32_t(e.UID)
	ce._pad_uid = 0
	ce.syscall_ret = C.int64_t(e.SyscallRet)
	for i := range ce.execve_cmdline {
		ce.execve_cmdline[i] = 0
	}
	_ = copyExecveCmdlineToC(&ce, e.ExecveCmdline)
	return ce
}

func execveCmdlineFromC(ce *C.RawMemoryEvent) string {
	var buf [C.RAW_EXECVE_CMDLINE_LEN]byte
	for i := 0; i < int(C.RAW_EXECVE_CMDLINE_LEN); i++ {
		buf[i] = byte(ce.execve_cmdline[i])
	}
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n])
}

func copyExecveCmdlineToC(ce *C.RawMemoryEvent, s string) int {
	max := int(C.RAW_EXECVE_CMDLINE_LEN)
	if max == 0 {
		return 0
	}
	b := []byte(s)
	if len(b) >= max {
		b = b[:max-1]
	}
	for i := range b {
		ce.execve_cmdline[i] = C.uint8_t(b[i])
	}
	if len(b) < max {
		ce.execve_cmdline[len(b)] = 0
	}
	return len(b) + 1
}
