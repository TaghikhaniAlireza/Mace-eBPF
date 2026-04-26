use std::{convert::TryFrom, fmt};

use aegis_ebpf_common::{EventType, MemoryEvent, MemorySyscall, SYSCALL_ARG_COUNT};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RawMemoryEvent {
    pub timestamp_ns: u64,
    pub tgid: u32,
    pub pid: u32,
    pub syscall_id: u32,
    pub _pad0: u32,
    pub args: [u64; 6],
    pub cgroup_id: u64,
    pub comm: [u8; 16],
}

impl From<&MemoryEvent> for RawMemoryEvent {
    fn from(event: &MemoryEvent) -> Self {
        let mut args = [0u64; SYSCALL_ARG_COUNT];
        let syscall = match event.event_type {
            EventType::Mmap => {
                args[0] = event.addr;
                args[1] = event.len;
                args[3] = event.flags;
                MemorySyscall::Mmap as u32
            }
            EventType::MprotectWX => {
                args[0] = event.addr;
                args[1] = event.len;
                args[2] = event.flags;
                MemorySyscall::Mprotect as u32
            }
            EventType::MemfdCreate => {
                args[0] = event.addr;
                args[1] = event.flags;
                MemorySyscall::MemfdCreate as u32
            }
            EventType::Ptrace => {
                args[0] = event.flags;
                args[1] = event.len;
                args[2] = event.addr;
                MemorySyscall::Ptrace as u32
            }
            EventType::Execve => {
                args[0] = event.addr;
                args[1] = event.len;
                MemorySyscall::Execve as u32
            }
            EventType::Openat => {
                args[0] = event.flags;
                args[1] = event.addr;
                args[2] = event.len;
                MemorySyscall::Openat as u32
            }
        };

        Self {
            timestamp_ns: event.timestamp_ns,
            tgid: event.tgid,
            pid: event.pid,
            syscall_id: syscall,
            _pad0: 0,
            args,
            cgroup_id: u64::from(event.tgid),
            comm: event.comm,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Info = 0,
    Warning = 1,
    Critical = 2,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub triggered_at_ns: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CSeverity {
    Info = 0,
    Warning = 1,
    Critical = 2,
}

impl From<Severity> for CSeverity {
    fn from(value: Severity) -> Self {
        match value {
            Severity::Info => Self::Info,
            Severity::Warning => Self::Warning,
            Severity::Critical => Self::Critical,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CAlert {
    pub rule_id: [u8; 64],
    pub rule_name: [u8; 128],
    pub severity: CSeverity,
    pub _pad0: [u8; 3],
    pub tgid: u32,
    pub _pad1: u32,
    pub cgroup_id: u64,
    pub triggered_at_ns: u64,
}

impl TryFrom<&Alert> for CAlert {
    type Error = FfiError;

    fn try_from(alert: &Alert) -> Result<Self, Self::Error> {
        Ok(Self {
            rule_id: encode_cstr::<64>(&alert.rule_id, "rule_id")?,
            rule_name: encode_cstr::<128>(&alert.rule_name, "rule_name")?,
            severity: CSeverity::from(alert.severity),
            _pad0: [0u8; 3],
            tgid: alert.tgid,
            _pad1: 0,
            cgroup_id: alert.cgroup_id,
            triggered_at_ns: alert.triggered_at_ns,
        })
    }
}

fn encode_cstr<const N: usize>(value: &str, field: &'static str) -> Result<[u8; N], FfiError> {
    let bytes = value.as_bytes();
    let max = N.saturating_sub(1);
    if bytes.len() > max {
        return Err(FfiError::StringTooLong {
            field,
            max,
            actual: bytes.len(),
        });
    }

    let mut out = [0u8; N];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

#[derive(Debug, PartialEq)]
pub enum FfiError {
    StringTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    NullPointer {
        context: &'static str,
    },
}

impl fmt::Display for FfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StringTooLong { field, max, actual } => {
                write!(
                    f,
                    "string too long for field '{field}': max={max}, actual={actual}"
                )
            }
            Self::NullPointer { context } => write!(f, "null pointer: {context}"),
        }
    }
}

impl std::error::Error for FfiError {}

#[cfg(test)]
mod tests {
    use std::mem::{align_of, offset_of, size_of};

    use super::*;

    fn sample_memory_event() -> MemoryEvent {
        MemoryEvent {
            timestamp_ns: 1_234_567,
            tgid: 42,
            pid: 77,
            comm: *b"demo-proc\0\0\0\0\0\0\0",
            event_type: EventType::MprotectWX,
            addr: 0x1000,
            len: 0x2000,
            flags: 0x4,
            ret: 0,
        }
    }

    #[test]
    fn test_rawmemoryevent_from_memory_event() {
        let source = sample_memory_event();
        let raw = RawMemoryEvent::from(&source);

        assert_eq!(raw.timestamp_ns, source.timestamp_ns);
        assert_eq!(raw.tgid, source.tgid);
        assert_eq!(raw.pid, source.pid);
        assert_eq!(raw.syscall_id, MemorySyscall::Mprotect as u32);
        assert_eq!(raw.cgroup_id, u64::from(source.tgid));
        assert_eq!(raw.comm, source.comm);
        assert_eq!(raw.args[0], source.addr);
        assert_eq!(raw.args[1], source.len);
        assert_eq!(raw.args[2], source.flags);
    }

    #[test]
    fn test_rawmemoryevent_layout() {
        // C equivalent: sizeof(RawMemoryEvent) must equal 96
        // uint64_t timestamp_ns (8) + uint32_t tgid (4) + uint32_t pid (4)
        // + uint32_t syscall_id (4) + uint32_t _pad0 (4) + uint64_t args[6] (48)
        // + uint64_t cgroup_id (8) + uint8_t comm[16] (16) = 96
        assert_eq!(size_of::<RawMemoryEvent>(), 96);
        assert_eq!(align_of::<RawMemoryEvent>(), 8);

        // uint64_t timestamp_ns -> offset 0, size 8
        assert_eq!(offset_of!(RawMemoryEvent, timestamp_ns), 0);
        // uint32_t tgid -> offset 8, size 4
        assert_eq!(offset_of!(RawMemoryEvent, tgid), 8);
        // uint32_t pid -> offset 12, size 4
        assert_eq!(offset_of!(RawMemoryEvent, pid), 12);
        // uint32_t syscall_id -> offset 16, size 4
        assert_eq!(offset_of!(RawMemoryEvent, syscall_id), 16);
        // uint32_t _pad0 -> offset 20, size 4
        assert_eq!(offset_of!(RawMemoryEvent, _pad0), 20);
        // uint64_t args[6] -> offset 24, size 48
        assert_eq!(offset_of!(RawMemoryEvent, args), 24);
        // uint64_t cgroup_id -> offset 72, size 8
        assert_eq!(offset_of!(RawMemoryEvent, cgroup_id), 72);
        // uint8_t comm[16] -> offset 80, size 16
        assert_eq!(offset_of!(RawMemoryEvent, comm), 80);
    }

    #[test]
    fn test_calert_from_alert_happy_path() {
        let alert = Alert {
            rule_id: "rule-001".to_string(),
            rule_name: "Test Rule".to_string(),
            severity: Severity::Critical,
            tgid: 9999,
            cgroup_id: 12345,
            triggered_at_ns: 1_000_000_000,
        };

        let c_alert = CAlert::try_from(&alert).expect("conversion should succeed");
        assert_eq!(c_alert.severity, CSeverity::Critical);
        assert_eq!(c_alert.tgid, 9999);
        assert_eq!(c_alert.cgroup_id, 12345);
        assert_eq!(c_alert.triggered_at_ns, 1_000_000_000);
        assert_eq!(&c_alert.rule_id[..9], b"rule-001\0");
        assert_eq!(&c_alert.rule_name[..10], b"Test Rule\0");
    }

    #[test]
    fn test_calert_string_too_long() {
        let alert = Alert {
            rule_id: "ok-id".to_string(),
            rule_name: "x".repeat(200),
            severity: Severity::Warning,
            tgid: 1,
            cgroup_id: 2,
            triggered_at_ns: 3,
        };

        let err = CAlert::try_from(&alert).expect_err("conversion should fail");
        assert_eq!(
            err,
            FfiError::StringTooLong {
                field: "rule_name",
                max: 127,
                actual: 200
            }
        );
    }

    #[test]
    fn test_calert_layout() {
        // C equivalent: sizeof(CAlert) must equal 224
        // uint8_t rule_id[64] (64) + uint8_t rule_name[128] (128) + uint8_t severity (1)
        // + uint8_t _pad0[3] (3) + uint32_t tgid (4) + uint32_t _pad1 (4)
        // + uint64_t cgroup_id (8) + uint64_t triggered_at_ns (8) + trailing padding (8) = 224
        assert_eq!(size_of::<CAlert>(), 224);
        assert_eq!(align_of::<CAlert>(), 8);

        assert_eq!(offset_of!(CAlert, rule_id), 0);
        assert_eq!(offset_of!(CAlert, rule_name), 64);
        assert_eq!(offset_of!(CAlert, severity), 192);
        assert_eq!(offset_of!(CAlert, _pad0), 193);
        assert_eq!(offset_of!(CAlert, tgid), 196);
        assert_eq!(offset_of!(CAlert, _pad1), 200);
        assert_eq!(offset_of!(CAlert, cgroup_id), 208);
        assert_eq!(offset_of!(CAlert, triggered_at_ns), 216);
    }

    #[test]
    fn test_cseverity_conversion() {
        assert_eq!(CSeverity::from(Severity::Info), CSeverity::Info);
        assert_eq!(CSeverity::from(Severity::Warning), CSeverity::Warning);
        assert_eq!(CSeverity::from(Severity::Critical), CSeverity::Critical);
        assert_eq!(CSeverity::Info as u8, 0);
        assert_eq!(CSeverity::Warning as u8, 1);
        assert_eq!(CSeverity::Critical as u8, 2);
    }

    #[test]
    fn test_rawmemoryevent_is_copy() {
        let event = RawMemoryEvent::from(&sample_memory_event());
        let a = event;
        let b = a;
        assert_eq!(a.tgid, 42);
        assert_eq!(b.tgid, 42);
    }

    #[test]
    fn test_padding_fields_are_zero_initialized() {
        let raw = RawMemoryEvent::from(&sample_memory_event());
        assert_eq!(raw._pad0, 0);

        let alert = Alert {
            rule_id: "rule-1".to_string(),
            rule_name: "rule name".to_string(),
            severity: Severity::Info,
            tgid: 1,
            cgroup_id: 2,
            triggered_at_ns: 3,
        };
        let c_alert = CAlert::try_from(&alert).expect("conversion should succeed");
        assert_eq!(c_alert._pad0, [0u8; 3]);
        assert_eq!(c_alert._pad1, 0);
    }
}

#[cfg(test)]
mod layout_assertions {
    use std::mem::{align_of, offset_of, size_of};

    use super::*;

    #[test]
    fn verify_rawmemoryevent_layout() {
        // C equivalent: sizeof(RawMemoryEvent) must equal 96
        assert_eq!(size_of::<RawMemoryEvent>(), 96);
        assert_eq!(align_of::<RawMemoryEvent>(), 8);
        assert_eq!(offset_of!(RawMemoryEvent, timestamp_ns), 0);
        assert_eq!(offset_of!(RawMemoryEvent, tgid), 8);
        assert_eq!(offset_of!(RawMemoryEvent, pid), 12);
        assert_eq!(offset_of!(RawMemoryEvent, syscall_id), 16);
        assert_eq!(offset_of!(RawMemoryEvent, _pad0), 20);
        assert_eq!(offset_of!(RawMemoryEvent, args), 24);
        assert_eq!(offset_of!(RawMemoryEvent, cgroup_id), 72);
        assert_eq!(offset_of!(RawMemoryEvent, comm), 80);
    }

    #[test]
    fn verify_calert_layout() {
        // C equivalent: sizeof(CAlert) must equal 224
        assert_eq!(size_of::<CAlert>(), 224);
        assert_eq!(align_of::<CAlert>(), 8);
        assert_eq!(offset_of!(CAlert, rule_id), 0);
        assert_eq!(offset_of!(CAlert, rule_name), 64);
        assert_eq!(offset_of!(CAlert, severity), 192);
        assert_eq!(offset_of!(CAlert, _pad0), 193);
        assert_eq!(offset_of!(CAlert, tgid), 196);
        assert_eq!(offset_of!(CAlert, _pad1), 200);
        assert_eq!(offset_of!(CAlert, cgroup_id), 208);
        assert_eq!(offset_of!(CAlert, triggered_at_ns), 216);
    }
}
