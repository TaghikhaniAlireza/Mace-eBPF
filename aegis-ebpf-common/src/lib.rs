#![no_std]

#[cfg(feature = "user")]
extern crate alloc;

pub const TASK_COMM_LEN: usize = 16;
pub const SYSCALL_ARG_COUNT: usize = 6;

/// Ring-buffer sample layout version (bump when `RingBufferSample` changes).
/// v2: adds `openat_path_blob` (in-kernel pathname capture for openat).
/// v3: shrinks argv/openat blobs so `PendingEvent` fits the BPF stack (~512 B) on all tracepoints.
/// v4: single `payload_blob` (max of argv vs openat) so eBPF `PendingEvent` holds one large buffer.
/// v5: full execve cmdline up to [`EXECVE_SCRATCH_LEN`] (built in per-CPU scratch in eBPF); openat prefix unchanged.
pub const RING_SAMPLE_LAYOUT_VERSION: u32 = 5;

/// Max bytes for `openat` pathname snapshot in BPF (including NUL).
pub const OPENAT_PATH_MAX_LEN: usize = 64;

/// Max bytes for concatenated `execve` argv (space-separated) in the ring buffer / scratch path.
pub const EXECVE_SCRATCH_LEN: usize = 4096;

/// One shared byte buffer in the ring sample: execve fills with joined argv (NUL-padded); openat uses prefix only.
pub const RING_PAYLOAD_BLOB_LEN: usize = const_max(EXECVE_SCRATCH_LEN, OPENAT_PATH_MAX_LEN);

const fn const_max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// Full ring-buffer record written by the eBPF program (kernel + syscall return + UID + argv blob).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RingBufferSample {
    pub kernel: KernelMemoryEvent,
    /// Syscall return value from `sys_exit_*` (`ctx` offset 16).
    pub syscall_ret: i64,
    /// Effective UID at syscall exit (`bpf_get_current_uid_gid()` low 32 bits).
    pub uid: u32,
    pub _reserved: u32,
    pub layout_version: u32,
    /// Execve: joined argv (space-separated, truncated to [`EXECVE_SCRATCH_LEN`]). Openat: first [`OPENAT_PATH_MAX_LEN`] bytes are the path.
    pub payload_blob: [u8; RING_PAYLOAD_BLOB_LEN],
}

impl RingBufferSample {
    pub const fn wire_size() -> usize {
        core::mem::size_of::<Self>()
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemorySyscall {
    Mmap = 1,
    Mprotect = 2,
    MemfdCreate = 3,
    Ptrace = 4,
    Execve = 5,
    Openat = 6,
}

impl MemorySyscall {
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Mmap),
            2 => Some(Self::Mprotect),
            3 => Some(Self::MemfdCreate),
            4 => Some(Self::Ptrace),
            5 => Some(Self::Execve),
            6 => Some(Self::Openat),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mmap => "mmap",
            Self::Mprotect => "mprotect",
            Self::MemfdCreate => "memfd_create",
            Self::Ptrace => "ptrace",
            Self::Execve => "execve",
            Self::Openat => "openat",
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KernelMemoryEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub syscall: u32,
    pub args: [u64; SYSCALL_ARG_COUNT],
    pub comm: [u8; TASK_COMM_LEN],
}

impl KernelMemoryEvent {
    pub const fn syscall_kind(&self) -> Option<MemorySyscall> {
        MemorySyscall::from_u32(self.syscall)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != core::mem::size_of::<Self>() {
            return None;
        }
        // Ring buffer samples are byte slices; read an unaligned copy into a plain POD struct.
        let event = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Self) };
        Some(event)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventType {
    Mmap = 0,
    MprotectWX = 1,
    MemfdCreate = 2,
    Ptrace = 3,
    Execve = 4,
    Openat = 5,
}

impl EventType {
    pub const fn from_syscall(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Mmap),
            2 => Some(Self::MprotectWX),
            3 => Some(Self::MemfdCreate),
            4 => Some(Self::Ptrace),
            5 => Some(Self::Execve),
            6 => Some(Self::Openat),
            _ => None,
        }
    }
}

#[cfg(not(feature = "user"))]
pub type MemoryEvent = KernelMemoryEvent;

#[cfg(feature = "user")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryEvent {
    pub timestamp_ns: u64,
    pub tgid: u32,
    pub pid: u32,
    /// Effective UID captured at syscall exit (from eBPF `bpf_get_current_uid_gid`).
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub event_type: EventType,
    pub addr: u64,
    pub len: u64,
    pub flags: u64,
    pub ret: i64,
    /// Joined argv snapshot for `execve` (from eBPF user-memory reads); empty for other syscalls.
    pub execve_cmdline: alloc::string::String,
    /// Path captured in-kernel at `sys_enter_openat` (empty when not `openat`).
    pub openat_path: alloc::string::String,
}

#[cfg(feature = "user")]
impl MemoryEvent {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (raw, syscall_ret, uid, payload_blob) = if bytes.len() == RingBufferSample::wire_size()
        {
            let sample =
                unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const RingBufferSample) };
            if sample.layout_version != RING_SAMPLE_LAYOUT_VERSION {
                return None;
            }
            (
                sample.kernel,
                sample.syscall_ret,
                sample.uid,
                Some(sample.payload_blob),
            )
        } else if bytes.len() == core::mem::size_of::<KernelMemoryEvent>() {
            let raw = KernelMemoryEvent::from_bytes(bytes)?;
            (raw, 0i64, 0u32, None)
        } else {
            return None;
        };

        let event_type = EventType::from_syscall(raw.syscall)?;

        let (addr, len, flags, ret) = match event_type {
            EventType::Mmap => (raw.args[0], raw.args[1], raw.args[3], syscall_ret),
            EventType::MprotectWX => (raw.args[0], raw.args[1], raw.args[2], syscall_ret),
            EventType::MemfdCreate => (raw.args[0], 0, raw.args[1], syscall_ret),
            // ptrace: request = args[0], target pid = args[1], data ptr = args[2]
            EventType::Ptrace => (raw.args[2], raw.args[1], raw.args[0], syscall_ret),
            // execve: filename userspace pointer, argv pointer (userspace rules may read /proc/pid/cmdline)
            EventType::Execve => (raw.args[0], raw.args[1], 0, syscall_ret),
            // openat: dfd, pathname user pointer, flags; fd returned on exit (stored in raw by userspace bridge if needed)
            EventType::Openat => (raw.args[1], raw.args[2], raw.args[0], syscall_ret),
        };

        let execve_cmdline = if event_type == EventType::Execve {
            payload_blob
                .as_ref()
                .map(|b| decode_execve_cmdline_blob(&b[..EXECVE_SCRATCH_LEN]))
                .unwrap_or_default()
        } else {
            alloc::string::String::new()
        };

        let openat_path = if event_type == EventType::Openat {
            payload_blob
                .as_ref()
                .map(|b| {
                    let path: &[u8; OPENAT_PATH_MAX_LEN] = b[..OPENAT_PATH_MAX_LEN]
                        .try_into()
                        .expect("RING_PAYLOAD_BLOB_LEN >= OPENAT_PATH_MAX_LEN");
                    decode_openat_path_blob(path)
                })
                .unwrap_or_default()
        } else {
            alloc::string::String::new()
        };

        Some(Self {
            timestamp_ns: raw.timestamp_ns,
            tgid: raw.tgid,
            pid: raw.pid,
            uid,
            comm: raw.comm,
            event_type,
            addr,
            len,
            flags,
            ret,
            execve_cmdline,
            openat_path,
        })
    }
}

#[cfg(feature = "user")]
fn decode_execve_cmdline_blob(blob: &[u8]) -> alloc::string::String {
    let end = blob.iter().position(|&b| b == 0).unwrap_or(blob.len());
    alloc::string::String::from_utf8_lossy(&blob[..end]).into_owned()
}

#[cfg(feature = "user")]
fn decode_openat_path_blob(blob: &[u8; OPENAT_PATH_MAX_LEN]) -> alloc::string::String {
    let end = blob.iter().position(|&b| b == 0).unwrap_or(blob.len());
    alloc::string::String::from_utf8_lossy(&blob[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// Unit tests (userspace / `user` feature for `MemoryEvent::from_bytes`)
// ---------------------------------------------------------------------------
//
// Run: `cargo test -p aegis-ebpf-common --features user`
//
// ```text
// mod tests {
//     memory_syscall_tests   // from_u32 / as_str
//     event_type_tests       // from_syscall
//     kernel_memory_event    // from_bytes + golden round-trip + alignment
//     memory_event           // #[cfg(feature = "user")] field mapping
// }
// ```

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes a [`KernelMemoryEvent`] to its exact wire layout for golden-byte tests.
    fn kernel_memory_event_to_bytes(
        event: &KernelMemoryEvent,
    ) -> [u8; core::mem::size_of::<KernelMemoryEvent>()] {
        let mut out = [0u8; core::mem::size_of::<KernelMemoryEvent>()];
        unsafe {
            core::ptr::copy_nonoverlapping(
                (event as *const KernelMemoryEvent).cast::<u8>(),
                out.as_mut_ptr(),
                out.len(),
            );
        }
        out
    }

    const fn kernel_event_size() -> usize {
        core::mem::size_of::<KernelMemoryEvent>()
    }

    // --- MemorySyscall ---

    /// Validates that `MemorySyscall::from_u32` accepts syscall ids 1–6 and maps them to the expected variants.
    #[test]
    fn memory_syscall_from_u32_valid_ids() {
        assert_eq!(MemorySyscall::from_u32(1), Some(MemorySyscall::Mmap));
        assert_eq!(MemorySyscall::from_u32(2), Some(MemorySyscall::Mprotect));
        assert_eq!(MemorySyscall::from_u32(3), Some(MemorySyscall::MemfdCreate));
        assert_eq!(MemorySyscall::from_u32(4), Some(MemorySyscall::Ptrace));
        assert_eq!(MemorySyscall::from_u32(5), Some(MemorySyscall::Execve));
        assert_eq!(MemorySyscall::from_u32(6), Some(MemorySyscall::Openat));
    }

    /// Validates that `MemorySyscall::from_u32` returns `None` for out-of-range ids (0, 7, u32::MAX).
    #[test]
    fn memory_syscall_from_u32_invalid_ids() {
        assert_eq!(MemorySyscall::from_u32(0), None);
        assert_eq!(MemorySyscall::from_u32(7), None);
        assert_eq!(MemorySyscall::from_u32(u32::MAX), None);
    }

    /// Validates that `MemorySyscall::as_str` returns stable kernel syscall names for each variant.
    #[test]
    fn memory_syscall_as_str() {
        assert_eq!(MemorySyscall::Mmap.as_str(), "mmap");
        assert_eq!(MemorySyscall::Mprotect.as_str(), "mprotect");
        assert_eq!(MemorySyscall::MemfdCreate.as_str(), "memfd_create");
        assert_eq!(MemorySyscall::Ptrace.as_str(), "ptrace");
        assert_eq!(MemorySyscall::Execve.as_str(), "execve");
        assert_eq!(MemorySyscall::Openat.as_str(), "openat");
    }

    // --- EventType ---

    /// Validates that `EventType::from_syscall` maps raw syscall ids 1–6 to the high-level event kinds used in userspace.
    #[test]
    fn event_type_from_syscall_valid() {
        assert_eq!(EventType::from_syscall(1), Some(EventType::Mmap));
        assert_eq!(EventType::from_syscall(2), Some(EventType::MprotectWX));
        assert_eq!(EventType::from_syscall(3), Some(EventType::MemfdCreate));
        assert_eq!(EventType::from_syscall(4), Some(EventType::Ptrace));
        assert_eq!(EventType::from_syscall(5), Some(EventType::Execve));
        assert_eq!(EventType::from_syscall(6), Some(EventType::Openat));
    }

    /// Validates that `EventType::from_syscall` returns `None` for unknown syscall ids.
    #[test]
    fn event_type_from_syscall_invalid() {
        assert_eq!(EventType::from_syscall(0), None);
        assert_eq!(EventType::from_syscall(7), None);
        assert_eq!(EventType::from_syscall(u32::MAX), None);
    }

    // --- KernelMemoryEvent::from_bytes ---

    /// Validates that a golden-serialized [`KernelMemoryEvent`] round-trips through `from_bytes` with exact length.
    #[test]
    fn kernel_memory_event_from_bytes_exact_size_round_trip() {
        let original = KernelMemoryEvent {
            timestamp_ns: 0x1122_3344_5566_7788,
            pid: 100,
            tgid: 200,
            syscall: 2,
            args: [10, 20, 30, 40, 50, 60],
            comm: *b"test-comm\0\0\0\0\0\0\0",
        };
        let bytes = kernel_memory_event_to_bytes(&original);
        assert_eq!(bytes.len(), kernel_event_size());
        let parsed = KernelMemoryEvent::from_bytes(&bytes).expect("exact size should parse");
        assert_eq!(parsed.timestamp_ns, original.timestamp_ns);
        assert_eq!(parsed.pid, original.pid);
        assert_eq!(parsed.tgid, original.tgid);
        assert_eq!(parsed.syscall, original.syscall);
        assert_eq!(parsed.args, original.args);
        assert_eq!(parsed.comm, original.comm);
    }

    /// Validates that `KernelMemoryEvent::from_bytes` returns `None` when the slice is shorter than the struct.
    #[test]
    fn kernel_memory_event_from_bytes_short_slice() {
        let bytes = [0u8; 4];
        assert!(KernelMemoryEvent::from_bytes(&bytes).is_none());
    }

    /// Validates that `KernelMemoryEvent::from_bytes` returns `None` when the slice is longer than the struct.
    #[test]
    fn kernel_memory_event_from_bytes_long_slice() {
        let buf = [0u8; 256];
        assert!(buf.len() > kernel_event_size());
        assert!(KernelMemoryEvent::from_bytes(&buf).is_none());
    }

    /// Validates that `KernelMemoryEvent::from_bytes` accepts a slice whose pointer is not aligned to the struct (unaligned load).
    #[test]
    fn kernel_memory_event_from_bytes_unaligned() {
        let original = KernelMemoryEvent {
            timestamp_ns: 1,
            pid: 2,
            tgid: 3,
            syscall: 1,
            args: [0; SYSCALL_ARG_COUNT],
            comm: [0; TASK_COMM_LEN],
        };
        let inner = kernel_memory_event_to_bytes(&original);
        let mut buf = [0u8; 256];
        // Place payload at offset 1 so `&buf[1..]` is not 8-byte aligned.
        buf[1..1 + inner.len()].copy_from_slice(&inner);
        let slice = &buf[1..1 + inner.len()];
        assert_ne!(
            slice.as_ptr() as usize % core::mem::align_of::<KernelMemoryEvent>(),
            0
        );
        let parsed = KernelMemoryEvent::from_bytes(slice).expect("read_unaligned should succeed");
        assert_eq!(parsed.timestamp_ns, original.timestamp_ns);
        assert_eq!(parsed.syscall, original.syscall);
    }

    /// Validates that `syscall_kind` mirrors `MemorySyscall::from_u32` for the embedded syscall field.
    #[test]
    fn kernel_memory_event_syscall_kind() {
        let ev = KernelMemoryEvent {
            timestamp_ns: 0,
            pid: 0,
            tgid: 0,
            syscall: 3,
            args: [0; SYSCALL_ARG_COUNT],
            comm: [0; TASK_COMM_LEN],
        };
        assert_eq!(ev.syscall_kind(), Some(MemorySyscall::MemfdCreate));
    }

    // --- MemoryEvent::from_bytes (requires `user` feature) ---

    #[cfg(feature = "user")]
    mod memory_event {
        use super::*;

        fn raw_with_syscall(syscall: u32, args: [u64; SYSCALL_ARG_COUNT]) -> KernelMemoryEvent {
            KernelMemoryEvent {
                timestamp_ns: 9_000,
                pid: 7,
                tgid: 42,
                syscall,
                args,
                comm: *b"demo\0\0\0\0\0\0\0\0\0\0\0\0",
            }
        }

        /// Validates that mmap syscall maps `args[0]`, `args[1]`, `args[3]` into addr, len, flags.
        #[test]
        fn memory_event_mmap_field_mapping() {
            let raw = raw_with_syscall(1, [0x1000, 0x2000, 0xAAAA, 0x7, 0, 0]);
            let bytes = super::kernel_memory_event_to_bytes(&raw);
            let ev = MemoryEvent::from_bytes(&bytes).expect("mmap should parse");
            assert_eq!(ev.event_type, EventType::Mmap);
            assert_eq!(ev.addr, 0x1000);
            assert_eq!(ev.len, 0x2000);
            assert_eq!(ev.flags, 0x7);
            assert_eq!(ev.timestamp_ns, raw.timestamp_ns);
            assert_eq!(ev.tgid, raw.tgid);
            assert_eq!(ev.pid, raw.pid);
            assert_eq!(ev.comm, raw.comm);
            assert_eq!(ev.ret, 0);
        }

        /// Validates that mprotect-style syscall maps `args[0]`, `args[1]`, `args[2]` into addr, len, flags.
        #[test]
        fn memory_event_mprotect_field_mapping() {
            let raw = raw_with_syscall(2, [0x5000, 0x100, 0x3, 0, 0, 0]);
            let bytes = super::kernel_memory_event_to_bytes(&raw);
            let ev = MemoryEvent::from_bytes(&bytes).expect("mprotect should parse");
            assert_eq!(ev.event_type, EventType::MprotectWX);
            assert_eq!(ev.addr, 0x5000);
            assert_eq!(ev.len, 0x100);
            assert_eq!(ev.flags, 0x3);
        }

        /// Validates that memfd_create syscall maps `args[0]` to addr, `args[1]` to flags, and len is zero.
        #[test]
        fn memory_event_memfd_create_field_mapping() {
            let raw = raw_with_syscall(3, [0x333, 0x444, 0, 0, 0, 0]);
            let bytes = super::kernel_memory_event_to_bytes(&raw);
            let ev = MemoryEvent::from_bytes(&bytes).expect("memfd_create should parse");
            assert_eq!(ev.event_type, EventType::MemfdCreate);
            assert_eq!(ev.addr, 0x333);
            assert_eq!(ev.len, 0);
            assert_eq!(ev.flags, 0x444);
        }

        /// Validates that ptrace syscall maps request=`args[0]`, target pid=`args[1]`, data ptr=`args[2]` into flags/len/addr.
        #[test]
        fn memory_event_ptrace_field_mapping() {
            let raw = raw_with_syscall(4, [0x99, 0x55, 0xDEAD, 0, 0, 0]);
            let bytes = super::kernel_memory_event_to_bytes(&raw);
            let ev = MemoryEvent::from_bytes(&bytes).expect("ptrace should parse");
            assert_eq!(ev.event_type, EventType::Ptrace);
            assert_eq!(ev.addr, 0xDEAD);
            assert_eq!(ev.len, 0x55);
            assert_eq!(ev.flags, 0x99);
        }

        /// Validates openat syscall maps pathname ptr, flags, and dirfd into addr/len/flags.
        #[test]
        fn memory_event_openat_field_mapping() {
            let raw = raw_with_syscall(6, [(-100i64) as u64, 0x7000, 0x8000, 0, 0, 0]);
            let bytes = super::kernel_memory_event_to_bytes(&raw);
            let ev = MemoryEvent::from_bytes(&bytes).expect("openat should parse");
            assert_eq!(ev.event_type, EventType::Openat);
            assert_eq!(ev.addr, 0x7000);
            assert_eq!(ev.len, 0x8000);
            assert_eq!(ev.flags, (-100i64) as u64); // AT_FDCWD (sign-extended in register)
        }

        /// Validates that an unknown syscall id yields `None` from `MemoryEvent::from_bytes`.
        #[test]
        fn memory_event_unknown_syscall_returns_none() {
            let raw = raw_with_syscall(99, [1, 2, 3, 4, 5, 6]);
            let bytes = super::kernel_memory_event_to_bytes(&raw);
            assert!(MemoryEvent::from_bytes(&bytes).is_none());
        }

        /// Validates that `MemoryEvent::from_bytes` returns `None` for wrong-length input.
        #[test]
        fn memory_event_wrong_length_returns_none() {
            assert!(MemoryEvent::from_bytes(&[]).is_none());
            let sz = super::kernel_event_size();
            if sz > 1 {
                let short = [0u8; 256];
                assert!(MemoryEvent::from_bytes(&short[..sz - 1]).is_none());
            }
            let long = [0u8; 256];
            assert!(sz < long.len());
            assert!(MemoryEvent::from_bytes(&long[..sz + 1]).is_none());
        }

        /// Validates full ring-buffer sample with execve argv blob and UID.
        #[test]
        fn memory_event_from_ring_sample_execve_argv_and_uid() {
            let joined = b"/bin/sh -c whoami";
            let mut payload = [0u8; RING_PAYLOAD_BLOB_LEN];
            payload[..joined.len()].copy_from_slice(joined);

            let kernel = KernelMemoryEvent {
                timestamp_ns: 1,
                pid: 9,
                tgid: 9,
                syscall: 5,
                args: [0x1111, 0x2222, 0, 0, 0, 0],
                comm: *b"sh\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            };
            let sample = RingBufferSample {
                kernel,
                syscall_ret: 0,
                uid: 0,
                _reserved: 0,
                layout_version: RING_SAMPLE_LAYOUT_VERSION,
                payload_blob: payload,
            };
            let mut bytes = [0u8; RingBufferSample::wire_size()];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (&sample as *const RingBufferSample).cast::<u8>(),
                    bytes.as_mut_ptr(),
                    bytes.len(),
                );
            }
            let ev = MemoryEvent::from_bytes(&bytes).expect("ring sample");
            assert_eq!(ev.event_type, EventType::Execve);
            assert_eq!(ev.uid, 0);
            assert_eq!(ev.execve_cmdline, "/bin/sh -c whoami");
        }

        /// v5: joined cmdline can fill the full scratch; ensure a tail marker is not truncated in userspace parse.
        #[test]
        fn memory_event_execve_cmdline_tail_preserved_at_max_len() {
            let mut payload = [0u8; RING_PAYLOAD_BLOB_LEN];
            payload.fill(b'x');
            let tail = b"Z_END_MARK_9";
            let n = tail.len();
            assert!(n < RING_PAYLOAD_BLOB_LEN);
            let start = RING_PAYLOAD_BLOB_LEN - n;
            payload[start..].copy_from_slice(tail);

            let kernel = KernelMemoryEvent {
                timestamp_ns: 1,
                pid: 1,
                tgid: 1,
                syscall: 5,
                args: [0; SYSCALL_ARG_COUNT],
                comm: [0; TASK_COMM_LEN],
            };
            let sample = RingBufferSample {
                kernel,
                syscall_ret: 0,
                uid: 0,
                _reserved: 0,
                layout_version: RING_SAMPLE_LAYOUT_VERSION,
                payload_blob: payload,
            };
            let mut bytes = [0u8; RingBufferSample::wire_size()];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (&sample as *const RingBufferSample).cast::<u8>(),
                    bytes.as_mut_ptr(),
                    bytes.len(),
                );
            }
            let ev = MemoryEvent::from_bytes(&bytes).expect("ring sample v5");
            assert!(ev.execve_cmdline.ends_with("Z_END_MARK_9"));
            assert_eq!(ev.execve_cmdline.len(), RING_PAYLOAD_BLOB_LEN);
        }

        /// Validates parsing of an all-zero raw kernel event for syscall id 1 (mmap with zero fields).
        #[test]
        fn memory_event_all_zero_raw_mmap() {
            let raw = KernelMemoryEvent {
                timestamp_ns: 0,
                pid: 0,
                tgid: 0,
                syscall: 1,
                args: [0; SYSCALL_ARG_COUNT],
                comm: [0; TASK_COMM_LEN],
            };
            let bytes = super::kernel_memory_event_to_bytes(&raw);
            let ev = MemoryEvent::from_bytes(&bytes).expect("mmap zero should parse");
            assert_eq!(ev.event_type, EventType::Mmap);
            assert_eq!(ev.addr, 0);
            assert_eq!(ev.len, 0);
            assert_eq!(ev.flags, 0);
        }
    }
}
