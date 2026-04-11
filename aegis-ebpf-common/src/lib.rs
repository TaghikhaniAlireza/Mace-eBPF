#![no_std]

pub const TASK_COMM_LEN: usize = 16;
pub const SYSCALL_ARG_COUNT: usize = 6;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemorySyscall {
    Mmap = 1,
    Mprotect = 2,
    MemfdCreate = 3,
    Ptrace = 4,
}

impl MemorySyscall {
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Mmap),
            2 => Some(Self::Mprotect),
            3 => Some(Self::MemfdCreate),
            4 => Some(Self::Ptrace),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mmap => "mmap",
            Self::Mprotect => "mprotect",
            Self::MemfdCreate => "memfd_create",
            Self::Ptrace => "ptrace",
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
#[derive(Clone, Copy, Debug)]
pub enum EventType {
    Mmap = 0,
    MprotectWX = 1,
    MemfdCreate = 2,
    Ptrace = 3,
}

impl EventType {
    pub const fn from_syscall(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Mmap),
            2 => Some(Self::MprotectWX),
            3 => Some(Self::MemfdCreate),
            4 => Some(Self::Ptrace),
            _ => None,
        }
    }
}

#[cfg(not(feature = "user"))]
pub type MemoryEvent = KernelMemoryEvent;

#[cfg(feature = "user")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemoryEvent {
    pub timestamp_ns: u64,
    pub tgid: u32,
    pub pid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub event_type: EventType,
    pub addr: u64,
    pub len: u64,
    pub flags: u64,
    pub ret: i64,
}

#[cfg(feature = "user")]
impl MemoryEvent {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let raw = KernelMemoryEvent::from_bytes(bytes)?;
        let event_type = EventType::from_syscall(raw.syscall)?;

        let (addr, len, flags) = match event_type {
            EventType::Mmap => (raw.args[0], raw.args[1], raw.args[3]),
            EventType::MprotectWX => (raw.args[0], raw.args[1], raw.args[2]),
            EventType::MemfdCreate => (raw.args[0], 0, raw.args[1]),
            EventType::Ptrace => (raw.args[2], 0, raw.args[0]),
        };

        Some(Self {
            timestamp_ns: raw.timestamp_ns,
            tgid: raw.tgid,
            pid: raw.pid,
            comm: raw.comm,
            event_type,
            addr,
            len,
            flags,
            ret: 0,
        })
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for MemoryEvent {}
