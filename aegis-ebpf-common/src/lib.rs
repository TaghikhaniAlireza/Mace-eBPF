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
pub struct MemoryEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub syscall: u32,
    pub args: [u64; SYSCALL_ARG_COUNT],
    pub comm: [u8; TASK_COMM_LEN],
}

impl MemoryEvent {
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
