//! Execve argv wire format (ring buffer layout v11+): NUL-separated arguments captured in eBPF
//! at `sys_enter_execve` / `sys_enter_execveat`, parsed in userspace without relying on `/proc/<pid>/cmdline`.

pub use mace_ebpf_common::parse_execve_argv_from_payload;

/// Split the v11+ execve payload (header + argv blob) into lossy UTF-8 [`String`] segments.
#[must_use]
pub fn parse_execve_argv_strings(blob: &[u8]) -> Vec<String> {
    parse_execve_argv_from_payload(blob)
}

#[cfg(test)]
mod tests {
    use mace_ebpf_common::{EXECVE_ARG_BLOB_LEN, EXECVE_WIRE_HEADER_LEN, ExecveWireHeader};

    use super::*;

    #[test]
    fn parse_three_args() {
        let mut blob = vec![0u8; EXECVE_WIRE_HEADER_LEN + EXECVE_ARG_BLOB_LEN];
        let argv = b"a\0b\0c\0";
        let hdr = ExecveWireHeader {
            pid: 1,
            args_count: 3,
            args_len: argv.len() as u32,
            is_truncated: 0,
        };
        unsafe {
            core::ptr::write_unaligned(blob.as_mut_ptr().cast(), hdr);
        }
        blob[EXECVE_WIRE_HEADER_LEN..EXECVE_WIRE_HEADER_LEN + argv.len()].copy_from_slice(argv);
        let v = parse_execve_argv_strings(&blob[..EXECVE_WIRE_HEADER_LEN + argv.len()]);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], "a");
        assert_eq!(v[1], "b");
        assert_eq!(v[2], "c");
    }

    #[test]
    fn parse_invalid_utf8_lossy() {
        let mut blob = vec![0u8; EXECVE_WIRE_HEADER_LEN + 8];
        let argv = [b'a', 0, 0xff, 0xff, 0];
        let hdr = ExecveWireHeader {
            pid: 2,
            args_count: 2,
            args_len: argv.len() as u32,
            is_truncated: 0,
        };
        unsafe {
            core::ptr::write_unaligned(blob.as_mut_ptr().cast(), hdr);
        }
        blob[EXECVE_WIRE_HEADER_LEN..EXECVE_WIRE_HEADER_LEN + argv.len()].copy_from_slice(&argv);
        let v = parse_execve_argv_strings(&blob[..EXECVE_WIRE_HEADER_LEN + argv.len()]);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], "a");
        assert_eq!(v[1].chars().next(), Some('\u{fffd}'));
    }
}
