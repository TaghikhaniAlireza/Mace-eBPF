//! Best-effort `/etc/passwd` lookup: map effective UID to login name (cached).

use std::{
    collections::HashMap,
    fs,
    sync::{OnceLock, RwLock},
};

static CACHE: OnceLock<RwLock<HashMap<u32, Option<String>>>> = OnceLock::new();

fn cache() -> &'static RwLock<HashMap<u32, Option<String>>> {
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Return the first field (username) for `uid` from `/etc/passwd`, or `None` if unknown.
pub fn username_for_uid(uid: u32) -> Option<String> {
    {
        let g = cache().read().ok()?;
        if let Some(v) = g.get(&uid) {
            return v.clone();
        }
    }
    let resolved = parse_passwd_for_uid(uid);
    if let Ok(mut w) = cache().write() {
        w.insert(uid, resolved.clone());
    }
    resolved
}

fn parse_passwd_for_uid(uid: u32) -> Option<String> {
    let data = fs::read_to_string("/etc/passwd").ok()?;
    for line in data.lines() {
        let mut parts = line.split(':');
        let name = parts.next()?;
        let _pw = parts.next()?;
        let uid_s = parts.next()?;
        let parsed: u32 = uid_s.parse().ok()?;
        if parsed == uid {
            return Some(name.to_string());
        }
    }
    None
}
