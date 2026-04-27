//! Path and command-line normalization before rule matching (anti-evasion for redundant slashes, etc.).

/// Collapse `//`, strip `./`, resolve `..` for absolute paths; best-effort for relative paths.
pub fn normalize_unix_path(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }
    let abs = s.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for part in s.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if abs {
                stack.pop();
            } else if stack.last() != Some(&"..") {
                if stack.is_empty() {
                    stack.push("..");
                } else {
                    stack.pop();
                }
            } else {
                stack.push("..");
            }
        } else {
            stack.push(part);
        }
    }
    let inner = stack.join("/");
    if abs {
        format!("/{inner}")
    } else if inner.is_empty() {
        ".".into()
    } else {
        inner
    }
}

/// Trim and collapse inner whitespace in cmdline snapshots.
pub fn normalize_cmdline(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapse_double_slash() {
        assert_eq!(normalize_unix_path("/etc//shadow"), "/etc/shadow");
    }

    #[test]
    fn dot_dot() {
        assert_eq!(normalize_unix_path("/etc/foo/../shadow"), "/etc/shadow");
    }
}
