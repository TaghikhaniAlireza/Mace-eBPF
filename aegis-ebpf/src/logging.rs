//! Aegis-specific log **severity** for the userspace core (independent of `RUST_LOG` granularity).
//!
//! Levels are ordered: `Trace` < `Info` < `Suppressed` < `Event` < `Alert`.
//! The active **filter floor** (minimum severity emitted) is raised to silence lower-noise lines
//! and avoid formatting / I/O when embedded callers set e.g. [`AegisLogLevel::Alert`] via FFI.

#[cfg(not(test))]
use std::io::Write;
use std::{
    fmt,
    str::FromStr,
    sync::atomic::{AtomicU8, Ordering},
};

/// Ordinal severity for Aegis core diagnostics (pipeline, rule match audit, etc.).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum AegisLogLevel {
    Trace = 0,
    Info = 1,
    Suppressed = 2,
    Event = 3,
    Alert = 4,
}

impl AegisLogLevel {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Trace),
            1 => Some(Self::Info),
            2 => Some(Self::Suppressed),
            3 => Some(Self::Event),
            4 => Some(Self::Alert),
            _ => None,
        }
    }
}

impl fmt::Display for AegisLogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Trace => "TRACE",
            Self::Info => "INFO",
            Self::Suppressed => "SUPPRESSED",
            Self::Event => "EVENT",
            Self::Alert => "ALERT",
        };
        f.write_str(s)
    }
}

impl FromStr for AegisLogLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "TRACE" => Ok(Self::Trace),
            "INFO" => Ok(Self::Info),
            "SUPPRESSED" => Ok(Self::Suppressed),
            "EVENT" => Ok(Self::Event),
            "ALERT" => Ok(Self::Alert),
            _ => Err(()),
        }
    }
}

static FILTER_FLOOR: AtomicU8 = AtomicU8::new(AegisLogLevel::Trace as u8);

/// Returns true if a message at `level` should be emitted at the current filter floor.
#[inline]
pub fn is_enabled(level: AegisLogLevel) -> bool {
    level.as_u8() >= FILTER_FLOOR.load(Ordering::Relaxed)
}

/// Minimum severity to emit (messages below this are dropped before formatting).
#[inline]
pub fn filter_floor() -> AegisLogLevel {
    AegisLogLevel::from_u8(FILTER_FLOOR.load(Ordering::Relaxed)).unwrap_or(AegisLogLevel::Trace)
}

/// Set the filter floor (e.g. [`AegisLogLevel::Alert`] keeps only alert-tier lines).
#[inline]
pub fn set_filter_floor(level: AegisLogLevel) {
    FILTER_FLOOR.store(level.as_u8(), Ordering::Relaxed);
}

/// Read `AEGIS_LOG_LEVEL` once; if unset, leaves the current atomic value unchanged.
pub fn apply_env_log_level() {
    if let Ok(s) = std::env::var("AEGIS_LOG_LEVEL") {
        if let Ok(lvl) = s.parse::<AegisLogLevel>() {
            set_filter_floor(lvl);
        }
    }
}

#[cfg(test)]
static TEST_LOGS: std::sync::Mutex<Vec<(AegisLogLevel, String)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub fn reset_test_log_state() {
    let _ = take_test_logs();
    set_filter_floor(AegisLogLevel::Trace);
}

#[cfg(test)]
pub fn take_test_logs() -> Vec<(AegisLogLevel, String)> {
    TEST_LOGS
        .lock()
        .map(|mut g| std::mem::take(&mut *g))
        .unwrap_or_default()
}

/// Emit one Aegis log line when `is_enabled(level)` (stderr in production; in-memory under tests).
pub fn log_line(level: AegisLogLevel, args: fmt::Arguments<'_>) {
    if !is_enabled(level) {
        return;
    }
    let line = format!("[Aegis][{level}] {args}");
    #[cfg(test)]
    {
        if let Ok(mut g) = TEST_LOGS.lock() {
            g.push((level, line));
        }
    }
    #[cfg(not(test))]
    {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "{line}");
    }
}

/// `aegis_log!(Alert, "rule={}", id);`
#[macro_export]
macro_rules! aegis_log {
    ($lvl:ident, $($arg:tt)*) => {{
        $crate::logging::log_line(
            $crate::logging::AegisLogLevel::$lvl,
            format_args!($($arg)*),
        )
    }};
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;

    #[test]
    #[serial(aegis_log)]
    fn alert_floor_hides_lower_severities() {
        reset_test_log_state();
        set_filter_floor(AegisLogLevel::Alert);
        log_line(AegisLogLevel::Trace, format_args!("t"));
        log_line(AegisLogLevel::Info, format_args!("i"));
        log_line(AegisLogLevel::Alert, format_args!("a"));
        let logs = take_test_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, AegisLogLevel::Alert);
        assert!(logs[0].1.contains("a"));
        set_filter_floor(AegisLogLevel::Trace);
    }

    #[test]
    #[serial(aegis_log)]
    fn trace_floor_shows_all() {
        reset_test_log_state();
        set_filter_floor(AegisLogLevel::Trace);
        log_line(AegisLogLevel::Trace, format_args!("x"));
        log_line(AegisLogLevel::Event, format_args!("y"));
        let logs = take_test_logs();
        assert_eq!(logs.len(), 2);
        set_filter_floor(AegisLogLevel::Trace);
    }

    #[test]
    #[serial(aegis_log)]
    fn event_floor_includes_event_and_alert() {
        reset_test_log_state();
        set_filter_floor(AegisLogLevel::Event);
        log_line(AegisLogLevel::Suppressed, format_args!("s"));
        log_line(AegisLogLevel::Event, format_args!("e"));
        log_line(AegisLogLevel::Alert, format_args!("a"));
        let logs = take_test_logs();
        assert_eq!(logs.len(), 2);
        set_filter_floor(AegisLogLevel::Trace);
    }

    #[test]
    #[serial(aegis_log)]
    fn parse_level_roundtrip() {
        assert_eq!(
            "TRACE".parse::<AegisLogLevel>().unwrap(),
            AegisLogLevel::Trace
        );
        assert_eq!(
            "alert".parse::<AegisLogLevel>().unwrap(),
            AegisLogLevel::Alert
        );
        assert!("nope".parse::<AegisLogLevel>().is_err());
    }
}
