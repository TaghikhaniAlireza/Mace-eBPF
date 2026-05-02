pub mod loader;
pub mod watcher;

use std::{error::Error, fmt, fs};

use mace_ebpf_common::EventType;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    enrichment::normalization::{normalize_cmdline, normalize_unix_path},
    pipeline::EnrichedEvent,
    state::ProcessState,
};

/// `comm` field from a [`MemoryEvent`](mace_ebpf_common::MemoryEvent) as a lossy UTF-8 string.
pub fn comm_to_process_name(comm: &[u8; mace_ebpf_common::TASK_COMM_LEN]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;
pub const MAP_ANONYMOUS: u64 = 0x20;

/// Linux `PTRACE_ATTACH` (used for rule matching on ptrace events).
pub const PTRACE_ATTACH: u64 = 16;

/// YAML `suppression:` entries suppress **alerts** (and clear `matched_rules` in [`crate::StandardizedEvent`])
/// when an event matches; detection rules are still evaluated for audit (`suppressed_by` is set).
#[derive(Clone, Debug, Deserialize)]
pub struct SuppressionEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub conditions: Conditions,
    #[serde(skip)]
    pub cgroup_regex: Option<Regex>,
    #[serde(skip)]
    pub process_name_regex: Option<Regex>,
    #[serde(skip)]
    pub pathname_regex: Option<Regex>,
    #[serde(skip)]
    pub cmdline_context_regex: Option<Regex>,
    #[serde(skip)]
    pub target_process_regex: Option<Regex>,
    #[serde(skip)]
    pub memfd_name_regex: Option<Regex>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum EnforcementMode {
    #[default]
    Enforce,
    /// Dry-run: match for telemetry / false-positive study; does not drive alert callback or enforce-path JSON.
    Shadow,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
    pub conditions: Conditions,
    #[serde(default)]
    pub stateful: Option<StatefulConditions>,
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
    /// Filled at load time from `conditions.cgroup_pattern` (never compile per event).
    #[serde(skip)]
    pub cgroup_regex: Option<Regex>,
    /// Filled at load time from `conditions.process_name_pattern` (never compile per event).
    #[serde(skip)]
    pub process_name_regex: Option<Regex>,
    /// Filled at load time from `conditions.pathname_pattern` for `openat` rules.
    #[serde(skip)]
    pub pathname_regex: Option<Regex>,
    /// Regex against inherited / current exec command line (execve snapshot or `cmdline_context` on later syscalls).
    #[serde(skip)]
    pub cmdline_context_regex: Option<Regex>,
    /// Compiled from `conditions.target_process_pattern` (ptrace target `comm`).
    #[serde(skip)]
    pub target_process_regex: Option<Regex>,
    /// Compiled from `conditions.memfd_name_pattern`.
    #[serde(skip)]
    pub memfd_name_regex: Option<Regex>,
    /// Ordered per-TGID state machine (optional).
    #[serde(default)]
    pub sequence: Option<SequenceRule>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub mitre_tactics: Vec<String>,
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Conditions {
    pub syscall: Option<String>,
    #[serde(default)]
    pub flags_contains: Vec<String>,
    #[serde(default)]
    pub flags_excludes: Vec<String>,
    /// Require `(event.flags & mask) == mask` (bitwise). Useful for exact `mprotect` prot combinations.
    #[serde(default)]
    pub flags_mask_all: Option<u64>,
    /// Require `(event.flags & mask) == 0` (none of these bits set).
    #[serde(default)]
    pub flags_mask_none: Option<u64>,
    pub min_size: Option<u64>,
    pub cgroup_pattern: Option<String>,
    /// Regex matched against the process `comm` (task name), e.g. `"^cat$"`.
    #[serde(default)]
    pub process_name_pattern: Option<String>,
    /// Substrings that must all appear in `/proc/<pid>/cmdline` (NULs replaced with spaces).
    /// Intended for `syscall: execve` rules (e.g. detect `whoami` in argv).
    #[serde(default)]
    pub argv_contains: Vec<String>,
    /// If set, effective UID from the event must match (from eBPF `bpf_get_current_uid_gid` at syscall exit).
    pub uid: Option<u32>,
    /// At least one substring must appear in the execve command line (prefers eBPF `execve_cmdline`, else `/proc` cmdline).
    #[serde(default)]
    pub cmdline_contains_any: Vec<String>,
    /// Regex matched against the resolved pathname for `syscall: openat` (in-kernel pathname snapshot).
    #[serde(default)]
    pub pathname_pattern: Option<String>,
    /// Regex matched against the command-line haystack (`execve_cmdline` or inherited `cmdline_context` from the pipeline).
    #[serde(default)]
    pub cmdline_context_pattern: Option<String>,
    /// Optional `ptrace` request number (e.g. 16 for `PTRACE_ATTACH`); if set, must equal `event.flags`.
    #[serde(default)]
    pub ptrace_request: Option<u64>,
    /// Sliding-window frequency: at least `min_occurrences` of `syscall` within `window_secs` for this TGID.
    #[serde(default)]
    pub frequency_window: Option<FrequencyWindow>,
    /// If true, require `event.inner.ret < 0` (syscall failure). Combine with `frequency_window` for brute-force style rules.
    #[serde(default)]
    pub syscall_failures_only: bool,
    /// Regex against **target** process `comm` for `ptrace` (`event.inner.len` holds target pid).
    #[serde(default)]
    pub target_process_pattern: Option<String>,
    /// Each substring must appear in `/proc/<pid>/environ` (NULs → newlines) for `execve` events.
    #[serde(default)]
    pub env_contains: Vec<String>,
    /// Regex against `memfd_create` name snapshot (`MemoryEvent.memfd_name`).
    #[serde(default)]
    pub memfd_name_pattern: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FrequencyWindow {
    pub min_occurrences: usize,
    pub syscall: String,
    /// Sliding window length in seconds (converted to ns at evaluation time).
    pub window_secs: u64,
}

/// Ordered syscall sequence per TGID. When set, the rule matches only when the **last** step is
/// observed and `conditions` match that final event; intermediate syscalls may be ignored if
/// `allow_unmapped_between` is true (noise tolerance).
#[derive(Clone, Debug, Deserialize)]
pub struct SequenceRule {
    /// Syscall names in order, e.g. `["mmap", "mprotect", "memfd_create"]`.
    #[serde(default)]
    pub steps: Vec<String>,
    /// If true, syscalls not listed in `steps` do not reset progress (only a wrong **mapped** step resets).
    #[serde(default)]
    pub allow_unmapped_between: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct StatefulConditions {
    pub min_event_count: Option<usize>,
    pub min_mprotect_exec_count: Option<usize>,
    pub min_rwx_bytes: Option<u64>,
}

#[derive(Debug)]
pub enum RuleError {
    IoError(std::io::Error),
    ParseError(serde_yaml::Error),
    InvalidCondition(String),
}

impl Rule {
    pub fn matches(&self, event: &EnrichedEvent) -> bool {
        self.matches_with_state(event, None)
    }

    pub fn matches_with_state(&self, event: &EnrichedEvent, state: Option<&ProcessState>) -> bool {
        if let Some(seq) = &self.sequence {
            if seq.steps.is_empty() {
                return false;
            }
            let Some(st) = state else {
                return false;
            };
            let n = seq.steps.len();
            let idx = *st.sequence_progress.get(&self.id).unwrap_or(&0);
            if idx != n {
                return false;
            }
            let last = seq.steps[n - 1].as_str();
            if !last.eq_ignore_ascii_case(event_syscall_name(event)) {
                return false;
            }
        }

        evaluate_rule_conditions(
            &self.conditions,
            self.process_name_regex.as_ref(),
            self.cgroup_regex.as_ref(),
            self.pathname_regex.as_ref(),
            self.cmdline_context_regex.as_ref(),
            self.target_process_regex.as_ref(),
            self.memfd_name_regex.as_ref(),
            event,
            state,
            self.stateful.as_ref(),
        )
    }

    /// Update per-TGID sequence progress for this rule **before** evaluating [`Self::matches_with_state`].
    pub fn advance_sequence(&self, event: &EnrichedEvent, state: &mut ProcessState) {
        let Some(seq) = &self.sequence else {
            return;
        };
        if seq.steps.is_empty() {
            return;
        }
        let entry = state.sequence_progress.entry(self.id.clone()).or_insert(0);
        let mut idx = *entry;
        if idx >= seq.steps.len() {
            idx = 0;
        }
        let cur = event_syscall_name(event);
        let expected = seq.steps[idx].as_str();
        if cur.eq_ignore_ascii_case(expected) {
            idx += 1;
            *entry = idx;
            return;
        }
        let maps_to_step = seq
            .steps
            .iter()
            .any(|s| s.as_str().eq_ignore_ascii_case(cur));
        if maps_to_step {
            *entry = 0;
            if seq.steps[0].as_str().eq_ignore_ascii_case(cur) {
                *entry = 1;
            }
        } else if !seq.allow_unmapped_between {
            *entry = 0;
        }
    }

    /// After a rule matched, allow a new chain to start.
    pub fn reset_sequence_progress(&self, state: &mut ProcessState) {
        if self.sequence.is_some() {
            state.sequence_progress.insert(self.id.clone(), 0);
        }
    }
}

/// Shared condition evaluation for [`Rule`] and [`SuppressionEntry`] (`stateful` is ignored for suppressions).
#[allow(clippy::too_many_arguments)] // Mirrors optional regex refs + optional state bundle.
pub(crate) fn evaluate_rule_conditions(
    conditions: &Conditions,
    process_name_regex: Option<&Regex>,
    cgroup_regex: Option<&Regex>,
    pathname_regex: Option<&Regex>,
    cmdline_context_regex: Option<&Regex>,
    target_process_regex: Option<&Regex>,
    memfd_name_regex: Option<&Regex>,
    event: &EnrichedEvent,
    state: Option<&ProcessState>,
    stateful: Option<&StatefulConditions>,
) -> bool {
    if let Some(expected) = conditions.syscall.as_deref()
        && !expected.eq_ignore_ascii_case(event_syscall_name(event))
    {
        return false;
    }

    let flags = event.inner.flags;
    if !conditions
        .flags_contains
        .iter()
        .all(|name| is_flag_present(flags, name))
    {
        return false;
    }

    if conditions
        .flags_excludes
        .iter()
        .any(|name| is_flag_present(flags, name))
    {
        return false;
    }

    if let Some(mask) = conditions.flags_mask_all
        && (flags & mask) != mask
    {
        return false;
    }

    if let Some(mask) = conditions.flags_mask_none
        && (flags & mask) != 0
    {
        return false;
    }

    if conditions.syscall_failures_only && event.inner.ret >= 0 {
        return false;
    }

    if let Some(fw) = &conditions.frequency_window {
        let Some(st) = state else {
            return false;
        };
        if fw.window_secs == 0 || fw.min_occurrences == 0 {
            return false;
        }
        let window_ns = fw.window_secs.saturating_mul(1_000_000_000);
        let cnt = st.frequency_count(
            fw.syscall.as_str(),
            window_ns,
            event.inner.timestamp_ns,
            conditions.syscall_failures_only,
        );
        if cnt < fw.min_occurrences {
            return false;
        }
    }

    if let Some(min_size) = conditions.min_size
        && event.inner.len < min_size
    {
        return false;
    }

    let process_name = comm_to_process_name(&event.inner.comm);
    if let Some(regex) = process_name_regex {
        if !regex.is_match(&process_name) {
            return false;
        }
    }

    if let Some(regex) = cgroup_regex {
        let Some(path) = event_cgroup_path(event) else {
            return false;
        };
        if !regex.is_match(&path) {
            return false;
        }
    }

    if let Some(expected_uid) = conditions.uid
        && event.inner.uid != expected_uid
    {
        return false;
    }

    if !conditions.argv_contains.is_empty() {
        let Some(cmdline) = rule_cmdline_haystack(event) else {
            return false;
        };
        if !conditions
            .argv_contains
            .iter()
            .all(|needle| cmdline.contains(needle.as_str()))
        {
            return false;
        }
    }

    if !conditions.cmdline_contains_any.is_empty() {
        let Some(cmdline) = rule_cmdline_haystack(event) else {
            return false;
        };
        if !conditions
            .cmdline_contains_any
            .iter()
            .any(|needle| cmdline.contains(needle.as_str()))
        {
            return false;
        }
    }

    if let Some(rx) = cmdline_context_regex {
        let Some(cmdline) = rule_cmdline_haystack(event) else {
            return false;
        };
        if !rx.is_match(&cmdline) {
            return false;
        }
    }

    if let Some(regex) = pathname_regex {
        if event.inner.event_type != EventType::Openat {
            return false;
        }
        let Some(path) = openat_resolved_path_for_rules(event) else {
            return false;
        };
        if !regex.is_match(&path) {
            return false;
        }
    }

    if let Some(req) = conditions.ptrace_request {
        if event.inner.event_type != EventType::Ptrace {
            return false;
        }
        if event.inner.flags != req {
            return false;
        }
    }

    if let Some(rx) = target_process_regex {
        if event.inner.event_type != EventType::Ptrace {
            return false;
        }
        let Ok(tid) = u32::try_from(event.inner.len) else {
            return false;
        };
        let Some(comm) = read_proc_comm_flat(tid) else {
            return false;
        };
        if !rx.is_match(&comm) {
            return false;
        }
    }

    if let Some(rx) = memfd_name_regex {
        if event.inner.event_type != EventType::MemfdCreate {
            return false;
        }
        if !rx.is_match(&event.inner.memfd_name) {
            return false;
        }
    }

    if !conditions.env_contains.is_empty() {
        if event.inner.event_type != EventType::Execve {
            return false;
        }
        let Some(env) = read_proc_environ_flat(event.inner.tgid) else {
            return false;
        };
        if !conditions
            .env_contains
            .iter()
            .all(|needle| env.contains(needle.as_str()))
        {
            return false;
        }
    }

    if let Some(stateful) = stateful {
        let Some(state) = state else {
            return false;
        };
        if let Some(min_event_count) = stateful.min_event_count
            && state.event_count < min_event_count
        {
            return false;
        }
        if let Some(min_mprotect_exec_count) = stateful.min_mprotect_exec_count
            && state.mprotect_exec_count < min_mprotect_exec_count
        {
            return false;
        }
        if let Some(min_rwx_bytes) = stateful.min_rwx_bytes
            && state.total_rwx_bytes < min_rwx_bytes
        {
            return false;
        }
    }

    true
}

impl SuppressionEntry {
    pub fn matches(&self, event: &EnrichedEvent) -> bool {
        evaluate_rule_conditions(
            &self.conditions,
            self.process_name_regex.as_ref(),
            self.cgroup_regex.as_ref(),
            self.pathname_regex.as_ref(),
            self.cmdline_context_regex.as_ref(),
            self.target_process_regex.as_ref(),
            self.memfd_name_regex.as_ref(),
            event,
            None,
            None,
        )
    }
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoError(err) => write!(f, "rule I/O error: {err}"),
            Self::ParseError(err) => write!(f, "rule parse error: {err}"),
            Self::InvalidCondition(msg) => write!(f, "invalid rule condition: {msg}"),
        }
    }
}

impl Error for RuleError {}

impl From<std::io::Error> for RuleError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

impl From<serde_yaml::Error> for RuleError {
    fn from(value: serde_yaml::Error) -> Self {
        Self::ParseError(value)
    }
}

pub(crate) fn validate_rule(rule: &Rule) -> Result<(), RuleError> {
    if rule.id.trim().is_empty() {
        return Err(RuleError::InvalidCondition(
            "rule id cannot be empty".into(),
        ));
    }
    if rule.name.trim().is_empty() {
        return Err(RuleError::InvalidCondition(
            "rule name cannot be empty".into(),
        ));
    }
    validate_conditions_structured(&rule.conditions)?;
    if let Some(seq) = &rule.sequence {
        if seq.steps.is_empty() {
            return Err(RuleError::InvalidCondition(
                "sequence.steps cannot be empty when sequence is set".into(),
            ));
        }
        for step in &seq.steps {
            if !is_supported_syscall(step) {
                return Err(RuleError::InvalidCondition(format!(
                    "sequence step has unsupported syscall: {step}"
                )));
            }
        }
        if let Some(last_cond) = rule.conditions.syscall.as_deref() {
            let last_step = seq.steps.last().expect("steps non-empty");
            if !last_step.eq_ignore_ascii_case(last_cond) {
                return Err(RuleError::InvalidCondition(format!(
                    "conditions.syscall must match the last sequence step (got {last_cond}, last step {last_step})"
                )));
            }
        }
    }
    Ok(())
}

/// Validates [`Conditions`] shared by rules and [`SuppressionEntry`] (regex syntax only — compilation is separate).
pub(crate) fn validate_conditions_structured(conditions: &Conditions) -> Result<(), RuleError> {
    if let Some(syscall) = conditions.syscall.as_deref()
        && !is_supported_syscall(syscall)
    {
        return Err(RuleError::InvalidCondition(format!(
            "unsupported syscall condition: {syscall}"
        )));
    }

    if conditions.pathname_pattern.is_some() {
        let ok = conditions
            .syscall
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("openat"))
            .unwrap_or(false);
        if !ok {
            return Err(RuleError::InvalidCondition(
                "pathname_pattern requires syscall: openat".into(),
            ));
        }
    }

    if conditions.ptrace_request.is_some() {
        let ok = conditions
            .syscall
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("ptrace"))
            .unwrap_or(false);
        if !ok {
            return Err(RuleError::InvalidCondition(
                "ptrace_request requires syscall: ptrace".into(),
            ));
        }
    }

    if let Some(fw) = &conditions.frequency_window {
        if fw.min_occurrences == 0 {
            return Err(RuleError::InvalidCondition(
                "frequency_window.min_occurrences must be >= 1".into(),
            ));
        }
        if fw.window_secs == 0 {
            return Err(RuleError::InvalidCondition(
                "frequency_window.window_secs must be >= 1".into(),
            ));
        }
        if !is_supported_syscall(&fw.syscall) {
            return Err(RuleError::InvalidCondition(format!(
                "frequency_window.syscall unsupported: {}",
                fw.syscall
            )));
        }
    }

    if conditions.syscall_failures_only && conditions.frequency_window.is_none() {
        return Err(RuleError::InvalidCondition(
            "syscall_failures_only requires frequency_window".into(),
        ));
    }

    if conditions.target_process_pattern.is_some() {
        let ok = conditions
            .syscall
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("ptrace"))
            .unwrap_or(false);
        if !ok {
            return Err(RuleError::InvalidCondition(
                "target_process_pattern requires syscall: ptrace".into(),
            ));
        }
    }

    if conditions.memfd_name_pattern.is_some() {
        let ok = conditions
            .syscall
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("memfd_create"))
            .unwrap_or(false);
        if !ok {
            return Err(RuleError::InvalidCondition(
                "memfd_name_pattern requires syscall: memfd_create".into(),
            ));
        }
    }

    if !conditions.env_contains.is_empty() {
        let ok = conditions
            .syscall
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("execve"))
            .unwrap_or(false);
        if !ok {
            return Err(RuleError::InvalidCondition(
                "env_contains requires syscall: execve".into(),
            ));
        }
    }

    for flag in &conditions.flags_contains {
        validate_flag_name(flag)?;
    }
    for flag in &conditions.flags_excludes {
        validate_flag_name(flag)?;
    }
    if let Some(pattern) = conditions.cgroup_pattern.as_deref() {
        Regex::new(pattern).map_err(|err| {
            RuleError::InvalidCondition(format!("invalid cgroup_pattern regex '{pattern}': {err}"))
        })?;
    }
    if let Some(pattern) = conditions.process_name_pattern.as_deref() {
        Regex::new(pattern).map_err(|err| {
            RuleError::InvalidCondition(format!(
                "invalid process_name_pattern regex '{pattern}': {err}"
            ))
        })?;
    }
    if let Some(pattern) = conditions.pathname_pattern.as_deref() {
        Regex::new(pattern).map_err(|err| {
            RuleError::InvalidCondition(format!(
                "invalid pathname_pattern regex '{pattern}': {err}"
            ))
        })?;
    }
    if let Some(pattern) = conditions.cmdline_context_pattern.as_deref() {
        Regex::new(pattern).map_err(|err| {
            RuleError::InvalidCondition(format!(
                "invalid cmdline_context_pattern regex '{pattern}': {err}"
            ))
        })?;
    }
    if let Some(pattern) = conditions.target_process_pattern.as_deref() {
        Regex::new(pattern).map_err(|err| {
            RuleError::InvalidCondition(format!(
                "invalid target_process_pattern regex '{pattern}': {err}"
            ))
        })?;
    }
    if let Some(pattern) = conditions.memfd_name_pattern.as_deref() {
        Regex::new(pattern).map_err(|err| {
            RuleError::InvalidCondition(format!(
                "invalid memfd_name_pattern regex '{pattern}': {err}"
            ))
        })?;
    }
    Ok(())
}

pub(crate) fn validate_suppression_entry(entry: &SuppressionEntry) -> Result<(), RuleError> {
    if entry.id.trim().is_empty() {
        return Err(RuleError::InvalidCondition(
            "suppression id cannot be empty".into(),
        ));
    }
    if entry.name.trim().is_empty() {
        return Err(RuleError::InvalidCondition(
            "suppression name cannot be empty".into(),
        ));
    }
    let c = &entry.conditions;
    if c.frequency_window.is_some() || c.syscall_failures_only {
        return Err(RuleError::InvalidCondition(
            "suppressions cannot use frequency_window or syscall_failures_only".into(),
        ));
    }
    validate_conditions_structured(&entry.conditions)
}

/// Compile regex fields on each rule after YAML parse. Call after `validate_rule` for each rule.
pub(crate) fn compile_rule_regexes(rule: &mut Rule) -> Result<(), RuleError> {
    rule.cgroup_regex = match rule.conditions.cgroup_pattern.as_deref() {
        Some(p) => Some(Regex::new(p).map_err(|e| {
            RuleError::InvalidCondition(format!("cgroup_pattern compile error: {e}"))
        })?),
        None => None,
    };
    rule.process_name_regex = match rule.conditions.process_name_pattern.as_deref() {
        Some(p) => Some(Regex::new(p).map_err(|e| {
            RuleError::InvalidCondition(format!("process_name_pattern compile error: {e}"))
        })?),
        None => None,
    };
    rule.pathname_regex = match rule.conditions.pathname_pattern.as_deref() {
        Some(p) => Some(Regex::new(p).map_err(|e| {
            RuleError::InvalidCondition(format!("pathname_pattern compile error: {e}"))
        })?),
        None => None,
    };
    rule.cmdline_context_regex = match rule.conditions.cmdline_context_pattern.as_deref() {
        Some(p) => Some(Regex::new(p).map_err(|e| {
            RuleError::InvalidCondition(format!("cmdline_context_pattern compile error: {e}"))
        })?),
        None => None,
    };
    rule.target_process_regex = match rule.conditions.target_process_pattern.as_deref() {
        Some(p) => Some(Regex::new(p).map_err(|e| {
            RuleError::InvalidCondition(format!("target_process_pattern compile error: {e}"))
        })?),
        None => None,
    };
    rule.memfd_name_regex = match rule.conditions.memfd_name_pattern.as_deref() {
        Some(p) => Some(Regex::new(p).map_err(|e| {
            RuleError::InvalidCondition(format!("memfd_name_pattern compile error: {e}"))
        })?),
        None => None,
    };
    Ok(())
}

pub(crate) fn compile_suppression_regexes(entry: &mut SuppressionEntry) -> Result<(), RuleError> {
    entry.cgroup_regex = match entry.conditions.cgroup_pattern.as_deref() {
        Some(p) => Some(Regex::new(p).map_err(|e| {
            RuleError::InvalidCondition(format!("cgroup_pattern compile error: {e}"))
        })?),
        None => None,
    };
    entry.process_name_regex = match entry.conditions.process_name_pattern.as_deref() {
        Some(p) => Some(Regex::new(p).map_err(|e| {
            RuleError::InvalidCondition(format!("process_name_pattern compile error: {e}"))
        })?),
        None => None,
    };
    entry.pathname_regex = match entry.conditions.pathname_pattern.as_deref() {
        Some(p) => Some(Regex::new(p).map_err(|e| {
            RuleError::InvalidCondition(format!("pathname_pattern compile error: {e}"))
        })?),
        None => None,
    };
    entry.cmdline_context_regex = match entry.conditions.cmdline_context_pattern.as_deref() {
        Some(p) => Some(Regex::new(p).map_err(|e| {
            RuleError::InvalidCondition(format!("cmdline_context_pattern compile error: {e}"))
        })?),
        None => None,
    };
    entry.target_process_regex = match entry.conditions.target_process_pattern.as_deref() {
        Some(p) => Some(Regex::new(p).map_err(|e| {
            RuleError::InvalidCondition(format!("target_process_pattern compile error: {e}"))
        })?),
        None => None,
    };
    entry.memfd_name_regex = match entry.conditions.memfd_name_pattern.as_deref() {
        Some(p) => Some(Regex::new(p).map_err(|e| {
            RuleError::InvalidCondition(format!("memfd_name_pattern compile error: {e}"))
        })?),
        None => None,
    };
    Ok(())
}

fn validate_flag_name(name: &str) -> Result<(), RuleError> {
    if flag_bit(name).is_none() && !name.eq_ignore_ascii_case("MAP_FILE") {
        return Err(RuleError::InvalidCondition(format!(
            "unsupported flag name: {name}"
        )));
    }
    Ok(())
}

fn event_syscall_name(event: &EnrichedEvent) -> &'static str {
    match event.inner.event_type {
        EventType::Mmap => "mmap",
        EventType::MprotectWX => "mprotect",
        EventType::MemfdCreate => "memfd_create",
        EventType::Ptrace => "ptrace",
        EventType::Execve => "execve",
        EventType::Openat => "openat",
    }
}

fn is_supported_syscall(syscall: &str) -> bool {
    matches!(
        syscall.to_ascii_lowercase().as_str(),
        "mmap" | "mprotect" | "memfd_create" | "ptrace" | "execve" | "openat"
    )
}

fn rule_cmdline_haystack(event: &EnrichedEvent) -> Option<String> {
    let raw = if !event.inner.execve_cmdline.is_empty() {
        Some(event.inner.execve_cmdline.clone())
    } else if let Some(ctx) = &event.cmdline_context {
        if !ctx.is_empty() {
            Some(ctx.clone())
        } else {
            None
        }
    } else {
        // Prefer TGID: `event.inner.pid` can be a thread id; `/proc/<tgid>/cmdline` is the stable
        // leader cmdline for rule haystack when eBPF argv is empty (default `execve_no_user_argv` build).
        read_proc_cmdline_flat(event.inner.tgid)
    }?;
    Some(normalize_execve_style_cmdline(&raw))
}

/// Normalize whitespace and obvious path tokens in execve/cmdline haystacks.
fn normalize_execve_style_cmdline(s: &str) -> String {
    let trimmed = normalize_cmdline(s);
    trimmed
        .split_whitespace()
        .map(|w| {
            if w.starts_with('/') || w.starts_with("./") || w.starts_with("../") {
                normalize_unix_path(w)
            } else {
                w.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_proc_cmdline_flat(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/cmdline");
    let raw = fs::read(&path).ok()?;
    let s = String::from_utf8_lossy(&raw);
    Some(
        s.split('\0')
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Task `comm` from `/proc/<pid>/comm` (16-byte kernel `comm`, newline-terminated in procfs).
fn read_proc_comm_flat(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/comm");
    let raw = fs::read(&path).ok()?;
    let s = String::from_utf8_lossy(&raw).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// `/proc/<pid>/environ` as a single string with NUL bytes replaced by newlines (substring search).
fn read_proc_environ_flat(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/environ");
    let raw = fs::read(&path).ok()?;
    if raw.is_empty() {
        return None;
    }
    let s = String::from_utf8_lossy(&raw).into_owned();
    Some(s.replace('\0', "\n"))
}

/// Build a normalized absolute-style path for `pathname_pattern` matching.
/// Uses in-kernel `openat_path` snapshot (no `process_vm_readv`); for relative paths, joins with
/// `/proc/<tgid>/fd/<dirfd>` when possible.
fn openat_resolved_path_for_rules(event: &EnrichedEvent) -> Option<String> {
    let raw = event.inner.openat_path.trim();
    if raw.is_empty() {
        return None;
    }
    let norm_piece = normalize_unix_path(raw);
    let dfd = event.inner.flags as i32;
    let path = if norm_piece.starts_with('/') || dfd == libc::AT_FDCWD {
        norm_piece
    } else {
        let proc_fd = format!("/proc/{}/fd/{dfd}", event.inner.tgid);
        let base = fs::read_link(&proc_fd).ok()?;
        base.join(norm_piece).to_string_lossy().into_owned()
    };
    Some(normalize_unix_path(&path))
}

fn event_cgroup_path(event: &EnrichedEvent) -> Option<String> {
    event
        .metadata
        .as_ref()
        .map(|meta| format!("/kubepods/{}/{}", meta.namespace, meta.pod_name))
}

fn is_flag_present(flags: u64, name: &str) -> bool {
    if name.eq_ignore_ascii_case("MAP_FILE") {
        // MAP_FILE is represented as "not MAP_ANONYMOUS" in Linux.
        return (flags & MAP_ANONYMOUS) == 0;
    }

    let Some(bit) = flag_bit(name) else {
        return false;
    };
    (flags & bit) != 0
}

fn flag_bit(name: &str) -> Option<u64> {
    match name.to_ascii_uppercase().as_str() {
        "PROT_READ" => Some(PROT_READ),
        "PROT_WRITE" => Some(PROT_WRITE),
        "PROT_EXEC" => Some(PROT_EXEC),
        "MAP_ANONYMOUS" => Some(MAP_ANONYMOUS),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        process::Command,
        sync::Arc,
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use mace_ebpf_common::{EventType, MemoryEvent};
    use serial_test::serial;
    use tokio::sync::mpsc;

    use super::{loader::RuleSet, *};
    use crate::{NoopEnricher, PipelineConfig, pipeline};

    fn fake_enriched_event(event_type: EventType, flags: u64, len: u64) -> crate::EnrichedEvent {
        crate::EnrichedEvent {
            inner: MemoryEvent {
                timestamp_ns: 1,
                tgid: 42,
                pid: 42,
                uid: 0,
                comm: [0; 16],
                event_type,
                addr: 0x1000,
                len,
                flags,
                ret: 0,
                execve_cmdline: String::new(),
                openat_path: String::new(),
                memfd_name: String::new(),
                execve_argv_truncated: false,
            },
            metadata: None,
            cmdline_context: None,
            username: None,
        }
    }

    #[test]
    fn rule_parsing_from_yaml() {
        let yaml = r#"
rules:
  - id: "MEM-001"
    name: "Example"
    severity: "high"
    description: "desc"
    conditions:
      syscall: "mprotect"
"#;
        let set = RuleSet::from_yaml_str(yaml).expect("yaml should parse");
        assert_eq!(set.rules.len(), 1);
        let rule = &set.rules[0];
        assert_eq!(rule.id, "MEM-001");
        assert_eq!(rule.name, "Example");
        assert_eq!(rule.severity, Severity::High);
    }

    #[test]
    fn argv_contains_matches_mmap_when_cmdline_context_set() {
        let rule = Rule {
            id: "CTX-MMAP".into(),
            name: "mmap after bad exec".into(),
            severity: Severity::High,
            description: "desc".into(),
            conditions: Conditions {
                syscall: Some("mmap".into()),
                argv_contains: vec!["evil".into()],
                ..Default::default()
            },
            stateful: None,
            enforcement_mode: EnforcementMode::Enforce,
            cgroup_regex: None,
            process_name_regex: None,
            pathname_regex: None,
            cmdline_context_regex: None,
            target_process_regex: None,
            memfd_name_regex: None,
            tags: vec![],
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            references: vec![],
            sequence: None,
        };
        let mut ev = fake_enriched_event(EventType::Mmap, 0, 4096);
        ev.cmdline_context = Some("/bin/evil.sh".into());
        assert!(rule.matches(&ev));
        ev.cmdline_context = None;
        assert!(!rule.matches(&ev));
    }

    #[test]
    fn uid_and_cmdline_contains_any_for_execve() {
        let rule = Rule {
            id: "R-UID-CMD".into(),
            name: "root sensitive".into(),
            severity: Severity::High,
            description: "desc".into(),
            conditions: Conditions {
                syscall: Some("execve".into()),
                uid: Some(0),
                cmdline_contains_any: vec!["whoami".into(), "cat /etc/shadow".into()],
                ..Default::default()
            },
            stateful: None,
            enforcement_mode: EnforcementMode::Enforce,
            cgroup_regex: None,
            process_name_regex: None,
            pathname_regex: None,
            cmdline_context_regex: None,
            target_process_regex: None,
            memfd_name_regex: None,
            tags: vec![],
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            references: vec![],
            sequence: None,
        };
        let mut ev = fake_enriched_event(EventType::Execve, 0, 0);
        ev.inner.uid = 0;
        ev.inner.execve_cmdline = "/bin/sh -c whoami".into();
        assert!(rule.matches(&ev));

        ev.inner.uid = 1;
        assert!(!rule.matches(&ev));

        ev.inner.uid = 0;
        ev.inner.execve_cmdline = "/bin/true".into();
        assert!(!rule.matches(&ev));
    }

    #[test]
    fn syscall_exact_match() {
        let rule = Rule {
            id: "R1".into(),
            name: "syscall".into(),
            severity: Severity::Low,
            description: "desc".into(),
            conditions: Conditions {
                syscall: Some("mprotect".into()),
                ..Default::default()
            },
            stateful: None,
            enforcement_mode: EnforcementMode::Enforce,
            cgroup_regex: None,
            process_name_regex: None,
            pathname_regex: None,
            cmdline_context_regex: None,
            target_process_regex: None,
            memfd_name_regex: None,
            tags: vec![],
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            references: vec![],
            sequence: None,
        };
        let mprotect_event = fake_enriched_event(EventType::MprotectWX, 0, 4096);
        let mmap_event = fake_enriched_event(EventType::Mmap, 0, 4096);
        assert!(rule.matches(&mprotect_event));
        assert!(!rule.matches(&mmap_event));
    }

    #[test]
    fn flags_contains_logic() {
        let rule = Rule {
            id: "R2".into(),
            name: "flags_contains".into(),
            severity: Severity::Medium,
            description: "desc".into(),
            conditions: Conditions {
                flags_contains: vec!["PROT_EXEC".into(), "PROT_WRITE".into()],
                ..Default::default()
            },
            stateful: None,
            enforcement_mode: EnforcementMode::Enforce,
            cgroup_regex: None,
            process_name_regex: None,
            pathname_regex: None,
            cmdline_context_regex: None,
            target_process_regex: None,
            memfd_name_regex: None,
            tags: vec![],
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            references: vec![],
            sequence: None,
        };

        let match_event = fake_enriched_event(
            EventType::MprotectWX,
            PROT_EXEC | PROT_WRITE | PROT_READ,
            4096,
        );
        let missing_event = fake_enriched_event(EventType::MprotectWX, PROT_EXEC, 4096);
        assert!(rule.matches(&match_event));
        assert!(!rule.matches(&missing_event));
    }

    #[test]
    fn flags_excludes_logic() {
        let rule = Rule {
            id: "R3".into(),
            name: "flags_excludes".into(),
            severity: Severity::Medium,
            description: "desc".into(),
            conditions: Conditions {
                flags_excludes: vec!["MAP_FILE".into()],
                ..Default::default()
            },
            stateful: None,
            enforcement_mode: EnforcementMode::Enforce,
            cgroup_regex: None,
            process_name_regex: None,
            pathname_regex: None,
            cmdline_context_regex: None,
            target_process_regex: None,
            memfd_name_regex: None,
            tags: vec![],
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            references: vec![],
            sequence: None,
        };

        let anonymous = fake_enriched_event(EventType::Mmap, MAP_ANONYMOUS | PROT_EXEC, 4096);
        let file_backed = fake_enriched_event(EventType::Mmap, PROT_EXEC, 4096);
        assert!(rule.matches(&anonymous));
        assert!(!rule.matches(&file_backed));
    }

    #[test]
    fn multiple_rules_evaluation() {
        let set = RuleSet {
            rules: vec![
                Rule {
                    id: "R1".into(),
                    name: "mmap".into(),
                    severity: Severity::Low,
                    description: "desc".into(),
                    conditions: Conditions {
                        syscall: Some("mmap".into()),
                        ..Default::default()
                    },
                    stateful: None,
                    enforcement_mode: EnforcementMode::Enforce,
                    cgroup_regex: None,
                    process_name_regex: None,
                    pathname_regex: None,
                    cmdline_context_regex: None,
                    target_process_regex: None,
                    memfd_name_regex: None,
                    tags: vec![],
                    mitre_tactics: vec![],
                    mitre_techniques: vec![],
                    references: vec![],
                    sequence: None,
                },
                Rule {
                    id: "R2".into(),
                    name: "mprotect".into(),
                    severity: Severity::Low,
                    description: "desc".into(),
                    conditions: Conditions {
                        syscall: Some("mprotect".into()),
                        ..Default::default()
                    },
                    stateful: None,
                    enforcement_mode: EnforcementMode::Enforce,
                    cgroup_regex: None,
                    process_name_regex: None,
                    pathname_regex: None,
                    cmdline_context_regex: None,
                    target_process_regex: None,
                    memfd_name_regex: None,
                    tags: vec![],
                    mitre_tactics: vec![],
                    mitre_techniques: vec![],
                    references: vec![],
                    sequence: None,
                },
                Rule {
                    id: "R3".into(),
                    name: "contains exec".into(),
                    severity: Severity::Low,
                    description: "desc".into(),
                    conditions: Conditions {
                        flags_contains: vec!["PROT_EXEC".into()],
                        ..Default::default()
                    },
                    stateful: None,
                    enforcement_mode: EnforcementMode::Enforce,
                    cgroup_regex: None,
                    process_name_regex: None,
                    pathname_regex: None,
                    cmdline_context_regex: None,
                    target_process_regex: None,
                    memfd_name_regex: None,
                    tags: vec![],
                    mitre_tactics: vec![],
                    mitre_techniques: vec![],
                    references: vec![],
                    sequence: None,
                },
            ],
            suppressions: vec![],
        };

        let event = fake_enriched_event(EventType::Mmap, PROT_EXEC, 4096);
        let matches = set.evaluate(&event, None);
        let ids: Vec<&str> = matches.iter().map(|rule| rule.id.as_str()).collect();
        assert_eq!(ids, vec!["R1", "R3"]);
    }

    #[test]
    fn empty_rule_set() {
        let set = RuleSet::default();
        let event = fake_enriched_event(EventType::Mmap, PROT_EXEC, 4096);
        assert!(set.evaluate(&event, None).is_empty());
    }

    #[test]
    fn frequency_window_openat_failures() {
        let yaml = r#"
rules:
  - id: "FREQ-OPENAT-FAIL"
    name: "many failed openat"
    severity: "high"
    description: "brute force style"
    conditions:
      syscall: "openat"
      syscall_failures_only: true
      frequency_window:
        min_occurrences: 3
        syscall: "openat"
        window_secs: 5
"#;
        let set = RuleSet::from_yaml_str(yaml).expect("parse");
        let mut st = crate::state::ProcessState {
            tgid: 1,
            first_seen: 0,
            last_seen: 0,
            event_count: 0,
            syscall_counts: std::collections::HashMap::new(),
            total_rwx_bytes: 0,
            mprotect_exec_count: 0,
            unique_addresses: std::collections::HashSet::new(),
            recent_syscalls: std::collections::VecDeque::new(),
            sequence_progress: std::collections::HashMap::new(),
        };
        let base = 1_000_000_000u64;
        for i in 0..2u64 {
            st.recent_syscalls.push_back(crate::state::RecentSyscall {
                timestamp_ns: base + i * 1_000_000,
                event_type: EventType::Openat,
                ret: -2,
            });
        }
        let ev = fake_enriched_event(EventType::Openat, 0, 0);
        let mut ev3 = ev.clone();
        ev3.inner.timestamp_ns = base + 3_000_000;
        ev3.inner.ret = -2;
        assert!(
            !set.rules[0].matches_with_state(&ev3, Some(&st)),
            "need third failure including current event"
        );
        st.recent_syscalls.push_back(crate::state::RecentSyscall {
            timestamp_ns: ev3.inner.timestamp_ns,
            event_type: EventType::Openat,
            ret: -2,
        });
        assert!(set.rules[0].matches_with_state(&ev3, Some(&st)));
    }

    #[test]
    fn flags_mask_all_exact_mprotect_rwx() {
        let prot_rwx = PROT_READ | PROT_WRITE | PROT_EXEC;
        let yaml = format!(
            r#"
rules:
  - id: "MASK-RWX"
    name: "exact prot"
    severity: "high"
    description: "d"
    conditions:
      syscall: "mprotect"
      flags_mask_all: {prot_rwx}
"#
        );
        let set = RuleSet::from_yaml_str(&yaml).expect("parse");
        let ok = fake_enriched_event(EventType::MprotectWX, prot_rwx, 4096);
        assert!(set.rules[0].matches(&ok));
        let missing_exec = fake_enriched_event(EventType::MprotectWX, PROT_READ | PROT_WRITE, 4096);
        assert!(!set.rules[0].matches(&missing_exec));
    }

    #[test]
    fn sequence_skip_unmapped_noise() {
        let yaml = r#"
rules:
  - id: "SEQ-ABC"
    name: "chain"
    severity: "high"
    description: "d"
    sequence:
      steps: ["mmap", "mprotect", "memfd_create"]
      allow_unmapped_between: true
    conditions:
      syscall: "memfd_create"
"#;
        let set = RuleSet::from_yaml_str(yaml).expect("parse");
        let rule = &set.rules[0];
        let mut st = crate::state::ProcessState {
            tgid: 99,
            first_seen: 0,
            last_seen: 0,
            event_count: 0,
            syscall_counts: std::collections::HashMap::new(),
            total_rwx_bytes: 0,
            mprotect_exec_count: 0,
            unique_addresses: std::collections::HashSet::new(),
            recent_syscalls: std::collections::VecDeque::new(),
            sequence_progress: std::collections::HashMap::new(),
        };

        let e1 = fake_enriched_event(EventType::Mmap, 0, 4096);
        rule.advance_sequence(&e1, &mut st);
        assert_eq!(*st.sequence_progress.get("SEQ-ABC").unwrap_or(&0), 1);

        let noise = fake_enriched_event(EventType::Openat, 0, 0);
        rule.advance_sequence(&noise, &mut st);
        assert_eq!(*st.sequence_progress.get("SEQ-ABC").unwrap_or(&0), 1);

        let e2 = fake_enriched_event(EventType::MprotectWX, PROT_EXEC, 4096);
        rule.advance_sequence(&e2, &mut st);
        assert_eq!(*st.sequence_progress.get("SEQ-ABC").unwrap_or(&0), 2);

        let e3 = fake_enriched_event(EventType::MemfdCreate, 0, 0);
        rule.advance_sequence(&e3, &mut st);
        assert_eq!(*st.sequence_progress.get("SEQ-ABC").unwrap_or(&0), 3);
        assert!(rule.matches_with_state(&e3, Some(&st)));

        rule.reset_sequence_progress(&mut st);
        assert_eq!(*st.sequence_progress.get("SEQ-ABC").unwrap_or(&0), 0);
    }

    #[test]
    fn sequence_wrong_mapped_step_resets() {
        let yaml = r#"
rules:
  - id: "SEQ-XY"
    name: "three step"
    severity: "high"
    description: "d"
    sequence:
      steps: ["mmap", "mprotect", "memfd_create"]
      allow_unmapped_between: true
    conditions:
      syscall: "memfd_create"
"#;
        let set = RuleSet::from_yaml_str(yaml).expect("parse");
        let rule = &set.rules[0];
        let mut st = crate::state::ProcessState {
            tgid: 5,
            first_seen: 0,
            last_seen: 0,
            event_count: 0,
            syscall_counts: std::collections::HashMap::new(),
            total_rwx_bytes: 0,
            mprotect_exec_count: 0,
            unique_addresses: std::collections::HashSet::new(),
            recent_syscalls: std::collections::VecDeque::new(),
            sequence_progress: std::collections::HashMap::new(),
        };
        let e1 = fake_enriched_event(EventType::Mmap, 0, 4096);
        rule.advance_sequence(&e1, &mut st);
        assert_eq!(*st.sequence_progress.get("SEQ-XY").unwrap_or(&0), 1);
        // memfd_create is in the chain but wrong order (expected mprotect next) → reset
        let wrong = fake_enriched_event(EventType::MemfdCreate, 0, 0);
        rule.advance_sequence(&wrong, &mut st);
        assert_eq!(*st.sequence_progress.get("SEQ-XY").unwrap_or(&0), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial(mace_log)]
    async fn integration_rule_match_logs_and_passthroughs() {
        crate::logging::reset_test_log_state();

        let yaml = r#"
rules:
  - id: "MEM-T1"
    name: "Executable mprotect"
    severity: "high"
    description: "desc"
    conditions:
      syscall: "mprotect"
      flags_contains: ["PROT_EXEC"]
"#;
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("mace-rule-test-{unique}.yaml"));
        fs::write(&path, yaml).expect("rule file should be written");

        let (raw_tx, raw_rx) = mpsc::channel(8);
        let config = PipelineConfig {
            reorder_window_ms: 1,
            rules_path: Some(path.clone()),
            ..PipelineConfig::default()
        };
        let mut handle = pipeline::start_pipeline_from_receiver_for_tests(
            raw_rx,
            config,
            Arc::new(NoopEnricher),
        )
        .expect("pipeline should start");

        raw_tx
            .send(MemoryEvent {
                timestamp_ns: 1,
                tgid: 77,
                pid: 77,
                uid: 0,
                comm: [0; 16],
                event_type: EventType::MprotectWX,
                addr: 0x1000,
                len: 4096,
                flags: PROT_EXEC,
                ret: 0,
                execve_cmdline: String::new(),
                openat_path: String::new(),
                memfd_name: String::new(),
                execve_argv_truncated: false,
            })
            .await
            .expect("send should succeed");

        let event = handle.next_event().await.expect("event should arrive");
        assert_eq!(event.inner.tgid, 77);

        handle.shutdown().await;
        let _ = fs::remove_file(path);

        let mace_logs = crate::logging::take_test_logs();
        assert!(
            mace_logs
                .iter()
                .any(|(_, line)| line.contains("MEM-T1") && line.contains("[ALERT]")),
            "expected Mace ALERT log with rule id, got: {mace_logs:?}"
        );
    }

    #[test]
    fn precompiled_regex_and_standardized_json_for_process_name() {
        let yaml = r#"
rules:
  - id: "TEST_001"
    name: "cat process"
    severity: "high"
    description: "match comm cat"
    conditions:
      syscall: "mmap"
      process_name_pattern: "^cat$"
"#;
        let set = RuleSet::from_yaml_str(yaml).expect("yaml");
        assert!(set.rules[0].process_name_regex.is_some());

        let mut comm = [0u8; 16];
        comm[..3].copy_from_slice(b"cat");

        let ev = crate::EnrichedEvent {
            inner: MemoryEvent {
                timestamp_ns: 99,
                tgid: 1,
                pid: 2,
                uid: 0,
                comm,
                event_type: EventType::Mmap,
                addr: 0x1000,
                len: 4096,
                flags: 0,
                ret: 0,
                execve_cmdline: String::new(),
                openat_path: String::new(),
                memfd_name: String::new(),
                execve_argv_truncated: false,
            },
            metadata: None,
            cmdline_context: None,
            username: None,
        };

        let matched = set.evaluate(&ev, None);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id, "TEST_001");

        let std_ev = crate::alert::build_standardized_event_from_rules(&ev, &matched, &[], None);
        assert_eq!(std_ev.matched_rules, vec!["TEST_001".to_string()]);
        assert_eq!(std_ev.process_name, "cat");

        let json = serde_json::to_string(&std_ev).expect("json");
        assert!(
            json.contains(r#""matched_rules":["TEST_001"]"#),
            "unexpected json: {json}"
        );
    }

    #[test]
    fn mitre_and_env_contains_parse_and_propagate_to_alert() {
        let yaml = r#"
rules:
  - id: "RULE-ENV-1"
    name: "ld preload execve"
    severity: "high"
    description: "test"
    mitre_techniques: ["T1574.006"]
    tags: ["persistence"]
    references: ["https://attack.mitre.org/techniques/T1574/006/"]
    conditions:
      syscall: "execve"
      env_contains: ["LD_PRELOAD"]
"#;
        let set = RuleSet::from_yaml_str(yaml).expect("yaml");
        let rule = &set.rules[0];
        assert_eq!(rule.mitre_techniques, vec!["T1574.006"]);
        assert_eq!(rule.tags, vec!["persistence"]);

        // Real `/proc/<pid>/environ` for a live task with LD_PRELOAD set.
        let child = Command::new("sleep")
            .arg("60")
            // Empty value still yields `LD_PRELOAD=` in the task environ (substring match) without
            // ld.so trying to load a missing shared object.
            .env("LD_PRELOAD", "")
            .spawn()
            .expect("spawn sleep child");
        let child_pid = child.id();

        let environ_path = format!("/proc/{child_pid}/environ");
        // Wait until `environ` is populated with LD_PRELOAD= (metadata alone is not enough).
        let mut ready = false;
        for _ in 0..200 {
            if let Ok(raw) = fs::read(&environ_path) {
                if raw.windows(11).any(|w| w == b"LD_PRELOAD=") {
                    ready = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready, "timeout waiting for LD_PRELOAD= in {}", environ_path);

        struct KillChild(std::process::Child);
        impl Drop for KillChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let _guard = KillChild(child);

        let ev = crate::EnrichedEvent {
            inner: MemoryEvent {
                timestamp_ns: 1,
                tgid: child_pid,
                pid: child_pid,
                uid: 0,
                comm: *b"sleep\0\0\0\0\0\0\0\0\0\0\0",
                event_type: EventType::Execve,
                addr: 0,
                len: 0,
                flags: 0,
                ret: 0,
                execve_cmdline: "/bin/sleep 60".into(),
                openat_path: String::new(),
                memfd_name: String::new(),
                execve_argv_truncated: false,
            },
            metadata: None,
            cmdline_context: None,
            username: None,
        };

        let matched = set.evaluate(&ev, None);
        assert_eq!(matched.len(), 1, "rule should match via /proc environ");

        let alert = crate::alert::Alert::from_rule_and_event(matched[0], &ev);
        assert_eq!(alert.mitre_techniques, vec!["T1574.006"]);
        assert_eq!(alert.tags, vec!["persistence"]);
        assert_eq!(
            alert.references,
            vec!["https://attack.mitre.org/techniques/T1574/006/"]
        );

        let std_ev = crate::alert::build_standardized_event_from_rules(&ev, &matched, &[], None);
        assert_eq!(std_ev.matched_rule_metadata.len(), 1);
        assert_eq!(
            std_ev.matched_rule_metadata[0].mitre_techniques,
            vec!["T1574.006"]
        );
        let json = serde_json::to_string(&std_ev).expect("json");
        assert!(json.contains("matched_rule_metadata"));
        assert!(json.contains("T1574.006"));
    }

    #[test]
    fn validate_rejects_env_contains_without_execve_syscall() {
        let yaml = r#"
rules:
  - id: "BAD"
    name: "x"
    severity: "low"
    description: "x"
    conditions:
      syscall: "mmap"
      env_contains: ["LD_PRELOAD"]
"#;
        let err = RuleSet::from_yaml_str(yaml).expect_err("should reject");
        assert!(
            err.to_string()
                .contains("env_contains requires syscall: execve"),
            "unexpected err: {err}"
        );
    }

    #[test]
    fn rule_watcher_precompiled_map_contains_rule_id() {
        let yaml = r#"
rules:
  - id: "TEST_001"
    name: "cat process"
    severity: "high"
    description: "match comm cat"
    conditions:
      syscall: "mmap"
      process_name_pattern: "^cat$"
"#;
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("mace-precompile-test-{unique}.yaml"));
        fs::write(&path, yaml).expect("write yaml");

        let watcher = super::watcher::RuleWatcher::new(path.clone()).expect("watcher");
        let map = watcher.precompiled_rules().load();
        assert!(
            map.contains_key("TEST_001"),
            "expected precompiled_rules to contain TEST_001, got keys: {:?}",
            map.keys().collect::<Vec<_>>()
        );
        assert!(map["TEST_001"].is_match("cat"));

        let _ = fs::remove_file(path);
    }
}
