use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use super::{
    EnforcementMode, Rule, RuleError, SuppressionEntry, compile_suppression_regexes, validate_rule,
    validate_suppression_entry,
};
use crate::{pipeline::EnrichedEvent, state::ProcessState};

/// Result of profiled rule evaluation: enforce matches, shadow matches, suppression ids, per-rule eval ns.
pub type ProfiledEvaluation<'a> = (
    Vec<&'a Rule>,
    Vec<&'a Rule>,
    Vec<String>,
    Vec<(String, u64)>,
);

#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    /// Trusted-process / noise suppressions — same condition language as rules, no `stateful`.
    pub suppressions: Vec<SuppressionEntry>,
}

#[derive(Deserialize)]
struct RuleFile {
    #[serde(default)]
    rules: Vec<Rule>,
    #[serde(default)]
    suppressions: Vec<SuppressionEntry>,
}

impl RuleSet {
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RuleError> {
        let content = fs::read_to_string(path)?;
        Self::from_yaml_str(&content)
    }

    /// Load every `*.yaml` / `*.yml` **directly** under `dir` (non-recursive), sort paths with
    /// [`Path::cmp`] (Unicode, portable), then merge: each file’s `rules` are appended in that
    /// order, then each file’s `suppressions` likewise. Same id in two files yields two entries
    /// unless you dedupe in policy.
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self, RuleError> {
        let mut rules = Vec::new();
        let mut suppressions = Vec::new();
        let mut entries: Vec<PathBuf> = fs::read_dir(dir.as_ref())?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.is_file()
                    && path
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(|ext| {
                            ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml")
                        })
                        .unwrap_or(false)
            })
            .collect();
        entries.sort();

        for path in entries {
            let mut file_rules = Self::from_file(&path)?;
            rules.append(&mut file_rules.rules);
            suppressions.extend(file_rules.suppressions);
        }
        Ok(Self {
            rules,
            suppressions,
        })
    }

    pub fn evaluate(&self, event: &EnrichedEvent, state: Option<&ProcessState>) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|rule| rule.matches_with_state(event, state))
            .collect()
    }

    /// Returns `(enforce_matches, shadow_matches, suppressed_by, per_rule_eval_ns)`.
    pub fn evaluate_with_suppressions_profiled(
        &self,
        event: &EnrichedEvent,
        state: Option<&ProcessState>,
    ) -> ProfiledEvaluation<'_> {
        use std::time::Instant;
        let mut enforce = Vec::new();
        let mut shadow = Vec::new();
        let mut timings = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            let t0 = Instant::now();
            let matched = rule.matches_with_state(event, state);
            let ns = t0.elapsed().as_nanos() as u64;
            timings.push((rule.id.clone(), ns));
            if matched {
                match rule.enforcement_mode {
                    EnforcementMode::Shadow => shadow.push(rule),
                    EnforcementMode::Enforce => enforce.push(rule),
                }
            }
        }
        let suppressed_by: Vec<String> = self
            .suppressions
            .iter()
            .filter(|s| s.matches(event))
            .map(|s| s.id.clone())
            .collect();
        (enforce, shadow, suppressed_by, timings)
    }

    pub fn evaluate_with_suppressions_split(
        &self,
        event: &EnrichedEvent,
        state: Option<&ProcessState>,
    ) -> (Vec<&Rule>, Vec<&Rule>, Vec<String>) {
        let (e, s, sup, _) = self.evaluate_with_suppressions_profiled(event, state);
        (e, s, sup)
    }

    pub fn evaluate_with_suppressions(
        &self,
        event: &EnrichedEvent,
        state: Option<&ProcessState>,
    ) -> (Vec<&Rule>, Vec<String>) {
        let (enforce, shadow, suppressed_by, _) =
            self.evaluate_with_suppressions_profiled(event, state);
        let mut matched_rules = enforce;
        matched_rules.extend(shadow);
        (matched_rules, suppressed_by)
    }

    pub fn evaluate_rule_timings_ns(
        &self,
        event: &EnrichedEvent,
        state: Option<&ProcessState>,
    ) -> Vec<(String, u64)> {
        self.evaluate_with_suppressions_profiled(event, state).3
    }

    pub fn from_yaml_str(yaml: &str) -> Result<Self, RuleError> {
        let mut parsed: RuleFile = serde_yaml::from_str(yaml)?;
        for rule in &mut parsed.rules {
            validate_rule(rule)?;
            super::compile_rule_regexes(rule)?;
        }
        for entry in &mut parsed.suppressions {
            validate_suppression_entry(entry)?;
            compile_suppression_regexes(entry)?;
        }
        Ok(Self {
            rules: parsed.rules,
            suppressions: parsed.suppressions,
        })
    }

    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            suppressions: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::RuleSet;

    #[test]
    fn from_dir_merges_yaml_in_sorted_path_order() {
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("02-b.yaml"),
            r#"
rules:
  - id: "RULE_B"
    name: "b"
    severity: "low"
    description: "d"
    conditions:
      syscall: "mmap"
"#,
        )
        .expect("write");
        fs::write(
            dir.path().join("01-a.yaml"),
            r#"
rules:
  - id: "RULE_A"
    name: "a"
    severity: "low"
    description: "d"
    conditions:
      syscall: "mmap"
"#,
        )
        .expect("write");
        // Non-yaml ignored
        fs::write(dir.path().join("readme.txt"), "x").expect("write");

        let set = RuleSet::from_dir(dir.path()).expect("from_dir");
        assert_eq!(
            set.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["RULE_A", "RULE_B"]
        );
    }

    #[test]
    fn from_dir_merges_suppressions_across_files() {
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("rules.yaml"),
            r#"
rules:
  - id: "R1"
    name: "n"
    severity: "low"
    description: "d"
    conditions:
      syscall: "mmap"

suppressions:
  - id: "S_A"
    name: "sa"
    description: "d"
    conditions:
      syscall: "mmap"
"#,
        )
        .expect("write");
        fs::write(
            dir.path().join("zz_more.yml"),
            r#"
suppressions:
  - id: "S_B"
    name: "sb"
    description: "d"
    conditions:
      syscall: "mmap"
"#,
        )
        .expect("write");

        let set = RuleSet::from_dir(dir.path()).expect("from_dir");
        assert_eq!(set.rules.len(), 1);
        let supp_ids: Vec<&str> = set.suppressions.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(supp_ids, vec!["S_A", "S_B"]);
    }
}
