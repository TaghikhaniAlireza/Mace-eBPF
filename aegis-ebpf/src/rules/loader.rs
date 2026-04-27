use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use super::{
    Rule, RuleError, SuppressionEntry, compile_suppression_regexes, validate_rule,
    validate_suppression_entry,
};
use crate::{pipeline::EnrichedEvent, state::ProcessState};

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
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RuleError> {
        let content = fs::read_to_string(path)?;
        Self::from_yaml_str(&content)
    }

    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self, RuleError> {
        let mut rules = Vec::new();
        let mut suppressions = Vec::new();
        let mut entries: Vec<PathBuf> = fs::read_dir(dir.as_ref())?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
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

    /// Like [`Self::evaluate`], but also returns suppression ids that matched this event (for logging / JSON).
    pub fn evaluate_with_suppressions(
        &self,
        event: &EnrichedEvent,
        state: Option<&ProcessState>,
    ) -> (Vec<&Rule>, Vec<String>) {
        let matched_rules: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|rule| rule.matches_with_state(event, state))
            .collect();
        let suppressed_by: Vec<String> = self
            .suppressions
            .iter()
            .filter(|s| s.matches(event))
            .map(|s| s.id.clone())
            .collect();
        (matched_rules, suppressed_by)
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
