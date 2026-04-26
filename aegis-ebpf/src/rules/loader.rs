use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use super::{Rule, RuleError, validate_rule};
use crate::{pipeline::EnrichedEvent, state::ProcessState};

#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

#[derive(Deserialize)]
struct RuleFile {
    #[serde(default)]
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RuleError> {
        let content = fs::read_to_string(path)?;
        Self::from_yaml_str(&content)
    }

    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self, RuleError> {
        let mut rules = Vec::new();
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
        }
        Ok(Self { rules })
    }

    pub fn evaluate(&self, event: &EnrichedEvent, state: Option<&ProcessState>) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|rule| rule.matches_with_state(event, state))
            .collect()
    }

    pub fn from_yaml_str(yaml: &str) -> Result<Self, RuleError> {
        let mut parsed: RuleFile = serde_yaml::from_str(yaml)?;
        for rule in &mut parsed.rules {
            validate_rule(rule)?;
            super::compile_rule_regexes(rule)?;
        }
        Ok(Self {
            rules: parsed.rules,
        })
    }

    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }
}
