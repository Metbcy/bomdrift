//! Repository-level policy config (`.bomdrift.toml`).
//!
//! The config supplies defaults for CLI runs and the GitHub Action. CLI flags
//! remain the escape hatch for one-off overrides; boolean config values only
//! turn on positive flags in v0.6 so the CLI surface does not grow a parallel
//! set of `--no-*` negations.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::cli::{DiffArgs, FailOn, InputFormat, OutputFormat};

const DEFAULT_CONFIG_PATH: &str = ".bomdrift.toml";

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    pub diff: Option<DiffConfig>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DiffConfig {
    pub output: Option<OutputFormat>,
    pub format: Option<InputFormat>,
    pub no_osv: Option<bool>,
    pub no_osv_cache: Option<bool>,
    pub baseline: Option<PathBuf>,
    pub no_maintainer_age: Option<bool>,
    pub fail_on: Option<FailOn>,
    pub summary_only: Option<bool>,
    pub findings_only: Option<bool>,
    pub include_file_components: Option<bool>,
    pub repo_url: Option<String>,
    pub max_added: Option<usize>,
    pub max_removed: Option<usize>,
    pub max_version_changed: Option<usize>,
}

pub fn apply_diff_config(args: &mut DiffArgs) -> Result<()> {
    let Some(config) = load_config(args.config.as_deref())? else {
        return Ok(());
    };

    apply_loaded_diff_config(args, config);
    Ok(())
}

fn apply_loaded_diff_config(args: &mut DiffArgs, config: Config) {
    let Some(diff) = config.diff else {
        return;
    };

    if args.output.is_none() {
        args.output = diff.output;
    }
    if args.format.is_none() {
        args.format = diff.format;
    }
    args.no_osv |= diff.no_osv.unwrap_or(false);
    args.no_osv_cache |= diff.no_osv_cache.unwrap_or(false);
    if args.baseline.is_none() {
        args.baseline = diff.baseline;
    }
    args.no_maintainer_age |= diff.no_maintainer_age.unwrap_or(false);
    if args.fail_on.is_none() {
        args.fail_on = diff.fail_on;
    }
    args.summary_only |= diff.summary_only.unwrap_or(false);
    args.findings_only |= diff.findings_only.unwrap_or(false);
    args.include_file_components |= diff.include_file_components.unwrap_or(false);
    if args.repo_url.is_none() {
        args.repo_url = diff.repo_url.filter(|s| !s.is_empty());
    }
    if args.max_added.is_none() {
        args.max_added = diff.max_added;
    }
    if args.max_removed.is_none() {
        args.max_removed = diff.max_removed;
    }
    if args.max_version_changed.is_none() {
        args.max_version_changed = diff.max_version_changed;
    }
}

fn load_config(explicit: Option<&Path>) -> Result<Option<Config>> {
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => {
            let default = PathBuf::from(DEFAULT_CONFIG_PATH);
            if !default.exists() {
                return Ok(None);
            }
            default
        }
    };

    let raw = fs::read_to_string(&path)
        .with_context(|| format!("reading bomdrift config: {}", path.display()))?;
    let config = toml::from_str(&raw)
        .with_context(|| format!("parsing bomdrift config: {}", path.display()))?;
    Ok(Some(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::DiffArgs;

    fn args() -> DiffArgs {
        DiffArgs {
            before: "before.json".into(),
            after: "after.json".into(),
            config: None,
            output: None,
            format: None,
            no_osv: false,
            no_osv_cache: false,
            baseline: None,
            no_maintainer_age: false,
            fail_on: None,
            summary_only: false,
            findings_only: false,
            include_file_components: false,
            repo_url: None,
            max_added: None,
            max_removed: None,
            max_version_changed: None,
        }
    }

    #[test]
    fn parses_diff_config() {
        let parsed: Config = toml::from_str(
            r#"
            [diff]
            output = "markdown"
            format = "cdx"
            fail_on = "license-change"
            baseline = ".bomdrift/baseline.json"
            no_osv = true
            findings_only = true
            max_added = 10
            "#,
        )
        .expect("valid config");
        let diff = parsed.diff.expect("diff section");
        assert_eq!(diff.output, Some(OutputFormat::Markdown));
        assert_eq!(diff.format, Some(InputFormat::Cdx));
        assert_eq!(diff.fail_on, Some(FailOn::LicenseChange));
        assert_eq!(
            diff.baseline,
            Some(PathBuf::from(".bomdrift/baseline.json"))
        );
        assert_eq!(diff.no_osv, Some(true));
        assert_eq!(diff.findings_only, Some(true));
        assert_eq!(diff.max_added, Some(10));
    }

    #[test]
    fn merge_keeps_explicit_cli_values() {
        let mut args = args();
        args.output = Some(OutputFormat::Json);
        args.fail_on = Some(FailOn::Typosquat);
        args.baseline = Some("cli-baseline.json".into());
        let diff = DiffConfig {
            output: Some(OutputFormat::Markdown),
            fail_on: Some(FailOn::CriticalCve),
            baseline: Some("config-baseline.json".into()),
            findings_only: Some(true),
            max_added: Some(5),
            ..Default::default()
        };

        let config = Config { diff: Some(diff) };
        apply_loaded_diff_config(&mut args, config);

        assert_eq!(args.output, Some(OutputFormat::Json));
        assert_eq!(args.fail_on, Some(FailOn::Typosquat));
        assert_eq!(args.baseline, Some(PathBuf::from("cli-baseline.json")));
        assert!(args.findings_only);
        assert_eq!(args.max_added, Some(5));
    }
}
