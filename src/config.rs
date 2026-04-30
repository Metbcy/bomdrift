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

use crate::cli::{DebugFormat, DiffArgs, FailOn, InputFormat, OutputFormat, Platform};

/// `[license]` block in `.bomdrift.toml`. CLI flags
/// (`--allow-licenses`/`--deny-licenses`) override this block when set
/// (override, not merge — matches the Dependency Review Action).
#[derive(Debug, Default, Deserialize)]
pub struct LicenseConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub allow_ambiguous: bool,
    /// SPDX exception identifiers permitted in `WITH` clauses. v0.9.5+.
    #[serde(default)]
    pub allow_exceptions: Vec<String>,
    /// SPDX exception identifiers forbidden in `WITH` clauses. v0.9.5+.
    #[serde(default)]
    pub deny_exceptions: Vec<String>,
}

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
    pub no_epss: Option<bool>,
    pub no_kev: Option<bool>,
    pub fail_on_epss: Option<f32>,
    pub license: Option<LicenseConfig>,
    pub baseline: Option<PathBuf>,
    pub no_maintainer_age: Option<bool>,
    pub fail_on: Option<FailOn>,
    pub summary_only: Option<bool>,
    pub findings_only: Option<bool>,
    pub include_file_components: Option<bool>,
    pub repo_url: Option<String>,
    pub platform: Option<Platform>,
    pub max_added: Option<usize>,
    pub max_removed: Option<usize>,
    pub max_version_changed: Option<usize>,
    pub debug_calibration: Option<bool>,
    pub debug_calibration_format: Option<DebugFormat>,
    pub output_file: Option<PathBuf>,
    /// VEX `author` field for `--emit-vex`. Falls back to `repo_url`,
    /// then to the literal `"bomdrift"`.
    pub vex_author: Option<String>,
    /// Default OpenVEX justification when an entry doesn't supply one.
    /// Defaults to `"vulnerable_code_not_in_execute_path"`.
    pub vex_default_justification: Option<String>,
    /// Skip registry-metadata enrichers (npm/PyPI/crates.io). v0.9+.
    pub no_registry: Option<bool>,
    /// Override the default 14-day recently-published threshold. v0.9+.
    pub recently_published_days: Option<i64>,
    /// Override the typosquat similarity threshold (default 0.92). v0.9.6+.
    pub typosquat_similarity_threshold: Option<f64>,
    /// Override the young-maintainer-days threshold (default 90). v0.9.6+.
    pub young_maintainer_days: Option<i64>,
    /// Override the on-disk cache TTL in hours (default 24). v0.9.6+.
    pub cache_ttl_hours: Option<u64>,
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
    args.no_epss |= diff.no_epss.unwrap_or(false);
    args.no_kev |= diff.no_kev.unwrap_or(false);
    if args.fail_on_epss.is_none() {
        args.fail_on_epss = diff.fail_on_epss;
    }
    if args.baseline.is_none() {
        // Config-derived baseline paths are tolerant of a missing file.
        // `bomdrift init` ships `.bomdrift.toml` pointing at
        // `.bomdrift/baseline.json` before any `/bomdrift suppress`
        // comment has had a chance to create it; failing the very first
        // PR-comment run because the file doesn't exist yet would defeat
        // the whole point of the scaffolded default. CLI `--baseline
        // path` remains strict (a typo'd path silently no-op'ing is the
        // worse footgun there) — that strict behavior lives in
        // `Baseline::load` and is unchanged.
        args.baseline = diff.baseline.filter(|p| p.exists());
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
    if args.platform.is_none() {
        args.platform = diff.platform;
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
    args.debug_calibration |= diff.debug_calibration.unwrap_or(false);
    if let Some(fmt) = diff.debug_calibration_format {
        // Only override the default when the config explicitly sets a value;
        // CLI flag still wins because it's the explicit form.
        if args.debug_calibration_format == DebugFormat::default() {
            args.debug_calibration_format = fmt;
        }
    }
    if args.output_file.is_none() {
        args.output_file = diff.output_file;
    }
    if args.vex_author.is_none() {
        args.vex_author = diff.vex_author.filter(|s| !s.is_empty());
    }
    if args.vex_default_justification.is_none() {
        args.vex_default_justification = diff.vex_default_justification.filter(|s| !s.is_empty());
    }
    args.no_registry |= diff.no_registry.unwrap_or(false);
    if args.recently_published_days.is_none() {
        args.recently_published_days = diff.recently_published_days;
    }
    if args.typosquat_similarity_threshold.is_none() {
        args.typosquat_similarity_threshold = diff.typosquat_similarity_threshold;
    }
    if args.young_maintainer_days.is_none() {
        args.young_maintainer_days = diff.young_maintainer_days;
    }
    if args.cache_ttl_hours.is_none() {
        args.cache_ttl_hours = diff.cache_ttl_hours;
    }

    // [license] block: CLI flags override (not merge) when set. Mirrors
    // Dependency Review Action semantics so users moving between bomdrift
    // and DRA don't get surprises.
    if let Some(lic) = diff.license {
        if args.allow_licenses.is_empty() {
            args.allow_licenses = lic.allow;
        }
        if args.deny_licenses.is_empty() {
            args.deny_licenses = lic.deny;
        }
        args.allow_ambiguous_licenses |= lic.allow_ambiguous;
        if args.allow_exception.is_empty() {
            args.allow_exception = lic.allow_exceptions;
        }
        if args.deny_exception.is_empty() {
            args.deny_exception = lic.deny_exceptions;
        }
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
            before: Some("before.json".into()),
            after: Some("after.json".into()),
            config: None,
            output: None,
            format: None,
            no_osv: false,
            no_osv_cache: false,
            no_epss: false,
            no_kev: false,
            fail_on_epss: None,
            baseline: None,
            no_maintainer_age: false,
            fail_on: None,
            summary_only: false,
            findings_only: false,
            include_file_components: false,
            repo_url: None,
            platform: None,
            max_added: None,
            max_removed: None,
            max_version_changed: None,
            debug_calibration: false,
            debug_calibration_format: DebugFormat::default(),
            output_file: None,
            allow_licenses: Vec::new(),
            deny_licenses: Vec::new(),
            allow_ambiguous_licenses: false,
            allow_exception: Vec::new(),
            deny_exception: Vec::new(),
            vex: Vec::new(),
            emit_vex: None,
            vex_author: None,
            vex_default_justification: None,
            no_registry: false,
            recently_published_days: None,
            typosquat_similarity_threshold: None,
            young_maintainer_days: None,
            cache_ttl_hours: None,
            before_attestation: None,
            after_attestation: None,
            cosign_identity: None,
            cosign_issuer: None,
            require_attestation: false,
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
    fn config_baseline_path_is_dropped_when_file_missing() {
        // Repro of the v0.6.0 rough edge: `bomdrift init` writes
        // `.bomdrift.toml` with `baseline = ".bomdrift/baseline.json"`
        // but the file doesn't exist yet (it's created on the first
        // `/bomdrift suppress` comment). The first PR-comment run on a
        // freshly-init'd repo must NOT fail before rendering — the diff
        // should run with no baseline applied.
        let mut args = args();
        let diff = DiffConfig {
            baseline: Some(PathBuf::from(
                "/nonexistent/this/path/should/not/exist/baseline.json",
            )),
            ..Default::default()
        };
        let config = Config { diff: Some(diff) };
        apply_loaded_diff_config(&mut args, config);
        assert!(
            args.baseline.is_none(),
            "config-derived baseline pointing at a missing file must be dropped, not propagated"
        );
    }

    #[test]
    fn config_baseline_path_is_kept_when_file_exists() {
        let mut args = args();
        let tmp = std::env::temp_dir();
        let path = tmp.join("bomdrift-config-baseline-fixture.json");
        std::fs::write(&path, "{}").expect("write fixture baseline");

        let diff = DiffConfig {
            baseline: Some(path.clone()),
            ..Default::default()
        };
        let config = Config { diff: Some(diff) };
        apply_loaded_diff_config(&mut args, config);
        assert_eq!(args.baseline.as_deref(), Some(path.as_path()));

        std::fs::remove_file(&path).ok();
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
