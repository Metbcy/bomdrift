use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::cli::InitArgs;

pub(super) fn run_init(args: InitArgs) -> Result<()> {
    write_scaffold_file(Path::new(".bomdrift.toml"), INIT_CONFIG, args.force)?;
    if !args.config_only {
        write_scaffold_file(
            Path::new(".github/workflows/sbom-diff.yml"),
            INIT_SBOM_WORKFLOW,
            args.force,
        )?;
        write_scaffold_file(
            Path::new(".github/workflows/bomdrift-suppress.yml"),
            INIT_SUPPRESS_WORKFLOW,
            args.force,
        )?;
    }
    eprintln!("bomdrift: initialized repository files");
    Ok(())
}

fn write_scaffold_file(path: &Path, contents: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; re-run with --force to overwrite",
            path.display()
        );
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating parent directory: {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("writing scaffold file: {}", path.display()))
}

const INIT_CONFIG: &str = r#"# bomdrift repo policy.
# CLI flags override these defaults for one-off runs.

[diff]
fail_on = "critical-cve"
baseline = ".bomdrift/baseline.json"
findings_only = false

# Optional churn budgets. Uncomment to fail the workflow when a PR changes too
# many dependencies at once.
# max_added = 25
# max_removed = 50
# max_version_changed = 10
"#;

const INIT_SBOM_WORKFLOW: &str = r#"name: SBOM diff

on: pull_request

permissions:
  contents: read
  pull-requests: write

jobs:
  diff:
    runs-on: ubuntu-latest
    steps:
      - uses: Metbcy/bomdrift@v1
        with:
          config: .bomdrift.toml
"#;

const INIT_SUPPRESS_WORKFLOW: &str = r#"name: bomdrift suppress

on:
  issue_comment:
    types: [created]

permissions:
  contents: write
  pull-requests: write

jobs:
  suppress:
    if: |
      github.event.issue.pull_request &&
      startsWith(github.event.comment.body, '/bomdrift suppress ')
    runs-on: ubuntu-latest
    steps:
      - uses: Metbcy/bomdrift/comment-suppress@v1
"#;
