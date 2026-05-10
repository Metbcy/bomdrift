use crate::render::markdown::platform::Platform;

/// Renderer toggles. Defaults match v0.2 behavior so existing callers keep
/// working unchanged.
#[derive(Debug, Default, Clone)]
pub struct Options {
    /// When true, emit only the summary-counts table plus a footer note —
    /// no per-section detail tables. Compresses a several-hundred-finding
    /// diff from "blow past GitHub's 65k comment cap" to a few KB. The
    /// reviewer follows the footer link to the full report (workflow-step
    /// summary, JSON artifact, etc.) when they need detail.
    pub summary_only: bool,
    /// When true, keep the summary table and risk-bearing sections but omit
    /// raw dependency churn detail (Added / Removed / Version changed). This
    /// keeps PR comments focused on review decisions while preserving the
    /// counts that show how large the dependency change is.
    pub findings_only: bool,
    /// Repository URL — `https://github.com/<owner>/<repo>` (or
    /// `https://gitlab.com/<group>/<project>`) form, no trailing slash.
    /// When supplied, the renderer appends a footer linking to a
    /// pre-filled "Report this finding" issue and a suppression hint.
    /// When `None`, the footer is omitted entirely so forks / standalone
    /// CLI use don't render dead links to bomdrift's own issue tracker.
    pub repo_url: Option<String>,
    /// Forge that the rendered markdown is destined for. Defaults to
    /// `GitHub` so existing consumers keep their v0.5 footer shape with
    /// no migration. The CLI flips this to `GitLab` when `--platform
    /// gitlab` is passed or the `GITLAB_CI` environment variable is set.
    pub platform: Platform,
}
