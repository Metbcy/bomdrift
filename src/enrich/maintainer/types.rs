use serde::Serialize;

pub(super) const GITHUB_API_BASE: &str = "https://api.github.com";
pub(super) const GITLAB_API_BASE: &str = "https://gitlab.com/api/v4";
pub(super) const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
pub(super) const USER_AGENT: &str = concat!("bomdrift/", env!("CARGO_PKG_VERSION"));

/// Repos with more contributors than this are treated as monorepos and skipped:
/// "top contributor joined recently" loses meaning when 200 people have committed.
pub(super) const MAX_CONTRIBUTORS_FOR_SIGNAL: u64 = 50;

/// Days threshold: top contributor's first commit younger than this fires the
/// finding. See module docs for rationale.
pub const YOUNG_MAINTAINER_DAYS: i64 = 90;

/// The forge host where a dependency's source repository lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Host {
    Github,
    Gitlab,
    Codeberg,
}

impl Host {
    pub(super) fn label(self) -> &'static str {
        match self {
            Host::Github => "GitHub",
            Host::Gitlab => "GitLab",
            Host::Codeberg => "Codeberg",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MaintainerAgeFinding {
    pub component: crate::model::Component,
    pub top_contributor: String,
    /// ISO-8601 string as returned by the forge (`2026-01-15T12:34:56Z`). Stored
    /// verbatim so renderers can show it without re-formatting.
    pub first_commit_at: String,
    pub days_old: i64,
    /// Which forge host the component's source URL belongs to.
    pub host: Host,
}

/// Cached per-repo lookup result, so multiple `cs.added` entries from the same
/// project (e.g. monorepo subpackages) don't re-issue the same three requests.
#[derive(Debug, Clone)]
pub(super) struct MaintainerInfo {
    /// `Some(...)` when the repo passed all filters and we got a date back.
    /// `None` when the repo was skipped (too many contributors, no commits,
    /// not-found, etc.) -- cached so we don't retry.
    pub(super) finding: Option<(String, String, i64)>,
}

pub(super) enum LookupError {
    RateLimited,
    Other(anyhow::Error),
}

pub(super) struct GithubResponse {
    pub(super) body: String,
    pub(super) link_header: Option<String>,
}

pub(super) struct GitlabResponse {
    pub(super) body: String,
    pub(super) link_header: Option<String>,
    /// GitLab includes the total item count in `X-Total` on every paginated
    /// response, regardless of `per_page`. Absent when the total exceeds
    /// GitLab's configured limit (very large repos).
    pub(super) x_total: Option<u64>,
}
