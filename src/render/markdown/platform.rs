/// Which forge the rendered markdown is destined for. Drives the action-
/// affordance footer: GitHub uses the v0.5 `/bomdrift suppress` comment-driven
/// flow and `/issues/new?...` URL shape; GitLab uses the project's
/// `/-/issues/new` shape and points reviewers at the manual `bomdrift baseline
/// add` CLI flow because GitLab in-comment suppression is deferred to v0.8.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// GitHub.com or GitHub Enterprise. Default — preserves the v0.5
    /// footer shape for existing consumers.
    #[default]
    GitHub,
    /// GitLab.com or Self-Managed GitLab. The MR-note footer omits the
    /// `/bomdrift suppress` hint and points at `bomdrift baseline add`
    /// instead.
    GitLab,
    /// Bitbucket Cloud or Bitbucket Data Center.
    Bitbucket,
    /// Azure DevOps Repos.
    AzureDevOps,
}
