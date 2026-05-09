use std::fmt::Write as _;

use crate::render::markdown::platform::Platform;

/// Renders the comment footer with action affordances. Omitted entirely
/// when `repo_url` is `None` so forks / standalone CLI use don't render
/// dead links to a repo they don't own. Wrapped in `<sub>` so it doesn't
/// compete visually with the section bodies.
pub fn render(repo_url: Option<&str>, platform: Platform) -> String {
    let Some(repo) = repo_url else {
        return String::new();
    };

    let repo = repo.trim_end_matches('/');
    let mut out = String::new();
    out.push_str("---\n");
    match platform {
        Platform::GitHub => {
            let _ = writeln!(
                out,
                "<sub>**False positive?** [Report it]({repo}/issues/new?labels=false-positive&template=false-positive.md) · \
                 **Suppress a finding?** Comment `/bomdrift suppress <ID>` (requires the \
                 [comment-suppress sub-action]({repo})) · \
                 [Docs](https://metbcy.github.io/bomdrift/)</sub>",
            );
        }
        Platform::GitLab => {
            let _ = writeln!(
                out,
                "<sub>**False positive?** [Report it]({repo}/-/issues/new?issuable_template=false-positive) · \
                 **Suppress a finding?** Run `bomdrift baseline add <ID>` and commit \
                 `.bomdrift/baseline.json` to your MR branch · \
                 [Docs](https://metbcy.github.io/bomdrift/)</sub>",
            );
        }
        Platform::Bitbucket => {
            let _ = writeln!(
                out,
                "<sub>**False positive?** [Report it]({repo}/issues/new) · \
                 **Suppress a finding?** Run `bomdrift baseline add <ID>` and commit \
                 `.bomdrift/baseline.json` to your PR branch · \
                 [Docs](https://metbcy.github.io/bomdrift/)</sub>",
            );
        }
        Platform::AzureDevOps => {
            let _ = writeln!(
                out,
                "<sub>**False positive?** [Report it]({repo}/_workitems/create?templateName=false-positive) · \
                 **Suppress a finding?** Run `bomdrift baseline add <ID>` and commit \
                 `.bomdrift/baseline.json` to your PR branch · \
                 [Docs](https://metbcy.github.io/bomdrift/)</sub>",
            );
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footer_omitted_when_repo_url_unset() {
        let md = render(None, Platform::GitHub);
        assert!(!md.contains("False positive?"));
        assert!(!md.contains("/issues/new"));
    }

    #[test]
    fn footer_renders_when_repo_url_supplied() {
        let md = render(Some("https://github.com/example/proj"), Platform::GitHub);
        assert!(md.contains("False positive?"));
        assert!(md.contains("https://github.com/example/proj/issues/new"));
        assert!(md.contains("/bomdrift suppress"));
        assert!(md.contains("https://metbcy.github.io/bomdrift/"));
    }

    #[test]
    fn footer_strips_trailing_slash_from_repo_url() {
        let md = render(Some("https://github.com/example/proj/"), Platform::GitHub);
        assert!(md.contains("https://github.com/example/proj/issues/new"));
        assert!(!md.contains("proj//issues"));
    }

    #[test]
    fn footer_renders_gitlab_shape_when_platform_is_gitlab() {
        let md = render(Some("https://gitlab.com/group/project"), Platform::GitLab);
        assert!(md.contains("False positive?"));
        assert!(
            md.contains("https://gitlab.com/group/project/-/issues/new"),
            "expected GitLab `/-/issues/new` URL shape; got:\n{md}"
        );
        assert!(
            md.contains("bomdrift baseline add"),
            "expected GitLab footer to point at `bomdrift baseline add`; got:\n{md}"
        );
        assert!(
            !md.contains("/bomdrift suppress"),
            "GitLab footer must NOT mention the GitHub-only `/bomdrift suppress` comment flow; got:\n{md}"
        );
        assert!(md.contains("https://metbcy.github.io/bomdrift/"));
    }

    #[test]
    fn footer_default_platform_preserves_github_shape() {
        assert_eq!(Platform::default(), Platform::GitHub);
        let md = render(Some("https://github.com/example/proj"), Platform::default());
        assert!(md.contains("/issues/new?labels=false-positive"));
        assert!(md.contains("/bomdrift suppress"));
    }

    #[test]
    fn footer_renders_bitbucket_shape() {
        let md = render(Some("https://bitbucket.org/team/proj"), Platform::Bitbucket);
        assert!(
            md.contains("https://bitbucket.org/team/proj/issues/new"),
            "expected Bitbucket /issues/new URL; got:\n{md}"
        );
        assert!(md.contains("bomdrift baseline add"));
        assert!(!md.contains("/bomdrift suppress"));
    }

    #[test]
    fn footer_renders_azure_devops_shape() {
        let md = render(
            Some("https://dev.azure.com/org/project/_git/repo"),
            Platform::AzureDevOps,
        );
        assert!(
            md.contains("/_workitems/create?templateName=false-positive"),
            "expected Azure DevOps work-item URL; got:\n{md}"
        );
        assert!(md.contains("bomdrift baseline add"));
    }
}
