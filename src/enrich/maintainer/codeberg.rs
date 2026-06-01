use super::types::{LookupError, MaintainerInfo};

/// Stub: Codeberg (Forgejo/Gitea v1) URL parsing and Host dispatch are wired,
/// but the per-author first-commit lookup is not yet implemented. Gitea's
/// commits endpoint gained reliable `?author=` filtering in v1.20; Codeberg's
/// exact API version and behavior need verification before shipping. Returns
/// no finding so the enricher stays clean rather than guessing.
///
/// TODO: implement lookup once Forgejo v1.20+ per-author commit filter is
/// confirmed. API base would be https://codeberg.org/api/v1.
pub(super) fn lookup_codeberg_repo(
    _agent: &ureq::Agent,
    _owner: &str,
    _repo: &str,
    _token: Option<&str>,
    _now_secs: i64,
) -> std::result::Result<MaintainerInfo, LookupError> {
    Ok(MaintainerInfo { finding: None })
}
