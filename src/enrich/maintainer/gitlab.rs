use anyhow::Context;

use super::parsing::{
    iso8601_to_unix_seconds, normalize_iso8601, parse_gitlab_first_commit_date,
    parse_gitlab_top_contributor_name, parse_link_last_page, percent_encode,
};
use super::types::{
    GITLAB_API_BASE, GitlabResponse, LookupError, MAX_CONTRIBUTORS_FOR_SIGNAL, MaintainerInfo,
    USER_AGENT,
};

/// Resolve a single `owner/repo` on GitLab using the v4 REST API.
/// Uses `X-Total` header for contributor count (no Link-header parsing needed).
/// Author names (not logins) are stored; GitLab contributors are identified by
/// commit author name/email, not a username.
pub(super) fn lookup_gitlab_repo(
    agent: &ureq::Agent,
    owner: &str,
    repo: &str,
    token: Option<&str>,
    now_secs: i64,
) -> std::result::Result<MaintainerInfo, LookupError> {
    let project_id = percent_encode(&format!("{owner}/{repo}"));

    // Steps 1+2 combined: per_page=1 returns the top contributor by commit
    // count, and GitLab includes X-Total (total contributor count) on any
    // paginated response regardless of per_page.
    let top_url = format!(
        "{GITLAB_API_BASE}/projects/{project_id}/repository/contributors\
         ?order_by=commits&sort=desc&per_page=1"
    );
    let top_resp = gitlab_get(agent, &top_url, token)?;

    let contributor_count = top_resp.x_total.unwrap_or(u64::MAX);
    if contributor_count > MAX_CONTRIBUTORS_FOR_SIGNAL {
        return Ok(MaintainerInfo { finding: None });
    }

    let top_name = parse_gitlab_top_contributor_name(&top_resp.body)
        .context("parsing GitLab top-contributor response")
        .map_err(LookupError::Other)?;
    let Some(top_name) = top_name else {
        return Ok(MaintainerInfo { finding: None });
    };

    // Step 3: first commit by that author. GitLab's commits endpoint accepts
    // ?author=<name> to filter by author name. Newest-first; paginate to last
    // page for the oldest commit, same Link-header trick as GitHub.
    let author_enc = percent_encode(&top_name);
    let commits_first_url = format!(
        "{GITLAB_API_BASE}/projects/{project_id}/repository/commits\
         ?author={author_enc}&per_page=1"
    );
    let commits_first = gitlab_get(agent, &commits_first_url, token)?;
    let last_page = parse_link_last_page(commits_first.link_header.as_deref());

    let oldest_body = match last_page {
        Some(page) if page > 1 => {
            let last_url = format!(
                "{GITLAB_API_BASE}/projects/{project_id}/repository/commits\
                 ?author={author_enc}&per_page=1&page={page}"
            );
            gitlab_get(agent, &last_url, token)?.body
        }
        _ => commits_first.body,
    };

    let date_str = match parse_gitlab_first_commit_date(&oldest_body) {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(MaintainerInfo { finding: None }),
        Err(e) => return Err(LookupError::Other(e)),
    };

    // GitLab timestamps vary: "2024-04-15T12:34:56.000+00:00", "...Z", etc.
    // Normalize to YYYY-MM-DDTHH:MM:SSZ for our parser. Day-granularity
    // calculations absorb the small UTC-offset error.
    let normalized = match normalize_iso8601(&date_str) {
        Some(d) => d,
        None => return Ok(MaintainerInfo { finding: None }),
    };

    let Some(commit_secs) = iso8601_to_unix_seconds(&normalized) else {
        return Ok(MaintainerInfo { finding: None });
    };
    let days = (now_secs - commit_secs) / 86_400;

    Ok(MaintainerInfo {
        finding: Some((top_name, normalized, days)),
    })
}

fn gitlab_get(
    agent: &ureq::Agent,
    url: &str,
    token: Option<&str>,
) -> std::result::Result<GitlabResponse, LookupError> {
    let mut req = agent.get(url).set("user-agent", USER_AGENT);
    if let Some(t) = token {
        req = req.set("PRIVATE-TOKEN", t);
    }
    match req.call() {
        Ok(resp) => {
            let link_header = resp.header("link").map(str::to_string);
            let x_total = resp.header("x-total").and_then(|v| v.parse::<u64>().ok());
            let body = resp
                .into_string()
                .context("reading GitLab response body")
                .map_err(LookupError::Other)?;
            Ok(GitlabResponse {
                body,
                link_header,
                x_total,
            })
        }
        Err(ureq::Error::Status(429, _)) => Err(LookupError::RateLimited),
        Err(ureq::Error::Status(401 | 403 | 404, _)) => {
            // 401/403: repo is private or token missing; skip silently.
            // 404: repo gone or moved; skip.
            Ok(GitlabResponse {
                body: "[]".to_string(),
                link_header: None,
                x_total: Some(0),
            })
        }
        Err(e) => Err(LookupError::Other(
            anyhow::Error::new(e).context(format!("GET {url} failed")),
        )),
    }
}
