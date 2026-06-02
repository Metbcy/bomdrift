use anyhow::Context;

use super::parsing::{parse_first_commit_date, parse_link_last_page, parse_top_contributor_login};
use super::types::{
    GithubResponse, LookupError, MAX_CONTRIBUTORS_FOR_SIGNAL, MaintainerInfo, USER_AGENT,
};
use crate::enrich::maintainer::parsing::iso8601_to_unix_seconds;

/// Resolve a single `owner/repo` on GitHub. Returns the maintainer's login +
/// first commit date + days-old when the repo is in scope, or
/// `MaintainerInfo { finding: None }` when deliberately skipped.
pub(super) fn lookup_github_repo(
    agent: &ureq::Agent,
    base_url: &str,
    owner: &str,
    repo: &str,
    token: Option<&str>,
    now_secs: i64,
) -> std::result::Result<MaintainerInfo, LookupError> {
    // Step 1: top contributor (per_page=1 returns the highest-commit-count author).
    let top_url = format!("{base_url}/repos/{owner}/{repo}/contributors?per_page=1");
    let top_resp = github_get(agent, &top_url, token)?;
    let top_login = parse_top_contributor_login(&top_resp.body)
        .context("parsing top-contributor response from GitHub")
        .map_err(LookupError::Other)?;
    let Some(top_login) = top_login else {
        return Ok(MaintainerInfo { finding: None });
    };

    // Step 2: estimate contributor count. Asking for per_page=1 and reading the
    // last-page number from the Link header is a one-request count without
    // pulling 100 contributor records we don't need.
    let count_url = format!("{base_url}/repos/{owner}/{repo}/contributors?per_page=1&anon=true");
    let count_resp = github_get(agent, &count_url, token)?;
    let contributor_count = parse_link_last_page(count_resp.link_header.as_deref()).unwrap_or(1);
    if contributor_count > MAX_CONTRIBUTORS_FOR_SIGNAL {
        return Ok(MaintainerInfo { finding: None });
    }

    // Step 3: first commit by that author. The `?author=...&per_page=1` query
    // returns commits newest-first; the LAST page contains the oldest commit.
    let commits_first_url =
        format!("{base_url}/repos/{owner}/{repo}/commits?author={top_login}&per_page=1");
    let commits_first = github_get(agent, &commits_first_url, token)?;
    let last_page = parse_link_last_page(commits_first.link_header.as_deref());

    let oldest_body = match last_page {
        Some(page) if page > 1 => {
            let last_url = format!(
                "{base_url}/repos/{owner}/{repo}/commits?author={top_login}&per_page=1&page={page}"
            );
            github_get(agent, &last_url, token)?.body
        }
        // No pagination, or single page: the first response IS the last page.
        _ => commits_first.body,
    };

    let date_str = match parse_first_commit_date(&oldest_body) {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(MaintainerInfo { finding: None }),
        Err(e) => return Err(LookupError::Other(e)),
    };

    let Some(commit_secs) = iso8601_to_unix_seconds(&date_str) else {
        return Ok(MaintainerInfo { finding: None });
    };
    let days = (now_secs - commit_secs) / 86_400;

    Ok(MaintainerInfo {
        finding: Some((top_login, date_str, days)),
    })
}

fn github_get(
    agent: &ureq::Agent,
    url: &str,
    token: Option<&str>,
) -> std::result::Result<GithubResponse, LookupError> {
    let mut req = agent
        .get(url)
        .set("user-agent", USER_AGENT)
        .set("accept", "application/vnd.github+json")
        .set("x-github-api-version", "2022-11-28");
    if let Some(t) = token {
        req = req.set("authorization", &format!("Bearer {t}"));
    }
    match req.call() {
        Ok(resp) => {
            let link_header = resp.header("link").map(str::to_string);
            let body = resp
                .into_string()
                .context("reading GitHub response body")
                .map_err(LookupError::Other)?;
            Ok(GithubResponse { body, link_header })
        }
        Err(ureq::Error::Status(403, resp)) => {
            if resp.header("x-ratelimit-remaining") == Some("0") {
                Err(LookupError::RateLimited)
            } else {
                Err(LookupError::Other(anyhow::anyhow!(
                    "GitHub returned 403 for {url}"
                )))
            }
        }
        Err(ureq::Error::Status(404, _)) => {
            // Not-found is a deliberate skip, not an error: the repo may have
            // moved or been deleted. Surface as an empty body the callers parse
            // as "no data".
            Ok(GithubResponse {
                body: "[]".to_string(),
                link_header: None,
            })
        }
        Err(e) => Err(LookupError::Other(
            anyhow::Error::new(e).context(format!("GET {url} failed")),
        )),
    }
}
