//! Maintainer-age enrichment: flag newly added dependencies hosted on GitHub,
//! GitLab, or Codeberg whose top contributor's first commit is suspiciously
//! recent.
//!
//! ## The signal
//!
//! The xz/`liblzma` backdoor of 2024 (CVE-2024-3094) was authored by a GitHub
//! identity ("Jia Tan") that started contributing two years before introducing
//! the malicious payload. The pattern -- a brand-new account becoming the de
//! facto sole maintainer of a low-traffic but widely-depended-upon package --
//! is a leading indicator of long-game supply-chain takeovers. We can't catch
//! Jia Tan in retrospect, but we can flag the next one earlier in their arc by
//! surfacing "this package's top contributor opened their first commit less than
//! 90 days ago" at the moment a new dep is added.
//!
//! ## Threshold
//!
//! 90 days is intentionally aggressive. Most legitimate new packages will trip
//! this on initial introduction; that's fine -- a human reviewer can dismiss
//! "the package is brand-new and the author is its only maintainer" trivially.
//! The expensive miss is the **silent takeover** of an existing package by a
//! recently-arrived contributor, which is what 90-day captures. Tune later if
//! the false-positive rate is unworkable in practice.
//!
//! ## Why no octocrab / no chrono
//!
//! `octocrab` pulls in `tokio` and ~70 transitive crates for what amounts to
//! three GET requests. `chrono` similarly bloats the dep tree for parsing one
//! ISO-8601 timestamp shape (GitHub always emits the canonical
//! `YYYY-MM-DDTHH:MM:SSZ`). Hand-rolled `ureq` calls and a 25-line ISO-8601
//! parser keep the binary under our 5 MB target. The same constraint applies
//! to GitLab and Codeberg; no new heavyweight dependencies are added.
//!
//! ## Network behavior
//!
//! Best-effort, mirrors the OSV enricher: per-request timeout 15 seconds,
//! errors surface as warnings on stderr, the diff still renders. Token env
//! vars raise rate limits: `GITHUB_TOKEN` (Bearer, GitHub REST), `GITLAB_TOKEN`
//! (PRIVATE-TOKEN header, GitLab v4), `CODEBERG_TOKEN` (Authorization: token,
//! Gitea v1). All three are optional; absent means unauthenticated requests,
//! fine for low volume.
//!
//! ## Skipped cases
//!
//! - Components without a `source_url` (CycloneDX `externalReferences[type=vcs]`
//!   absent, etc.) -- silently skipped.
//! - Source URLs not matching github.com, gitlab.com, or codeberg.org --
//!   silently skipped.
//! - Repositories with > 50 contributors -- skipped because the "top
//!   contributor's first commit" loses meaning on monorepos and multi-vendor
//!   projects (Linux, Kubernetes, React).
//! - Per-repo results are cached within a single bomdrift run so repeated
//!   `cs.added` entries from the same project don't multiply HTTP requests.
//!
//! Always informational severity -- never trips fail-on.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::diff::ChangeSet;
use crate::model::Component;

const GITHUB_API_BASE: &str = "https://api.github.com";
const GITLAB_API_BASE: &str = "https://gitlab.com/api/v4";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const USER_AGENT: &str = concat!("bomdrift/", env!("CARGO_PKG_VERSION"));

/// Repos with more contributors than this are treated as monorepos and skipped:
/// "top contributor joined recently" loses meaning when 200 people have committed.
const MAX_CONTRIBUTORS_FOR_SIGNAL: u64 = 50;

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
    fn label(self) -> &'static str {
        match self {
            Host::Github => "GitHub",
            Host::Gitlab => "GitLab",
            Host::Codeberg => "Codeberg",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MaintainerAgeFinding {
    pub component: Component,
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
struct MaintainerInfo {
    /// `Some(...)` when the repo passed all filters and we got a date back.
    /// `None` when the repo was skipped (too many contributors, no commits,
    /// not-found, etc.) -- cached so we don't retry.
    finding: Option<(String, String, i64)>,
}

pub fn enrich(cs: &ChangeSet) -> Result<Vec<MaintainerAgeFinding>> {
    enrich_with(cs, GITHUB_API_BASE, DEFAULT_TIMEOUT, None)
}

/// GitHub-only enrichment. Accepts a `base_url` override so tests can point at
/// an unreachable address and confirm that non-GitHub URLs short-circuit before
/// any HTTP is issued. For multi-host production use, call `enrich_with_hosts`.
pub fn enrich_with(
    cs: &ChangeSet,
    base_url: &str,
    timeout: Duration,
    young_maintainer_days: Option<i64>,
) -> Result<Vec<MaintainerAgeFinding>> {
    let threshold = young_maintainer_days.unwrap_or(YOUNG_MAINTAINER_DAYS);
    if cs.added.is_empty() {
        return Ok(Vec::new());
    }

    let token = std::env::var("GITHUB_TOKEN").ok();
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let mut cache: HashMap<String, MaintainerInfo> = HashMap::new();
    let mut out: Vec<MaintainerAgeFinding> = Vec::new();

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    for comp in &cs.added {
        let Some(url) = comp.source_url.as_deref() else {
            continue;
        };
        let Some((owner, repo)) = parse_github_repo(url) else {
            continue;
        };
        let key = format!("{owner}/{repo}");

        let info = if let Some(cached) = cache.get(&key) {
            cached.clone()
        } else {
            let lookup =
                lookup_github_repo(&agent, base_url, &owner, &repo, token.as_deref(), now_secs);
            match lookup {
                Ok(info) => {
                    cache.insert(key.clone(), info.clone());
                    info
                }
                Err(LookupError::RateLimited) => {
                    eprintln!(
                        "warning: GitHub rate limit exhausted, skipping remaining maintainer-age lookups"
                    );
                    break;
                }
                Err(LookupError::Other(err)) => {
                    return Err(err);
                }
            }
        };

        if let Some((login, date, days)) = info.finding
            && days < threshold
        {
            out.push(MaintainerAgeFinding {
                component: comp.clone(),
                top_contributor: login,
                first_commit_at: date,
                days_old: days,
                host: Host::Github,
            });
        }
    }

    Ok(out)
}

/// Multi-host enrichment covering GitHub, GitLab, and Codeberg. This is the
/// production entry point used by `run.rs`. The `github_base_url` parameter
/// mirrors the `base_url` parameter of `enrich_with` so existing call sites
/// require only a rename.
pub fn enrich_with_hosts(
    cs: &ChangeSet,
    github_base_url: &str,
    timeout: Duration,
    young_maintainer_days: Option<i64>,
) -> Result<Vec<MaintainerAgeFinding>> {
    let threshold = young_maintainer_days.unwrap_or(YOUNG_MAINTAINER_DAYS);
    if cs.added.is_empty() {
        return Ok(Vec::new());
    }

    let github_token = std::env::var("GITHUB_TOKEN").ok();
    let gitlab_token = std::env::var("GITLAB_TOKEN").ok();
    let codeberg_token = std::env::var("CODEBERG_TOKEN").ok();
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let mut cache: HashMap<String, MaintainerInfo> = HashMap::new();
    let mut out: Vec<MaintainerAgeFinding> = Vec::new();
    // Per-host rate-limit flags: [github, gitlab, codeberg].
    let mut rate_limited = [false; 3];

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    for comp in &cs.added {
        let Some(url) = comp.source_url.as_deref() else {
            continue;
        };

        let (host, owner, repo) = if let Some((o, r)) = parse_github_repo(url) {
            (Host::Github, o, r)
        } else if let Some((o, r)) = parse_gitlab_repo(url) {
            (Host::Gitlab, o, r)
        } else if let Some((o, r)) = parse_codeberg_repo(url) {
            (Host::Codeberg, o, r)
        } else {
            continue;
        };

        let host_idx = match host {
            Host::Github => 0,
            Host::Gitlab => 1,
            Host::Codeberg => 2,
        };
        if rate_limited[host_idx] {
            continue;
        }

        let host_str = match host {
            Host::Github => "github",
            Host::Gitlab => "gitlab",
            Host::Codeberg => "codeberg",
        };
        let key = format!("{host_str}/{owner}/{repo}");

        let info = if let Some(cached) = cache.get(&key) {
            cached.clone()
        } else {
            let lookup = match host {
                Host::Github => lookup_github_repo(
                    &agent,
                    github_base_url,
                    &owner,
                    &repo,
                    github_token.as_deref(),
                    now_secs,
                ),
                Host::Gitlab => {
                    lookup_gitlab_repo(&agent, &owner, &repo, gitlab_token.as_deref(), now_secs)
                }
                Host::Codeberg => {
                    lookup_codeberg_repo(&agent, &owner, &repo, codeberg_token.as_deref(), now_secs)
                }
            };
            match lookup {
                Ok(info) => {
                    cache.insert(key.clone(), info.clone());
                    info
                }
                Err(LookupError::RateLimited) => {
                    rate_limited[host_idx] = true;
                    eprintln!(
                        "warning: {} rate limit exhausted, skipping remaining {} maintainer-age lookups",
                        host.label(),
                        host.label(),
                    );
                    cache.insert(key, MaintainerInfo { finding: None });
                    continue;
                }
                Err(LookupError::Other(err)) => {
                    return Err(err);
                }
            }
        };

        if let Some((login, date, days)) = info.finding
            && days < threshold
        {
            out.push(MaintainerAgeFinding {
                component: comp.clone(),
                top_contributor: login,
                first_commit_at: date,
                days_old: days,
                host,
            });
        }
    }

    Ok(out)
}

enum LookupError {
    RateLimited,
    Other(anyhow::Error),
}

// ---- GitHub ----

/// Resolve a single `owner/repo` on GitHub. Returns the maintainer's login +
/// first commit date + days-old when the repo is in scope, or
/// `MaintainerInfo { finding: None }` when deliberately skipped.
fn lookup_github_repo(
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

struct GithubResponse {
    body: String,
    link_header: Option<String>,
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

// ---- GitLab ----

/// Resolve a single `owner/repo` on GitLab using the v4 REST API.
/// Uses `X-Total` header for contributor count (no Link-header parsing needed).
/// Author names (not logins) are stored; GitLab contributors are identified by
/// commit author name/email, not a username.
fn lookup_gitlab_repo(
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

struct GitlabResponse {
    body: String,
    link_header: Option<String>,
    /// GitLab includes the total item count in `X-Total` on every paginated
    /// response, regardless of `per_page`. Absent when the total exceeds
    /// GitLab's configured limit (very large repos).
    x_total: Option<u64>,
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

// ---- Codeberg ----

/// Stub: Codeberg (Forgejo/Gitea v1) URL parsing and Host dispatch are wired,
/// but the per-author first-commit lookup is not yet implemented. Gitea's
/// commits endpoint gained reliable `?author=` filtering in v1.20; Codeberg's
/// exact API version and behavior need verification before shipping. Returns
/// no finding so the enricher stays clean rather than guessing.
///
/// TODO: implement lookup once Forgejo v1.20+ per-author commit filter is
/// confirmed. API base would be https://codeberg.org/api/v1.
fn lookup_codeberg_repo(
    _agent: &ureq::Agent,
    _owner: &str,
    _repo: &str,
    _token: Option<&str>,
    _now_secs: i64,
) -> std::result::Result<MaintainerInfo, LookupError> {
    Ok(MaintainerInfo { finding: None })
}

// ---- shared utilities ----

/// Percent-encode a string for use in URL path segments or query values.
/// Unreserved characters (RFC 3986) are passed through; everything else,
/// including `/`, is encoded as `%XX`.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 10);
    for &byte in s.as_bytes() {
        if matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(b"0123456789ABCDEF"[(byte >> 4) as usize] as char);
            out.push(b"0123456789ABCDEF"[(byte & 0xF) as usize] as char);
        }
    }
    out
}

/// Normalize an ISO-8601 timestamp to `YYYY-MM-DDTHH:MM:SSZ` for our parser.
/// Strips fractional seconds and timezone offset, keeping only the first 19
/// characters. Safe for day-granularity age calculations where an hour of
/// timezone drift does not affect the 90-day threshold.
fn normalize_iso8601(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    // Validate the structural separators at fixed positions.
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    // Defend against malformed input with a multi-byte UTF-8 char straddling
    // byte 19 (the slice point). The structural-separator checks above only
    // pin 5 of the first 19 bytes; the rest could in principle be anything.
    if !s.is_char_boundary(19) {
        return None;
    }
    Some(format!("{}Z", &s[..19]))
}

/// Extract `(owner, repo)` from a GitHub source URL. Returns `None` for
/// non-GitHub hosts. Strips a trailing `.git` suffix and any trailing path.
pub(crate) fn parse_github_repo(url: &str) -> Option<(String, String)> {
    // Accept: https://github.com/o/r, http://github.com/o/r, github.com/o/r,
    //         git+https://github.com/o/r.git, git@github.com:o/r.git, etc.
    let stripped = url
        .trim()
        .trim_start_matches("git+")
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("git://")
        .trim_start_matches("ssh://")
        .trim_start_matches("git@");

    let rest = stripped
        .strip_prefix("github.com/")
        .or_else(|| stripped.strip_prefix("github.com:"))
        .or_else(|| stripped.strip_prefix("www.github.com/"))?;

    let mut parts = rest.split('/');
    let owner = parts.next()?.to_string();
    let repo_raw = parts.next()?;
    let repo = repo_raw
        .split(['#', '?'])
        .next()
        .unwrap_or(repo_raw)
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_string();

    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner, repo))
}

/// Extract `(owner, repo)` from a GitLab source URL. Returns `None` for
/// non-GitLab hosts. Strips a trailing `.git` suffix and any trailing path.
///
/// Note: GitLab subgroup URLs (`gitlab.com/group/subgroup/repo`) are not
/// supported; the parser returns the first two path segments. Such URLs will
/// produce a 404 on the API call and be silently skipped.
pub(crate) fn parse_gitlab_repo(url: &str) -> Option<(String, String)> {
    let stripped = url
        .trim()
        .trim_start_matches("git+")
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("git://")
        .trim_start_matches("ssh://")
        .trim_start_matches("git@");

    let rest = stripped
        .strip_prefix("gitlab.com/")
        .or_else(|| stripped.strip_prefix("gitlab.com:"))?;

    let mut parts = rest.split('/');
    let owner = parts.next()?.to_string();
    let repo_raw = parts.next()?;
    let repo = repo_raw
        .split(['#', '?'])
        .next()
        .unwrap_or(repo_raw)
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_string();

    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner, repo))
}

/// Extract `(owner, repo)` from a Codeberg source URL. Returns `None` for
/// non-Codeberg hosts. Strips a trailing `.git` suffix and any trailing path.
pub(crate) fn parse_codeberg_repo(url: &str) -> Option<(String, String)> {
    let stripped = url
        .trim()
        .trim_start_matches("git+")
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("git://")
        .trim_start_matches("ssh://")
        .trim_start_matches("git@");

    let rest = stripped
        .strip_prefix("codeberg.org/")
        .or_else(|| stripped.strip_prefix("codeberg.org:"))?;

    let mut parts = rest.split('/');
    let owner = parts.next()?.to_string();
    let repo_raw = parts.next()?;
    let repo = repo_raw
        .split(['#', '?'])
        .next()
        .unwrap_or(repo_raw)
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_string();

    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner, repo))
}

/// Parse the page number out of `<...?page=N>; rel="last"` in a Link header.
/// GitHub's Link header looks like:
///   `<https://api.github.com/...?page=2>; rel="next", <https://api.github.com/...?page=42>; rel="last"`
pub(crate) fn parse_link_last_page(link: Option<&str>) -> Option<u64> {
    let header = link?;
    for segment in header.split(',') {
        let segment = segment.trim();
        if !segment.contains(r#"rel="last""#) {
            continue;
        }
        let url_start = segment.find('<')?;
        let url_end = segment.find('>')?;
        if url_end <= url_start {
            return None;
        }
        let url = &segment[url_start + 1..url_end];
        let page_param = url
            .split(['?', '&'])
            .find_map(|p| p.strip_prefix("page="))?;
        return page_param.parse::<u64>().ok();
    }
    None
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` (GitHub's canonical timestamp form) into Unix
/// seconds. Returns `None` for any deviation from that exact shape -- we do not
/// try to be a full ISO-8601 parser.
pub(crate) fn iso8601_to_unix_seconds(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }

    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days since 1970-01-01 for a proleptic Gregorian (year, month, day). Howard
/// Hinnant's `days_from_civil` algorithm -- exact, branch-free, ~10 lines.
/// See <https://howardhinnant.github.io/date_algorithms.html>.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as u64 + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

fn parse_top_contributor_login(body: &str) -> Result<Option<String>> {
    let value: serde_json::Value = serde_json::from_str(body).context("invalid JSON")?;
    let Some(arr) = value.as_array() else {
        return Ok(None);
    };
    let Some(first) = arr.first() else {
        return Ok(None);
    };
    Ok(first
        .get("login")
        .and_then(|v| v.as_str())
        .map(str::to_string))
}

fn parse_first_commit_date(body: &str) -> Result<Option<String>> {
    let value: serde_json::Value = serde_json::from_str(body).context("invalid JSON")?;
    let Some(arr) = value.as_array() else {
        return Ok(None);
    };
    // The "last page" of newest-first commits contains the OLDEST commits;
    // within that page the chronologically-oldest record is the LAST element.
    let Some(last) = arr.last() else {
        return Ok(None);
    };
    Ok(last
        .pointer("/commit/author/date")
        .and_then(|v| v.as_str())
        .map(str::to_string))
}

fn parse_gitlab_top_contributor_name(body: &str) -> Result<Option<String>> {
    let value: serde_json::Value = serde_json::from_str(body).context("invalid JSON")?;
    let Some(arr) = value.as_array() else {
        return Ok(None);
    };
    let Some(first) = arr.first() else {
        return Ok(None);
    };
    // GitLab contributors are identified by commit author name, not a username.
    Ok(first
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_string))
}

fn parse_gitlab_first_commit_date(body: &str) -> Result<Option<String>> {
    let value: serde_json::Value = serde_json::from_str(body).context("invalid JSON")?;
    let Some(arr) = value.as_array() else {
        return Ok(None);
    };
    // Newest-first ordering on the last page: the chronologically-oldest
    // record is the LAST element.
    let Some(last) = arr.last() else {
        return Ok(None);
    };
    // `authored_date` is when the commit was written; fall back to
    // `committed_date` for forges that omit authored_date.
    let date = last
        .get("authored_date")
        .and_then(|v| v.as_str())
        .or_else(|| last.get("committed_date").and_then(|v| v.as_str()))
        .map(str::to_string);
    Ok(date)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )]
    use super::*;
    use crate::model::{Component, Ecosystem, Relationship};

    fn comp_with_url(name: &str, url: Option<&str>) -> Component {
        Component {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            purl: Some(format!("pkg:npm/{name}@1.0.0")),
            licenses: Vec::new(),
            supplier: None,
            hashes: Vec::new(),
            relationship: Relationship::Unknown,
            source_url: url.map(str::to_string),
            bom_ref: None,
        }
    }

    // ---- GitHub URL parsing ----

    #[test]
    fn parse_github_repo_extracts_https_url() {
        let parsed = parse_github_repo("https://github.com/axios/axios");
        assert_eq!(parsed, Some(("axios".to_string(), "axios".to_string())));
    }

    #[test]
    fn parse_github_repo_strips_dot_git_suffix() {
        let parsed = parse_github_repo("https://github.com/foo/bar.git");
        assert_eq!(parsed, Some(("foo".to_string(), "bar".to_string())));
    }

    #[test]
    fn parse_github_repo_handles_trailing_path_and_fragment() {
        assert_eq!(
            parse_github_repo("https://github.com/foo/bar/tree/main/sub"),
            Some(("foo".to_string(), "bar".to_string()))
        );
        assert_eq!(
            parse_github_repo("https://github.com/foo/bar#readme"),
            Some(("foo".to_string(), "bar".to_string()))
        );
    }

    #[test]
    fn parse_github_repo_handles_git_plus_and_ssh_forms() {
        assert_eq!(
            parse_github_repo("git+https://github.com/foo/bar.git"),
            Some(("foo".to_string(), "bar".to_string()))
        );
        assert_eq!(
            parse_github_repo("git@github.com:foo/bar.git"),
            Some(("foo".to_string(), "bar".to_string()))
        );
    }

    #[test]
    fn parse_github_repo_returns_none_for_non_github() {
        assert_eq!(parse_github_repo("https://gitlab.com/foo/bar"), None);
        assert_eq!(parse_github_repo("https://example.com/foo/bar"), None);
        assert_eq!(parse_github_repo(""), None);
        assert_eq!(parse_github_repo("https://github.com/onlyowner"), None);
    }

    // ---- GitLab URL parsing ----

    #[test]
    fn parse_gitlab_repo_extracts_https_url() {
        assert_eq!(
            parse_gitlab_repo("https://gitlab.com/foo/bar"),
            Some(("foo".to_string(), "bar".to_string()))
        );
    }

    #[test]
    fn parse_gitlab_repo_strips_dot_git_suffix() {
        assert_eq!(
            parse_gitlab_repo("https://gitlab.com/foo/bar.git"),
            Some(("foo".to_string(), "bar".to_string()))
        );
    }

    #[test]
    fn parse_gitlab_repo_handles_trailing_path_and_fragment() {
        assert_eq!(
            parse_gitlab_repo("https://gitlab.com/foo/bar/-/tree/main"),
            Some(("foo".to_string(), "bar".to_string()))
        );
        assert_eq!(
            parse_gitlab_repo("https://gitlab.com/foo/bar#readme"),
            Some(("foo".to_string(), "bar".to_string()))
        );
    }

    #[test]
    fn parse_gitlab_repo_handles_git_plus_and_ssh_forms() {
        assert_eq!(
            parse_gitlab_repo("git+https://gitlab.com/foo/bar.git"),
            Some(("foo".to_string(), "bar".to_string()))
        );
        assert_eq!(
            parse_gitlab_repo("git@gitlab.com:foo/bar.git"),
            Some(("foo".to_string(), "bar".to_string()))
        );
    }

    #[test]
    fn parse_gitlab_repo_returns_none_for_non_gitlab() {
        assert_eq!(parse_gitlab_repo("https://github.com/foo/bar"), None);
        assert_eq!(parse_gitlab_repo("https://codeberg.org/foo/bar"), None);
        assert_eq!(parse_gitlab_repo("https://example.com/foo/bar"), None);
        assert_eq!(parse_gitlab_repo(""), None);
        assert_eq!(parse_gitlab_repo("https://gitlab.com/onlyowner"), None);
    }

    // ---- Codeberg URL parsing ----

    #[test]
    fn parse_codeberg_repo_extracts_https_url() {
        assert_eq!(
            parse_codeberg_repo("https://codeberg.org/foo/bar"),
            Some(("foo".to_string(), "bar".to_string()))
        );
    }

    #[test]
    fn parse_codeberg_repo_strips_dot_git_suffix() {
        assert_eq!(
            parse_codeberg_repo("https://codeberg.org/foo/bar.git"),
            Some(("foo".to_string(), "bar".to_string()))
        );
    }

    #[test]
    fn parse_codeberg_repo_handles_trailing_path_and_fragment() {
        assert_eq!(
            parse_codeberg_repo("https://codeberg.org/foo/bar/src/branch/main"),
            Some(("foo".to_string(), "bar".to_string()))
        );
        assert_eq!(
            parse_codeberg_repo("https://codeberg.org/foo/bar#readme"),
            Some(("foo".to_string(), "bar".to_string()))
        );
    }

    #[test]
    fn parse_codeberg_repo_handles_ssh_form() {
        assert_eq!(
            parse_codeberg_repo("git@codeberg.org:foo/bar.git"),
            Some(("foo".to_string(), "bar".to_string()))
        );
    }

    #[test]
    fn parse_codeberg_repo_returns_none_for_non_codeberg() {
        assert_eq!(parse_codeberg_repo("https://github.com/foo/bar"), None);
        assert_eq!(parse_codeberg_repo("https://gitlab.com/foo/bar"), None);
        assert_eq!(parse_codeberg_repo("https://example.com/foo/bar"), None);
        assert_eq!(parse_codeberg_repo(""), None);
        assert_eq!(parse_codeberg_repo("https://codeberg.org/onlyowner"), None);
    }

    // ---- Link header parsing ----

    #[test]
    fn parse_link_last_page_extracts_page_number() {
        let header = r#"<https://api.github.com/repositories/1/contributors?per_page=1&page=2>; rel="next", <https://api.github.com/repositories/1/contributors?per_page=1&page=42>; rel="last""#;
        assert_eq!(parse_link_last_page(Some(header)), Some(42));
    }

    #[test]
    fn parse_link_last_page_returns_none_when_no_last_rel() {
        let header = r#"<https://api.github.com/...?page=2>; rel="next""#;
        assert_eq!(parse_link_last_page(Some(header)), None);
    }

    #[test]
    fn parse_link_last_page_handles_missing_header() {
        assert_eq!(parse_link_last_page(None), None);
    }

    // ---- ISO-8601 parsing ----

    #[test]
    fn iso8601_round_trips_known_date() {
        // 2024-03-29T00:00:00Z is xz-backdoor-disclosure day. Sanity check the
        // parser by computing days since unix epoch (1970-01-01 -> 19,811 days).
        let secs = iso8601_to_unix_seconds("2024-03-29T00:00:00Z").expect("valid date");
        assert_eq!(secs, 19811 * 86_400);
    }

    #[test]
    fn iso8601_handles_non_midnight_time() {
        // 2026-01-15T12:34:56Z = 1_768_480_496 (verified via `date -d ... +%s`).
        let secs = iso8601_to_unix_seconds("2026-01-15T12:34:56Z").expect("valid date");
        assert_eq!(secs, 1_768_480_496);
    }

    #[test]
    fn iso8601_unix_epoch_is_zero() {
        assert_eq!(iso8601_to_unix_seconds("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn iso8601_rejects_malformed_input() {
        assert_eq!(iso8601_to_unix_seconds(""), None);
        assert_eq!(iso8601_to_unix_seconds("2024-03-29"), None);
        assert_eq!(iso8601_to_unix_seconds("2024-13-01T00:00:00Z"), None);
        assert_eq!(iso8601_to_unix_seconds("2024-03-29T25:00:00Z"), None);
        assert_eq!(iso8601_to_unix_seconds("2024-03-29T00:00:00"), None);
    }

    // ---- normalize_iso8601 ----

    #[test]
    fn normalize_iso8601_handles_canonical_zulu_form() {
        assert_eq!(
            normalize_iso8601("2024-04-15T12:34:56Z"),
            Some("2024-04-15T12:34:56Z".to_string())
        );
    }

    #[test]
    fn normalize_iso8601_strips_fractional_seconds() {
        assert_eq!(
            normalize_iso8601("2024-04-15T12:34:56.123Z"),
            Some("2024-04-15T12:34:56Z".to_string())
        );
        assert_eq!(
            normalize_iso8601("2024-04-15T12:34:56.000+00:00"),
            Some("2024-04-15T12:34:56Z".to_string())
        );
    }

    #[test]
    fn normalize_iso8601_rejects_short_input() {
        assert_eq!(normalize_iso8601(""), None);
        assert_eq!(normalize_iso8601("2024-04-15"), None);
        assert_eq!(normalize_iso8601("2024-04-15T12:34"), None);
    }

    #[test]
    fn normalize_iso8601_rejects_multibyte_at_slice_point() {
        // Structural separators pass, but byte 18 is the start of a 3-byte
        // UTF-8 sequence (the "é" in this hand-crafted nonsense input lands
        // such that index 19 falls mid-codepoint). Must return None, not panic.
        let s = "2024-04-15T12:34:5\u{00e9}rest";
        assert_eq!(normalize_iso8601(s), None);
    }

    // ---- percent_encode ----

    #[test]
    fn percent_encode_passes_through_unreserved_chars() {
        assert_eq!(percent_encode("foo-bar_baz.qux~123"), "foo-bar_baz.qux~123");
    }

    #[test]
    fn percent_encode_encodes_slash_and_space() {
        assert_eq!(percent_encode("owner/repo"), "owner%2Frepo");
        assert_eq!(percent_encode("Jia Tan"), "Jia%20Tan");
    }

    // ---- enrich_with smoke tests (GitHub-only path) ----

    #[test]
    fn empty_changeset_short_circuits_to_empty_ok() {
        let cs = ChangeSet::default();
        let out = enrich(&cs).expect("empty must succeed without I/O");
        assert!(out.is_empty());
    }

    #[test]
    fn components_without_source_url_are_silently_skipped() {
        // No HTTP must be attempted, so an unreachable base_url is fine.
        let cs = ChangeSet {
            added: vec![comp_with_url("foo", None)],
            ..Default::default()
        };
        let out = enrich_with(&cs, "http://127.0.0.1:1", Duration::from_millis(50), None)
            .expect("no source_url means no HTTP, must succeed");
        assert!(out.is_empty());
    }

    #[test]
    fn non_github_source_urls_are_silently_skipped() {
        // enrich_with is GitHub-only; GitLab/Codeberg URLs short-circuit before
        // any HTTP call, so an unreachable base_url is fine here.
        let cs = ChangeSet {
            added: vec![comp_with_url("foo", Some("https://gitlab.com/foo/bar"))],
            ..Default::default()
        };
        let out = enrich_with(&cs, "http://127.0.0.1:1", Duration::from_millis(50), None)
            .expect("non-github means no HTTP, must succeed");
        assert!(out.is_empty());
    }

    // ---- enrich_with_hosts smoke tests ----

    #[test]
    fn hosts_empty_changeset_short_circuits() {
        let cs = ChangeSet::default();
        let out = enrich_with_hosts(&cs, "http://127.0.0.1:1", Duration::from_millis(50), None)
            .expect("empty changeset must short-circuit without I/O");
        assert!(out.is_empty());
    }

    #[test]
    fn hosts_no_source_url_skipped() {
        let cs = ChangeSet {
            added: vec![comp_with_url("foo", None)],
            ..Default::default()
        };
        let out = enrich_with_hosts(&cs, "http://127.0.0.1:1", Duration::from_millis(50), None)
            .expect("no source_url means no HTTP");
        assert!(out.is_empty());
    }

    #[test]
    fn hosts_unknown_forge_url_skipped() {
        let cs = ChangeSet {
            added: vec![comp_with_url("foo", Some("https://example.com/foo/bar"))],
            ..Default::default()
        };
        let out = enrich_with_hosts(&cs, "http://127.0.0.1:1", Duration::from_millis(50), None)
            .expect("unknown forge means no HTTP");
        assert!(out.is_empty());
    }

    // ---- JSON parsers ----

    #[test]
    fn parse_top_contributor_returns_login_field() {
        let body = r#"[{"login":"jia-tan","id":1}]"#;
        assert_eq!(
            parse_top_contributor_login(body).unwrap(),
            Some("jia-tan".to_string())
        );
    }

    #[test]
    fn parse_top_contributor_returns_none_for_empty_array() {
        assert_eq!(parse_top_contributor_login("[]").unwrap(), None);
    }

    #[test]
    fn parse_first_commit_date_takes_last_array_element() {
        // Newest-first ordering: the OLDEST commit is the LAST element on the
        // last page. We assert that the parser returns the date of the last
        // element, not the first.
        let body = r#"[
            {"commit":{"author":{"date":"2024-06-01T00:00:00Z"}}},
            {"commit":{"author":{"date":"2024-01-01T00:00:00Z"}}}
        ]"#;
        assert_eq!(
            parse_first_commit_date(body).unwrap(),
            Some("2024-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn parse_first_commit_date_handles_empty_array() {
        assert_eq!(parse_first_commit_date("[]").unwrap(), None);
    }

    #[test]
    fn parse_gitlab_top_contributor_name_returns_name_field() {
        let body = r#"[{"name":"Jia Tan","email":"jia.tan@example.com","commits":42}]"#;
        assert_eq!(
            parse_gitlab_top_contributor_name(body).unwrap(),
            Some("Jia Tan".to_string())
        );
    }

    #[test]
    fn parse_gitlab_top_contributor_name_returns_none_for_empty_array() {
        assert_eq!(parse_gitlab_top_contributor_name("[]").unwrap(), None);
    }

    #[test]
    fn parse_gitlab_first_commit_date_takes_last_element_authored_date() {
        let body = r#"[
            {"authored_date":"2024-06-01T00:00:00.000+00:00","committed_date":"2024-06-01T00:00:00.000+00:00"},
            {"authored_date":"2024-01-01T00:00:00.000+00:00","committed_date":"2024-01-01T00:00:00.000+00:00"}
        ]"#;
        assert_eq!(
            parse_gitlab_first_commit_date(body).unwrap(),
            Some("2024-01-01T00:00:00.000+00:00".to_string())
        );
    }

    #[test]
    fn parse_gitlab_first_commit_date_falls_back_to_committed_date() {
        let body = r#"[{"committed_date":"2024-03-01T08:00:00.000Z"}]"#;
        assert_eq!(
            parse_gitlab_first_commit_date(body).unwrap(),
            Some("2024-03-01T08:00:00.000Z".to_string())
        );
    }

    #[test]
    fn parse_gitlab_first_commit_date_handles_empty_array() {
        assert_eq!(parse_gitlab_first_commit_date("[]").unwrap(), None);
    }
}
