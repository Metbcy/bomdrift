use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::diff::ChangeSet;

use super::codeberg::lookup_codeberg_repo;
use super::github::lookup_github_repo;
use super::gitlab::lookup_gitlab_repo;
use super::parsing::{parse_codeberg_repo, parse_github_repo, parse_gitlab_repo};
use super::types::{
    DEFAULT_TIMEOUT, GITHUB_API_BASE, Host, LookupError, MaintainerAgeFinding, MaintainerInfo,
    YOUNG_MAINTAINER_DAYS,
};

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
