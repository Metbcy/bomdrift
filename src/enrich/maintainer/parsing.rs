use anyhow::{Context, Result};

/// Percent-encode a string for use in URL path segments or query values.
/// Unreserved characters (RFC 3986) are passed through; everything else,
/// including `/`, is encoded as `%XX`.
pub(super) fn percent_encode(s: &str) -> String {
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
pub(super) fn normalize_iso8601(s: &str) -> Option<String> {
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

pub(super) fn parse_top_contributor_login(body: &str) -> Result<Option<String>> {
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

pub(super) fn parse_first_commit_date(body: &str) -> Result<Option<String>> {
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

pub(super) fn parse_gitlab_top_contributor_name(body: &str) -> Result<Option<String>> {
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

pub(super) fn parse_gitlab_first_commit_date(body: &str) -> Result<Option<String>> {
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
