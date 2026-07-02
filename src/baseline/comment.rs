//! Comment-directive parsing: pull a single `/bomdrift suppress <ID>`
//! directive out of a PR or MR comment body.

use anyhow::Result;

/// Parse the body of a PR/MR comment and extract a single
/// `/bomdrift suppress <ID>[ reason: <text>]` directive. The grammar
/// is documented in CLI help and in
/// `examples/gitlab-ci/comment-bridge/`'s threat model. The same
/// shape is honored by `comment-suppress/entrypoint.sh` for the
/// GitHub flow — keep these in lockstep.
///
/// Returns `Ok(Some((id, optional_reason)))` on a single match,
/// `Ok(None)` on no match, `Err` on a malformed ID.
pub fn parse_comment_directive(body: &str) -> Result<Option<(String, Option<String>)>> {
    // Looks for `/bomdrift suppress <ID>[ reason: <text>]` on each
    // line; the directive may be preceded by free-form prose and/or
    // mention markers. A leading `^\s*` anchor on the directive itself
    // is too strict — reviewers paste the directive after a comment.
    for line in body.lines() {
        let Some(idx) = line.find("/bomdrift") else {
            continue;
        };
        let rest = &line[idx + "/bomdrift".len()..];
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix("suppress") else {
            continue;
        };
        let rest = rest.trim_start();
        if rest.is_empty() {
            continue;
        }
        let mut iter = rest.splitn(2, char::is_whitespace);
        let raw_id = iter.next().unwrap_or("").trim();
        if raw_id.is_empty() {
            continue;
        }
        if !is_valid_advisory_id(raw_id) {
            anyhow::bail!(
                "comment directive contained a malformed advisory ID: {raw_id:?} \
                 (expected GHSA-/CVE-/MAL-/OSV- prefix and alnum/dash body)"
            );
        }
        let reason = iter.next().and_then(|tail| {
            let tail = tail.trim();
            tail.strip_prefix("reason:")
                .map(|r| r.trim().to_string())
                .filter(|s| !s.is_empty())
        });
        return Ok(Some((raw_id.to_string(), reason)));
    }
    Ok(None)
}

fn is_valid_advisory_id(s: &str) -> bool {
    // Aligns with comment-suppress/entrypoint.sh's regex:
    //   ^(GHSA-[a-z0-9-]+|CVE-[0-9]{4}-[0-9]+|MAL-[0-9]{4}-[0-9]+|OSV-[A-Z0-9-]+)$
    // Kept slightly looser here (we accept GHSA-uppercase and OSV-* too)
    // so future advisory schemes don't trip the bridge unnecessarily.
    let Some((prefix, rest)) = s.split_once('-') else {
        return false;
    };
    if !matches!(prefix, "GHSA" | "CVE" | "MAL" | "OSV") {
        return false;
    }
    if rest.is_empty() {
        return false;
    }
    rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}
