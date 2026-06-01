#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

use std::time::Duration;

use super::parsing::{
    iso8601_to_unix_seconds, normalize_iso8601, parse_codeberg_repo, parse_first_commit_date,
    parse_github_repo, parse_gitlab_first_commit_date, parse_gitlab_repo,
    parse_gitlab_top_contributor_name, parse_link_last_page, parse_top_contributor_login,
    percent_encode,
};
use super::pipeline::{enrich, enrich_with, enrich_with_hosts};
use crate::diff::ChangeSet;
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
