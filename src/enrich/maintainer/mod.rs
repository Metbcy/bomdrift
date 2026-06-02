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

mod codeberg;
mod github;
mod gitlab;
mod parsing;
mod pipeline;
mod types;

#[cfg(test)]
mod tests;

pub use pipeline::{enrich, enrich_with, enrich_with_hosts};
pub use types::{Host, MaintainerAgeFinding, YOUNG_MAINTAINER_DAYS};

// Re-export crate-visible helpers that callers outside this module historically
// accessed via `crate::enrich::maintainer::...`. The pre-split file made
// `parse_github_repo`, `parse_gitlab_repo`, `parse_codeberg_repo`,
// `parse_link_last_page`, and `iso8601_to_unix_seconds` `pub(crate)`; keep
// those paths working even if no in-tree caller currently uses them.
#[allow(unused_imports)]
pub(crate) use parsing::{
    iso8601_to_unix_seconds, parse_codeberg_repo, parse_github_repo, parse_gitlab_repo,
    parse_link_last_page,
};
