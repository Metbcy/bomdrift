//! `bomdrift refresh-typosquat` subcommand: pull a fresh per-ecosystem
//! top-package list from the same upstream source `data/npm-top1k.txt` was
//! sourced from, and persist it under the user's XDG cache directory so the
//! typosquat enricher can prefer it over the snapshot baked into the binary.
//!
//! ## Why this is its own subcommand
//!
//! The lists go stale: new packages climb the popularity charts, others fall
//! off. Re-shipping the binary just to ship a fresher list is the wrong
//! cadence. A dedicated subcommand lets users (and downstream automation)
//! refresh on their own schedule without waiting for a release.
//!
//! ## Cache location
//!
//! On Linux this resolves to `<XDG_CACHE_HOME>/bomdrift/typosquat/<eco>.txt`,
//! falling back to `~/.cache/bomdrift/typosquat/<eco>.txt` when the env var is
//! unset. Resolution goes through the [`directories`] crate using qualifier
//! `dev`, organization `bomdrift`, application `bomdrift` — the org and
//! application names are intentionally identical (we own the namespace) and
//! the qualifier `dev` is a stable bucket for tools without a domain.
//!
//! ## v0.2 scope
//!
//! Wired ecosystems: `npm`, `pypi`, `cargo`. Each fetches from its canonical
//! upstream source and writes a refreshed list under `<cache>/typosquat/`.
//! `maven` is accepted on the `--ecosystem` flag but emits an informational
//! notice rather than fetching anything: Maven Central has no canonical
//! "top N" feed, so the curated `data/maven-top100.txt` shipped in the
//! binary is the source of truth.
//!
//! ## Atomicity
//!
//! Each list is written via the temp-file + rename pattern (`<file>.tmp` →
//! `rename` to `<file>`). bomdrift is single-user, so no flock is needed; the
//! atomic rename is enough to prevent the typosquat loader from observing a
//! half-written file even if `refresh-typosquat` is run concurrently with a
//! `diff` invocation.
//!
//! ## Testability
//!
//! Network and filesystem are split off the public [`run`] entry point via
//! [`run_with`], which accepts an injected fetcher closure and an explicit
//! cache root. Tests use a fake fetcher returning canned anvaka markdown plus
//! a tempdir cache root, so the test suite stays fully offline.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::cli::{RefreshArgs, RefreshEcosystem};

/// Source URL for the npm top-1000 list — the same anvaka gist that
/// `data/npm-top1k.txt` was originally generated from. Documented in
/// `data/README.md`.
pub const NPM_SOURCE_URL: &str =
    "https://gist.githubusercontent.com/anvaka/8e8fa57c7ee1350e3491/raw/01.most-dependent-upon.md";

/// Source URL for the PyPI top-N list. Returns a JSON object with a `rows`
/// array of `{download_count, project}`; we take the first 200.
pub const PYPI_SOURCE_URL: &str =
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json";

/// Pageable source URL for the crates.io top-N list. We fetch pages 1 and 2
/// (100 names per page) for a total of 200, with a 1 req/sec sleep between
/// pages to respect crates.io's rate limit.
pub const CARGO_SOURCE_URL_TEMPLATE: &str =
    "https://crates.io/api/v1/crates?sort=downloads&per_page=100&page=";

/// Source URL for the NuGet top-N list. The v3 search API supports
/// `orderby=totalDownloads&take=N` and returns up to 200 in one call —
/// no pagination needed at this list size.
pub const NUGET_SOURCE_URL: &str =
    "https://api-v2v3search-0.nuget.org/query?orderby=totalDownloads&take=200&prerelease=false";

/// How many crates.io pages to walk on a refresh. 2 pages * 100/page = 200
/// names, matching `data/cargo-top200.txt`.
const CARGO_PAGES: u32 = 2;

/// Sleep between paginated crates.io requests. Crates.io's rate-limit
/// guidance is "1 request per second", so a 1.0s gap is the conservative
/// floor. Tests inject a no-op sleeper to keep the suite fast.
const CARGO_PAGE_DELAY: Duration = Duration::from_secs(1);

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Public entry point used by `bomdrift refresh-typosquat`. Resolves the cache
/// root via `directories::ProjectDirs` and uses [`ureq`] for HTTP fetches.
pub fn run(args: RefreshArgs) -> Result<()> {
    let cache_root = default_cache_root()?;
    run_with(args, default_fetcher, &cache_root)
}

/// Test/internal entry point. Accepts an injected fetcher and an explicit
/// cache root so the test suite can exercise the full pipeline without
/// touching the network or the user's real cache directory.
pub(crate) fn run_with<F>(args: RefreshArgs, fetcher: F, cache_root: &Path) -> Result<()>
where
    F: Fn(&str) -> Result<Vec<u8>>,
{
    let mut any_failure = false;

    for eco in selected_ecosystems(args.ecosystem) {
        let result = match eco {
            RefreshEcosystem::Npm => refresh_npm(&fetcher, cache_root),
            RefreshEcosystem::PyPI => refresh_pypi(&fetcher, cache_root),
            RefreshEcosystem::Cargo => refresh_cargo(&fetcher, cache_root, std::thread::sleep),
            RefreshEcosystem::NuGet => refresh_nuget(&fetcher, cache_root),
            RefreshEcosystem::Maven => {
                eprintln!(
                    "skipping maven: no canonical upstream feed exists. The maven \
                     typosquat list is curated and shipped embedded; edit \
                     data/maven-top100.txt and rebuild bomdrift to update it."
                );
                Ok(())
            }
            RefreshEcosystem::Go => {
                eprintln!(
                    "skipping go: pkg.go.dev does not expose a public popularity feed. \
                     The Go typosquat list is curated and shipped embedded; edit \
                     data/go-top200.txt and rebuild bomdrift to update it."
                );
                Ok(())
            }
            RefreshEcosystem::Gem => {
                eprintln!(
                    "skipping gem: rubygems.org's public most-downloaded API has been \
                     unstable across releases. The Gem typosquat list is curated and \
                     shipped embedded; edit data/gem-top200.txt and rebuild bomdrift \
                     to update it."
                );
                Ok(())
            }
            RefreshEcosystem::Composer => {
                eprintln!(
                    "skipping composer: packagist.org's public statistics API has \
                     been unstable across releases. The Composer typosquat list is \
                     curated and shipped embedded; edit data/composer-top200.txt and \
                     rebuild bomdrift to update it."
                );
                Ok(())
            }
            RefreshEcosystem::All => unreachable!("`All` is expanded by selected_ecosystems"),
        };
        if let Err(err) = result {
            eprintln!("error: failed to refresh {eco:?} list: {err:#}");
            any_failure = true;
        }
    }

    if any_failure {
        bail!("one or more ecosystems failed to refresh");
    }
    Ok(())
}

/// Expand `All` into the concrete list of currently-wired ecosystems. Adding a
/// new ecosystem only requires extending this match arm.
fn selected_ecosystems(eco: RefreshEcosystem) -> Vec<RefreshEcosystem> {
    match eco {
        RefreshEcosystem::All => vec![
            RefreshEcosystem::Npm,
            RefreshEcosystem::PyPI,
            RefreshEcosystem::Cargo,
            RefreshEcosystem::Maven,
            RefreshEcosystem::Go,
            RefreshEcosystem::Gem,
            RefreshEcosystem::NuGet,
            RefreshEcosystem::Composer,
        ],
        single => vec![single],
    }
}

fn refresh_npm<F>(fetcher: &F, cache_root: &Path) -> Result<()>
where
    F: Fn(&str) -> Result<Vec<u8>>,
{
    eprintln!("refreshing npm from {NPM_SOURCE_URL}...");
    let body = fetcher(NPM_SOURCE_URL).context("fetching npm top-list source")?;
    let body_str =
        std::str::from_utf8(&body).context("npm top-list source was not valid UTF-8 markdown")?;
    let names = parse_anvaka_markdown(body_str);
    persist_list(cache_root, "npm.txt", "npm", &names)
}

/// Refresh PyPI: GET the hugovk JSON, take the first 200 project names. The
/// upstream document is sorted by descending download count, so a simple
/// truncation is the right "top N" semantics.
fn refresh_pypi<F>(fetcher: &F, cache_root: &Path) -> Result<()>
where
    F: Fn(&str) -> Result<Vec<u8>>,
{
    eprintln!("refreshing pypi from {PYPI_SOURCE_URL}...");
    let body = fetcher(PYPI_SOURCE_URL).context("fetching pypi top-list source")?;
    let names = parse_pypi_json(&body)?;
    persist_list(cache_root, "pypi.txt", "pypi", &names)
}

/// Refresh Cargo: paginate the crates.io API. Two pages of 100 is the
/// matching `data/cargo-top200.txt` size; the polite-pause sleeper is
/// dependency-injected so tests can run instantly.
fn refresh_cargo<F, S>(fetcher: &F, cache_root: &Path, sleep: S) -> Result<()>
where
    F: Fn(&str) -> Result<Vec<u8>>,
    S: Fn(Duration),
{
    let mut all_names: Vec<String> = Vec::new();
    for page in 1..=CARGO_PAGES {
        let url = format!("{CARGO_SOURCE_URL_TEMPLATE}{page}");
        eprintln!("refreshing cargo: page {page}/{CARGO_PAGES} from {url}...");
        let body = fetcher(&url).with_context(|| format!("fetching cargo page {page}"))?;
        let mut page_names =
            parse_cargo_json(&body).with_context(|| format!("parsing cargo page {page}"))?;
        all_names.append(&mut page_names);
        if page < CARGO_PAGES {
            sleep(CARGO_PAGE_DELAY);
        }
    }
    persist_list(cache_root, "cargo.txt", "cargo", &all_names)
}

/// Refresh NuGet: GET the v3 search API ordered by total downloads, take
/// 200 IDs in one shot. NuGet's search endpoint accepts `take=200` directly
/// so no pagination is required at this list size.
fn refresh_nuget<F>(fetcher: &F, cache_root: &Path) -> Result<()>
where
    F: Fn(&str) -> Result<Vec<u8>>,
{
    eprintln!("refreshing nuget from {NUGET_SOURCE_URL}...");
    let body = fetcher(NUGET_SOURCE_URL).context("fetching nuget top-list source")?;
    let names = parse_nuget_json(&body)?;
    persist_list(cache_root, "nuget.txt", "nuget", &names)
}

/// Shared cache-write tail for all per-ecosystem refresh paths. Refuses to
/// overwrite the cache with an empty list (so a transient upstream parse
/// regression doesn't silently neuter the typosquat enricher).
fn persist_list(cache_root: &Path, filename: &str, label: &str, names: &[String]) -> Result<()> {
    if names.is_empty() {
        bail!(
            "parsed zero {label} package names from upstream — refusing to overwrite cache with empty list"
        );
    }
    let target_dir = cache_root.join("typosquat");
    fs::create_dir_all(&target_dir)
        .with_context(|| format!("creating cache directory {}", target_dir.display()))?;
    let target = target_dir.join(filename);
    write_list_atomically(&target, names)
        .with_context(|| format!("writing {}", target.display()))?;
    eprintln!(
        "refreshing {label}... wrote {} names to {}",
        names.len(),
        target.display()
    );
    Ok(())
}

/// Parse the hugovk top-pypi-packages JSON. Shape:
/// `{"rows": [{"download_count": <int>, "project": "<name>"}, ...]}`.
/// Returns the first [`PYPI_TOP_N`] project names in upstream (descending
/// download-count) order.
pub(crate) fn parse_pypi_json(body: &[u8]) -> Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Row {
        project: String,
    }
    #[derive(serde::Deserialize)]
    struct Top {
        rows: Vec<Row>,
    }
    let parsed: Top = serde_json::from_slice(body).context("decoding pypi JSON")?;
    Ok(parsed
        .rows
        .into_iter()
        .take(PYPI_TOP_N)
        .map(|r| r.project)
        .collect())
}

/// How many PyPI names to take from the upstream JSON. Matches the size of
/// the embedded `data/pypi-top200.txt` snapshot.
const PYPI_TOP_N: usize = 200;

/// Parse one page of crates.io API JSON. Shape:
/// `{"crates": [{"name": "<name>", ...}, ...], ...}`. Returns the names in
/// the upstream (descending download-count) order.
pub(crate) fn parse_cargo_json(body: &[u8]) -> Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Crate {
        name: String,
    }
    #[derive(serde::Deserialize)]
    struct Page {
        crates: Vec<Crate>,
    }
    let parsed: Page = serde_json::from_slice(body).context("decoding cargo JSON")?;
    Ok(parsed.crates.into_iter().map(|c| c.name).collect())
}

/// Parse the NuGet v3 search API JSON. Shape:
/// `{"data": [{"id": "<name>", ...}, ...], "totalHits": ...}`. Returns the
/// IDs in upstream (descending downloads) order.
pub(crate) fn parse_nuget_json(body: &[u8]) -> Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Pkg {
        id: String,
    }
    #[derive(serde::Deserialize)]
    struct SearchResult {
        data: Vec<Pkg>,
    }
    let parsed: SearchResult = serde_json::from_slice(body).context("decoding nuget JSON")?;
    Ok(parsed.data.into_iter().map(|p| p.id).collect())
}

/// Extract package names from the anvaka most-depended-upon markdown gist.
/// Lines look like `1. [lodash](https://npmjs.com/package/lodash)` (with
/// optional leading whitespace). Returns a deduplicated, sorted list so cache
/// files diff cleanly across refreshes.
pub(crate) fn parse_anvaka_markdown(input: &str) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for line in input.lines() {
        let trimmed = line.trim_start();
        let Some(dot_pos) = trimmed.find(". [") else {
            continue;
        };
        let prefix = &trimmed[..dot_pos];
        if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let after = &trimmed[dot_pos + 3..];
        let Some(end) = after.find(']') else {
            continue;
        };
        let name = after[..end].trim();
        if name.is_empty() {
            continue;
        }
        set.insert(name.to_string());
    }
    set.into_iter().collect()
}

/// Write `names` (one per line) to `path` via temp-file + rename. The temp
/// file lives next to the target so the rename stays on the same filesystem
/// (atomic on POSIX); we don't bother flushing parent directories — bomdrift
/// is single-user and the next reader either sees the old file or the new
/// file, never a torn intermediate.
fn write_list_atomically(path: &Path, names: &[String]) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);

    let mut body = String::with_capacity(names.iter().map(|n| n.len() + 1).sum());
    for name in names {
        body.push_str(name);
        body.push('\n');
    }
    fs::write(&tmp, body).with_context(|| format!("writing temp file {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Resolve `<XDG_CACHE_HOME>/bomdrift/` (or the platform equivalent) without
/// the trailing `typosquat/` segment — callers join the per-feature subdir.
pub fn default_cache_root() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("dev", "bomdrift", "bomdrift")
        .context("could not determine a platform cache directory for bomdrift")?;
    Ok(dirs.cache_dir().to_path_buf())
}

/// Default `ureq`-based fetcher. Bytes-in, bytes-out so it's cleanly mockable.
fn default_fetcher(url: &str) -> Result<Vec<u8>> {
    let agent = ureq::AgentBuilder::new().timeout(DEFAULT_TIMEOUT).build();
    let resp = agent
        .get(url)
        .set(
            "user-agent",
            concat!("bomdrift/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .with_context(|| format!("HTTP GET {url} failed"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .with_context(|| format!("reading body of {url}"))?;
    Ok(buf)
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

    const SAMPLE_MARKDOWN: &str = "\
# Most depended-upon packages

Updated weekly.

  1. [lodash](https://www.npmjs.com/package/lodash)
  2. [chalk](https://www.npmjs.com/package/chalk)
  3. [react](https://www.npmjs.com/package/react)
 10. [axios](https://www.npmjs.com/package/axios)
100. [crypto-js](https://www.npmjs.com/package/crypto-js)
foo. [not-a-package](https://example.com)
1. [lodash](https://www.npmjs.com/package/lodash)
not a package line at all
";

    #[test]
    fn parser_extracts_names_correctly_from_anvaka_markdown() {
        let names = parse_anvaka_markdown(SAMPLE_MARKDOWN);
        // Sorted + deduped (lodash appears twice).
        assert_eq!(
            names,
            vec!["axios", "chalk", "crypto-js", "lodash", "react"]
        );
    }

    #[test]
    fn parser_skips_lines_with_non_numeric_prefix() {
        let input = "abc. [bad](url)\n1. [good](url)\n";
        let names = parse_anvaka_markdown(input);
        assert_eq!(names, vec!["good"]);
    }

    #[test]
    fn parser_handles_empty_input_without_crashing() {
        assert!(parse_anvaka_markdown("").is_empty());
        assert!(parse_anvaka_markdown("\n\n\n").is_empty());
    }

    #[test]
    fn refresh_writes_parsed_npm_list_to_cache_dir() {
        let tmp = tempdir();
        let cache_root = tmp.path().to_path_buf();
        let fetcher = |url: &str| -> Result<Vec<u8>> {
            assert_eq!(url, NPM_SOURCE_URL);
            Ok(SAMPLE_MARKDOWN.as_bytes().to_vec())
        };

        run_with(
            RefreshArgs {
                ecosystem: RefreshEcosystem::Npm,
            },
            fetcher,
            &cache_root,
        )
        .expect("refresh should succeed");

        let target = cache_root.join("typosquat").join("npm.txt");
        let body = fs::read_to_string(&target).expect("cache file must exist");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(
            lines,
            vec!["axios", "chalk", "crypto-js", "lodash", "react"]
        );
        // No leftover temp file.
        assert!(!cache_root.join("typosquat").join("npm.txt.tmp").exists());
    }

    #[test]
    fn refresh_all_includes_all_eight_ecosystems() {
        let ecos = selected_ecosystems(RefreshEcosystem::All);
        assert_eq!(
            ecos,
            vec![
                RefreshEcosystem::Npm,
                RefreshEcosystem::PyPI,
                RefreshEcosystem::Cargo,
                RefreshEcosystem::Maven,
                RefreshEcosystem::Go,
                RefreshEcosystem::Gem,
                RefreshEcosystem::NuGet,
                RefreshEcosystem::Composer,
            ]
        );
    }

    // ---- PyPI -------------------------------------------------------------

    const SAMPLE_PYPI_JSON: &[u8] = br#"{
        "last_update": "2026-04-01",
        "rows": [
            {"download_count": 999, "project": "boto3"},
            {"download_count": 888, "project": "requests"},
            {"download_count": 777, "project": "numpy"}
        ]
    }"#;

    #[test]
    fn parse_pypi_json_extracts_names_in_order() {
        let names = parse_pypi_json(SAMPLE_PYPI_JSON).expect("parses");
        assert_eq!(names, vec!["boto3", "requests", "numpy"]);
    }

    #[test]
    fn parse_pypi_json_rejects_non_json() {
        assert!(parse_pypi_json(b"<html>not json</html>").is_err());
    }

    #[test]
    fn refresh_writes_parsed_pypi_list_to_cache_dir() {
        let tmp = tempdir();
        let cache_root = tmp.path().to_path_buf();
        let fetcher = |url: &str| -> Result<Vec<u8>> {
            assert_eq!(url, PYPI_SOURCE_URL);
            Ok(SAMPLE_PYPI_JSON.to_vec())
        };
        run_with(
            RefreshArgs {
                ecosystem: RefreshEcosystem::PyPI,
            },
            fetcher,
            &cache_root,
        )
        .expect("refresh should succeed");
        let target = cache_root.join("typosquat").join("pypi.txt");
        let body = fs::read_to_string(&target).expect("pypi cache file must exist");
        assert_eq!(body, "boto3\nrequests\nnumpy\n");
    }

    // ---- Cargo ------------------------------------------------------------

    const SAMPLE_CARGO_JSON: &[u8] = br#"{
        "crates": [
            {"name": "syn"},
            {"name": "serde"},
            {"name": "tokio"}
        ],
        "meta": {"total": 3}
    }"#;

    #[test]
    fn parse_cargo_json_extracts_names_in_order() {
        let names = parse_cargo_json(SAMPLE_CARGO_JSON).expect("parses");
        assert_eq!(names, vec!["syn", "serde", "tokio"]);
    }

    #[test]
    fn refresh_cargo_concatenates_pages_and_writes_cache() {
        let tmp = tempdir();
        let cache_root = tmp.path().to_path_buf();
        let fetcher = |url: &str| -> Result<Vec<u8>> {
            assert!(
                url.starts_with(CARGO_SOURCE_URL_TEMPLATE),
                "unexpected URL: {url}"
            );
            Ok(SAMPLE_CARGO_JSON.to_vec())
        };
        // Inject no-op sleep so the test stays fast even though the production
        // path waits 1s between pages.
        let no_sleep = |_: Duration| {};
        refresh_cargo(&fetcher, &cache_root, no_sleep).expect("cargo refresh succeeds");
        let body = fs::read_to_string(cache_root.join("typosquat").join("cargo.txt"))
            .expect("cargo cache file must exist");
        // 2 pages of the sample = 6 names, in order.
        assert_eq!(body, "syn\nserde\ntokio\nsyn\nserde\ntokio\n");
    }

    // ---- Maven (no-op path) ----------------------------------------------

    #[test]
    fn refresh_maven_is_a_noop_no_cache_file_written() {
        let tmp = tempdir();
        let cache_root = tmp.path().to_path_buf();
        // Fetcher must NOT be called for the Maven path.
        let fetcher = |url: &str| -> Result<Vec<u8>> {
            panic!("Maven refresh must not call fetcher; got URL: {url}")
        };
        run_with(
            RefreshArgs {
                ecosystem: RefreshEcosystem::Maven,
            },
            fetcher,
            &cache_root,
        )
        .expect("Maven path must succeed (no-op)");
        // Confirm no cache file was created — the embedded list stays the
        // source of truth.
        assert!(!cache_root.join("typosquat").join("maven.txt").exists());
    }

    // ---- NuGet -----------------------------------------------------------

    const SAMPLE_NUGET_JSON: &[u8] = br#"{
        "totalHits": 3,
        "data": [
            {"id": "Newtonsoft.Json", "version": "13.0.3"},
            {"id": "Microsoft.Extensions.Logging", "version": "8.0.0"},
            {"id": "System.Text.Json", "version": "8.0.0"}
        ]
    }"#;

    #[test]
    fn parse_nuget_json_extracts_ids_in_order() {
        let names = parse_nuget_json(SAMPLE_NUGET_JSON).expect("parses");
        assert_eq!(
            names,
            vec![
                "Newtonsoft.Json",
                "Microsoft.Extensions.Logging",
                "System.Text.Json"
            ]
        );
    }

    #[test]
    fn parse_nuget_json_rejects_non_json() {
        assert!(parse_nuget_json(b"<html>not json</html>").is_err());
    }

    #[test]
    fn refresh_writes_parsed_nuget_list_to_cache_dir() {
        let tmp = tempdir();
        let cache_root = tmp.path().to_path_buf();
        let fetcher = |url: &str| -> Result<Vec<u8>> {
            assert_eq!(url, NUGET_SOURCE_URL);
            Ok(SAMPLE_NUGET_JSON.to_vec())
        };
        run_with(
            RefreshArgs {
                ecosystem: RefreshEcosystem::NuGet,
            },
            fetcher,
            &cache_root,
        )
        .expect("nuget refresh should succeed");
        let target = cache_root.join("typosquat").join("nuget.txt");
        let body = fs::read_to_string(&target).expect("nuget cache file must exist");
        assert_eq!(
            body,
            "Newtonsoft.Json\nMicrosoft.Extensions.Logging\nSystem.Text.Json\n"
        );
    }

    // ---- Go / Gem / Composer (no-op paths) -------------------------------

    #[test]
    fn refresh_go_is_a_noop_no_cache_file_written() {
        let tmp = tempdir();
        let cache_root = tmp.path().to_path_buf();
        let fetcher = |url: &str| -> Result<Vec<u8>> {
            panic!("Go refresh must not call fetcher; got URL: {url}")
        };
        run_with(
            RefreshArgs {
                ecosystem: RefreshEcosystem::Go,
            },
            fetcher,
            &cache_root,
        )
        .expect("Go path must succeed (no-op)");
        assert!(!cache_root.join("typosquat").join("go.txt").exists());
    }

    #[test]
    fn refresh_gem_is_a_noop_no_cache_file_written() {
        let tmp = tempdir();
        let cache_root = tmp.path().to_path_buf();
        let fetcher = |url: &str| -> Result<Vec<u8>> {
            panic!("Gem refresh must not call fetcher; got URL: {url}")
        };
        run_with(
            RefreshArgs {
                ecosystem: RefreshEcosystem::Gem,
            },
            fetcher,
            &cache_root,
        )
        .expect("Gem path must succeed (no-op)");
        assert!(!cache_root.join("typosquat").join("gem.txt").exists());
    }

    #[test]
    fn refresh_composer_is_a_noop_no_cache_file_written() {
        let tmp = tempdir();
        let cache_root = tmp.path().to_path_buf();
        let fetcher = |url: &str| -> Result<Vec<u8>> {
            panic!("Composer refresh must not call fetcher; got URL: {url}")
        };
        run_with(
            RefreshArgs {
                ecosystem: RefreshEcosystem::Composer,
            },
            fetcher,
            &cache_root,
        )
        .expect("Composer path must succeed (no-op)");
        assert!(!cache_root.join("typosquat").join("composer.txt").exists());
    }

    #[test]
    fn refresh_fails_loudly_when_fetcher_returns_unparseable_body() {
        let tmp = tempdir();
        let fetcher = |_: &str| -> Result<Vec<u8>> { Ok(b"<html>not markdown</html>".to_vec()) };
        let err = run_with(
            RefreshArgs {
                ecosystem: RefreshEcosystem::Npm,
            },
            fetcher,
            tmp.path(),
        )
        .expect_err("zero parsed names must fail rather than silently truncate the cache");
        let chain = format!("{err:#}");
        assert!(
            chain.contains("one or more ecosystems failed"),
            "expected aggregate failure, got: {chain}"
        );
    }

    #[test]
    fn refresh_propagates_fetcher_errors_with_context() {
        let tmp = tempdir();
        let fetcher =
            |_: &str| -> Result<Vec<u8>> { Err(anyhow::anyhow!("simulated DNS failure")) };
        let err = run_with(
            RefreshArgs {
                ecosystem: RefreshEcosystem::Npm,
            },
            fetcher,
            tmp.path(),
        )
        .expect_err("fetcher failure must surface");
        assert!(format!("{err:#}").contains("one or more ecosystems failed"));
    }

    #[test]
    fn write_list_atomically_overwrites_existing_file() {
        let tmp = tempdir();
        let target = tmp.path().join("npm.txt");
        fs::write(&target, "stale\n").unwrap();
        write_list_atomically(&target, &["fresh".to_string()]).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "fresh\n");
    }

    // Tiny in-tree tempdir helper so we don't add `tempfile` as a dev-dep just
    // for these tests. The directory is removed on Drop; uniqueness comes from
    // a process-id + monotonically-incremented counter pair.
    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "bomdrift-refresh-test-{}-{}",
            std::process::id(),
            n
        ));
        fs::create_dir_all(&base).expect("create tempdir");
        TempDir(base)
    }
}
