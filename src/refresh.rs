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
//! ## v0 scope
//!
//! Only `npm` is wired up. PyPI, Cargo, and Maven are accepted on the
//! `--ecosystem` flag but currently emit a "not yet wired" warning rather
//! than failing — the contract is that `refresh-typosquat --ecosystem all`
//! should keep working as new ecosystems are added without users having to
//! change their invocation.
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
        match eco {
            RefreshEcosystem::Npm => {
                if let Err(err) = refresh_npm(&fetcher, cache_root) {
                    eprintln!("error: failed to refresh npm list: {err:#}");
                    any_failure = true;
                }
            }
            RefreshEcosystem::All => unreachable!("`All` is expanded by selected_ecosystems"),
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
        RefreshEcosystem::All => vec![RefreshEcosystem::Npm],
        RefreshEcosystem::Npm => vec![RefreshEcosystem::Npm],
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
    if names.is_empty() {
        bail!(
            "parsed zero package names from {NPM_SOURCE_URL} — refusing to overwrite cache with empty list"
        );
    }

    let target_dir = cache_root.join("typosquat");
    fs::create_dir_all(&target_dir)
        .with_context(|| format!("creating cache directory {}", target_dir.display()))?;
    let target = target_dir.join("npm.txt");
    write_list_atomically(&target, &names)
        .with_context(|| format!("writing {}", target.display()))?;
    eprintln!(
        "refreshing npm... wrote {} names to {}",
        names.len(),
        target.display()
    );
    Ok(())
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
    fn refresh_all_currently_only_includes_npm() {
        let ecos = selected_ecosystems(RefreshEcosystem::All);
        assert_eq!(ecos, vec![RefreshEcosystem::Npm]);
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
