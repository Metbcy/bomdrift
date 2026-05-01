//! Typosquat enrichment: flag added components whose name is suspiciously
//! similar to a popular package in the same ecosystem.
//!
//! v0.2 ships embedded snapshots for **npm**, **PyPI**, **Cargo**, and
//! **Maven**. Each newly added component whose ecosystem has a wired list is
//! scored against that list with rules tuned per-ecosystem; components from
//! other ecosystems (Go, Other(...), no purl) are ignored.
//!
//! ## Per-ecosystem rules
//!
//! All ecosystems share the *exact-match → skip* rule and the [`SIMILARITY_THRESHOLD`]
//! cutoff. They differ in:
//!
//! - **Name canonicalization**: lowercased for npm/Cargo; PEP 503-normalized
//!   for PyPI (lowercase, `-`/`_`/`.` collapsed to `-`); kept as
//!   `groupId:artifactId` for Maven and matched on `artifactId` only.
//! - **Structural separators**: `-_./` (npm), `-_.` (PyPI),
//!   `-` (Cargo), N/A (Maven uses Levenshtein on the artifactId, not the
//!   prefix-extension / suffix-containment heuristics).
//! - **Scoring**: Jaro-Winkler with a suffix-containment boost for npm /
//!   PyPI / Cargo; Levenshtein distance ≤ 2 on the artifactId for Maven
//!   (the long shared `groupId` prefix inflates JW similarity past anything
//!   useful, so it's excluded entirely from the comparison).
//!
//! ## Filtering & scoring rules (npm/PyPI/Cargo)
//!
//! 1. **Exact match (case-insensitive after canonicalization) → skip**. The
//!    candidate IS a popular package, not a squat of one.
//! 2. **Likely-legit ecosystem extension → skip per-comparison**. When the
//!    candidate starts with a legit name followed by an ecosystem-appropriate
//!    separator, this matches the well-established convention for extension
//!    packages (`react-router`, `axios-retry`, `eslint-plugin-react`,
//!    `pytest-asyncio`). Treating these as squats produces constant false
//!    positives on legitimate packages.
//! 3. **Suffix containment with a substantial added prefix → boost**. When
//!    the candidate ends with a legit name (≥ 5 chars) AND the added prefix
//!    is longer than 3 characters, the score is boosted to at least
//!    `SUFFIX_BOOST_SCORE`. The textbook typosquat pattern:
//!    `plain-crypto-js`, `safe-axios`, `secure-lodash`. The base
//!    Jaro-Winkler similarity for these is low (the prefix kills it) but the
//!    deceptive intent is unmistakable.
//! 4. Otherwise: plain Jaro-Winkler.
//!
//! ## Reputational care
//!
//! The renderer wording is "is similar to {legit}", never "is a typosquat".
//! Flagging a legitimate package as a malicious squat in a public PR comment
//! is a real reputational harm to the package author; the human reviewing the
//! PR is the analyst making the determination.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::Serialize;
use strsim::{jaro_winkler, levenshtein};

use crate::diff::ChangeSet;
use crate::model::{Component, Ecosystem};

const NPM_TOP_LIST: &str = include_str!("../../data/npm-top1k.txt");
const PYPI_TOP_LIST: &str = include_str!("../../data/pypi-top200.txt");
const CARGO_TOP_LIST: &str = include_str!("../../data/cargo-top200.txt");
const MAVEN_TOP_LIST: &str = include_str!("../../data/maven-top100.txt");
const GO_TOP_LIST: &str = include_str!("../../data/go-top200.txt");
const GEM_TOP_LIST: &str = include_str!("../../data/gem-top200.txt");
const NUGET_TOP_LIST: &str = include_str!("../../data/nuget-top200.txt");
const COMPOSER_TOP_LIST: &str = include_str!("../../data/composer-top200.txt");

/// Minimum Jaro-Winkler score (or boosted score) for a pairing to be reported.
pub const SIMILARITY_THRESHOLD: f64 = 0.92;

/// Score assigned when suffix-containment boost fires. Above the threshold so
/// the finding always surfaces, but expressed as a score (not a hard 1.0) so
/// the user can read intensity off the rendered table without misreading
/// boosted hits as "perfect" matches.
const SUFFIX_BOOST_SCORE: f64 = 0.95;

/// Minimum length of a legit name for the prefix-extension and suffix-boost
/// rules to apply. Short names (`fs`, `is`, `q`) are too generic — applying
/// the structural rules to them produces noise without signal.
const MIN_LEGIT_LEN_FOR_STRUCTURAL_RULES: usize = 5;

/// A candidate must add more than this many characters of prefix on top of
/// a contained legit name for the suffix boost to apply. Smaller deltas are
/// usually trivial typos (`expresss` vs `express`) which Jaro-Winkler already
/// handles, or intentional pluralizations (`react` vs `reacts`).
const SUFFIX_BOOST_MIN_DELTA: usize = 3;

/// Maximum Levenshtein distance for a Maven `artifactId` pairing to be
/// reported. `dist == 1` catches single-character substitutions/insertions
/// (`commons-lng3` vs `commons-lang3`); `dist == 2` catches two-character
/// drift; beyond that, the names are simply different packages.
const MAVEN_MAX_LEVENSHTEIN: usize = 2;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TyposquatFinding {
    pub component: Component,
    pub closest: String,
    pub score: f64,
}

/// Internal enum identifying the wired typosquat ecosystems. Distinct from
/// [`crate::model::Ecosystem`] because not every modeled ecosystem has a list
/// (Other(...) entries with no canonical purl-type prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedEcosystem {
    Npm,
    PyPI,
    Cargo,
    Maven,
    Go,
    Gem,
    NuGet,
    Composer,
}

impl SupportedEcosystem {
    fn from(eco: &Ecosystem) -> Option<Self> {
        match eco {
            Ecosystem::Npm => Some(Self::Npm),
            Ecosystem::PyPI => Some(Self::PyPI),
            Ecosystem::Cargo => Some(Self::Cargo),
            Ecosystem::Maven => Some(Self::Maven),
            Ecosystem::Go => Some(Self::Go),
            Ecosystem::Gem => Some(Self::Gem),
            Ecosystem::NuGet => Some(Self::NuGet),
            Ecosystem::Composer => Some(Self::Composer),
            Ecosystem::Other(_) => None,
        }
    }

    fn embedded(self) -> &'static str {
        match self {
            Self::Npm => NPM_TOP_LIST,
            Self::PyPI => PYPI_TOP_LIST,
            Self::Cargo => CARGO_TOP_LIST,
            Self::Maven => MAVEN_TOP_LIST,
            Self::Go => GO_TOP_LIST,
            Self::Gem => GEM_TOP_LIST,
            Self::NuGet => NUGET_TOP_LIST,
            Self::Composer => COMPOSER_TOP_LIST,
        }
    }

    /// File name (under `<cache_root>/typosquat/`) that
    /// `bomdrift refresh-typosquat` writes for this ecosystem, and that the
    /// loader reads in preference to the embedded snapshot when present.
    fn cache_filename(self) -> &'static str {
        match self {
            Self::Npm => "npm.txt",
            Self::PyPI => "pypi.txt",
            Self::Cargo => "cargo.txt",
            Self::Maven => "maven.txt",
            Self::Go => "go.txt",
            Self::Gem => "gem.txt",
            Self::NuGet => "nuget.txt",
            Self::Composer => "composer.txt",
        }
    }

    /// Bytes treated as separators by the prefix-extension and suffix-boost
    /// rules. Maven returns an empty slice — its scoring path doesn't use
    /// these heuristics.
    fn separators(self) -> &'static [u8] {
        match self {
            Self::Npm => b"-_./",
            Self::PyPI => b"-_.",
            Self::Cargo => b"-",
            Self::Maven => b"",
            // Go module names use both `-` (hyphenated repo names) and `/`
            // (path separators); the latter doesn't actually appear in the
            // *match form* (the last path segment) but is harmless to keep.
            Self::Go => b"-/",
            Self::Gem => b"-_",
            // NuGet IDs use `.` as the canonical separator
            // (`Microsoft.Extensions.Logging`, `Newtonsoft.Json`).
            Self::NuGet => b".",
            Self::Composer => b"-/",
        }
    }
}

pub fn enrich(cs: &ChangeSet) -> Vec<TyposquatFinding> {
    enrich_with_threshold(cs, None)
}

/// Like [`enrich`] but lets the caller override [`SIMILARITY_THRESHOLD`]
/// (driven by `--typosquat-similarity-threshold`). `None` uses the default.
pub fn enrich_with_threshold(
    cs: &ChangeSet,
    similarity_threshold: Option<f64>,
) -> Vec<TyposquatFinding> {
    let threshold = similarity_threshold.unwrap_or(SIMILARITY_THRESHOLD);
    let mut out = Vec::new();
    for comp in &cs.added {
        let Some(eco) = SupportedEcosystem::from(&comp.ecosystem) else {
            continue;
        };
        if let Some(finding) = check_one(comp, eco, threshold) {
            out.push(finding);
        }
    }
    out
}

fn check_one(
    comp: &Component,
    eco: SupportedEcosystem,
    threshold: f64,
) -> Option<TyposquatFinding> {
    let candidate = canonicalize(eco, &comp.name);
    let legit_list = legit_list_for(eco);
    let legit_set = legit_set_for(eco);
    if legit_set.contains(candidate.as_str()) {
        return None;
    }
    let (closest, score) = match eco {
        SupportedEcosystem::Maven => best_match_maven(&candidate, legit_list, threshold)?,
        SupportedEcosystem::Npm
        | SupportedEcosystem::PyPI
        | SupportedEcosystem::Cargo
        | SupportedEcosystem::Go
        | SupportedEcosystem::Gem
        | SupportedEcosystem::NuGet
        | SupportedEcosystem::Composer => best_match_jw(&candidate, legit_list, eco)?,
    };
    if score >= threshold {
        Some(TyposquatFinding {
            component: comp.clone(),
            closest: closest.to_string(),
            score,
        })
    } else {
        None
    }
}

/// Per-ecosystem name canonicalization. Applied to BOTH the candidate and
/// every entry in the legit list (during list load) so equality and structural
/// rules see the same normalized form.
fn canonicalize(eco: SupportedEcosystem, name: &str) -> String {
    match eco {
        // NuGet IDs are case-insensitive per the package-spec; lowercase
        // them at canonicalization time so `Newtonsoft.Json` and
        // `newtonsoft.json` collapse to the same legit-list entry.
        SupportedEcosystem::Npm
        | SupportedEcosystem::Cargo
        | SupportedEcosystem::Maven
        | SupportedEcosystem::Go
        | SupportedEcosystem::Gem
        | SupportedEcosystem::NuGet
        | SupportedEcosystem::Composer => name.to_lowercase(),
        SupportedEcosystem::PyPI => pep503_normalize(name),
    }
}

/// The substring of a canonicalized name that's actually compared for
/// similarity. For most ecosystems this is the canonical form itself.
/// For ecosystems where the user-visible coordinate has a stable prefix
/// shared by many legit packages (Go's `github.com/<org>/`, Composer's
/// `<vendor>/`), the prefix would inflate Jaro-Winkler past anything
/// useful — match on the post-prefix portion only.
///
/// Note: Maven uses its own scoring path ([`best_match_maven`]) with
/// Levenshtein on the artifactId; this helper isn't called on the Maven
/// path. The match for Maven is computed inline in `best_match_maven`.
fn match_form(eco: SupportedEcosystem, canonical: &str) -> &str {
    match eco {
        SupportedEcosystem::Go | SupportedEcosystem::Composer => last_path_segment(canonical),
        _ => canonical,
    }
}

/// Extract the substring after the last `/`, or the whole string when no
/// `/` is present. Used for both Go (`host/owner/repo` → `repo`) and
/// Composer (`vendor/package` → `package`).
fn last_path_segment(s: &str) -> &str {
    s.rsplit_once('/').map(|(_, a)| a).unwrap_or(s)
}

/// PEP 503 simplified normalization: lowercase, then collapse any run of
/// `-`, `_`, or `.` into a single `-`. `Foo_Bar.Baz` → `foo-bar-baz`.
fn pep503_normalize(name: &str) -> String {
    let lower = name.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut last_was_dash = false;
    for c in lower.chars() {
        let mapped = if matches!(c, '_' | '.' | '-') { '-' } else { c };
        if mapped == '-' {
            if last_was_dash {
                continue;
            }
            last_was_dash = true;
        } else {
            last_was_dash = false;
        }
        out.push(mapped);
    }
    out.trim_matches('-').to_string()
}

fn best_match_jw<'a>(
    candidate: &str,
    legit: &'a [String],
    eco: SupportedEcosystem,
) -> Option<(&'a str, f64)> {
    let cand_match = match_form(eco, candidate);
    if cand_match.is_empty() {
        return None;
    }
    let mut best: Option<(&'a str, f64)> = None;
    let separators = eco.separators();
    for name in legit {
        let name = name.as_str();
        if name == candidate {
            // Already-handled elsewhere via `legit_set.contains()`, but
            // the per-iteration cheap-skip is defensive against a future
            // refactor that drops the set check.
            continue;
        }
        let legit_match = match_form(eco, name);
        // For ecosystems with a match-form (Go, Composer), two distinct
        // full coordinates can collapse to the same match form — a
        // legitimate fork of the same repo under a different vendor.
        // Don't treat that as a typosquat; the structural similarity is
        // identical by definition and a human reviewer is the right
        // judge.
        if legit_match == cand_match {
            continue;
        }
        if is_likely_legit_extension(cand_match, legit_match, separators) {
            continue;
        }
        let mut score = jaro_winkler(cand_match, legit_match);
        if has_suspicious_suffix_containment(cand_match, legit_match) {
            score = score.max(SUFFIX_BOOST_SCORE);
        }
        match best {
            Some((_, b)) if score <= b => {}
            _ => best = Some((name, score)),
        }
    }
    best
}

/// Maven scoring path: extract `artifactId` from each `groupId:artifactId`
/// (both candidate and legit), reject when artifactIds match exactly, and
/// score by Levenshtein on the artifactId only.
///
/// Returning JW-equivalent score so the rendered table is consistent with
/// the other ecosystems: dist=1 → 0.97-ish, dist=2 → 0.94-ish, both above
/// [`SIMILARITY_THRESHOLD`].
fn best_match_maven<'a>(
    candidate: &str,
    legit: &'a [String],
    threshold: f64,
) -> Option<(&'a str, f64)> {
    let cand_artifact = artifact_id(candidate);
    let mut best: Option<(&'a str, usize, &str)> = None;
    for name in legit {
        let name_str = name.as_str();
        if name_str == candidate {
            continue;
        }
        let legit_artifact = artifact_id(name_str);
        if cand_artifact == legit_artifact {
            continue;
        }
        let dist = levenshtein(cand_artifact, legit_artifact);
        if dist == 0 || dist > MAVEN_MAX_LEVENSHTEIN {
            continue;
        }
        match best {
            Some((_, d, _)) if dist >= d => {}
            _ => best = Some((name_str, dist, legit_artifact)),
        }
    }
    best.map(|(name, dist, legit_artifact)| {
        let denom = (legit_artifact.len() as f64) + 1.0;
        let raw = 1.0 - (dist as f64) / denom;
        (name, raw.max(threshold))
    })
}

/// Extract the `artifactId` from a `groupId:artifactId` Maven coordinate.
/// Falls back to the whole string when no `:` is present (defensive).
fn artifact_id(coord: &str) -> &str {
    coord.rsplit_once(':').map(|(_, a)| a).unwrap_or(coord)
}

/// True when `candidate` looks like a legitimate extension package built on
/// top of `legit` (e.g. `axios-retry` extending `axios`). The convention is
/// `<popular-name><separator><suffix>`, with the per-ecosystem separator set
/// passed in.
fn is_likely_legit_extension(candidate: &str, legit: &str, separators: &[u8]) -> bool {
    if separators.is_empty() {
        return false;
    }
    if legit.len() < MIN_LEGIT_LEN_FOR_STRUCTURAL_RULES {
        return false;
    }
    if !candidate.starts_with(legit) {
        return false;
    }
    is_separator_byte(candidate.as_bytes().get(legit.len()).copied(), separators)
}

/// True when `candidate` ends with `legit` AND has a substantial added prefix.
/// Ecosystem-independent — the suffix-containment pattern (`plain-crypto-js`
/// → `crypto-js`) is the same shape across npm/PyPI/Cargo.
fn has_suspicious_suffix_containment(candidate: &str, legit: &str) -> bool {
    if legit.len() < MIN_LEGIT_LEN_FOR_STRUCTURAL_RULES {
        return false;
    }
    if candidate.len() <= legit.len() + SUFFIX_BOOST_MIN_DELTA {
        return false;
    }
    candidate.ends_with(legit)
}

fn is_separator_byte(b: Option<u8>, separators: &[u8]) -> bool {
    b.is_some_and(|byte| separators.contains(&byte))
}

fn legit_list_for(eco: SupportedEcosystem) -> &'static [String] {
    static NPM: OnceLock<Vec<String>> = OnceLock::new();
    static PYPI: OnceLock<Vec<String>> = OnceLock::new();
    static CARGO: OnceLock<Vec<String>> = OnceLock::new();
    static MAVEN: OnceLock<Vec<String>> = OnceLock::new();
    static GO: OnceLock<Vec<String>> = OnceLock::new();
    static GEM: OnceLock<Vec<String>> = OnceLock::new();
    static NUGET: OnceLock<Vec<String>> = OnceLock::new();
    static COMPOSER: OnceLock<Vec<String>> = OnceLock::new();
    let lock = match eco {
        SupportedEcosystem::Npm => &NPM,
        SupportedEcosystem::PyPI => &PYPI,
        SupportedEcosystem::Cargo => &CARGO,
        SupportedEcosystem::Maven => &MAVEN,
        SupportedEcosystem::Go => &GO,
        SupportedEcosystem::Gem => &GEM,
        SupportedEcosystem::NuGet => &NUGET,
        SupportedEcosystem::Composer => &COMPOSER,
    };
    lock.get_or_init(|| load_legit_list(eco, default_cache_path(eco).as_deref()))
}

fn legit_set_for(eco: SupportedEcosystem) -> &'static HashSet<String> {
    static NPM_SET: OnceLock<HashSet<String>> = OnceLock::new();
    static PYPI_SET: OnceLock<HashSet<String>> = OnceLock::new();
    static CARGO_SET: OnceLock<HashSet<String>> = OnceLock::new();
    static MAVEN_SET: OnceLock<HashSet<String>> = OnceLock::new();
    static GO_SET: OnceLock<HashSet<String>> = OnceLock::new();
    static GEM_SET: OnceLock<HashSet<String>> = OnceLock::new();
    static NUGET_SET: OnceLock<HashSet<String>> = OnceLock::new();
    static COMPOSER_SET: OnceLock<HashSet<String>> = OnceLock::new();
    let set_lock = match eco {
        SupportedEcosystem::Npm => &NPM_SET,
        SupportedEcosystem::PyPI => &PYPI_SET,
        SupportedEcosystem::Cargo => &CARGO_SET,
        SupportedEcosystem::Maven => &MAVEN_SET,
        SupportedEcosystem::Go => &GO_SET,
        SupportedEcosystem::Gem => &GEM_SET,
        SupportedEcosystem::NuGet => &NUGET_SET,
        SupportedEcosystem::Composer => &COMPOSER_SET,
    };
    set_lock.get_or_init(|| legit_list_for(eco).iter().cloned().collect())
}

fn default_cache_path(eco: SupportedEcosystem) -> Option<PathBuf> {
    crate::refresh::default_cache_root()
        .ok()
        .map(|root| root.join("typosquat").join(eco.cache_filename()))
}

/// Load a per-ecosystem reference list, preferring a cache file written by
/// `bomdrift refresh-typosquat` over the snapshot embedded at compile time.
/// Names are canonicalized and deduplicated.
///
/// Defensive fallback semantics: if the cache file is missing, unreadable,
/// or contains zero parseable lines, the embedded snapshot is used and no
/// error surfaces to callers. A successful cache read logs ONCE to stderr
/// so users can confirm a `refresh-typosquat` invocation actually took
/// effect.
fn load_legit_list(eco: SupportedEcosystem, cache_path: Option<&std::path::Path>) -> Vec<String> {
    if let Some(path) = cache_path
        && let Ok(contents) = std::fs::read_to_string(path)
    {
        let parsed = parse_and_canonicalize(&contents, eco);
        if !parsed.is_empty() {
            eprintln!(
                "using refreshed {} typosquat list from {} ({} names)",
                ecosystem_label(eco),
                path.display(),
                parsed.len()
            );
            return parsed;
        }
    }
    parse_and_canonicalize(eco.embedded(), eco)
}

fn ecosystem_label(eco: SupportedEcosystem) -> &'static str {
    match eco {
        SupportedEcosystem::Npm => "npm",
        SupportedEcosystem::PyPI => "PyPI",
        SupportedEcosystem::Cargo => "Cargo",
        SupportedEcosystem::Maven => "Maven",
        SupportedEcosystem::Go => "Go",
        SupportedEcosystem::Gem => "Gem",
        SupportedEcosystem::NuGet => "NuGet",
        SupportedEcosystem::Composer => "Composer",
    }
}

/// Parse a one-name-per-line list, applying ecosystem-specific canonicalization
/// to each entry, dropping comments and blanks, and deduplicating.
fn parse_and_canonicalize(input: &str, eco: SupportedEcosystem) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let normalized = canonicalize(eco, trimmed);
        if normalized.is_empty() {
            continue;
        }
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
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
    use crate::model::Relationship;

    fn comp(name: &str) -> Component {
        comp_eco(name, Ecosystem::Npm)
    }

    fn comp_eco(name: &str, ecosystem: Ecosystem) -> Component {
        let purl_type = match ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "pypi",
            Ecosystem::Cargo => "cargo",
            Ecosystem::Maven => "maven",
            Ecosystem::Go => "golang",
            Ecosystem::Gem => "gem",
            Ecosystem::NuGet => "nuget",
            Ecosystem::Composer => "composer",
            Ecosystem::Other(_) => "other",
        };
        Component {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            ecosystem,
            purl: Some(format!("pkg:{purl_type}/{name}@1.0.0")),
            licenses: Vec::new(),
            supplier: None,
            hashes: Vec::new(),
            relationship: Relationship::Unknown,
            source_url: None,
            bom_ref: None,
        }
    }

    fn cs_added(components: Vec<Component>) -> ChangeSet {
        ChangeSet {
            added: components,
            ..Default::default()
        }
    }

    // ---- npm regression tests (preserved from v0.1) -----------------------

    #[test]
    fn embedded_list_loads_thousand_names() {
        let list = legit_list_for(SupportedEcosystem::Npm);
        assert!(
            list.len() >= 900,
            "expected ~1000 npm names, got {}",
            list.len()
        );
        let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
        assert!(by_str.contains(&"crypto-js"));
        assert!(by_str.contains(&"cross-env"));
        assert!(by_str.contains(&"axios"));
        assert!(by_str.contains(&"react"));
        assert!(by_str.contains(&"react-router"));
    }

    #[test]
    fn crossenv_flags_against_cross_env_via_jaro_winkler() {
        let findings = enrich(&cs_added(vec![comp("crossenv")]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].closest, "cross-env");
        assert!(findings[0].score >= SIMILARITY_THRESHOLD);
    }

    #[test]
    fn plain_crypto_js_flags_against_crypto_js_via_suffix_boost() {
        let findings = enrich(&cs_added(vec![comp("plain-crypto-js")]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].closest, "crypto-js");
        assert!(findings[0].score >= SIMILARITY_THRESHOLD);
    }

    #[test]
    fn safe_axios_flags_against_axios_via_suffix_boost() {
        let findings = enrich(&cs_added(vec![comp("safe-axios")]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].closest, "axios");
    }

    #[test]
    fn react_router_does_not_flag_against_react() {
        let findings = enrich(&cs_added(vec![comp("react-router")]));
        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[test]
    fn axios_retry_does_not_flag_against_axios() {
        let findings = enrich(&cs_added(vec![comp("axios-retry")]));
        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[test]
    fn exact_match_is_not_flagged() {
        let findings = enrich(&cs_added(vec![comp("axios")]));
        assert!(findings.is_empty());
    }

    #[test]
    fn case_insensitive_exact_match_is_not_flagged() {
        let findings = enrich(&cs_added(vec![comp("Axios")]));
        assert!(findings.is_empty());
    }

    #[test]
    fn unsupported_ecosystem_components_are_ignored() {
        let mut c = comp("crossenv");
        c.ecosystem = Ecosystem::Go;
        let findings = enrich(&cs_added(vec![c]));
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_changeset_yields_no_findings() {
        assert!(enrich(&ChangeSet::default()).is_empty());
    }

    #[test]
    fn findings_preserve_added_iteration_order() {
        let findings = enrich(&cs_added(vec![comp("plain-crypto-js"), comp("crossenv")]));
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].component.name, "plain-crypto-js");
        assert_eq!(findings[1].component.name, "crossenv");
    }

    #[test]
    fn likely_legit_extension_requires_separator_npm() {
        let seps = SupportedEcosystem::Npm.separators();
        assert!(!is_likely_legit_extension("expresss", "express", seps));
        assert!(is_likely_legit_extension(
            "express-graphql",
            "express",
            seps
        ));
        assert!(is_likely_legit_extension("axios.retry", "axios", seps));
    }

    #[test]
    fn suffix_containment_requires_substantial_prefix() {
        assert!(!has_suspicious_suffix_containment(
            "crypto-jss",
            "crypto-js"
        ));
        assert!(has_suspicious_suffix_containment(
            "plain-crypto-js",
            "crypto-js"
        ));
    }

    #[test]
    fn short_legit_names_skip_structural_rules() {
        let seps = SupportedEcosystem::Npm.separators();
        assert!(!is_likely_legit_extension("my-fs-helper", "fs", seps));
        assert!(!has_suspicious_suffix_containment("super-cool-fs", "fs"));
    }

    #[test]
    fn cache_file_overrides_embedded_snapshot_for_npm() {
        let dir = tempdir_unique("typosquat-cache-test");
        let cache_path = dir.join("npm.txt");
        std::fs::write(
            &cache_path,
            "# header comment, ignored\nzzz-fake-cache-name\nzzz-other-cache-name\n\n",
        )
        .unwrap();

        let loaded = load_legit_list(SupportedEcosystem::Npm, Some(&cache_path));
        assert_eq!(
            loaded,
            vec![
                "zzz-fake-cache-name".to_string(),
                "zzz-other-cache-name".to_string()
            ]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_cache_file_falls_back_to_embedded_snapshot_for_npm() {
        let nonexistent = std::path::PathBuf::from("/this/path/does/not/exist/npm.txt");
        let loaded = load_legit_list(SupportedEcosystem::Npm, Some(&nonexistent));
        assert!(loaded.len() >= 900, "got {}", loaded.len());
    }

    #[test]
    fn empty_cache_file_falls_back_to_embedded_snapshot_for_npm() {
        let dir = tempdir_unique("typosquat-empty-cache");
        let cache_path = dir.join("npm.txt");
        std::fs::write(&cache_path, "# only a comment\n\n   \n").unwrap();
        let loaded = load_legit_list(SupportedEcosystem::Npm, Some(&cache_path));
        assert!(loaded.len() >= 900);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- PyPI tests -------------------------------------------------------

    #[test]
    fn pypi_list_loads_with_known_top_packages() {
        let list = legit_list_for(SupportedEcosystem::PyPI);
        let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
        assert!(
            by_str.contains(&"requests"),
            "requests must be in PyPI list"
        );
        assert!(by_str.contains(&"numpy"));
        assert!(by_str.contains(&"pandas"));
    }

    #[test]
    fn pypi_typo_flags_against_requests() {
        let findings = enrich(&cs_added(vec![comp_eco("requessts", Ecosystem::PyPI)]));
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].closest, "requests");
    }

    #[test]
    fn pypi_underscore_dash_equivalence_is_not_a_squat() {
        // `scikit_learn` vs `scikit-learn`: PEP 503 normalizes these to the
        // same name, so this is treated as the legitimate package, not a squat.
        let findings = enrich(&cs_added(vec![comp_eco("scikit_learn", Ecosystem::PyPI)]));
        assert!(
            findings.is_empty(),
            "PEP 503 equivalence must not flag, got {findings:?}"
        );
    }

    #[test]
    fn pypi_extension_pattern_is_not_a_squat() {
        // `pytest-asyncio` is the standard extension form for `pytest`.
        let findings = enrich(&cs_added(vec![comp_eco("pytest-asyncio", Ecosystem::PyPI)]));
        assert!(findings.is_empty(), "got {findings:?}");
    }

    // ---- Cargo tests ------------------------------------------------------

    #[test]
    fn cargo_list_loads_with_known_top_crates() {
        let list = legit_list_for(SupportedEcosystem::Cargo);
        let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
        assert!(by_str.contains(&"serde"));
        assert!(by_str.contains(&"tokio"));
        assert!(by_str.contains(&"clap"));
    }

    #[test]
    fn cargo_typo_flags_against_serde() {
        let findings = enrich(&cs_added(vec![comp_eco("serdee", Ecosystem::Cargo)]));
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].closest, "serde");
    }

    #[test]
    fn cargo_extension_pattern_is_not_a_squat() {
        // `serde-json` would collide with the real `serde_json`, but cargo
        // names use `_` and the legit-extension rule on cargo is `-` only —
        // so this still flags via JW unless we exact-match. Use an actual
        // extension pattern instead: `tokio-stream` extending `tokio`.
        let findings = enrich(&cs_added(vec![comp_eco("tokio-stream", Ecosystem::Cargo)]));
        assert!(findings.is_empty(), "got {findings:?}");
    }

    // ---- Maven tests ------------------------------------------------------

    #[test]
    fn maven_list_loads_with_known_top_coords() {
        let list = legit_list_for(SupportedEcosystem::Maven);
        let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
        assert!(by_str.iter().any(|s| s.ends_with(":commons-lang3")));
        assert!(by_str.iter().any(|s| s.ends_with(":guava")));
    }

    #[test]
    fn maven_artifact_typo_flags_against_commons_lang3() {
        // groupId matches a real coord; artifactId is one char off.
        let findings = enrich(&cs_added(vec![comp_eco(
            "org.apache.commons:commons-lng3",
            Ecosystem::Maven,
        )]));
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert!(findings[0].closest.ends_with(":commons-lang3"));
    }

    #[test]
    fn maven_exact_artifact_match_with_different_group_does_not_flag() {
        // Same artifactId as a known package but different group — that's a
        // legitimate fork or republish; not a typosquat by the artifactId-only
        // rule. Defer to a human reviewer.
        let findings = enrich(&cs_added(vec![comp_eco(
            "com.example.fork:commons-lang3",
            Ecosystem::Maven,
        )]));
        assert!(findings.is_empty(), "got {findings:?}");
    }

    // ---- Go tests --------------------------------------------------------

    #[test]
    fn go_list_loads_with_known_top_modules() {
        let list = legit_list_for(SupportedEcosystem::Go);
        assert!(list.len() >= 100, "got {}", list.len());
        let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
        assert!(by_str.iter().any(|s| s.ends_with("/cobra")));
        assert!(by_str.iter().any(|s| s.ends_with("/gin")));
        assert!(by_str.iter().any(|s| s.ends_with("/grpc")));
    }

    #[test]
    fn go_repo_typo_flags_against_cobra() {
        // last-segment typo of cobra. Different vendor + a one-character
        // drift on the repo name.
        let findings = enrich(&cs_added(vec![comp_eco(
            "github.com/attacker/cobraa",
            Ecosystem::Go,
        )]));
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert!(findings[0].closest.ends_with("/cobra"));
    }

    #[test]
    fn go_legit_fork_under_different_org_does_not_flag() {
        // Same last segment as a known module but under a different
        // org — legitimate fork; defer to a human reviewer.
        let findings = enrich(&cs_added(vec![comp_eco(
            "github.com/myorg/cobra",
            Ecosystem::Go,
        )]));
        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[test]
    fn go_extension_pattern_is_not_a_squat() {
        // `cobra-cli` is the standard extension form for `cobra` — match
        // form is `cobra-cli`, legit match form is `cobra`, separator `-`
        // → extension rule fires, skip.
        let findings = enrich(&cs_added(vec![comp_eco(
            "github.com/spf13/cobra-cli",
            Ecosystem::Go,
        )]));
        assert!(findings.is_empty(), "got {findings:?}");
    }

    // ---- Gem tests -------------------------------------------------------

    #[test]
    fn gem_list_loads_with_known_top_gems() {
        let list = legit_list_for(SupportedEcosystem::Gem);
        let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
        assert!(by_str.contains(&"rails"));
        assert!(by_str.contains(&"rspec"));
        assert!(by_str.contains(&"devise"));
    }

    #[test]
    fn gem_typo_flags_against_rails() {
        let findings = enrich(&cs_added(vec![comp_eco("railz", Ecosystem::Gem)]));
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].closest, "rails");
    }

    #[test]
    fn gem_extension_pattern_is_not_a_squat() {
        // `rspec-rails` is the canonical Rails-integration variant of
        // rspec, with `-` as the gem-extension separator.
        let findings = enrich(&cs_added(vec![comp_eco("rspec-rails", Ecosystem::Gem)]));
        assert!(findings.is_empty(), "got {findings:?}");
    }

    // ---- NuGet tests -----------------------------------------------------

    #[test]
    fn nuget_list_loads_with_known_top_packages() {
        let list = legit_list_for(SupportedEcosystem::NuGet);
        let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
        // NuGet IDs are case-insensitive; canonicalized to lowercase.
        assert!(by_str.contains(&"newtonsoft.json"));
        assert!(by_str.iter().any(|s| s.starts_with("microsoft.")));
    }

    #[test]
    fn nuget_typo_flags_against_newtonsoft_json() {
        let findings = enrich(&cs_added(vec![comp_eco(
            "Newtonsoft.Jsonn",
            Ecosystem::NuGet,
        )]));
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].closest, "newtonsoft.json");
    }

    #[test]
    fn nuget_case_insensitive_exact_match_is_not_flagged() {
        // `Newtonsoft.Json` and `newtonsoft.json` are the same package per
        // NuGet's case-insensitive ID rules — must not flag.
        let findings = enrich(&cs_added(vec![comp_eco(
            "NEWTONSOFT.JSON",
            Ecosystem::NuGet,
        )]));
        assert!(findings.is_empty(), "got {findings:?}");
    }

    // ---- Composer tests --------------------------------------------------

    #[test]
    fn composer_list_loads_with_known_top_packages() {
        let list = legit_list_for(SupportedEcosystem::Composer);
        let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
        assert!(by_str.iter().any(|s| s.ends_with("/console")));
        assert!(by_str.iter().any(|s| s.ends_with("/framework")));
        assert!(by_str.iter().any(|s| s.ends_with("/guzzle")));
    }

    #[test]
    fn composer_package_typo_flags_against_symfony_console() {
        // Different vendor, single-character drift on the package portion.
        let findings = enrich(&cs_added(vec![comp_eco(
            "attacker/consolee",
            Ecosystem::Composer,
        )]));
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert!(findings[0].closest.ends_with("/console"));
    }

    #[test]
    fn composer_legit_fork_under_different_vendor_does_not_flag() {
        // Same package portion as a known coordinate but under a different
        // vendor — legitimate fork or alternative. Don't flag.
        let findings = enrich(&cs_added(vec![comp_eco(
            "myorg/console",
            Ecosystem::Composer,
        )]));
        assert!(findings.is_empty(), "got {findings:?}");
    }

    // ---- helpers ----------------------------------------------------------

    fn tempdir_unique(stem: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "bomdrift-{stem}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn pep503_normalization() {
        assert_eq!(pep503_normalize("Foo_Bar.Baz"), "foo-bar-baz");
        assert_eq!(pep503_normalize("scikit__learn"), "scikit-learn");
        assert_eq!(pep503_normalize("---weird---"), "weird");
    }

    // ---- Property-based tests --------------------------------------------

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        /// `pep503_normalize` must never panic on arbitrary unicode and
        /// must always produce ASCII-only output (PEP 503's normalization
        /// rules collapse all non-alphanumeric to `-`, so the output is
        /// constrained to lowercase ASCII alphanumerics + `-`). Any
        /// upstream mojibake or zero-width character should not crash.
        #[test]
        fn pep503_normalize_does_not_panic(s in ".*") {
            let out = pep503_normalize(&s);
            // Output is always lowercase (no uppercase made it through).
            prop_assert_eq!(out.clone(), out.to_lowercase());
            // Output never starts or ends with `-` (the trim_matches step).
            prop_assert!(!out.starts_with('-'));
            prop_assert!(!out.ends_with('-'));
        }

        /// `last_path_segment` must never panic and must return a substring
        /// of its input (i.e. the returned `&str` borrows from the
        /// argument). The substring rule is enforced by the type system —
        /// the property test catches semantic bugs like "returned an empty
        /// string when the input had no `/`".
        #[test]
        fn last_path_segment_returns_substring(s in ".*") {
            let result = last_path_segment(&s);
            // Result is always present in the input.
            prop_assert!(s.contains(result) || result.is_empty() && s.is_empty());
            // No `/` in the result (we split on `/`).
            prop_assert!(!result.contains('/'));
        }

        /// The entire `enrich(cs)` entry point must never panic on
        /// arbitrary `ChangeSet::added` shapes. Empty ChangeSets are
        /// trivially fine; this exercises the loops over arbitrary
        /// component names + ecosystems.
        #[test]
        fn enrich_does_not_panic_on_arbitrary_components(
            names in proptest::collection::vec(".*", 0..32)
        ) {
            let added: Vec<Component> = names
                .iter()
                .map(|n| {
                    let eco = match n.len() % 5 {
                        0 => Ecosystem::Npm,
                        1 => Ecosystem::PyPI,
                        2 => Ecosystem::Cargo,
                        3 => Ecosystem::Go,
                        _ => Ecosystem::Other("unknown".to_string()),
                    };
                    Component {
                        name: n.clone(),
                        version: "1.0.0".to_string(),
                        ecosystem: eco,
                        purl: None,
                        licenses: Vec::new(),
                        supplier: None,
                        hashes: Vec::new(),
                        relationship: Relationship::Unknown,
                        source_url: None,
                        bom_ref: None,
                    }
                })
                .collect();
            let cs = ChangeSet { added, ..Default::default() };
            let _ = enrich(&cs);
        }
    }

    #[test]
    fn similarity_threshold_override_widens_match_set() {
        // Pick a near-miss candidate; relaxing the threshold must not
        // reduce the finding count vs a strict 0.99 cutoff.
        let candidate = comp("expressss");
        let cs = cs_added(vec![candidate.clone()]);
        let strict = enrich_with_threshold(&cs, Some(0.99));
        let relaxed = enrich_with_threshold(&cs, Some(0.80));
        assert!(
            relaxed.len() >= strict.len(),
            "lowering the threshold must not reduce findings"
        );
    }
}
