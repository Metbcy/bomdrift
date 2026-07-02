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

mod canonical;
mod ecosystem;
mod lists;
mod matching;
#[cfg(test)]
mod tests;

use serde::Serialize;

use crate::diff::ChangeSet;
use crate::model::Component;

use canonical::canonicalize;
use ecosystem::SupportedEcosystem;
use lists::{legit_list_for, legit_set_for};
use matching::{best_match_jw, best_match_maven};

pub(super) const NPM_TOP_LIST: &str = include_str!("../../../data/npm-top1k.txt");
pub(super) const PYPI_TOP_LIST: &str = include_str!("../../../data/pypi-top200.txt");
pub(super) const CARGO_TOP_LIST: &str = include_str!("../../../data/cargo-top200.txt");
pub(super) const MAVEN_TOP_LIST: &str = include_str!("../../../data/maven-top100.txt");
pub(super) const GO_TOP_LIST: &str = include_str!("../../../data/go-top200.txt");
pub(super) const GEM_TOP_LIST: &str = include_str!("../../../data/gem-top200.txt");
pub(super) const NUGET_TOP_LIST: &str = include_str!("../../../data/nuget-top200.txt");
pub(super) const COMPOSER_TOP_LIST: &str = include_str!("../../../data/composer-top200.txt");

/// Minimum Jaro-Winkler score (or boosted score) for a pairing to be reported.
pub const SIMILARITY_THRESHOLD: f64 = 0.92;

/// Score assigned when suffix-containment boost fires. Above the threshold so
/// the finding always surfaces, but expressed as a score (not a hard 1.0) so
/// the user can read intensity off the rendered table without misreading
/// boosted hits as "perfect" matches.
pub(super) const SUFFIX_BOOST_SCORE: f64 = 0.95;

/// Minimum length of a legit name for the prefix-extension and suffix-boost
/// rules to apply. Short names (`fs`, `is`, `q`) are too generic — applying
/// the structural rules to them produces noise without signal.
pub(super) const MIN_LEGIT_LEN_FOR_STRUCTURAL_RULES: usize = 5;

/// A candidate must add more than this many characters of prefix on top of
/// a contained legit name for the suffix boost to apply. Smaller deltas are
/// usually trivial typos (`expresss` vs `express`) which Jaro-Winkler already
/// handles, or intentional pluralizations (`react` vs `reacts`).
pub(super) const SUFFIX_BOOST_MIN_DELTA: usize = 3;

/// Maximum Levenshtein distance for a Maven `artifactId` pairing to be
/// reported. `dist == 1` catches single-character substitutions/insertions
/// (`commons-lng3` vs `commons-lang3`); `dist == 2` catches two-character
/// drift; beyond that, the names are simply different packages.
pub(super) const MAVEN_MAX_LEVENSHTEIN: usize = 2;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TyposquatFinding {
    pub component: Component,
    pub closest: String,
    pub score: f64,
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
