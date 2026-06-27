//! Similarity scoring: Jaro-Winkler with suffix boost, plus the Maven Levenshtein path.

use strsim::{jaro_winkler, levenshtein};

use super::canonical::match_form;
use super::{
    MAVEN_MAX_LEVENSHTEIN, MIN_LEGIT_LEN_FOR_STRUCTURAL_RULES, SUFFIX_BOOST_MIN_DELTA,
    SUFFIX_BOOST_SCORE, SupportedEcosystem,
};

pub(super) fn best_match_jw<'a>(
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
pub(super) fn best_match_maven<'a>(
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
pub(super) fn artifact_id(coord: &str) -> &str {
    coord.rsplit_once(':').map(|(_, a)| a).unwrap_or(coord)
}

/// True when `candidate` looks like a legitimate extension package built on
/// top of `legit` (e.g. `axios-retry` extending `axios`). The convention is
/// `<popular-name><separator><suffix>`, with the per-ecosystem separator set
/// passed in.
pub(super) fn is_likely_legit_extension(candidate: &str, legit: &str, separators: &[u8]) -> bool {
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
pub(super) fn has_suspicious_suffix_containment(candidate: &str, legit: &str) -> bool {
    if legit.len() < MIN_LEGIT_LEN_FOR_STRUCTURAL_RULES {
        return false;
    }
    if candidate.len() <= legit.len() + SUFFIX_BOOST_MIN_DELTA {
        return false;
    }
    candidate.ends_with(legit)
}

pub(super) fn is_separator_byte(b: Option<u8>, separators: &[u8]) -> bool {
    b.is_some_and(|byte| separators.contains(&byte))
}
