//! Per-ecosystem name canonicalization and match-form extraction.

use std::collections::HashSet;

use super::SupportedEcosystem;

/// Per-ecosystem name canonicalization. Applied to BOTH the candidate and
/// every entry in the legit list (during list load) so equality and structural
/// rules see the same normalized form.
pub(super) fn canonicalize(eco: SupportedEcosystem, name: &str) -> String {
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
pub(super) fn match_form(eco: SupportedEcosystem, canonical: &str) -> &str {
    match eco {
        SupportedEcosystem::Go | SupportedEcosystem::Composer => last_path_segment(canonical),
        _ => canonical,
    }
}

/// Extract the substring after the last `/`, or the whole string when no
/// `/` is present. Used for both Go (`host/owner/repo` → `repo`) and
/// Composer (`vendor/package` → `package`).
pub(super) fn last_path_segment(s: &str) -> &str {
    s.rsplit_once('/').map(|(_, a)| a).unwrap_or(s)
}

/// PEP 503 simplified normalization: lowercase, then collapse any run of
/// `-`, `_`, or `.` into a single `-`. `Foo_Bar.Baz` → `foo-bar-baz`.
pub(super) fn pep503_normalize(name: &str) -> String {
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

/// Parse a one-name-per-line list, applying ecosystem-specific canonicalization
/// to each entry, dropping comments and blanks, and deduplicating.
pub(super) fn parse_and_canonicalize(input: &str, eco: SupportedEcosystem) -> Vec<String> {
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
