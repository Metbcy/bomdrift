//! Reference-list loading: embedded snapshots, optional XDG cache, and the dedup sets.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::OnceLock;

use super::SupportedEcosystem;
use super::canonical::parse_and_canonicalize;
use super::ecosystem::ecosystem_label;

pub(super) fn legit_list_for(eco: SupportedEcosystem) -> &'static [String] {
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

pub(super) fn legit_set_for(eco: SupportedEcosystem) -> &'static HashSet<String> {
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

pub(super) fn default_cache_path(eco: SupportedEcosystem) -> Option<PathBuf> {
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
pub(super) fn load_legit_list(
    eco: SupportedEcosystem,
    cache_path: Option<&std::path::Path>,
) -> Vec<String> {
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
