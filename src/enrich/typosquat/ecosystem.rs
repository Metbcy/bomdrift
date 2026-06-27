//! The supported-ecosystem enum and its list/separator/cache mappings.

use crate::model::Ecosystem;

use super::{
    CARGO_TOP_LIST, COMPOSER_TOP_LIST, GEM_TOP_LIST, GO_TOP_LIST, MAVEN_TOP_LIST, NPM_TOP_LIST,
    NUGET_TOP_LIST, PYPI_TOP_LIST,
};

/// Internal enum identifying the wired typosquat ecosystems. Distinct from
/// [`crate::model::Ecosystem`] because not every modeled ecosystem has a list
/// (Other(...) entries with no canonical purl-type prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupportedEcosystem {
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
    pub(super) fn from(eco: &Ecosystem) -> Option<Self> {
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

    pub(super) fn embedded(self) -> &'static str {
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
    pub(super) fn cache_filename(self) -> &'static str {
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
    pub(super) fn separators(self) -> &'static [u8] {
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

pub(super) fn ecosystem_label(eco: SupportedEcosystem) -> &'static str {
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
