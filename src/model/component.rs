//! Unified component model. Every SBOM input format normalizes into `Component` so the
//! diff and enrichment passes only ever see one shape.
//!
//! ## JSON serialization
//!
//! All public types in this module derive [`serde::Serialize`] so the diff result
//! graph round-trips through `--output json`. Field names are kept as-is
//! (snake_case) to match Rust convention and avoid any rename indirection.
//!
//! Enums with an `Other(String)` escape hatch ([`Ecosystem`], [`HashAlg`])
//! serialize as plain JSON strings via hand-rolled [`serde::Serialize`] impls so
//! `Ecosystem::Other("library")` becomes `"library"` (not
//! `{"Other": "library"}`), keeping downstream JSON consumers from having to
//! special-case the variant tagging.

use std::fmt;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    /// Package URL (purl) string. Stored as a validated string in v0; the typed wrapper
    /// from the `packageurl` crate will be introduced when the diff core needs it for
    /// canonical keying.
    pub purl: Option<String>,
    /// SPDX license expressions, one per declared license. CycloneDX permits multiple.
    pub licenses: Vec<String>,
    pub supplier: Option<String>,
    pub hashes: Vec<Hash>,
    pub relationship: Relationship,
    /// VCS source URL when the SBOM provides one (CycloneDX `externalReferences[type=vcs]`,
    /// SPDX `externalRefs`, Syft `metadata.source`).
    pub source_url: Option<String>,
    /// Identifier preserved from the source SBOM for traceability back to the original record.
    pub bom_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ecosystem {
    Npm,
    PyPI,
    Cargo,
    Maven,
    Go,
    Gem,
    NuGet,
    Composer,
    Other(String),
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Npm => f.write_str("npm"),
            Self::PyPI => f.write_str("pypi"),
            Self::Cargo => f.write_str("cargo"),
            Self::Maven => f.write_str("maven"),
            Self::Go => f.write_str("go"),
            Self::Gem => f.write_str("gem"),
            Self::NuGet => f.write_str("nuget"),
            Self::Composer => f.write_str("composer"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

impl Serialize for Ecosystem {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hash {
    pub alg: HashAlg,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha512,
    Md5,
    Other(String),
}

impl HashAlg {
    fn as_str(&self) -> &str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::Md5 => "md5",
            Self::Other(s) => s.as_str(),
        }
    }
}

impl Serialize for HashAlg {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Relationship {
    Direct,
    Transitive,
    Unknown,
}
