//! Unified component model. Every SBOM input format normalizes into `Component` so the
//! diff and enrichment passes only ever see one shape.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
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
            Self::Other(s) => f.write_str(s),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relationship {
    Direct,
    Transitive,
    Unknown,
}
