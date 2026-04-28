//! Unified component model. Every SBOM input format normalizes into `Component` so the
//! diff and enrichment passes only ever see one shape.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub purl: Option<String>,
    pub licenses: Vec<String>,
    pub source_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Npm,
    PyPI,
    Cargo,
    Maven,
    Go,
    Other(String),
}
