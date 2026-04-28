//! Syft JSON parser.
//!
//! Hand-rolled because there is no published Rust crate against Syft's schema.
//! We consume only the `artifacts` array — Syft's `source`, `distro`, and per-format
//! `metadata` blocks vary wildly between package types and aren't needed for diff.
//!
//! Hashes, supplier, and source_url are intentionally not extracted in v0; Syft puts
//! them under `metadata.<format-specific-fields>` (e.g. `metadata.author` for npm,
//! `metadata.maintainer` for python wheels) and a useful normalization across all
//! supported package types is its own follow-up. The unified diff and the OSV
//! enricher don't need these fields, so they can land later without blocking the wedge.

use serde::Deserialize;
use serde_json::Value;

use crate::model::{Component, Ecosystem, Relationship, Sbom, SbomFormat};
use crate::parse::{ParseError, SbomParser, ecosystem_from_purl};

pub struct SyftParser;

impl SbomParser for SyftParser {
    fn parse(value: Value) -> Result<Sbom, ParseError> {
        let root: SyftRoot = serde_json::from_value(value)?;

        let components = root
            .artifacts
            .unwrap_or_default()
            .into_iter()
            .map(normalize)
            .collect();

        let serial = root.source.and_then(|s| s.id);

        Ok(Sbom {
            format: SbomFormat::Syft,
            serial,
            components,
        })
    }
}

fn normalize(a: SyftArtifact) -> Component {
    let ecosystem = a
        .purl
        .as_deref()
        .and_then(ecosystem_from_purl)
        .unwrap_or_else(|| ecosystem_from_syft_type(a.artifact_type.as_deref()));

    let licenses = a
        .licenses
        .unwrap_or_default()
        .into_iter()
        .filter_map(license_to_string)
        .collect();

    Component {
        name: a.name,
        version: a.version.unwrap_or_default(),
        ecosystem,
        purl: a.purl,
        licenses,
        supplier: None,
        hashes: Vec::new(),
        relationship: Relationship::Unknown,
        source_url: None,
        bom_ref: a.id,
    }
}

/// Map Syft's per-package-manager `type` strings to ecosystems for cases where the
/// purl is absent or unparseable. Syft uses `python` (not `pypi`), `rust-crate`
/// (not `cargo`), `java-archive` for Maven jars, and `go-module` for Go.
fn ecosystem_from_syft_type(ty: Option<&str>) -> Ecosystem {
    match ty {
        Some("npm") => Ecosystem::Npm,
        Some("python") => Ecosystem::PyPI,
        Some("rust-crate") => Ecosystem::Cargo,
        Some("java-archive") => Ecosystem::Maven,
        Some("go-module") => Ecosystem::Go,
        Some(other) => Ecosystem::Other(other.to_string()),
        None => Ecosystem::Other("unknown".to_string()),
    }
}

/// Syft's license shape changed between versions. Pre-v13 emitted plain strings;
/// v13+ emits objects with `value` and (optionally) `spdxExpression`. We accept both.
fn license_to_string(entry: SyftLicense) -> Option<String> {
    match entry {
        SyftLicense::Plain(s) if !s.is_empty() => Some(s),
        SyftLicense::Plain(_) => None,
        SyftLicense::Object(o) => o.spdx_expression.or(o.value),
    }
}

// --- Wire-level Syft JSON shapes ----------------------------------------------------
// Only the subset bomdrift consumes; unknown fields are ignored by serde defaults.

#[derive(Deserialize)]
struct SyftRoot {
    artifacts: Option<Vec<SyftArtifact>>,
    source: Option<SyftSource>,
}

#[derive(Deserialize)]
struct SyftSource {
    id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyftArtifact {
    id: Option<String>,
    name: String,
    version: Option<String>,
    #[serde(rename = "type")]
    artifact_type: Option<String>,
    purl: Option<String>,
    licenses: Option<Vec<SyftLicense>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SyftLicense {
    Plain(String),
    Object(SyftLicenseObject),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyftLicenseObject {
    value: Option<String>,
    spdx_expression: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_to_ecosystem_handles_syft_specific_names() {
        assert_eq!(ecosystem_from_syft_type(Some("npm")), Ecosystem::Npm);
        assert_eq!(ecosystem_from_syft_type(Some("python")), Ecosystem::PyPI);
        assert_eq!(
            ecosystem_from_syft_type(Some("rust-crate")),
            Ecosystem::Cargo
        );
        assert_eq!(
            ecosystem_from_syft_type(Some("java-archive")),
            Ecosystem::Maven
        );
        assert_eq!(ecosystem_from_syft_type(Some("go-module")), Ecosystem::Go);
        assert_eq!(
            ecosystem_from_syft_type(Some("gem")),
            Ecosystem::Other("gem".to_string())
        );
        assert_eq!(
            ecosystem_from_syft_type(None),
            Ecosystem::Other("unknown".to_string())
        );
    }

    #[test]
    fn license_string_form() {
        assert_eq!(
            license_to_string(SyftLicense::Plain("MIT".to_string())),
            Some("MIT".to_string())
        );
        assert_eq!(license_to_string(SyftLicense::Plain(String::new())), None);
    }

    #[test]
    fn license_object_prefers_spdx_expression() {
        let l = SyftLicense::Object(SyftLicenseObject {
            value: Some("MIT".to_string()),
            spdx_expression: Some("MIT OR Apache-2.0".to_string()),
        });
        assert_eq!(license_to_string(l), Some("MIT OR Apache-2.0".to_string()));
    }

    #[test]
    fn license_object_falls_back_to_value() {
        let l = SyftLicense::Object(SyftLicenseObject {
            value: Some("Custom".to_string()),
            spdx_expression: None,
        });
        assert_eq!(license_to_string(l), Some("Custom".to_string()));
    }
}
