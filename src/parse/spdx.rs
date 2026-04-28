//! SPDX 2.3 JSON parser.
//!
//! Hand-rolled because we only need the `packages` block; the typed `spdx-rs` crate
//! is lightly maintained and pulls in more than this use-case warrants. SPDX 2.3 is
//! the format GitHub's Dependency Graph SBOM export emits, so this parser is the
//! integration point for `gh api repos/.../dependency-graph/sbom`.
//!
//! Relationships parsing (direct vs transitive resolution) is deferred to the
//! diff-core PR; for v0 every component is `Relationship::Unknown`.

use serde::Deserialize;
use serde_json::Value;

use crate::model::{Component, Ecosystem, Hash, Relationship, Sbom, SbomFormat};
use crate::parse::{ParseError, SbomParser, ecosystem_from_purl, hash_alg};

pub struct SpdxParser;

impl SbomParser for SpdxParser {
    fn parse(value: Value) -> Result<Sbom, ParseError> {
        let root: SpdxRoot = serde_json::from_value(value)?;

        let components = root
            .packages
            .unwrap_or_default()
            .into_iter()
            .map(normalize)
            .collect();

        Ok(Sbom {
            format: SbomFormat::Spdx,
            serial: root.document_namespace,
            components,
        })
    }
}

fn normalize(p: SpdxPackage) -> Component {
    let purl = p
        .external_refs
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|r| {
            r.reference_category.eq_ignore_ascii_case("PACKAGE-MANAGER")
                && r.reference_type.eq_ignore_ascii_case("purl")
        })
        .map(|r| r.reference_locator.clone());

    let ecosystem = purl
        .as_deref()
        .and_then(ecosystem_from_purl)
        .unwrap_or(Ecosystem::Other("spdx-package".to_string()));

    let licenses = pick_license(
        p.license_concluded.as_deref(),
        p.license_declared.as_deref(),
    );

    let hashes = p
        .checksums
        .unwrap_or_default()
        .into_iter()
        .map(|c| Hash {
            alg: hash_alg(&c.algorithm),
            value: c.checksum_value,
        })
        .collect();

    let supplier = p
        .supplier
        .as_deref()
        .or(p.originator.as_deref())
        .and_then(parse_actor);

    let source_url = p
        .download_location
        .as_deref()
        .and_then(parse_download_location);

    Component {
        name: p.name,
        version: p.version_info.unwrap_or_default(),
        ecosystem,
        purl,
        licenses,
        supplier,
        hashes,
        relationship: Relationship::Unknown,
        source_url,
        bom_ref: p.spdx_id,
    }
}

/// Prefer `licenseConcluded` over `licenseDeclared` per SPDX semantics, filtering out
/// the SPDX sentinel values `NOASSERTION` and `NONE`.
fn pick_license(concluded: Option<&str>, declared: Option<&str>) -> Vec<String> {
    for s in [concluded, declared].into_iter().flatten() {
        if let Some(lic) = normalize_license(s) {
            return vec![lic];
        }
    }
    Vec::new()
}

fn normalize_license(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed == "NOASSERTION" || trimmed == "NONE" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Parse SPDX actor strings like `Person: Foo Bar (foo@bar.com)` or
/// `Organization: Acme`. `NOASSERTION` returns `None`. The email suffix is preserved
/// for now since downstream renderers may want to surface it.
fn parse_actor(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed == "NOASSERTION" || trimmed.is_empty() {
        return None;
    }
    let stripped = trimmed
        .strip_prefix("Person: ")
        .or_else(|| trimmed.strip_prefix("Organization: "))
        .or_else(|| trimmed.strip_prefix("Tool: "))
        .unwrap_or(trimmed);
    Some(stripped.to_string())
}

/// Treat `downloadLocation` as a source URL only when it's actually a fetchable URL.
/// `NOASSERTION`/`NONE` and bare strings are dropped. The `git+` prefix is stripped
/// so the result is consistently a plain URL.
fn parse_download_location(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed == "NOASSERTION" || trimmed == "NONE" {
        return None;
    }
    let stripped = trimmed.strip_prefix("git+").unwrap_or(trimmed);
    if stripped.starts_with("http://")
        || stripped.starts_with("https://")
        || stripped.starts_with("git://")
        || stripped.starts_with("ssh://")
    {
        Some(stripped.to_string())
    } else {
        None
    }
}

// --- Wire-level SPDX 2.3 shapes -----------------------------------------------------
// Only the subset bomdrift consumes; unknown fields are ignored by serde defaults.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxRoot {
    document_namespace: Option<String>,
    packages: Option<Vec<SpdxPackage>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: Option<String>,
    name: String,
    version_info: Option<String>,
    download_location: Option<String>,
    license_concluded: Option<String>,
    license_declared: Option<String>,
    supplier: Option<String>,
    originator: Option<String>,
    checksums: Option<Vec<SpdxChecksum>>,
    external_refs: Option<Vec<SpdxExternalRef>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxChecksum {
    algorithm: String,
    checksum_value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxExternalRef {
    reference_category: String,
    reference_type: String,
    reference_locator: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn license_prefers_concluded() {
        assert_eq!(pick_license(Some("MIT"), Some("Apache-2.0")), vec!["MIT"]);
    }

    #[test]
    fn license_falls_back_to_declared_when_noassertion() {
        assert_eq!(pick_license(Some("NOASSERTION"), Some("MIT")), vec!["MIT"]);
    }

    #[test]
    fn license_empty_when_both_noassertion() {
        assert!(pick_license(Some("NOASSERTION"), Some("NONE")).is_empty());
    }

    #[test]
    fn actor_strips_prefix() {
        assert_eq!(
            parse_actor("Person: Matt Zabriskie"),
            Some("Matt Zabriskie".to_string())
        );
        assert_eq!(
            parse_actor("Organization: Anchore Inc."),
            Some("Anchore Inc.".to_string())
        );
        assert_eq!(parse_actor("NOASSERTION"), None);
        assert_eq!(parse_actor("Bare Name"), Some("Bare Name".to_string()));
    }

    #[test]
    fn download_location_strips_git_plus_and_filters_sentinels() {
        assert_eq!(
            parse_download_location("git+https://github.com/axios/axios"),
            Some("https://github.com/axios/axios".to_string())
        );
        assert_eq!(
            parse_download_location("https://example.com/foo"),
            Some("https://example.com/foo".to_string())
        );
        assert_eq!(parse_download_location("NOASSERTION"), None);
        assert_eq!(parse_download_location("NONE"), None);
        assert_eq!(parse_download_location("not-a-url"), None);
    }
}
