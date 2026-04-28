//! CycloneDX 1.5/1.6 JSON parser.
//!
//! Hand-rolled against the public CycloneDX schema rather than via the `cyclonedx-bom`
//! crate to keep the dependency tree small. Migration to the typed crate is a
//! follow-up if/when we need full schema fidelity (vulnerabilities, services,
//! formulation, etc.). For SBOM-diff purposes only the `components` block is required.

use serde::Deserialize;
use serde_json::Value;

use crate::model::{Component, Ecosystem, Hash, HashAlg, Relationship, Sbom, SbomFormat};
use crate::parse::{ParseError, SbomParser};

pub struct CycloneDxParser;

impl SbomParser for CycloneDxParser {
    fn parse(value: Value) -> Result<Sbom, ParseError> {
        let root: CdxRoot = serde_json::from_value(value)?;

        let components = root
            .components
            .unwrap_or_default()
            .into_iter()
            .map(normalize)
            .collect();

        Ok(Sbom {
            format: SbomFormat::CycloneDx,
            serial: root.serial_number,
            components,
        })
    }
}

fn normalize(c: CdxComponent) -> Component {
    let ecosystem = c
        .purl
        .as_deref()
        .and_then(ecosystem_from_purl)
        .unwrap_or_else(|| ecosystem_from_component_type(c.component_type.as_deref()));

    let licenses = c
        .licenses
        .unwrap_or_default()
        .into_iter()
        .filter_map(license_to_string)
        .collect();

    let hashes = c
        .hashes
        .unwrap_or_default()
        .into_iter()
        .map(|h| Hash {
            alg: hash_alg(&h.alg),
            value: h.content,
        })
        .collect();

    let source_url = c
        .external_references
        .unwrap_or_default()
        .into_iter()
        .find(|r| matches!(r.ref_type.as_str(), "vcs" | "vcs-git"))
        .map(|r| r.url);

    let supplier = c.supplier.and_then(|s| s.name);

    Component {
        name: c.name,
        version: c.version.unwrap_or_default(),
        ecosystem,
        purl: c.purl,
        licenses,
        supplier,
        hashes,
        relationship: Relationship::Unknown,
        source_url,
        bom_ref: c.bom_ref,
    }
}

/// Extract the package-url type prefix (everything between `pkg:` and the first `/`).
/// Returns `None` for malformed purls; ecosystem inference falls through to
/// `ecosystem_from_component_type`.
fn ecosystem_from_purl(purl: &str) -> Option<Ecosystem> {
    let after = purl.strip_prefix("pkg:")?;
    let ty = after.split(['/', '@']).next()?;
    Some(match ty {
        "npm" => Ecosystem::Npm,
        "pypi" => Ecosystem::PyPI,
        "cargo" => Ecosystem::Cargo,
        "maven" => Ecosystem::Maven,
        "golang" => Ecosystem::Go,
        other if !other.is_empty() => Ecosystem::Other(other.to_string()),
        _ => return None,
    })
}

fn ecosystem_from_component_type(ty: Option<&str>) -> Ecosystem {
    Ecosystem::Other(ty.unwrap_or("unknown").to_string())
}

fn license_to_string(entry: CdxLicense) -> Option<String> {
    if let Some(expr) = entry.expression {
        return Some(expr);
    }
    let lic = entry.license?;
    lic.id.or(lic.name)
}

fn hash_alg(s: &str) -> HashAlg {
    match s.to_ascii_uppercase().as_str() {
        "SHA-1" | "SHA1" => HashAlg::Sha1,
        "SHA-256" | "SHA256" => HashAlg::Sha256,
        "SHA-512" | "SHA512" => HashAlg::Sha512,
        "MD5" => HashAlg::Md5,
        _ => HashAlg::Other(s.to_string()),
    }
}

// --- Wire-level CycloneDX shapes ----------------------------------------------------
// Only the subset bomdrift consumes; unknown fields are ignored by serde defaults.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxRoot {
    #[serde(rename = "serialNumber")]
    serial_number: Option<String>,
    components: Option<Vec<CdxComponent>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxComponent {
    #[serde(rename = "type")]
    component_type: Option<String>,
    name: String,
    version: Option<String>,
    purl: Option<String>,
    #[serde(rename = "bom-ref")]
    bom_ref: Option<String>,
    licenses: Option<Vec<CdxLicense>>,
    hashes: Option<Vec<CdxHash>>,
    supplier: Option<CdxSupplier>,
    external_references: Option<Vec<CdxExternalRef>>,
}

#[derive(Deserialize)]
struct CdxLicense {
    license: Option<CdxLicenseId>,
    expression: Option<String>,
}

#[derive(Deserialize)]
struct CdxLicenseId {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct CdxHash {
    alg: String,
    content: String,
}

#[derive(Deserialize)]
struct CdxSupplier {
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxExternalRef {
    #[serde(rename = "type")]
    ref_type: String,
    url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecosystem_inference() {
        assert_eq!(
            ecosystem_from_purl("pkg:npm/axios@1.14.0"),
            Some(Ecosystem::Npm)
        );
        assert_eq!(
            ecosystem_from_purl("pkg:pypi/requests@2.31.0"),
            Some(Ecosystem::PyPI)
        );
        assert_eq!(
            ecosystem_from_purl("pkg:cargo/serde@1.0.0"),
            Some(Ecosystem::Cargo)
        );
        assert_eq!(
            ecosystem_from_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0"),
            Some(Ecosystem::Maven)
        );
        assert_eq!(
            ecosystem_from_purl("pkg:golang/github.com/spf13/cobra@v1.8.0"),
            Some(Ecosystem::Go)
        );
        assert_eq!(
            ecosystem_from_purl("pkg:gem/rails@7.1.0"),
            Some(Ecosystem::Other("gem".to_string()))
        );
        assert_eq!(ecosystem_from_purl("not-a-purl"), None);
    }

    #[test]
    fn hash_alg_normalization() {
        assert_eq!(hash_alg("SHA-256"), HashAlg::Sha256);
        assert_eq!(hash_alg("sha256"), HashAlg::Sha256);
        assert_eq!(hash_alg("MD5"), HashAlg::Md5);
        assert_eq!(hash_alg("BLAKE3"), HashAlg::Other("BLAKE3".to_string()));
    }

    #[test]
    fn license_flattens_expression_first() {
        let l = CdxLicense {
            license: Some(CdxLicenseId {
                id: Some("MIT".to_string()),
                name: None,
            }),
            expression: Some("MIT OR Apache-2.0".to_string()),
        };
        assert_eq!(license_to_string(l), Some("MIT OR Apache-2.0".to_string()));
    }

    #[test]
    fn license_falls_back_to_id_then_name() {
        let id_only = CdxLicense {
            license: Some(CdxLicenseId {
                id: Some("MIT".to_string()),
                name: None,
            }),
            expression: None,
        };
        assert_eq!(license_to_string(id_only), Some("MIT".to_string()));

        let name_only = CdxLicense {
            license: Some(CdxLicenseId {
                id: None,
                name: Some("Custom Proprietary".to_string()),
            }),
            expression: None,
        };
        assert_eq!(
            license_to_string(name_only),
            Some("Custom Proprietary".to_string())
        );
    }
}
