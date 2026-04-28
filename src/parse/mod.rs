//! SBOM parser layer. Each supported format implements [`SbomParser`]; [`detect_format`]
//! identifies the format by peeking at the JSON without fully deserializing.

pub mod cyclonedx;
pub mod spdx;
pub mod syft;

use serde_json::Value;
use thiserror::Error;

use crate::model::{Ecosystem, HashAlg, Sbom, SbomFormat};

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown SBOM format — no `bomFormat`, `spdxVersion`, or Syft `schema` marker found")]
    UnknownFormat,
    #[error("{format} parsing not implemented yet (tracking issue: v0.1.0)")]
    NotImplemented { format: SbomFormat },
}

pub trait SbomParser {
    fn parse(value: Value) -> Result<Sbom, ParseError>;
}

/// Identify an SBOM's format by inspecting top-level JSON keys without full deserialization.
///
/// Detection rules (in order):
/// 1. `bomFormat == "CycloneDX"` → CycloneDX (case-insensitive per spec).
/// 2. `spdxVersion` present → SPDX.
/// 3. `schema.url` containing "anchore.io/schema/syft" → Syft.
///
/// Returns [`ParseError::UnknownFormat`] when none match.
pub fn detect_format(value: &Value) -> Result<SbomFormat, ParseError> {
    if let Some(s) = value.get("bomFormat").and_then(Value::as_str)
        && s.eq_ignore_ascii_case("cyclonedx")
    {
        return Ok(SbomFormat::CycloneDx);
    }

    if value.get("spdxVersion").is_some() {
        return Ok(SbomFormat::Spdx);
    }

    if let Some(url) = value
        .get("schema")
        .and_then(|s| s.get("url"))
        .and_then(Value::as_str)
        && url.contains("anchore.io/schema/syft")
    {
        return Ok(SbomFormat::Syft);
    }

    Err(ParseError::UnknownFormat)
}

/// Parse an SBOM from a JSON value, dispatching to the appropriate format parser.
pub fn parse(value: Value) -> Result<Sbom, ParseError> {
    let format = detect_format(&value)?;
    match format {
        SbomFormat::CycloneDx => cyclonedx::CycloneDxParser::parse(value),
        SbomFormat::Spdx => spdx::SpdxParser::parse(value),
        SbomFormat::Syft => syft::SyftParser::parse(value),
    }
}

// ----- Cross-format helpers --------------------------------------------------------

/// Extract an [`Ecosystem`] from a Package URL prefix. Returns `None` for malformed
/// purls so callers can fall back to format-specific inference.
pub(crate) fn ecosystem_from_purl(purl: &str) -> Option<Ecosystem> {
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

/// Normalize hash-algorithm strings from any SBOM format to [`HashAlg`].
pub(crate) fn hash_alg(s: &str) -> HashAlg {
    match s.to_ascii_uppercase().as_str() {
        "SHA-1" | "SHA1" => HashAlg::Sha1,
        "SHA-256" | "SHA256" => HashAlg::Sha256,
        "SHA-512" | "SHA512" => HashAlg::Sha512,
        "MD5" => HashAlg::Md5,
        _ => HashAlg::Other(s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_cyclonedx() {
        let v = json!({"bomFormat": "CycloneDX", "specVersion": "1.5"});
        assert_eq!(detect_format(&v).unwrap(), SbomFormat::CycloneDx);
    }

    #[test]
    fn detects_cyclonedx_case_insensitive() {
        let v = json!({"bomFormat": "cyclonedx"});
        assert_eq!(detect_format(&v).unwrap(), SbomFormat::CycloneDx);
    }

    #[test]
    fn detects_spdx() {
        let v = json!({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"});
        assert_eq!(detect_format(&v).unwrap(), SbomFormat::Spdx);
    }

    #[test]
    fn detects_syft() {
        let v = json!({
            "schema": {"version": "16.0.0", "url": "https://raw.githubusercontent.com/anchore/syft/main/internal/jsonschema/anchore.io/schema/syft/json/16.0.0/document.json"},
            "artifacts": []
        });
        assert_eq!(detect_format(&v).unwrap(), SbomFormat::Syft);
    }

    #[test]
    fn rejects_unknown() {
        let v = json!({"foo": "bar"});
        assert!(matches!(detect_format(&v), Err(ParseError::UnknownFormat)));
    }

    #[test]
    fn purl_ecosystem_inference() {
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
}
