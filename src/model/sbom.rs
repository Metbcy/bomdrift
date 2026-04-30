use std::fmt;

use serde::Serialize;

use crate::model::Component;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sbom {
    pub format: SbomFormat,
    /// Document-level identifier (CycloneDX `serialNumber`, SPDX `documentNamespace`).
    pub serial: Option<String>,
    pub components: Vec<Component>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
    Syft,
}

impl SbomFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CycloneDx => "CycloneDX",
            Self::Spdx => "SPDX",
            Self::Syft => "Syft",
        }
    }
}

impl fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for SbomFormat {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn as_str_round_trips_each_variant() {
        // The string form is load-bearing for the SBOM diff comment header
        // (`format = CycloneDX` in the metadata footer) and the SARIF run
        // tool description. A typo in any branch silently mislabels every
        // diff for that format.
        assert_eq!(SbomFormat::CycloneDx.as_str(), "CycloneDX");
        assert_eq!(SbomFormat::Spdx.as_str(), "SPDX");
        assert_eq!(SbomFormat::Syft.as_str(), "Syft");
    }

    #[test]
    fn display_matches_as_str_for_each_variant() {
        // `format!` and `to_string()` go through Display::fmt, which must
        // be byte-identical to as_str() — the diff renderer interleaves
        // the two and a divergence would produce mixed-case labels in the
        // same comment.
        for f in [SbomFormat::CycloneDx, SbomFormat::Spdx, SbomFormat::Syft] {
            assert_eq!(f.to_string(), f.as_str());
            assert_eq!(format!("{f}"), f.as_str());
        }
    }

    #[test]
    fn serialize_emits_canonical_string_form() {
        // JSON output of `bomdrift diff --output json` includes
        // `"format": "CycloneDX"` in the SBOM block; downstream tooling
        // pattern-matches on that value. Serialize MUST emit the same
        // string as_str() returns, NOT the Rust enum-variant name
        // (`"CycloneDx"`) or any debug form.
        for (variant, expected) in [
            (SbomFormat::CycloneDx, "\"CycloneDX\""),
            (SbomFormat::Spdx, "\"SPDX\""),
            (SbomFormat::Syft, "\"Syft\""),
        ] {
            let s = serde_json::to_string(&variant).unwrap();
            assert_eq!(s, expected);
        }
    }
}
