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
