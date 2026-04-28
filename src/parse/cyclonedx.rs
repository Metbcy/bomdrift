//! CycloneDX 1.5/1.6 JSON parser. Implementation lands in the next PR.

use serde_json::Value;

use crate::model::{Sbom, SbomFormat};
use crate::parse::{ParseError, SbomParser};

pub struct CycloneDxParser;

impl SbomParser for CycloneDxParser {
    fn parse(_value: Value) -> Result<Sbom, ParseError> {
        Err(ParseError::NotImplemented {
            format: SbomFormat::CycloneDx,
        })
    }
}
