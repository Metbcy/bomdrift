//! SPDX 2.3 JSON parser. Implementation lands in the next PR.

use serde_json::Value;

use crate::model::{Sbom, SbomFormat};
use crate::parse::{ParseError, SbomParser};

pub struct SpdxParser;

impl SbomParser for SpdxParser {
    fn parse(_value: Value) -> Result<Sbom, ParseError> {
        Err(ParseError::NotImplemented {
            format: SbomFormat::Spdx,
        })
    }
}
