//! Syft JSON parser. Implementation lands in the next PR.

use serde_json::Value;

use crate::model::{Sbom, SbomFormat};
use crate::parse::{ParseError, SbomParser};

pub struct SyftParser;

impl SbomParser for SyftParser {
    fn parse(_value: Value) -> Result<Sbom, ParseError> {
        Err(ParseError::NotImplemented {
            format: SbomFormat::Syft,
        })
    }
}
