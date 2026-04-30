#![no_main]
//! Fuzz target for the CycloneDX JSON parser.
//!
//! Two-stage shape: first decode the bytes as `serde_json::Value` so
//! that ill-formed-JSON inputs are dropped at the well-tested
//! `serde_json` boundary, then hand the parsed value to bomdrift's
//! own parser. This focuses fuzzing budget on bomdrift-side logic
//! (schema interpretation, purl handling, hash normalization) rather
//! than re-fuzzing serde_json.

use bomdrift::parse::{SbomParser, cyclonedx::CycloneDxParser};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = CycloneDxParser::parse(value);
    }
});
