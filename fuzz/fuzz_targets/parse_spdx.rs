#![no_main]
//! Fuzz target for the SPDX 2.3 JSON parser. See parse_cyclonedx.rs
//! for the rationale behind the two-stage decode.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = bomdrift::parse::spdx::SpdxParser::parse(value);
    }
});
