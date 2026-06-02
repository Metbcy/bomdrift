use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::SARIF_ARTIFACT_URI;

/// Stable per-rule identity hash for SARIF `partialFingerprints`. GitHub
/// Code Scanning uses these to thread alert state across runs (resolved /
/// dismissed / open) so the value MUST stay byte-equal for the same logical
/// finding. We hex-encode SHA-256 of a `|`-joined identity string so the
/// inputs are inspectable from a debugger and the output is filename-safe.
///
/// The `/v1` suffix on the fingerprint key (see emit sites) lets us evolve
/// the identity scheme later without GitHub re-opening every alert.
pub(crate) fn fingerprint(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            h.update(b"|");
        }
        h.update(p.as_bytes());
    }
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub(super) fn plugin_sarif_level(severity: crate::plugin::PluginSeverity) -> &'static str {
    use crate::plugin::PluginSeverity;
    match severity {
        PluginSeverity::Info => "note",
        PluginSeverity::Warning => "warning",
        PluginSeverity::Error => "error",
    }
}

pub(super) fn synthetic_location() -> Value {
    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": SARIF_ARTIFACT_URI }
        }
    })
}

/// Map our internal [`Severity`] enum to the SARIF `level` enum. Critical and
/// High are the actionable buckets that block-on-merge tooling cares about;
/// everything below collapses to `warning` so reviewers still see the finding
/// without a hard fail in code-scanning views.
pub(super) fn sarif_level(severity: crate::enrich::Severity) -> &'static str {
    use crate::enrich::Severity;
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low | Severity::None => "warning",
    }
}
