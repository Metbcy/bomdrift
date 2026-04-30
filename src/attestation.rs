//! OCI-attached SBOM attestation fetch + verify (Phase B, v0.9.6).
//!
//! Shells out to the user's locally-installed `cosign` binary to verify
//! a CycloneDX SBOM attestation attached to an OCI artifact and returns
//! the raw SBOM JSON ready for the standard parser pipeline.
//!
//! Cosign is treated as an *optional runtime dep*: a missing or failing
//! `cosign` is reported back to the caller with a clear error pointing
//! at the install docs. We deliberately do NOT pull in any sigstore
//! crates — the verify step demands a Fulcio CA bundle, transparency-log
//! checkpoint, and rekor witness validation that the cosign CLI already
//! ships, and reproducing it in-process is out of scope for v0.9.6.
//!
//! Wire format produced by `cosign verify-attestation`:
//!
//! ```json
//! {
//!   "payloadType": "application/vnd.in-toto+json",
//!   "payload": "<base64 in-toto Statement>",
//!   "signatures": [{ "keyid": "...", "sig": "..." }]
//! }
//! ```
//!
//! Decoded `payload` is an in-toto Statement whose `predicateType` is
//! `https://cyclonedx.org/bom` (or compatible) and whose `predicate`
//! field is the actual CycloneDX SBOM. We extract `predicate` and hand
//! it back as a serialized JSON string — that's what the parser layer
//! expects.

use anyhow::{Context, Result, bail};
use base64::Engine;

const COSIGN_INSTALL_URL: &str = "https://docs.sigstore.dev/system_config/installation/";

/// Fetch and verify a CycloneDX SBOM attached as a cosign attestation
/// to an OCI artifact. Shells out to `cosign verify-attestation`.
///
/// Errors include:
/// - cosign-not-on-PATH (clear message pointing at install docs);
/// - cosign exit non-zero (verification failure: cert mismatch, sig
///   invalid, no attestation found);
/// - malformed in-toto envelope output (cosign succeeded but stdout
///   wasn't the expected JSON shape).
pub fn fetch_verified_sbom(oci_ref: &str, identity_regexp: &str, issuer: &str) -> Result<String> {
    let output = std::process::Command::new("cosign")
        .args([
            "verify-attestation",
            "--type=cyclonedx",
            "--certificate-identity-regexp",
            identity_regexp,
            "--certificate-oidc-issuer",
            issuer,
            oci_ref,
        ])
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "cosign binary not on PATH; install per {COSIGN_INSTALL_URL} and retry. \
                     underlying error: {err}"
                )
            } else {
                anyhow::Error::from(err)
                    .context(format!("invoking cosign verify-attestation for {oci_ref}"))
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "cosign verify-attestation failed for {oci_ref}: exit {}\n{}",
            output.status,
            stderr.trim()
        );
    }

    let stdout = std::str::from_utf8(&output.stdout)
        .with_context(|| format!("cosign stdout was not utf-8 for {oci_ref}"))?;

    extract_sbom_from_envelope(stdout)
        .with_context(|| format!("parsing cosign attestation envelope for {oci_ref}"))
}

/// Decode an in-toto DSSE envelope (the JSON shape cosign emits to
/// stdout) and pull out the embedded CycloneDX SBOM as serialized JSON.
///
/// The envelope's `payload` field is base64-encoded JSON. Within that
/// JSON, `predicate` is the SBOM object — that's what the parser needs.
///
/// Cosign sometimes emits MULTIPLE envelopes back-to-back (one per
/// signature) separated by newlines. Take the first parseable one and
/// return its predicate; subsequent envelopes are ignored because they
/// carry the same predicate by construction.
pub fn extract_sbom_from_envelope(stdout: &str) -> Result<String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        bail!("cosign produced empty stdout; expected a DSSE envelope JSON");
    }

    // Cosign may print one envelope per line, or a single pretty-printed
    // object. Try whole-buffer parse first; fall back to per-line.
    let envelope: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => {
            let mut found: Option<serde_json::Value> = None;
            for line in trimmed.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    found = Some(v);
                    break;
                }
            }
            found.ok_or_else(|| {
                anyhow::anyhow!(
                    "no parseable JSON object in cosign stdout (got {} bytes)",
                    trimmed.len()
                )
            })?
        }
    };

    let payload_b64 = envelope
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("DSSE envelope missing string `payload` field"))?;

    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .context("decoding base64 `payload` field")?;
    let statement: serde_json::Value =
        serde_json::from_slice(&payload_bytes).context("parsing in-toto Statement payload")?;

    let predicate = statement
        .get("predicate")
        .ok_or_else(|| anyhow::anyhow!("in-toto Statement missing `predicate` field"))?;

    serde_json::to_string(predicate).context("re-serializing CycloneDX predicate")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;

    /// Build a synthetic DSSE envelope whose payload encodes an in-toto
    /// Statement whose predicate is the given CycloneDX-shaped JSON.
    fn make_envelope(predicate: &serde_json::Value) -> String {
        let stmt = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://cyclonedx.org/bom",
            "subject": [{"name": "test", "digest": {"sha256": "00".repeat(32)}}],
            "predicate": predicate,
        });
        let payload = B64.encode(serde_json::to_vec(&stmt).unwrap());
        let env = serde_json::json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": payload,
            "signatures": [{"keyid": "kid-1", "sig": "fake"}],
        });
        serde_json::to_string(&env).unwrap()
    }

    #[test]
    fn extracts_predicate_from_well_formed_envelope() {
        let predicate = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [],
        });
        let envelope = make_envelope(&predicate);
        let sbom_json = extract_sbom_from_envelope(&envelope).expect("parses");
        let parsed: serde_json::Value = serde_json::from_str(&sbom_json).unwrap();
        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.6");
    }

    #[test]
    fn handles_per_line_envelope_emission() {
        let predicate = serde_json::json!({"bomFormat": "CycloneDX", "specVersion": "1.6"});
        let env = make_envelope(&predicate);
        // Cosign occasionally prefixes a status line like
        // "Verification for <ref> --" before the JSON; reproduce that.
        let combined = format!("Verification for example.com/img@sha256:abc --\n{env}\n");
        let sbom_json = extract_sbom_from_envelope(&combined).expect("parses");
        let parsed: serde_json::Value = serde_json::from_str(&sbom_json).unwrap();
        assert_eq!(parsed["bomFormat"], "CycloneDX");
    }

    #[test]
    fn missing_payload_field_errors_clearly() {
        let env = serde_json::json!({
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [],
        })
        .to_string();
        let err = extract_sbom_from_envelope(&env).unwrap_err();
        assert!(
            format!("{err:#}").contains("payload"),
            "error must mention the missing field; got: {err:#}"
        );
    }

    #[test]
    fn empty_stdout_errors_clearly() {
        let err = extract_sbom_from_envelope("").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("empty") || msg.contains("DSSE"), "got: {msg}");
    }

    #[test]
    fn missing_predicate_in_statement_errors() {
        // Hand-craft an envelope whose Statement has no predicate.
        let stmt = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://cyclonedx.org/bom",
            "subject": [],
        });
        let payload = B64.encode(serde_json::to_vec(&stmt).unwrap());
        let env = serde_json::json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": payload,
            "signatures": [],
        })
        .to_string();
        let err = extract_sbom_from_envelope(&env).unwrap_err();
        assert!(format!("{err:#}").contains("predicate"));
    }

    #[test]
    fn malformed_base64_payload_errors() {
        let env = serde_json::json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": "this is not base64!@#$",
            "signatures": [],
        })
        .to_string();
        let err = extract_sbom_from_envelope(&env).unwrap_err();
        assert!(format!("{err:#}").to_lowercase().contains("base64"));
    }

    /// Integration: write a fake `cosign` script to a tempdir, prepend
    /// it to PATH, call `fetch_verified_sbom`, assert the round-trip.
    /// PATH mutation is serialized via `clock::test_env_lock()`.
    #[cfg(unix)]
    #[test]
    fn fetch_verified_sbom_invokes_cosign_on_path() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let _guard = crate::clock::test_env_lock();

        let dir = std::env::temp_dir().join(format!(
            "bomdrift-attestation-fakecosign-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let predicate = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [],
        });
        let envelope = make_envelope(&predicate);

        let script = dir.join("cosign");
        let body = format!("#!/bin/sh\ncat <<'EOF'\n{envelope}\nEOF\n");
        {
            let mut f = std::fs::File::create(&script).unwrap();
            f.write_all(body.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();

        let prev_path = std::env::var_os("PATH");
        let new_path = match &prev_path {
            Some(p) => {
                let mut v = std::ffi::OsString::from(&dir);
                v.push(":");
                v.push(p);
                v
            }
            None => std::ffi::OsString::from(&dir),
        };
        // SAFETY: serialized via test_env_lock above.
        unsafe { std::env::set_var("PATH", &new_path) };

        let result = fetch_verified_sbom(
            "example.com/img:tag",
            "https://github.com/owner/.+",
            "https://token.actions.githubusercontent.com",
        );

        // Restore PATH BEFORE asserting so a panic doesn't leave the
        // test environment in a weird state for parallel tests.
        match prev_path {
            Some(p) => {
                // SAFETY: still serialized via the test_env_lock guard held above.
                unsafe { std::env::set_var("PATH", p) }
            }
            None => {
                // SAFETY: still serialized via the test_env_lock guard held above.
                unsafe { std::env::remove_var("PATH") }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);

        let sbom = result.expect("fake cosign returns valid envelope");
        let parsed: serde_json::Value = serde_json::from_str(&sbom).unwrap();
        assert_eq!(parsed["bomFormat"], "CycloneDX");
    }

    #[cfg(unix)]
    #[test]
    fn fetch_verified_sbom_reports_missing_cosign() {
        let _guard = crate::clock::test_env_lock();

        let prev_path = std::env::var_os("PATH");
        // SAFETY: serialized via test_env_lock above.
        unsafe { std::env::set_var("PATH", "/nonexistent-bomdrift-empty-path-12345") };

        let result = fetch_verified_sbom(
            "example.com/img:tag",
            "https://example.com/.+",
            "https://example.com",
        );

        // SAFETY: still serialized via the test_env_lock guard held above.
        match prev_path {
            Some(p) => {
                // SAFETY: still serialized via the test_env_lock guard held above.
                unsafe { std::env::set_var("PATH", p) }
            }
            None => {
                // SAFETY: still serialized via the test_env_lock guard held above.
                unsafe { std::env::remove_var("PATH") }
            }
        }

        let err = result.expect_err("must surface clear error when cosign is missing");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("cosign") && msg.contains(COSIGN_INSTALL_URL),
            "error must mention cosign + install URL; got: {msg}"
        );
    }
}
