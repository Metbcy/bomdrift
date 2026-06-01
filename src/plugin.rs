//! External-process plugin loader (Phase C, v0.9.6).
//!
//! Plugins are external executables that bomdrift shells out to, one
//! invocation per (component, event) pair, with JSON over stdin/stdout.
//! Manifest is TOML, the executable is whatever language the plugin
//! author wants — bomdrift makes no language commitment.
//!
//! ## Protocol (v1)
//!
//! bomdrift writes one JSON object to the plugin's stdin then closes
//! stdin:
//!
//! ```json
//! {
//!   "component": { ...component JSON... },
//!   "event": "added" | "version-changed",
//!   "before": null | { ...component JSON... }
//! }
//! ```
//!
//! Plugin writes one JSON object to stdout and exits 0:
//!
//! ```json
//! {
//!   "findings": [
//!     {
//!       "kind": "string-tag",
//!       "message": "...",
//!       "severity": "info" | "warning" | "error",
//!       "rule_id": "..."
//!     }
//!   ]
//! }
//! ```
//!
//! ## Best-effort failures
//!
//! Non-zero exit, malformed JSON, or timeout → plugin findings dropped
//! and a warning emitted to stderr at `BOMDRIFT_DEBUG=1`. The diff
//! still renders. This matches the contract used by every other v0.9
//! enricher (OSV / EPSS / KEV / Registry).
//!
//! Timeouts are enforced via the `wait-timeout` crate (v0.9.7+), which
//! provides a proper platform-aware wait primitive — a real
//! `WaitForSingleObject` on Windows and a self-pipe / sigchld setup
//! on Unix. The earlier 25ms `try_wait()` polling loop is gone; this
//! makes Windows plugin timeouts first-class instead of best-effort.
//!
//! ## Stability
//!
//! The wire shape above is `v1` and may evolve. We expose
//! `protocol_version: 1` on the wire so future bomdrift releases can
//! detect old plugins and stay backward-compatible. Today, plugins
//! that ignore the field continue to work unchanged.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wait_timeout::ChildExt;

use crate::diff::ChangeSet;
use crate::model::Component;

const PROTOCOL_VERSION: u32 = 1;
const DEFAULT_TIMEOUT_MS: u64 = 5000;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InvokeEvent {
    Added,
    VersionChanged,
}

impl InvokeEvent {
    fn as_wire(&self) -> &'static str {
        match self {
            InvokeEvent::Added => "added",
            InvokeEvent::VersionChanged => "version-changed",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestFile {
    plugin: PluginSection,
}

#[derive(Debug, Clone, Deserialize)]
struct PluginSection {
    name: String,
    #[serde(default)]
    description: Option<String>,
    exec: PathBuf,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_invoke_on")]
    invoke_on: Vec<InvokeEvent>,
}

fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}
fn default_invoke_on() -> Vec<InvokeEvent> {
    vec![InvokeEvent::Added, InvokeEvent::VersionChanged]
}

#[derive(Debug, Clone, PartialEq)]
pub struct PluginManifest {
    pub name: String,
    pub description: Option<String>,
    /// Resolved absolute path to the plugin executable. Relative paths
    /// in the manifest are resolved against the manifest's parent dir
    /// at load time so subsequent invocations don't depend on cwd.
    pub exec: PathBuf,
    pub timeout_ms: u64,
    pub invoke_on: Vec<InvokeEvent>,
    /// Path the manifest was loaded from. Useful in stderr diagnostics.
    pub manifest_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginSeverity {
    Info,
    Warning,
    Error,
}

impl PluginSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            PluginSeverity::Info => "info",
            PluginSeverity::Warning => "warning",
            PluginSeverity::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PluginFinding {
    pub plugin_name: String,
    pub component_purl: String,
    pub kind: String,
    pub message: String,
    pub severity: PluginSeverity,
    pub rule_id: String,
}

impl PluginFinding {
    /// Stable per-finding identity hash for SARIF `partialFingerprints`.
    /// Distinct per `(plugin_name, component_purl, rule_id)` so two
    /// plugins emitting the same `rule_id` don't collide, and the same
    /// plugin emitting the same `rule_id` against two purls produces
    /// two distinct fingerprints.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"bomdrift.plugin|");
        h.update(self.plugin_name.as_bytes());
        h.update(b"|");
        h.update(self.component_purl.as_bytes());
        h.update(b"|");
        h.update(self.rule_id.as_bytes());
        let digest = h.finalize();
        let mut out = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

/// Wire-format input written to plugin stdin.
#[derive(Debug, Serialize)]
struct PluginInput<'a> {
    protocol_version: u32,
    component: &'a Component,
    event: &'a str,
    before: Option<&'a Component>,
}

/// Wire-format output read from plugin stdout.
#[derive(Debug, Deserialize)]
struct PluginOutput {
    findings: Vec<RawFinding>,
}

#[derive(Debug, Deserialize)]
struct RawFinding {
    kind: String,
    message: String,
    severity: PluginSeverity,
    rule_id: String,
}

/// Load + validate a plugin manifest from `path`. Resolves relative
/// `exec` paths against the manifest's parent directory.
pub fn load_manifest(path: &Path) -> Result<PluginManifest> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading plugin manifest: {}", path.display()))?;
    let parsed: ManifestFile = toml::from_str(&raw)
        .with_context(|| format!("parsing plugin manifest TOML: {}", path.display()))?;

    let exec = if parsed.plugin.exec.is_absolute() {
        parsed.plugin.exec
    } else if let Some(parent) = path.parent() {
        parent.join(&parsed.plugin.exec)
    } else {
        parsed.plugin.exec
    };

    if parsed.plugin.timeout_ms == 0 {
        anyhow::bail!("plugin manifest {}: timeout_ms must be > 0", path.display());
    }

    Ok(PluginManifest {
        name: parsed.plugin.name,
        description: parsed.plugin.description,
        exec,
        timeout_ms: parsed.plugin.timeout_ms,
        invoke_on: parsed.plugin.invoke_on,
        manifest_path: path.to_path_buf(),
    })
}

/// Run every plugin against the relevant components in `cs` and return
/// the merged finding list. Best-effort: a plugin that errors is logged
/// to stderr at `BOMDRIFT_DEBUG=1` and contributes no findings.
pub fn run_plugins(manifests: &[PluginManifest], cs: &ChangeSet) -> Vec<PluginFinding> {
    let mut out = Vec::new();
    for manifest in manifests {
        if manifest.invoke_on.contains(&InvokeEvent::Added) {
            for component in &cs.added {
                run_one(manifest, component, InvokeEvent::Added, None, &mut out);
            }
        }
        if manifest.invoke_on.contains(&InvokeEvent::VersionChanged) {
            for (before, after) in &cs.version_changed {
                run_one(
                    manifest,
                    after,
                    InvokeEvent::VersionChanged,
                    Some(before),
                    &mut out,
                );
            }
        }
    }
    out
}

fn run_one(
    manifest: &PluginManifest,
    component: &Component,
    event: InvokeEvent,
    before: Option<&Component>,
    out: &mut Vec<PluginFinding>,
) {
    let purl = component
        .purl
        .clone()
        .unwrap_or_else(|| component.name.clone());

    match invoke_blocking(manifest, component, event, before) {
        Ok(findings) => {
            for f in findings {
                out.push(PluginFinding {
                    plugin_name: manifest.name.clone(),
                    component_purl: purl.clone(),
                    kind: f.kind,
                    message: f.message,
                    severity: f.severity,
                    rule_id: f.rule_id,
                });
            }
        }
        Err(err) => {
            if std::env::var("BOMDRIFT_DEBUG").is_ok() {
                eprintln!("plugin {} on {}: {err:#}", manifest.name, purl);
            }
        }
    }
}

fn invoke_blocking(
    manifest: &PluginManifest,
    component: &Component,
    event: InvokeEvent,
    before: Option<&Component>,
) -> Result<Vec<RawFinding>> {
    use std::io::Write;

    let input = PluginInput {
        protocol_version: PROTOCOL_VERSION,
        component,
        event: event.as_wire(),
        before,
    };
    let stdin_bytes = serde_json::to_vec(&input).context("serializing plugin stdin payload")?;

    let mut child = Command::new(&manifest.exec)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning plugin executable: {}", manifest.exec.display()))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&stdin_bytes)
            .context("writing plugin stdin")?;
        // Drop stdin to send EOF.
    }

    let timeout = Duration::from_millis(manifest.timeout_ms);
    // `wait_timeout` returns `Some(status)` if the child exits within
    // the budget, or `None` on timeout. The crate handles platform
    // differences (a real WaitForSingleObject on Windows; a
    // self-pipe + sigchld setup on Unix) which the previous
    // try_wait()-polling loop only approximated.
    let status = match child.wait_timeout(timeout).context("waiting for plugin")? {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("plugin timed out after {}ms", manifest.timeout_ms);
        }
    };

    let mut stdout = String::new();
    if let Some(mut s) = child.stdout.take() {
        use std::io::Read;
        let _ = s.read_to_string(&mut stdout);
    }
    if !status.success() {
        let mut stderr = String::new();
        if let Some(mut s) = child.stderr.take() {
            use std::io::Read;
            let _ = s.read_to_string(&mut stderr);
        }
        anyhow::bail!("plugin exited {status}; stderr: {}", stderr.trim());
    }
    let parsed: PluginOutput = serde_json::from_str(stdout.trim())
        .with_context(|| format!("parsing plugin stdout as JSON (got {} bytes)", stdout.len()))?;
    Ok(parsed.findings)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )]
    use super::*;
    #[cfg(unix)]
    use crate::model::{Ecosystem, Relationship};

    fn write_manifest(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("plugin.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    fn unique_dir(stem: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "bomdrift-plugin-test-{stem}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[cfg(unix)]
    fn comp(name: &str) -> Component {
        Component {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            purl: Some(format!("pkg:npm/{name}@1.0.0")),
            licenses: Vec::new(),
            supplier: None,
            hashes: Vec::new(),
            relationship: Relationship::Unknown,
            source_url: None,
            bom_ref: None,
        }
    }

    #[cfg(unix)]
    fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[test]
    fn manifest_parses_minimum_valid_toml() {
        let dir = unique_dir("min-manifest");
        let path = write_manifest(
            &dir,
            r#"
[plugin]
name = "demo"
exec = "./run.sh"
"#,
        );
        let m = load_manifest(&path).expect("parses");
        assert_eq!(m.name, "demo");
        assert_eq!(m.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(
            m.invoke_on,
            vec![InvokeEvent::Added, InvokeEvent::VersionChanged]
        );
        assert!(m.exec.is_absolute(), "relative exec must resolve");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_parses_full_toml() {
        // Use a platform-appropriate absolute path so this test runs
        // identically on Unix and Windows. The semantic under test is
        // "absolute path in TOML is preserved as-is, not joined to
        // manifest dir."
        #[cfg(unix)]
        let abs_exec = "/abs/path/to/check";
        #[cfg(windows)]
        let abs_exec = "C:\\\\abs\\\\path\\\\to\\\\check";
        let dir = unique_dir("full-manifest");
        let path = write_manifest(
            &dir,
            &format!(
                r#"
[plugin]
name = "banned-packages"
description = "Flag dependencies on org-banned packages"
exec = "{abs_exec}"
timeout_ms = 10000
invoke_on = ["added"]
"#
            ),
        );
        let m = load_manifest(&path).expect("parses");
        assert_eq!(m.name, "banned-packages");
        assert_eq!(
            m.description.as_deref(),
            Some("Flag dependencies on org-banned packages")
        );
        assert_eq!(m.timeout_ms, 10000);
        assert_eq!(m.invoke_on, vec![InvokeEvent::Added]);
        #[cfg(unix)]
        assert_eq!(m.exec, PathBuf::from("/abs/path/to/check"));
        #[cfg(windows)]
        assert_eq!(m.exec, PathBuf::from("C:\\abs\\path\\to\\check"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_missing_exec_field_errors() {
        let dir = unique_dir("missing-exec");
        let path = write_manifest(
            &dir,
            r#"
[plugin]
name = "broken"
"#,
        );
        let err = load_manifest(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("exec"), "error must mention exec; got: {msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_unknown_invoke_on_value_errors() {
        let dir = unique_dir("bad-event");
        let path = write_manifest(
            &dir,
            r#"
[plugin]
name = "broken"
exec = "./x"
invoke_on = ["removed"]
"#,
        );
        let err = load_manifest(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("removed") || msg.contains("invoke_on") || msg.contains("variant"),
            "error must surface the bad enum value; got: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn plugin_stdin_envelope_includes_protocol_version_1() {
        // Regression guard: docs/src/plugins.md and the module preamble
        // both promise plugins see `protocol_version: 1` on the wire so
        // future bomdrift releases can detect old plugins. We have the
        // constant (`PROTOCOL_VERSION`) and we serialize it into
        // `PluginInput`, but nothing previously asserted it actually
        // reaches the plugin's stdin. This test captures real stdin to a
        // sibling file and greps it.
        let dir = unique_dir("envelope");
        std::fs::create_dir_all(&dir).unwrap();
        let stdin_capture = dir.join("stdin.json");
        let script_body = format!(
            "#!/bin/sh\ncat > {capture}\necho '{{\"findings\":[]}}'\n",
            capture = stdin_capture.display(),
        );
        let exec = write_script(&dir, "capture.sh", &script_body);
        let manifest = PluginManifest {
            name: "envelope".into(),
            description: None,
            exec,
            timeout_ms: 5000,
            invoke_on: vec![InvokeEvent::Added],
            manifest_path: dir.clone(),
        };
        let cs = ChangeSet {
            added: vec![comp("left-pad")],
            ..Default::default()
        };
        let _ = run_plugins(std::slice::from_ref(&manifest), &cs);

        let captured = std::fs::read_to_string(&stdin_capture)
            .expect("plugin script should have captured stdin to the sibling file");
        let parsed: serde_json::Value =
            serde_json::from_str(&captured).expect("plugin stdin must be a JSON object");
        assert_eq!(
            parsed.get("protocol_version").and_then(|v| v.as_u64()),
            Some(1),
            "plugin stdin must carry `protocol_version: 1`; got envelope:\n{captured}"
        );
        // The constant and the wire value must agree — if anyone bumps
        // PROTOCOL_VERSION they have to update the docs + this test
        // together.
        assert_eq!(
            parsed.get("protocol_version").and_then(|v| v.as_u64()),
            Some(u64::from(PROTOCOL_VERSION)),
            "wire `protocol_version` must equal the PROTOCOL_VERSION constant"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn plugin_invocation_returns_findings() {
        let dir = unique_dir("happy");
        let exec = write_script(
            &dir,
            "ok.sh",
            "#!/bin/sh\ncat > /dev/null\ncat <<'EOF'\n{\"findings\":[{\"kind\":\"banned\",\"message\":\"left-pad is banned\",\"severity\":\"warning\",\"rule_id\":\"banned/left-pad\"}]}\nEOF\n",
        );
        let manifest = PluginManifest {
            name: "demo".into(),
            description: None,
            exec,
            timeout_ms: 5000,
            invoke_on: vec![InvokeEvent::Added],
            manifest_path: dir.clone(),
        };
        let cs = ChangeSet {
            added: vec![comp("left-pad")],
            ..Default::default()
        };
        let findings = run_plugins(std::slice::from_ref(&manifest), &cs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin_name, "demo");
        assert_eq!(findings[0].kind, "banned");
        assert_eq!(findings[0].rule_id, "banned/left-pad");
        assert_eq!(findings[0].severity, PluginSeverity::Warning);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn plugin_timeout_drops_findings() {
        let dir = unique_dir("timeout");
        let exec = write_script(&dir, "slow.sh", "#!/bin/sh\nsleep 10\n");
        let manifest = PluginManifest {
            name: "slow".into(),
            description: None,
            exec,
            timeout_ms: 100,
            invoke_on: vec![InvokeEvent::Added],
            manifest_path: dir.clone(),
        };
        let cs = ChangeSet {
            added: vec![comp("foo")],
            ..Default::default()
        };
        let started = std::time::Instant::now();
        let findings = run_plugins(std::slice::from_ref(&manifest), &cs);
        let elapsed = started.elapsed();
        assert!(findings.is_empty());
        assert!(
            elapsed < Duration::from_secs(3),
            "timeout must fire well before sleep 10 completes; elapsed={elapsed:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn plugin_nonzero_exit_drops_findings() {
        let dir = unique_dir("nonzero");
        let exec = write_script(&dir, "fail.sh", "#!/bin/sh\nexit 1\n");
        let manifest = PluginManifest {
            name: "fail".into(),
            description: None,
            exec,
            timeout_ms: 5000,
            invoke_on: vec![InvokeEvent::Added],
            manifest_path: dir.clone(),
        };
        let cs = ChangeSet {
            added: vec![comp("foo")],
            ..Default::default()
        };
        let findings = run_plugins(std::slice::from_ref(&manifest), &cs);
        assert!(findings.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn plugin_malformed_json_drops_findings() {
        let dir = unique_dir("badjson");
        let exec = write_script(
            &dir,
            "bad.sh",
            "#!/bin/sh\ncat > /dev/null\necho 'not json'\n",
        );
        let manifest = PluginManifest {
            name: "bad".into(),
            description: None,
            exec,
            timeout_ms: 5000,
            invoke_on: vec![InvokeEvent::Added],
            manifest_path: dir.clone(),
        };
        let cs = ChangeSet {
            added: vec![comp("foo")],
            ..Default::default()
        };
        let findings = run_plugins(std::slice::from_ref(&manifest), &cs);
        assert!(findings.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn two_plugins_findings_are_merged() {
        let dir = unique_dir("two");
        let exec_a = write_script(
            &dir,
            "a.sh",
            "#!/bin/sh\ncat > /dev/null\necho '{\"findings\":[{\"kind\":\"k1\",\"message\":\"a\",\"severity\":\"info\",\"rule_id\":\"a-1\"}]}'\n",
        );
        let exec_b = write_script(
            &dir,
            "b.sh",
            "#!/bin/sh\ncat > /dev/null\necho '{\"findings\":[{\"kind\":\"k2\",\"message\":\"b\",\"severity\":\"error\",\"rule_id\":\"b-1\"}]}'\n",
        );
        let m_a = PluginManifest {
            name: "a".into(),
            description: None,
            exec: exec_a,
            timeout_ms: 5000,
            invoke_on: vec![InvokeEvent::Added],
            manifest_path: dir.clone(),
        };
        let m_b = PluginManifest {
            name: "b".into(),
            description: None,
            exec: exec_b,
            timeout_ms: 5000,
            invoke_on: vec![InvokeEvent::Added],
            manifest_path: dir.clone(),
        };
        let cs = ChangeSet {
            added: vec![comp("foo")],
            ..Default::default()
        };
        let findings = run_plugins(&[m_a, m_b], &cs);
        assert_eq!(findings.len(), 2);
        let names: Vec<&str> = findings.iter().map(|f| f.plugin_name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        let mk = |plugin: &str, purl: &str, rule: &str| PluginFinding {
            plugin_name: plugin.into(),
            component_purl: purl.into(),
            kind: "k".into(),
            message: "m".into(),
            severity: PluginSeverity::Info,
            rule_id: rule.into(),
        };
        let a = mk("p1", "pkg:npm/x", "r1").fingerprint();
        let a2 = mk("p1", "pkg:npm/x", "r1").fingerprint();
        let b = mk("p2", "pkg:npm/x", "r1").fingerprint();
        let c = mk("p1", "pkg:npm/y", "r1").fingerprint();
        let d = mk("p1", "pkg:npm/x", "r2").fingerprint();
        assert_eq!(a, a2, "byte-stable for the same identity");
        assert_ne!(a, b, "distinct per plugin_name");
        assert_ne!(a, c, "distinct per purl");
        assert_ne!(a, d, "distinct per rule_id");
    }
}
