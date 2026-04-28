//! End-to-end CLI tests that spawn the actual binary via the path Cargo provides
//! through the `CARGO_BIN_EXE_<name>` env var. These verify the user-visible
//! behavior of `bomdrift diff <before> <after>` rather than internal API shape.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_bomdrift")
}

fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

#[test]
fn diff_axios_fixture_pair_prints_pr_comment_markdown() {
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--no-osv",
        ])
        .output()
        .expect("spawn bomdrift");

    assert!(
        out.status.success(),
        "exit code: {}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    assert!(stdout.starts_with("## SBOM diff\n"));
    assert!(stdout.contains("| Added | 1 |"));
    assert!(stdout.contains("| Removed | 1 |"));
    assert!(stdout.contains("| Version changed | 1 |"));
    assert!(stdout.contains("| npm | plain-crypto-js | 4.2.1 |"));
    assert!(stdout.contains("| npm | axios | 1.14.0 | 1.14.1 |"));
}

#[test]
fn diff_explicit_format_cdx_succeeds_on_cdx_input() {
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--format",
            "cdx",
            "--no-osv",
            "--no-maintainer-age",
        ])
        .output()
        .expect("spawn bomdrift");
    assert!(
        out.status.success(),
        "exit code: {}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn diff_explicit_format_overrides_autodetection() {
    // Auto-detect on CycloneDX inputs produces the documented diff. Forcing
    // `--format spdx` against the same files routes them through the SPDX
    // parser, which finds zero packages in CycloneDX-shaped JSON, yielding
    // "no changes". A different output proves the hint took effect — i.e.
    // the flag is no longer dead code.
    let auto_out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--no-osv",
            "--no-maintainer-age",
        ])
        .output()
        .expect("spawn bomdrift (auto)");

    let forced_out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--format",
            "spdx",
            "--no-osv",
            "--no-maintainer-age",
        ])
        .output()
        .expect("spawn bomdrift (forced spdx)");

    let auto_stdout = String::from_utf8(auto_out.stdout).expect("utf-8");
    let forced_stdout = String::from_utf8(forced_out.stdout).expect("utf-8");

    assert!(
        auto_stdout.contains("plain-crypto-js"),
        "auto-detect should produce the documented diff, got: {auto_stdout}"
    );
    assert!(
        forced_stdout.contains("_No dependency changes._"),
        "forcing --format spdx on CycloneDX inputs should yield no diff, got: {forced_stdout}"
    );
    assert_ne!(
        auto_stdout, forced_stdout,
        "--format must change behavior when it overrides auto-detection"
    );
}

#[test]
fn diff_self_against_self_reports_no_changes() {
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-minimal.json",
            "--no-osv",
        ])
        .output()
        .expect("spawn bomdrift");

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    assert!(stdout.contains("_No dependency changes._"));
}

#[test]
fn diff_explicit_markdown_flag_is_identical_to_default() {
    let default_out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--no-osv",
        ])
        .output()
        .expect("spawn bomdrift");

    let explicit_out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--no-osv",
            "--output",
            "markdown",
        ])
        .output()
        .expect("spawn bomdrift");

    assert_eq!(default_out.stdout, explicit_out.stdout);
}

#[test]
fn diff_missing_file_fails_with_useful_error() {
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/does-not-exist.json",
            "tests/fixtures/cdx-after.json",
        ])
        .output()
        .expect("spawn bomdrift");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("does-not-exist.json"));
    assert!(
        stderr.contains("reading SBOM file") || stderr.contains("No such file"),
        "stderr should mention the failing file or the reason: {stderr}"
    );
}

#[test]
fn diff_json_output_produces_parseable_json() {
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--no-osv",
            "--output",
            "json",
        ])
        .output()
        .expect("spawn bomdrift");

    assert!(
        out.status.success(),
        "exit code: {}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("--output json must produce parseable JSON");

    assert!(
        v.get("changes").is_some(),
        "missing top-level `changes` key"
    );
    assert!(
        v.get("enrichment").is_some(),
        "missing top-level `enrichment` key"
    );

    // The axios-incident fixture pair always produces the plain-crypto-js
    // typosquat finding (pure compute, no network — runs even with --no-osv).
    let typosquats = v["enrichment"]["typosquats"]
        .as_array()
        .expect("enrichment.typosquats must be an array");
    let names: Vec<&str> = typosquats
        .iter()
        .filter_map(|t| t["component"]["name"].as_str())
        .collect();
    assert!(
        names.contains(&"plain-crypto-js"),
        "expected plain-crypto-js in enrichment.typosquats, got names: {names:?}"
    );
}

#[test]
fn refresh_typosquat_help_advertises_ecosystem_flag() {
    // The full subcommand makes a network request and writes to disk, so its
    // happy-path is covered by the in-process `run_with` tests in
    // `src/refresh.rs::tests` (fake fetcher + tempdir cache root). Here we
    // just verify the CLI surface — the subcommand exists, takes
    // `--ecosystem`, and accepts `npm` / `all` — without actually firing
    // either a real fetch or attempting to scribble in the user's `~/.cache`.
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args(["refresh-typosquat", "--help"])
        .output()
        .expect("spawn bomdrift");

    assert!(
        out.status.success(),
        "exit code: {}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--ecosystem"),
        "refresh-typosquat --help must advertise --ecosystem; got:\n{stdout}"
    );
    assert!(
        stdout.contains("npm"),
        "refresh-typosquat --help must list npm as a value; got:\n{stdout}"
    );
}

#[test]
fn diff_sarif_output_produces_valid_sarif_with_typosquat_finding() {
    // End-to-end SARIF: feed the axios fixture pair, verify the output is
    // parseable JSON with the v2.1.0 envelope, and that the load-bearing
    // typosquat finding (`plain-crypto-js` -> `crypto-js`) shows up as a
    // `bomdrift.typosquat` result. `--no-osv` and `--no-maintainer-age` keep
    // the test offline and deterministic.
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--no-osv",
            "--no-maintainer-age",
            "--output",
            "sarif",
        ])
        .output()
        .expect("spawn bomdrift");

    assert!(
        out.status.success(),
        "exit code: {}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("--output sarif must produce parseable JSON");

    assert_eq!(v["version"], "2.1.0");
    assert!(
        v["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-schema-2.1.0.json")
    );
    let driver = &v["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "bomdrift");

    let results = v["runs"][0]["results"].as_array().expect("results array");
    let typosquat_purls: Vec<&str> = results
        .iter()
        .filter(|r| r["ruleId"] == "bomdrift.typosquat")
        .filter_map(|r| r["properties"]["purl"].as_str())
        .collect();
    assert!(
        typosquat_purls
            .iter()
            .any(|p| p.contains("plain-crypto-js")),
        "expected a bomdrift.typosquat result for plain-crypto-js, got: {typosquat_purls:?}"
    );
}

#[test]
fn diff_axios_fixture_pair_renders_typosquat_section() {
    // End-to-end: typosquat enricher always runs (pure compute, no I/O), so
    // even with `--no-osv` the "Possible typosquats" section appears for the
    // axios-incident fixture pair.
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--no-osv",
        ])
        .output()
        .expect("spawn bomdrift");

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    assert!(
        stdout.contains("### Possible typosquats"),
        "expected typosquat section, got:\n{stdout}"
    );
    assert!(stdout.contains("| Possible typosquats | 1 |"));
    assert!(stdout.contains("plain-crypto-js"));
    assert!(stdout.contains("crypto-js"));
    assert!(
        !stdout.contains("is a typosquat"),
        "wording must be 'similar to', never 'is a typosquat'"
    );
}

#[test]
fn diff_fail_on_typosquat_exits_2_but_still_prints_markdown_body() {
    // The axios fixture pair always produces the plain-crypto-js typosquat
    // (pure compute, no network). With --fail-on=typosquat we expect:
    //   1. exit code 2 (the documented "fail-on tripped" code)
    //   2. the full markdown body still on stdout — the action's tee+rc
    //      wrapper relies on this so the PR comment posts even on exit-2.
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--no-osv",
            "--no-maintainer-age",
            "--output",
            "markdown",
            "--fail-on",
            "typosquat",
        ])
        .output()
        .expect("spawn bomdrift");

    assert_eq!(
        out.status.code(),
        Some(2),
        "fail-on=typosquat with a typosquat finding must exit 2; got status: {} stderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    assert!(
        stdout.contains("plain-crypto-js"),
        "exit-2 path must still emit the markdown body for PR-comment posting; got:\n{stdout}"
    );
    assert!(
        stdout.contains("### Possible typosquats"),
        "exit-2 path must still emit the typosquat section; got:\n{stdout}"
    );
}

#[test]
fn diff_fail_on_cve_with_no_findings_exits_0() {
    // Self-diff has no findings of any kind. --fail-on=cve must NOT trip.
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-minimal.json",
            "--no-osv",
            "--no-maintainer-age",
            "--fail-on",
            "cve",
        ])
        .output()
        .expect("spawn bomdrift");

    assert!(
        out.status.success(),
        "self-diff with --fail-on=cve must exit 0; got status: {} stderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn diff_fail_on_critical_cve_with_no_cve_findings_does_not_warn() {
    // critical-cve is treated as cve in v0.2 with a documented stderr warning
    // explaining the limitation. The warning must fire ONLY when the threshold
    // actually trips — pollutting every invocation that uses `critical-cve`
    // would be obnoxious.
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--no-osv",
            "--no-maintainer-age",
            "--fail-on",
            "critical-cve",
        ])
        .output()
        .expect("spawn bomdrift");

    assert!(
        out.status.success(),
        "critical-cve with no CVE findings must NOT trip; got status: {} stderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("critical-cve is treated as"),
        "v0.2 critical-cve warning must only fire on trip, not on every invocation; stderr:\n{stderr}"
    );
}

#[test]
fn diff_terminal_output_in_non_tty_falls_back_to_markdown() {
    // When the binary is invoked under `Command::output()`, stdout is captured
    // (a pipe, not a TTY). The terminal renderer must therefore fall back to
    // plain markdown so PR-comment workflows that pipe `bomdrift` output stay
    // safe regardless of the user's chosen format flag.
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--no-osv",
            "--no-maintainer-age",
            "--output",
            "terminal",
        ])
        .output()
        .expect("spawn bomdrift");

    assert!(
        out.status.success(),
        "exit code: {}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    assert!(
        stdout.starts_with("## SBOM diff"),
        "non-TTY terminal output must fall back to markdown headline; got:\n{stdout}"
    );
    assert!(
        !stdout.contains("\x1b["),
        "non-TTY output must contain no ANSI escapes; got:\n{stdout}"
    );
}

#[test]
fn diff_no_maintainer_age_flag_skips_enricher() {
    // With --no-maintainer-age (and --no-osv to keep the run fully offline),
    // the diff renders successfully and the "Young maintainers" section is
    // absent. This guards against accidentally always-running the GitHub-API
    // enricher in test/CI environments where GITHUB_TOKEN may be unset and
    // the unauth rate limit (60/hr) is shared with other concurrent jobs.
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args([
            "diff",
            "tests/fixtures/cdx-minimal.json",
            "tests/fixtures/cdx-after.json",
            "--no-osv",
            "--no-maintainer-age",
        ])
        .output()
        .expect("spawn bomdrift");

    assert!(
        out.status.success(),
        "exit code: {}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    assert!(
        !stdout.contains("### Young maintainers"),
        "young-maintainers section must not render when --no-maintainer-age is set; got:\n{stdout}"
    );
    assert!(
        !stdout.contains("| Young maintainers |"),
        "young-maintainers summary row must not appear when the enricher is skipped"
    );
}
