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
fn diff_json_output_returns_not_implemented_error() {
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

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("json is not implemented"));
}

#[test]
fn refresh_typosquat_returns_not_implemented_error() {
    let out = Command::new(bin())
        .current_dir(manifest_dir())
        .args(["refresh-typosquat"])
        .output()
        .expect("spawn bomdrift");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refresh-typosquat"));
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
fn diff_no_maintainer_age_flag_skips_enricher() {
    // With --no-maintainer-age (and --no-osv to keep the run fully offline),
    // the diff renders successfully and the "Young maintainers" section is
    // absent. This guards against accidentally always-running the GitHub-API
    // enricher in test/CI environments where GITHUB_TOKEN may be unset and
    // the unauth rate limit (60/hr) is shared with other concurrent jobs.
    let out = std::process::Command::new(bin())
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
