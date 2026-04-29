//! GitHub-Flavored Markdown renderer.
//!
//! Output structure:
//! - `## SBOM diff` headline (always present so the comment-tag upsert lands on a
//!   stable selector).
//! - Summary table of counts per change category, plus a "Vulnerabilities" row
//!   when OSV enrichment found any, a "Possible typosquats" row when the
//!   typosquat enricher fires, and a "Multi-major version jumps" row when the
//!   version-jump heuristic fires.
//! - Per-category tables. Sections with zero entries are omitted entirely so the
//!   PR comment stays scannable.
//! - License-changed section is prefaced with an investigation note since same-
//!   version-different-license is the suspicious case.
//! - Vulnerabilities section lists components from `added` + `version_changed`
//!   that have known advisories per OSV.dev, with hyperlinks to osv.dev.
//! - Possible typosquats section lists added components whose name resembles a
//!   popular package. Wording is "is similar to {legit}" — never "is a
//!   typosquat" — to avoid impugning the author of an innocent package.

use std::fmt::Write as _;

use crate::diff::ChangeSet;
use crate::enrich::Enrichment;
use crate::enrich::maintainer::MaintainerAgeFinding;
use crate::enrich::typosquat::TyposquatFinding;
use crate::enrich::version_jump::VersionJumpFinding;
use crate::model::Component;

/// Which forge the rendered markdown is destined for. Drives the action-
/// affordance footer: GitHub uses the v0.5 `/bomdrift suppress` comment-driven
/// flow and `/issues/new?...` URL shape; GitLab uses the project's
/// `/-/issues/new` shape and points reviewers at the manual `bomdrift baseline
/// add` CLI flow because GitLab in-comment suppression is deferred to v0.8.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// GitHub.com or GitHub Enterprise. Default — preserves the v0.5
    /// footer shape for existing consumers.
    #[default]
    GitHub,
    /// GitLab.com or Self-Managed GitLab. The MR-note footer omits the
    /// `/bomdrift suppress` hint and points at `bomdrift baseline add`
    /// instead.
    GitLab,
}

/// Renderer toggles. Defaults match v0.2 behavior so existing callers keep
/// working unchanged.
#[derive(Debug, Default, Clone)]
pub struct Options {
    /// When true, emit only the summary-counts table plus a footer note —
    /// no per-section detail tables. Compresses a several-hundred-finding
    /// diff from "blow past GitHub's 65k comment cap" to a few KB. The
    /// reviewer follows the footer link to the full report (workflow-step
    /// summary, JSON artifact, etc.) when they need detail.
    pub summary_only: bool,
    /// When true, keep the summary table and risk-bearing sections but omit
    /// raw dependency churn detail (Added / Removed / Version changed). This
    /// keeps PR comments focused on review decisions while preserving the
    /// counts that show how large the dependency change is.
    pub findings_only: bool,
    /// Repository URL — `https://github.com/<owner>/<repo>` (or
    /// `https://gitlab.com/<group>/<project>`) form, no trailing slash.
    /// When supplied, the renderer appends a footer linking to a
    /// pre-filled "Report this finding" issue and a suppression hint.
    /// When `None`, the footer is omitted entirely so forks / standalone
    /// CLI use don't render dead links to bomdrift's own issue tracker.
    pub repo_url: Option<String>,
    /// Forge that the rendered markdown is destined for. Defaults to
    /// `GitHub` so existing consumers keep their v0.5 footer shape with
    /// no migration. The CLI flips this to `GitLab` when `--platform
    /// gitlab` is passed or the `GITLAB_CI` environment variable is set.
    pub platform: Platform,
}

pub fn render(cs: &ChangeSet, enrichment: &Enrichment) -> String {
    render_with_options(cs, enrichment, Options::default())
}

pub fn render_with_options(cs: &ChangeSet, enrichment: &Enrichment, opts: Options) -> String {
    let mut out = String::new();
    out.push_str("## SBOM diff\n\n");

    if cs.is_empty() && !enrichment.has_findings() {
        out.push_str("_No dependency changes._\n");
        return out;
    }

    out.push_str("| Change | Count |\n|---|---:|\n");
    let _ = writeln!(out, "| Added | {} |", cs.added.len());
    let _ = writeln!(out, "| Removed | {} |", cs.removed.len());
    let _ = writeln!(out, "| Version changed | {} |", cs.version_changed.len());
    let _ = writeln!(out, "| License changed | {} |", cs.license_changed.len());
    if !enrichment.vulns.is_empty() {
        let _ = writeln!(
            out,
            "| Vulnerabilities | {} |",
            enrichment.vulns.values().map(Vec::len).sum::<usize>()
        );
    }
    if !enrichment.typosquats.is_empty() {
        let _ = writeln!(
            out,
            "| Possible typosquats | {} |",
            enrichment.typosquats.len()
        );
    }
    if !enrichment.version_jumps.is_empty() {
        let _ = writeln!(
            out,
            "| Multi-major version jumps | {} |",
            enrichment.version_jumps.len()
        );
    }
    if !enrichment.maintainer_age.is_empty() {
        let _ = writeln!(
            out,
            "| Young maintainers | {} |",
            enrichment.maintainer_age.len()
        );
    }
    if !enrichment.license_violations.is_empty() {
        let _ = writeln!(
            out,
            "| License violations | {} |",
            enrichment.license_violations.len()
        );
    }
    if enrichment.vex_suppressed_count > 0 {
        let _ = writeln!(
            out,
            "| Suppressed by VEX | {} |",
            enrichment.vex_suppressed_count
        );
    }
    out.push('\n');

    if opts.summary_only {
        out.push_str(
            "_Per-category detail elided (`--summary-only`). The full diff is \
             available as `bomdrift diff <before> <after> --output markdown` \
             without the flag, or as the JSON / SARIF artifact attached to \
             the workflow step summary._\n",
        );
        return out;
    }

    if opts.findings_only
        && (!cs.added.is_empty() || !cs.removed.is_empty() || !cs.version_changed.is_empty())
    {
        out.push_str(
            "_Raw dependency churn detail elided (`--findings-only`); risk-bearing \
             sections remain below._\n\n",
        );
    }

    if !opts.findings_only && !cs.added.is_empty() {
        section_open(&mut out, "Added", cs.added.len(), None);
        out.push_str("| Ecosystem | Name | Version |\n|---|---|---|\n");
        for c in &cs.added {
            let _ = writeln!(out, "| {} | {} | {} |", c.ecosystem, c.name, c.version);
        }
        section_close(&mut out);
    }

    if !opts.findings_only && !cs.removed.is_empty() {
        section_open(&mut out, "Removed", cs.removed.len(), None);
        out.push_str("| Ecosystem | Name | Version |\n|---|---|---|\n");
        for c in &cs.removed {
            let _ = writeln!(out, "| {} | {} | {} |", c.ecosystem, c.name, c.version);
        }
        section_close(&mut out);
    }

    if !opts.findings_only && !cs.version_changed.is_empty() {
        section_open(&mut out, "Version changed", cs.version_changed.len(), None);
        out.push_str("| Ecosystem | Name | Before | After |\n|---|---|---|---|\n");
        for (b, a) in &cs.version_changed {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                a.ecosystem, a.name, b.version, a.version
            );
        }
        section_close(&mut out);
    }

    if !enrichment.license_violations.is_empty() {
        section_open(
            &mut out,
            "License violations",
            enrichment.license_violations.len(),
            None,
        );
        out.push_str(
            "One or more changed components have a license that the configured \
             policy disallows. Review the matched rule and either update the \
             component, exempt it via an explicit baseline entry, or relax the \
             policy. \
             [Why this matters](https://metbcy.github.io/bomdrift/license-policy.html)\n\n",
        );
        out.push_str("| Ecosystem | Name | Version | License | Rule |\n|---|---|---|---|---|\n");
        for v in &enrichment.license_violations {
            let _ = writeln!(
                out,
                "| {} | {} | {} | `{}` | {} |",
                v.component.ecosystem,
                v.component.name,
                v.component.version,
                v.license,
                v.matched_rule,
            );
        }
        section_close(&mut out);
    }

    if !cs.license_changed.is_empty() {
        section_open(
            &mut out,
            "License changed (same version)",
            cs.license_changed.len(),
            None,
        );
        out.push_str(
            "Same version, different licenses — investigate. A re-publish under \
             different terms can indicate a corrected SBOM, a deliberate license \
             change, or a supply-chain swap. Verify the source matches. \
             [Why this matters](https://metbcy.github.io/bomdrift/output-formats.html#sarif-v210)\n\n",
        );
        out.push_str("| Ecosystem | Name | Version | Before | After |\n|---|---|---|---|---|\n");
        for (b, a) in &cs.license_changed {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                a.ecosystem,
                a.name,
                a.version,
                license_cell(&b.licenses),
                license_cell(&a.licenses),
            );
        }
        section_close(&mut out);
    }

    if !enrichment.vulns.is_empty() {
        let count = enrichment.vulns.values().map(Vec::len).sum::<usize>();
        let teaser = vuln_teaser(cs, enrichment);
        section_open(
            &mut out,
            "Vulnerabilities (added/upgraded deps)",
            count,
            teaser.as_deref(),
        );
        out.push_str(
            "Advisories per OSV.dev. Click each ID for details. Severity is the highest \
             of GHSA's `database_specific.severity` for that advisory; advisories that \
             pre-date the GHSA tagging or weren't reachable at lookup time render as \
             `NONE` and don't trip `--fail-on critical-cve`. \
             [Why this matters](https://metbcy.github.io/bomdrift/enrichers/osv-cve.html)\n\n",
        );
        out.push_str("| Ecosystem | Name | Version | Advisories |\n|---|---|---|---|\n");
        // Component-row order: highest max-severity first, then alphabetical
        // by ecosystem+name. Per-component advisories are themselves
        // severity-sorted in `write_one_vuln_row`. The combined ordering
        // means Critical / High findings always cluster at the top of the
        // table — reviewers scanning the comment see the load-bearing rows
        // before the noise.
        for c in vuln_components_sorted(cs, enrichment) {
            write_one_vuln_row(&mut out, c, enrichment);
        }
        section_close(&mut out);
    }

    if !enrichment.typosquats.is_empty() {
        let teaser = typosquat_teaser(enrichment);
        section_open(
            &mut out,
            "Possible typosquats",
            enrichment.typosquats.len(),
            teaser.as_deref(),
        );
        out.push_str(
            "These newly added dependencies have names similar to popular packages. \
             High similarity does not prove malicious intent — investigate the package \
             source before merging. \
             [Why this matters](https://metbcy.github.io/bomdrift/enrichers/typosquat.html)\n\n",
        );
        out.push_str(
            "| Ecosystem | Name | Version | Similar to | Similarity |\n|---|---|---|---|---:|\n",
        );
        for f in &enrichment.typosquats {
            write_typosquat_row(&mut out, f);
        }
        section_close(&mut out);
    }

    if !enrichment.version_jumps.is_empty() {
        section_open(
            &mut out,
            "Multi-major version jumps",
            enrichment.version_jumps.len(),
            None,
        );
        out.push_str(
            "These dependencies crossed two or more major versions in a single diff. \
             Multi-major bumps can hide takeover swaps, namespace reuse, or large \
             refactors that bypass the SemVer signals reviewers usually rely on. \
             Confirm the upgrade is intentional and the source matches. \
             [Why this matters](https://metbcy.github.io/bomdrift/enrichers/version-jump.html)\n\n",
        );
        out.push_str(
            "| Ecosystem | Name | Before | After | Major bump |\n|---|---|---|---|---:|\n",
        );
        for f in &enrichment.version_jumps {
            write_version_jump_row(&mut out, f);
        }
        section_close(&mut out);
    }

    if !enrichment.maintainer_age.is_empty() {
        section_open(
            &mut out,
            "Young maintainers (added deps)",
            enrichment.maintainer_age.len(),
            None,
        );
        out.push_str(
            "The top contributor to each repository below opened their first commit \
             recently. The xz/liblzma backdoor (CVE-2024-3094) was authored by an \
             identity that took over maintainership after a sustained ramp-up; a \
             very-recent top contributor on a newly-introduced dependency is the \
             early signal of that pattern. Investigate the maintainer's history \
             before merging. \
             [Why this matters](https://metbcy.github.io/bomdrift/enrichers/maintainer-age.html)\n\n",
        );
        out.push_str(
            "| Ecosystem | Name | Version | Top contributor | Days since first commit |\n\
             |---|---|---|---|---:|\n",
        );
        for f in &enrichment.maintainer_age {
            write_maintainer_age_row(&mut out, f);
        }
        section_close(&mut out);
    }

    write_footer(&mut out, &opts);

    out
}

/// Open a per-category collapsible section. The `### {label} ({count})`
/// markdown header stays outside the `<details>` block so it remains
/// visible (and TOC-eligible) even when the section is collapsed; the
/// `<details>` wrapper hides the body table by default to keep the comment
/// scannable for big diffs. `teaser` populates the `<summary>` line with
/// the most-actionable item in the section (e.g. `top severity: CRITICAL`)
/// so the reviewer knows whether expanding is worth their time.
fn section_open(out: &mut String, label: &str, count: usize, teaser: Option<&str>) {
    let _ = writeln!(out, "### {} ({})\n", label, count);
    out.push_str("<details><summary>Show details");
    if let Some(t) = teaser {
        let _ = write!(out, " · {}", t);
    }
    // Blank line after `</summary>` is required by GitHub-Flavored Markdown
    // for the markdown body inside `<details>` to render as markdown rather
    // than as raw HTML. Same blank line on close.
    out.push_str("</summary>\n\n");
}

fn section_close(out: &mut String) {
    out.push_str("\n</details>\n\n");
}

/// Renders the comment footer with action affordances. Omitted entirely
/// when `repo_url` is `None` so forks / standalone CLI use don't render
/// dead links to a repo they don't own. Wrapped in `<sub>` so it doesn't
/// compete visually with the section bodies.
///
/// Footer shape branches on [`Options::platform`]. GitHub points reviewers
/// at the v0.5 `/bomdrift suppress <ID>` companion-action flow; GitLab
/// points them at the manual `bomdrift baseline add <ID>` CLI flow because
/// GitLab in-comment suppression is deferred to v0.8 (note webhooks are a
/// different model than GitHub PR comments).
fn write_footer(out: &mut String, opts: &Options) {
    let Some(repo) = opts.repo_url.as_deref() else {
        return;
    };
    let repo = repo.trim_end_matches('/');
    out.push_str("---\n");
    match opts.platform {
        Platform::GitHub => {
            let _ = writeln!(
                out,
                "<sub>**False positive?** [Report it]({repo}/issues/new?labels=false-positive&template=false-positive.md) · \
                 **Suppress a finding?** Comment `/bomdrift suppress <ID>` (requires the \
                 [comment-suppress sub-action]({repo})) · \
                 [Docs](https://metbcy.github.io/bomdrift/)</sub>",
            );
        }
        Platform::GitLab => {
            // GitLab issue creation uses `/-/issues/new` (the `-/` is the
            // namespace separator GitLab inserts between the project URL
            // and the issue tracker route). `issuable_template=` selects a
            // saved description template if the project has one named
            // `false-positive`; projects without that template still get
            // a working "new issue" form.
            let _ = writeln!(
                out,
                "<sub>**False positive?** [Report it]({repo}/-/issues/new?issuable_template=false-positive) · \
                 **Suppress a finding?** Run `bomdrift baseline add <ID>` and commit \
                 `.bomdrift/baseline.json` to your MR branch · \
                 [Docs](https://metbcy.github.io/bomdrift/)</sub>",
            );
        }
    }
}

/// Cross-component vulnerability ordering: components affected by the
/// highest-severity advisory first, ties broken alphabetically by
/// `ecosystem` then `name`. The plan calls this out explicitly: Critical /
/// High findings should cluster at the top of the table for skimmability.
fn vuln_components_sorted<'a>(cs: &'a ChangeSet, enrichment: &Enrichment) -> Vec<&'a Component> {
    let mut comps: Vec<&Component> = Vec::new();
    for c in &cs.added {
        if !enrichment.vulns_for(c.purl.as_deref()).is_empty() {
            comps.push(c);
        }
    }
    for (_, after) in &cs.version_changed {
        if !enrichment.vulns_for(after.purl.as_deref()).is_empty() {
            comps.push(after);
        }
    }
    comps.sort_by(|a, b| {
        let sa = max_severity(enrichment, a);
        let sb = max_severity(enrichment, b);
        sb.cmp(&sa)
            .then_with(|| a.ecosystem.to_string().cmp(&b.ecosystem.to_string()))
            .then_with(|| a.name.cmp(&b.name))
    });
    comps
}

fn max_severity(enrichment: &Enrichment, c: &Component) -> crate::enrich::Severity {
    enrichment
        .vulns_for(c.purl.as_deref())
        .iter()
        .map(|v| v.severity)
        .max()
        .unwrap_or(crate::enrich::Severity::None)
}

fn vuln_teaser(cs: &ChangeSet, enrichment: &Enrichment) -> Option<String> {
    let comps = vuln_components_sorted(cs, enrichment);
    let top = comps.first()?;
    let refs = enrichment.vulns_for(top.purl.as_deref());
    let mut sorted: Vec<&crate::enrich::VulnRef> = refs.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    let head = sorted.first()?;
    Some(format!("top severity: {} ({})", head.severity, head.id))
}

fn typosquat_teaser(enrichment: &Enrichment) -> Option<String> {
    let top = enrichment.typosquats.iter().max_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    })?;
    Some(format!(
        "top similarity: {:.2} ({} → {})",
        top.score, top.component.name, top.closest
    ))
}

fn write_version_jump_row(out: &mut String, f: &VersionJumpFinding) {
    let _ = writeln!(
        out,
        "| {} | {} | {} | {} | {} → {} |",
        f.after.ecosystem,
        f.after.name,
        f.before.version,
        f.after.version,
        f.before_major,
        f.after_major,
    );
}

fn write_maintainer_age_row(out: &mut String, f: &MaintainerAgeFinding) {
    let _ = writeln!(
        out,
        "| {} | {} | {} | {} | {} |",
        f.component.ecosystem, f.component.name, f.component.version, f.top_contributor, f.days_old
    );
}

fn write_typosquat_row(out: &mut String, f: &TyposquatFinding) {
    let _ = writeln!(
        out,
        "| {} | {} | {} | {} | {:.2} |",
        f.component.ecosystem, f.component.name, f.component.version, f.closest, f.score
    );
}

fn write_one_vuln_row(out: &mut String, c: &Component, enrichment: &Enrichment) {
    let refs = enrichment.vulns_for(c.purl.as_deref());
    if refs.is_empty() {
        return;
    }
    // Sort highest-severity-first, then by advisory ID for tie-breaking. Stable
    // ordering matters because the action's PR-comment upsert keys on full-body
    // equality.
    let mut sorted: Vec<&crate::enrich::VulnRef> = refs.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    let advisories = sorted
        .iter()
        .map(|r| {
            let mut s = format!(
                "[{}](https://osv.dev/vulnerability/{}) `{}`",
                r.id, r.id, r.severity
            );
            if let Some(score) = r.epss_score {
                s.push_str(&format!(" · EPSS {score:.2}"));
            }
            if r.kev {
                s.push_str(" · **KEV**");
            }
            let key = format!("cve:{}:{}", c.purl.as_deref().unwrap_or(""), r.id);
            if let Some(ann) = enrichment.vex_annotations.get(&key) {
                s.push_str(&format!(" · VEX:{}", ann.status));
                if let Some(j) = &ann.justification {
                    s.push_str(&format!(" ({j})"));
                }
            }
            s
        })
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(
        out,
        "| {} | {} | {} | {} |",
        c.ecosystem, c.name, c.version, advisories
    );
}

fn license_cell(licenses: &[String]) -> String {
    if licenses.is_empty() {
        "(none)".to_string()
    } else {
        licenses.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, Ecosystem, Relationship};

    fn comp(name: &str, version: &str, eco: Ecosystem, purl: Option<&str>) -> Component {
        Component {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem: eco,
            purl: purl.map(str::to_string),
            licenses: Vec::new(),
            supplier: None,
            hashes: Vec::new(),
            relationship: Relationship::Unknown,
            source_url: None,
            bom_ref: None,
        }
    }

    #[test]
    fn empty_changeset_says_no_changes() {
        let md = render(&ChangeSet::default(), &Enrichment::default());
        assert!(md.starts_with("## SBOM diff\n\n"));
        assert!(md.contains("_No dependency changes._"));
    }

    #[test]
    fn renders_added_section() {
        let cs = ChangeSet {
            added: vec![comp("plain-crypto-js", "4.2.1", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(md.contains("### Added"));
        assert!(md.contains("| npm | plain-crypto-js | 4.2.1 |"));
    }

    #[test]
    fn renders_version_change_table_columns() {
        let before = comp("axios", "1.14.0", Ecosystem::Npm, None);
        let after = comp("axios", "1.14.1", Ecosystem::Npm, None);
        let cs = ChangeSet {
            version_changed: vec![(before, after)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(md.contains("### Version changed"));
        assert!(md.contains("| Ecosystem | Name | Before | After |"));
        assert!(md.contains("| npm | axios | 1.14.0 | 1.14.1 |"));
    }

    #[test]
    fn license_changed_section_includes_investigation_callout() {
        let mut before_c = comp("axios", "1.14.0", Ecosystem::Npm, None);
        before_c.licenses = vec!["MIT".to_string()];
        let mut after_c = comp("axios", "1.14.0", Ecosystem::Npm, None);
        after_c.licenses = vec!["GPL-3.0".to_string()];
        let cs = ChangeSet {
            license_changed: vec![(before_c, after_c)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(md.contains("### License changed (same version)"));
        assert!(md.contains("investigate"));
        assert!(md.contains("supply-chain swap"));
        assert!(md.contains("| npm | axios | 1.14.0 | MIT | GPL-3.0 |"));
    }

    #[test]
    fn empty_sections_are_omitted() {
        let cs = ChangeSet {
            added: vec![comp("foo", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(md.contains("### Added"));
        assert!(!md.contains("### Removed"));
        assert!(!md.contains("### Version changed"));
        assert!(!md.contains("### License changed"));
        assert!(!md.contains("### Vulnerabilities"));
    }

    #[test]
    fn render_is_deterministic() {
        let cs = ChangeSet {
            added: vec![comp("a", "1.0", Ecosystem::Npm, None)],
            removed: vec![comp("b", "1.0", Ecosystem::Cargo, None)],
            ..Default::default()
        };
        let e = Enrichment::default();
        assert_eq!(render(&cs, &e), render(&cs, &e));
    }

    #[test]
    fn empty_license_list_renders_as_none() {
        let mut before_c = comp("foo", "1.0", Ecosystem::Npm, None);
        before_c.licenses = vec![];
        let mut after_c = comp("foo", "1.0", Ecosystem::Npm, None);
        after_c.licenses = vec!["MIT".to_string()];
        let cs = ChangeSet {
            license_changed: vec![(before_c, after_c)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(md.contains("| npm | foo | 1.0 | (none) | MIT |"));
    }

    #[test]
    fn vulnerability_section_renders_with_osv_links() {
        let cs = ChangeSet {
            added: vec![comp(
                "plain-crypto-js",
                "4.2.1",
                Ecosystem::Npm,
                Some("pkg:npm/plain-crypto-js@4.2.1"),
            )],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/plain-crypto-js@4.2.1".to_string(),
            vec![crate::enrich::VulnRef {
                id: "GHSA-xxxx-yyyy-zzzz".to_string(),
                severity: crate::enrich::Severity::Critical,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        let md = render(&cs, &e);
        assert!(md.contains("### Vulnerabilities (added/upgraded deps)"));
        assert!(md.contains("| Vulnerabilities | 1 |"));
        assert!(
            md.contains("[GHSA-xxxx-yyyy-zzzz](https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz)")
        );
        assert!(
            md.contains("`CRITICAL`"),
            "severity badge must render next to advisory id"
        );
    }

    #[test]
    fn vulnerability_section_sorts_advisories_by_severity_then_id() {
        let cs = ChangeSet {
            added: vec![comp(
                "vuln",
                "1.0",
                Ecosystem::Npm,
                Some("pkg:npm/vuln@1.0"),
            )],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/vuln@1.0".to_string(),
            vec![
                crate::enrich::VulnRef {
                    id: "CVE-2025-medium".to_string(),
                    severity: crate::enrich::Severity::Medium,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
                crate::enrich::VulnRef {
                    id: "CVE-2025-critical".to_string(),
                    severity: crate::enrich::Severity::Critical,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
                crate::enrich::VulnRef {
                    id: "CVE-2025-high".to_string(),
                    severity: crate::enrich::Severity::High,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
            ],
        );
        let md = render(&cs, &e);
        // Critical must appear before High; High before Medium.
        let pos_crit = md.find("CVE-2025-critical").unwrap();
        let pos_high = md.find("CVE-2025-high").unwrap();
        let pos_med = md.find("CVE-2025-medium").unwrap();
        assert!(pos_crit < pos_high && pos_high < pos_med);
    }

    #[test]
    fn summary_only_keeps_summary_table_and_drops_detail() {
        let cs = ChangeSet {
            added: vec![comp(
                "axios",
                "1.14.1",
                Ecosystem::Npm,
                Some("pkg:npm/axios@1.14.1"),
            )],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/axios@1.14.1".to_string(),
            vec![crate::enrich::VulnRef {
                id: "GHSA-xxxx-yyyy-zzzz".to_string(),
                severity: crate::enrich::Severity::Critical,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        let summary = render_with_options(
            &cs,
            &e,
            Options {
                summary_only: true,
                ..Default::default()
            },
        );
        // Summary table is preserved (the load-bearing part of the comment).
        assert!(summary.contains("## SBOM diff"));
        assert!(summary.contains("| Added | 1 |"));
        assert!(summary.contains("| Vulnerabilities | 1 |"));
        // Per-section detail tables are dropped.
        assert!(!summary.contains("### Added"));
        assert!(!summary.contains("### Vulnerabilities"));
        assert!(!summary.contains("GHSA-xxxx-yyyy-zzzz"));
        // Footer points the reader at the full output.
        assert!(summary.contains("--summary-only"));
    }

    #[test]
    fn summary_only_does_not_change_no_changes_short_circuit() {
        // Empty changeset still emits the "No dependency changes." line, even
        // with summary_only=true. The footer is *only* meaningful when the
        // diff was big enough to compress.
        let out = render_with_options(
            &ChangeSet::default(),
            &Enrichment::default(),
            Options {
                summary_only: true,
                ..Default::default()
            },
        );
        assert!(out.contains("_No dependency changes._"));
        assert!(!out.contains("Per-category detail elided"));
    }

    #[test]
    fn findings_only_hides_raw_churn_but_keeps_risk_sections() {
        let cs = ChangeSet {
            added: vec![comp(
                "axios",
                "1.14.1",
                Ecosystem::Npm,
                Some("pkg:npm/axios@1.14.1"),
            )],
            version_changed: vec![(
                comp("left-pad", "1.0.0", Ecosystem::Npm, None),
                comp("left-pad", "4.0.0", Ecosystem::Npm, None),
            )],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/axios@1.14.1".to_string(),
            vec![crate::enrich::VulnRef {
                id: "GHSA-xxxx-yyyy-zzzz".to_string(),
                severity: crate::enrich::Severity::High,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );

        let md = render_with_options(
            &cs,
            &e,
            Options {
                findings_only: true,
                ..Default::default()
            },
        );

        assert!(md.contains("| Added | 1 |"));
        assert!(md.contains("| Version changed | 1 |"));
        assert!(md.contains("Raw dependency churn detail elided"));
        assert!(!md.contains("### Added"));
        assert!(!md.contains("### Version changed"));
        assert!(md.contains("### Vulnerabilities"));
        assert!(md.contains("GHSA-xxxx-yyyy-zzzz"));
    }

    #[test]
    fn vulnerability_section_omitted_when_no_findings() {
        let cs = ChangeSet {
            added: vec![comp(
                "safe",
                "1.0",
                Ecosystem::Npm,
                Some("pkg:npm/safe@1.0"),
            )],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(!md.contains("### Vulnerabilities"));
        assert!(!md.contains("| Vulnerabilities |"));
    }

    #[test]
    fn typosquat_section_renders_with_similarity_table() {
        let cs = ChangeSet {
            added: vec![comp(
                "plain-crypto-js",
                "4.2.1",
                Ecosystem::Npm,
                Some("pkg:npm/plain-crypto-js@4.2.1"),
            )],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.typosquats
            .push(crate::enrich::typosquat::TyposquatFinding {
                component: cs.added[0].clone(),
                closest: "crypto-js".to_string(),
                score: 0.95,
            });
        let md = render(&cs, &e);
        assert!(md.contains("### Possible typosquats"));
        assert!(md.contains("| Possible typosquats | 1 |"));
        assert!(md.contains("similar to popular packages"));
        assert!(
            !md.contains("is a typosquat"),
            "must use 'similar to' wording, not 'is a typosquat' (reputational care)"
        );
        assert!(md.contains("| npm | plain-crypto-js | 4.2.1 | crypto-js | 0.95 |"));
    }

    #[test]
    fn typosquat_section_omitted_when_no_findings() {
        let cs = ChangeSet {
            added: vec![comp("safe", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(!md.contains("### Possible typosquats"));
        assert!(!md.contains("| Possible typosquats |"));
    }

    #[test]
    fn typosquat_summary_row_only_when_typosquats_present() {
        // Typosquats present but no vulns: only "Possible typosquats" row,
        // no "Vulnerabilities | 0 |" noise.
        let cs = ChangeSet {
            added: vec![comp("plain-crypto-js", "4.2.1", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.typosquats
            .push(crate::enrich::typosquat::TyposquatFinding {
                component: cs.added[0].clone(),
                closest: "crypto-js".to_string(),
                score: 0.95,
            });
        let md = render(&cs, &e);
        assert!(md.contains("| Possible typosquats | 1 |"));
        assert!(!md.contains("| Vulnerabilities |"));
    }

    #[test]
    fn version_jump_section_renders_with_table() {
        let before = comp("react", "16.14.0", Ecosystem::Npm, None);
        let after = comp("react", "19.0.0", Ecosystem::Npm, None);
        let cs = ChangeSet {
            version_changed: vec![(before.clone(), after.clone())],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.version_jumps
            .push(crate::enrich::version_jump::VersionJumpFinding {
                before,
                after,
                before_major: 16,
                after_major: 19,
            });
        let md = render(&cs, &e);
        assert!(md.contains("### Multi-major version jumps"));
        assert!(md.contains("| Multi-major version jumps | 1 |"));
        assert!(md.contains("| Ecosystem | Name | Before | After | Major bump |"));
        assert!(md.contains("| npm | react | 16.14.0 | 19.0.0 | 16 → 19 |"));
        assert!(md.contains("takeover swaps"));
    }

    #[test]
    fn version_jump_section_omitted_when_no_findings() {
        let cs = ChangeSet {
            added: vec![comp("safe", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(!md.contains("### Multi-major version jumps"));
        assert!(!md.contains("| Multi-major version jumps |"));
    }

    fn maintainer_finding(name: &str, contributor: &str, days: i64) -> MaintainerAgeFinding {
        MaintainerAgeFinding {
            component: comp(name, "1.0.0", Ecosystem::Npm, None),
            top_contributor: contributor.to_string(),
            first_commit_at: "2026-04-01T00:00:00Z".to_string(),
            days_old: days,
        }
    }

    #[test]
    fn maintainer_age_section_renders_with_table_and_xz_callout() {
        let cs = ChangeSet {
            added: vec![comp("liblzma-shim", "5.6.1", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.maintainer_age
            .push(maintainer_finding("liblzma-shim", "jia-tan", 14));
        let md = render(&cs, &e);
        assert!(md.contains("### Young maintainers (added deps)"));
        assert!(md.contains("| Young maintainers | 1 |"));
        assert!(
            md.contains("xz") || md.contains("CVE-2024-3094"),
            "section copy must reference the xz incident as the motivating signal"
        );
        assert!(md.contains(
            "| Ecosystem | Name | Version | Top contributor | Days since first commit |"
        ));
        assert!(md.contains("| npm | liblzma-shim | 1.0.0 | jia-tan | 14 |"));
    }

    #[test]
    fn maintainer_age_section_omitted_when_no_findings() {
        let cs = ChangeSet {
            added: vec![comp("safe", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(!md.contains("### Young maintainers"));
        assert!(!md.contains("| Young maintainers |"));
    }

    // ---- Phase C: collapsible sections, cross-component vuln sort, footer ----

    #[test]
    fn sections_are_wrapped_in_collapsible_details_with_count() {
        // Each populated section gets a `### Header (N)` line followed by
        // a `<details><summary>Show details...</summary>` wrapper. Reviewers
        // see the section name + count without expanding; expand to see the
        // table.
        let cs = ChangeSet {
            added: vec![comp("a", "1.0", Ecosystem::Npm, None)],
            removed: vec![comp("b", "1.0", Ecosystem::Cargo, None)],
            version_changed: vec![(
                comp("c", "1.0", Ecosystem::Npm, None),
                comp("c", "2.0", Ecosystem::Npm, None),
            )],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(md.contains("### Added (1)\n"));
        assert!(md.contains("### Removed (1)\n"));
        assert!(md.contains("### Version changed (1)\n"));
        // Each opens a details block
        let details_count = md.matches("<details>").count();
        let summary_count = md.matches("</summary>").count();
        let close_count = md.matches("</details>").count();
        assert_eq!(details_count, 3);
        assert_eq!(summary_count, 3);
        assert_eq!(close_count, 3);
        // Show details prefix appears in every summary line
        assert!(md.contains("<details><summary>Show details"));
    }

    #[test]
    fn vuln_section_summary_includes_top_severity_teaser() {
        // The summary line must include the top severity + advisory ID so
        // a reviewer skimming the collapsed comment knows whether to expand.
        let cs = ChangeSet {
            added: vec![
                comp(
                    "low-risk",
                    "1.0",
                    Ecosystem::Npm,
                    Some("pkg:npm/low-risk@1.0"),
                ),
                comp("hot", "1.0", Ecosystem::Npm, Some("pkg:npm/hot@1.0")),
            ],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/low-risk@1.0".into(),
            vec![crate::enrich::VulnRef {
                id: "GHSA-medium".into(),
                severity: crate::enrich::Severity::Medium,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        e.vulns.insert(
            "pkg:npm/hot@1.0".into(),
            vec![crate::enrich::VulnRef {
                id: "CVE-2025-critical".into(),
                severity: crate::enrich::Severity::Critical,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        let md = render(&cs, &e);
        // Summary teaser cites the highest-severity advisory, not just any.
        assert!(
            md.contains("top severity: CRITICAL (CVE-2025-critical)"),
            "summary line missing severity teaser; got:\n{md}"
        );
    }

    #[test]
    fn vuln_rows_sorted_by_max_severity_across_components() {
        // `low-risk` is alphabetically first but only has Medium; `hot` has
        // Critical. The Critical row must appear before the Medium row in
        // the Vulnerabilities table — even though they appear in the
        // opposite order in the Added section above it. Scope the search
        // to the Vulnerabilities section to isolate the assertion.
        let cs = ChangeSet {
            added: vec![
                comp(
                    "low-risk",
                    "1.0",
                    Ecosystem::Npm,
                    Some("pkg:npm/low-risk@1.0"),
                ),
                comp("hot", "1.0", Ecosystem::Npm, Some("pkg:npm/hot@1.0")),
            ],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/low-risk@1.0".into(),
            vec![crate::enrich::VulnRef {
                id: "GHSA-medium".into(),
                severity: crate::enrich::Severity::Medium,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        e.vulns.insert(
            "pkg:npm/hot@1.0".into(),
            vec![crate::enrich::VulnRef {
                id: "CVE-2025-critical".into(),
                severity: crate::enrich::Severity::Critical,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        let md = render(&cs, &e);
        let vuln_start = md
            .find("### Vulnerabilities")
            .expect("vulnerabilities section present");
        let vuln_section = &md[vuln_start..];
        let pos_hot = vuln_section
            .find("| npm | hot |")
            .expect("hot row present in vulns table");
        let pos_low = vuln_section
            .find("| npm | low-risk |")
            .expect("low-risk row present in vulns table");
        assert!(
            pos_hot < pos_low,
            "Critical-severity component must render before Medium-severity component within the Vulnerabilities table"
        );
    }

    #[test]
    fn typosquat_section_summary_includes_top_similarity_teaser() {
        let cs = ChangeSet {
            added: vec![
                comp("plain-crypto-js", "4.2.1", Ecosystem::Npm, None),
                comp("axiosx", "1.0.0", Ecosystem::Npm, None),
            ],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.typosquats
            .push(crate::enrich::typosquat::TyposquatFinding {
                component: cs.added[0].clone(),
                closest: "crypto-js".to_string(),
                score: 0.95,
            });
        e.typosquats
            .push(crate::enrich::typosquat::TyposquatFinding {
                component: cs.added[1].clone(),
                closest: "axios".to_string(),
                score: 0.85,
            });
        let md = render(&cs, &e);
        // Top score (0.95) wins — that's the actionable finding to surface
        // in the collapsed summary line.
        assert!(
            md.contains("top similarity: 0.95 (plain-crypto-js → crypto-js)"),
            "typosquat summary missing teaser; got:\n{md}"
        );
    }

    #[test]
    fn footer_omitted_when_repo_url_unset() {
        let cs = ChangeSet {
            added: vec![comp("a", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(!md.contains("False positive?"));
        assert!(!md.contains("/issues/new"));
    }

    #[test]
    fn footer_renders_when_repo_url_supplied() {
        let cs = ChangeSet {
            added: vec![comp("a", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render_with_options(
            &cs,
            &Enrichment::default(),
            Options {
                repo_url: Some("https://github.com/example/proj".to_string()),
                ..Default::default()
            },
        );
        assert!(md.contains("False positive?"));
        assert!(md.contains("https://github.com/example/proj/issues/new"));
        assert!(md.contains("/bomdrift suppress"));
        assert!(md.contains("https://metbcy.github.io/bomdrift/"));
    }

    #[test]
    fn footer_strips_trailing_slash_from_repo_url() {
        // Forks and fork-of-forks may pass a URL with a trailing slash;
        // produce the same `/issues/new` suffix regardless.
        let cs = ChangeSet {
            added: vec![comp("a", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render_with_options(
            &cs,
            &Enrichment::default(),
            Options {
                repo_url: Some("https://github.com/example/proj/".to_string()),
                ..Default::default()
            },
        );
        assert!(md.contains("https://github.com/example/proj/issues/new"));
        assert!(!md.contains("proj//issues"));
    }

    #[test]
    fn footer_renders_gitlab_shape_when_platform_is_gitlab() {
        // Platform::GitLab swaps two things: the issue-creation URL uses
        // GitLab's `/-/issues/new?issuable_template=...` shape, and the
        // suppression hint points at `bomdrift baseline add` instead of
        // the `/bomdrift suppress` comment-driven flow (deferred to v0.8
        // for GitLab).
        let cs = ChangeSet {
            added: vec![comp("a", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render_with_options(
            &cs,
            &Enrichment::default(),
            Options {
                repo_url: Some("https://gitlab.com/group/project".to_string()),
                platform: Platform::GitLab,
                ..Default::default()
            },
        );
        assert!(md.contains("False positive?"));
        assert!(
            md.contains("https://gitlab.com/group/project/-/issues/new"),
            "expected GitLab `/-/issues/new` URL shape; got:\n{md}"
        );
        assert!(
            md.contains("bomdrift baseline add"),
            "expected GitLab footer to point at `bomdrift baseline add`; got:\n{md}"
        );
        assert!(
            !md.contains("/bomdrift suppress"),
            "GitLab footer must NOT mention the GitHub-only `/bomdrift suppress` comment flow; got:\n{md}"
        );
        assert!(md.contains("https://metbcy.github.io/bomdrift/"));
    }

    #[test]
    fn footer_default_platform_preserves_github_shape() {
        // Backward-compat guarantee: callers that don't set `platform`
        // explicitly (i.e. v0.5 / v0.6 consumers compiled against the
        // pre-v0.7 Options struct after migration) get the GitHub footer
        // they had before. `Platform::default()` is GitHub.
        assert_eq!(Platform::default(), Platform::GitHub);
        let cs = ChangeSet {
            added: vec![comp("a", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render_with_options(
            &cs,
            &Enrichment::default(),
            Options {
                repo_url: Some("https://github.com/example/proj".to_string()),
                ..Default::default()
            },
        );
        assert!(md.contains("/issues/new?labels=false-positive"));
        assert!(md.contains("/bomdrift suppress"));
    }

    #[test]
    fn why_this_matters_link_appears_in_each_finding_section() {
        let cs = ChangeSet {
            added: vec![comp(
                "vuln",
                "1.0",
                Ecosystem::Npm,
                Some("pkg:npm/vuln@1.0"),
            )],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/vuln@1.0".into(),
            vec![crate::enrich::VulnRef {
                id: "GHSA-x".into(),
                severity: crate::enrich::Severity::High,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        e.typosquats
            .push(crate::enrich::typosquat::TyposquatFinding {
                component: cs.added[0].clone(),
                closest: "vulnx".to_string(),
                score: 0.9,
            });
        let md = render(&cs, &e);
        // SARIF helpUri reuse — the same docs URL should appear in markdown
        // so reviewers can click through to the per-rule explanation.
        assert!(md.contains("https://metbcy.github.io/bomdrift/enrichers/osv-cve.html"));
        assert!(md.contains("https://metbcy.github.io/bomdrift/enrichers/typosquat.html"));
    }
}
