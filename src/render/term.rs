//! Terminal renderer with TTY-aware ANSI color.
//!
//! Output is a tree-style summary using bracketed prefix tokens
//! (`[ADD]`, `[REM]`, `[VER]`, `[CVE]`, `[SQT]`) — no emojis, per project
//! convention. Colors are applied via `owo-colors` and gated through
//! `supports-color`, which automatically respects the `NO_COLOR` and
//! `CLICOLOR_FORCE` environment variables.
//!
//! The actual TTY check (so that piped output stays plain) lives in
//! [`mod@crate::run`]; this module assumes the caller has already decided
//! that ANSI is appropriate. Color emission is still further gated by
//! `if_supports_color(Stdout, ...)` so even if invoked directly, output
//! degrades gracefully when stdout cannot render escapes.
//!
//! Sections with zero entries are omitted, mirroring the markdown renderer.
//! When the changeset is empty and no enrichment findings are present,
//! a single neutral line "No dependency changes." is emitted.
//!
//! # Test-time color control
//!
//! `cargo test` runs with stdout redirected, so `if_supports_color` skips
//! styling. To exercise the colored path deterministically, the public
//! [`render_with_color`] entrypoint accepts a [`ColorChoice`] override.
//! Production callers use [`render`], which delegates to
//! `render_with_color(.., ColorChoice::Auto)`.

use std::fmt::Write as _;

use owo_colors::{OwoColorize, Stream, Style};

use crate::diff::ChangeSet;
use crate::enrich::Enrichment;
use crate::enrich::typosquat::TyposquatFinding;
use crate::model::Component;

/// Whether the terminal renderer should emit ANSI escape sequences.
///
/// `Auto` defers to `owo-colors`' `if_supports_color(Stdout, ..)`, which in
/// turn consults `supports-color` (honoring `NO_COLOR` / `CLICOLOR_FORCE`).
/// `Always` and `Never` are unconditional and exist primarily for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

pub fn render(cs: &ChangeSet, enrichment: &Enrichment) -> String {
    render_with_color(cs, enrichment, ColorChoice::Auto)
}

pub fn render_with_color(cs: &ChangeSet, enrichment: &Enrichment, color: ColorChoice) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "bomdrift v{}", env!("CARGO_PKG_VERSION"));
    out.push('\n');

    if cs.is_empty() && !enrichment.has_findings() {
        out.push_str("No dependency changes.\n");
        return out;
    }

    let total_changes =
        cs.added.len() + cs.removed.len() + cs.version_changed.len() + cs.license_changed.len();

    if total_changes > 0 {
        let _ = writeln!(out, "Changes ({total_changes}):");
        for c in &cs.added {
            let _ = writeln!(
                out,
                "  {} {}:{}@{}",
                tag("[ADD]", Tone::High, color),
                c.ecosystem,
                c.name,
                c.version
            );
        }
        for c in &cs.removed {
            let _ = writeln!(
                out,
                "  {} {}:{}@{}",
                tag("[REM]", Tone::Caution, color),
                c.ecosystem,
                c.name,
                c.version
            );
        }
        for (b, a) in &cs.version_changed {
            let _ = writeln!(
                out,
                "  {} {}:{} {} -> {}",
                tag("[VER]", Tone::Info, color),
                a.ecosystem,
                a.name,
                b.version,
                a.version
            );
        }
        for (b, a) in &cs.license_changed {
            let _ = writeln!(
                out,
                "  {} {}:{}@{} {} -> {}",
                tag("[LIC]", Tone::Info, color),
                a.ecosystem,
                a.name,
                a.version,
                license_cell(&b.licenses),
                license_cell(&a.licenses)
            );
        }
        out.push('\n');
    }

    let vuln_components: Vec<&Component> = cs
        .added
        .iter()
        .chain(cs.version_changed.iter().map(|(_, a)| a))
        .filter(|c| !enrichment.vulns_for(c.purl.as_deref()).is_empty())
        .collect();

    if !vuln_components.is_empty() {
        let total_vulns: usize = vuln_components
            .iter()
            .map(|c| enrichment.vulns_for(c.purl.as_deref()).len())
            .sum();
        let _ = writeln!(out, "Vulnerabilities ({total_vulns}):");
        for c in &vuln_components {
            let refs = enrichment.vulns_for(c.purl.as_deref());
            // Sort highest-severity-first, ties broken by id, so the on-screen
            // line reads worst → less-bad and the rendered output is
            // byte-deterministic across runs.
            let mut sorted: Vec<&crate::enrich::VulnRef> = refs.iter().collect();
            sorted.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
            let advisories = sorted
                .iter()
                .map(|r| {
                    let mut s = format!("{} ({})", r.id, r.severity);
                    if let Some(score) = r.epss_score {
                        s.push_str(&format!(" EPSS {score:.2}"));
                    }
                    if r.kev {
                        s.push_str(" KEV");
                    }
                    s
                })
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                out,
                "  {} {}:{}@{} - {}",
                tag("[CVE]", Tone::High, color),
                c.ecosystem,
                c.name,
                c.version,
                advisories
            );
        }
        out.push('\n');
    }

    if !enrichment.typosquats.is_empty() {
        let _ = writeln!(
            out,
            "Possible typosquats ({}):",
            enrichment.typosquats.len()
        );
        for f in &enrichment.typosquats {
            write_typosquat_line(&mut out, f, color);
        }
        out.push('\n');
    }

    if !enrichment.license_violations.is_empty() {
        let _ = writeln!(
            out,
            "License violations ({}):",
            enrichment.license_violations.len()
        );
        for v in &enrichment.license_violations {
            let _ = writeln!(
                out,
                "  {} {}:{}@{} - {} [{}]",
                tag("[LIC]", Tone::High, color),
                v.component.ecosystem,
                v.component.name,
                v.component.version,
                v.license,
                v.matched_rule,
            );
        }
        out.push('\n');
    }

    if !enrichment.plugin_findings.is_empty() {
        let _ = writeln!(
            out,
            "Plugin findings ({}):",
            enrichment.plugin_findings.len()
        );
        for f in &enrichment.plugin_findings {
            let (token, tone) = match f.severity {
                crate::plugin::PluginSeverity::Info => ("[PLG]", Tone::Info),
                crate::plugin::PluginSeverity::Warning => ("[PLG]", Tone::Caution),
                crate::plugin::PluginSeverity::Error => ("[PLG]", Tone::High),
            };
            let _ = writeln!(
                out,
                "  {} {} :: {} :: {} - {} ({})",
                tag(token, tone, color),
                f.plugin_name,
                f.component_purl,
                f.kind,
                f.message,
                f.rule_id,
            );
        }
        out.push('\n');
    }

    out
}

fn write_typosquat_line(out: &mut String, f: &TyposquatFinding, color: ColorChoice) {
    let _ = writeln!(
        out,
        "  {} {}:{}@{} ~ {} ({:.2})",
        tag("[SQT]", Tone::Caution, color),
        f.component.ecosystem,
        f.component.name,
        f.component.version,
        f.closest,
        f.score
    );
}

fn license_cell(licenses: &[String]) -> String {
    if licenses.is_empty() {
        "(none)".to_string()
    } else {
        licenses.join(", ")
    }
}

#[derive(Clone, Copy)]
enum Tone {
    /// Red + bold. Used for additions and CVEs (high-attention signals).
    High,
    /// Yellow. Used for removals and typosquat warnings (caution signals).
    Caution,
    /// Cyan. Used for version/license changes (neutral informational signals).
    Info,
}

fn tag(token: &'static str, tone: Tone, choice: ColorChoice) -> String {
    match choice {
        ColorChoice::Never => token.to_string(),
        ColorChoice::Always => format!("{}", token.style(style_for(tone))),
        ColorChoice::Auto => {
            let style = style_for(tone);
            format!(
                "{}",
                token.if_supports_color(Stream::Stdout, move |t| t.style(style))
            )
        }
    }
}

fn style_for(tone: Tone) -> Style {
    match tone {
        Tone::High => Style::new().red().bold(),
        Tone::Caution => Style::new().yellow(),
        Tone::Info => Style::new().cyan(),
    }
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
        let out = render(&ChangeSet::default(), &Enrichment::default());
        assert!(
            out.contains("No dependency changes."),
            "expected 'No dependency changes.' in:\n{out}"
        );
    }

    #[test]
    fn renders_added_section() {
        let cs = ChangeSet {
            added: vec![comp("plain-crypto-js", "4.2.1", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let out = render_with_color(&cs, &Enrichment::default(), ColorChoice::Never);
        assert!(out.contains("Changes (1):"));
        assert!(out.contains("[ADD]"));
        assert!(out.contains("npm:plain-crypto-js@4.2.1"));
    }

    #[test]
    fn renders_removed_version_typosquat_lines() {
        let added = comp("plain-crypto-js", "4.2.1", Ecosystem::Npm, None);
        let cs = ChangeSet {
            added: vec![added.clone()],
            removed: vec![comp(
                "no-purl-component",
                "0.1.0",
                Ecosystem::Other("library".to_string()),
                None,
            )],
            version_changed: vec![(
                comp("axios", "1.14.0", Ecosystem::Npm, None),
                comp("axios", "1.14.1", Ecosystem::Npm, None),
            )],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.typosquats.push(TyposquatFinding {
            component: added,
            closest: "crypto-js".to_string(),
            score: 0.95,
        });

        let out = render_with_color(&cs, &e, ColorChoice::Never);

        assert!(out.contains("[ADD]"), "missing [ADD] in:\n{out}");
        assert!(out.contains("[REM]"), "missing [REM] in:\n{out}");
        assert!(out.contains("library:no-purl-component@0.1.0"));
        assert!(out.contains("[VER]"), "missing [VER] in:\n{out}");
        assert!(out.contains("npm:axios 1.14.0 -> 1.14.1"));
        assert!(out.contains("[SQT]"), "missing [SQT] in:\n{out}");
        assert!(out.contains("~ crypto-js (0.95)"));
    }

    #[test]
    fn vulnerability_lines_render_advisory_ids() {
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
                id: "MAL-2026-2306".to_string(),
                severity: crate::enrich::Severity::Critical,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );

        let out = render_with_color(&cs, &e, ColorChoice::Never);
        assert!(out.contains("Vulnerabilities (1):"));
        assert!(out.contains("[CVE]"));
        assert!(out.contains("MAL-2026-2306"));
        assert!(out.contains("(CRITICAL)"));
        assert!(out.contains("npm:plain-crypto-js@4.2.1"));
    }

    #[test]
    fn empty_sections_are_omitted() {
        let cs = ChangeSet {
            added: vec![comp("foo", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let out = render_with_color(&cs, &Enrichment::default(), ColorChoice::Never);
        assert!(out.contains("Changes (1):"));
        assert!(!out.contains("Vulnerabilities ("));
        assert!(!out.contains("Possible typosquats ("));
    }

    #[test]
    fn render_is_deterministic() {
        let cs = ChangeSet {
            added: vec![comp("a", "1.0", Ecosystem::Npm, None)],
            removed: vec![comp("b", "1.0", Ecosystem::Cargo, None)],
            ..Default::default()
        };
        let e = Enrichment::default();
        let a = render_with_color(&cs, &e, ColorChoice::Never);
        let b = render_with_color(&cs, &e, ColorChoice::Never);
        assert_eq!(a, b);
        let c = render_with_color(&cs, &e, ColorChoice::Always);
        let d = render_with_color(&cs, &e, ColorChoice::Always);
        assert_eq!(c, d);
    }

    #[test]
    fn forced_color_emits_ansi_escapes() {
        let cs = ChangeSet {
            added: vec![comp("plain-crypto-js", "4.2.1", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let with_color = render_with_color(&cs, &Enrichment::default(), ColorChoice::Always);
        assert!(
            with_color.contains("\x1b["),
            "ColorChoice::Always must emit ANSI escapes; got:\n{with_color}"
        );
    }

    #[test]
    fn color_off_emits_no_ansi_escapes() {
        let cs = ChangeSet {
            added: vec![comp("plain-crypto-js", "4.2.1", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let plain = render_with_color(&cs, &Enrichment::default(), ColorChoice::Never);
        assert!(
            !plain.contains("\x1b["),
            "ColorChoice::Never must not emit ANSI escapes; got:\n{plain}"
        );
    }

    #[test]
    fn empty_changeset_under_forced_color_has_no_escapes_on_neutral_line() {
        // The "No dependency changes." line is intentionally unstyled. Verify that
        // even with color forced ON, no escape leaks onto it.
        let out = render_with_color(
            &ChangeSet::default(),
            &Enrichment::default(),
            ColorChoice::Always,
        );
        assert!(out.contains("No dependency changes."));
        assert!(
            !out.contains("\x1b["),
            "neutral 'no changes' output must stay plain even when color forced; got:\n{out}"
        );
    }
}
