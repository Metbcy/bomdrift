use std::fmt::Write;

use crate::diff::ChangeSet;
use crate::enrich::Enrichment;
use crate::model::Component;

const CSS: &str = r#"
:root {
    --bg: #1a1b26;
    --bg-surface: #24283b;
    --bg-hover: #292e42;
    --text: #c0caf5;
    --text-muted: #565f89;
    --accent: #7aa2f7;
    --green: #9ece6a;
    --red: #f7768e;
    --yellow: #e0af68;
    --orange: #ff9e64;
    --purple: #bb9af7;
    --cyan: #7dcfff;
    --border: #3b4261;
    --radius: 8px;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    padding: 2rem;
    line-height: 1.6;
}
h1 { color: var(--accent); margin-bottom: 1.5rem; font-size: 1.8rem; }
h2 { color: var(--accent); font-size: 1.2rem; }
table {
    width: 100%; border-collapse: collapse; margin: 0.5rem 0;
    background: var(--bg-surface); border-radius: var(--radius);
    overflow: hidden;
}
th { background: var(--bg-hover); color: var(--accent); text-align: left; padding: 0.6rem 1rem; font-size: 0.85rem; }
td { padding: 0.5rem 1rem; border-top: 1px solid var(--border); font-size: 0.85rem; }
tr:hover td { background: var(--bg-hover); }
details {
    background: var(--bg-surface); border: 1px solid var(--border);
    border-radius: var(--radius); margin-bottom: 1rem; overflow: hidden;
}
summary {
    padding: 0.8rem 1rem; cursor: pointer; font-weight: 600;
    user-select: none; display: flex; align-items: center; gap: 0.5rem;
}
summary:hover { background: var(--bg-hover); }
summary::marker { color: var(--accent); }
.badge {
    display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
    font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
}
.badge-critical { background: var(--red); color: var(--bg); }
.badge-high { background: var(--orange); color: var(--bg); }
.badge-medium { background: var(--yellow); color: var(--bg); }
.badge-low { background: var(--cyan); color: var(--bg); }
.badge-green { background: var(--green); color: var(--bg); }
.badge-red { background: var(--red); color: var(--bg); }
.badge-purple { background: var(--purple); color: var(--bg); }
.badge-count {
    background: var(--border); color: var(--text); padding: 0.1rem 0.45rem;
    border-radius: 10px; font-size: 0.75rem; margin-left: auto;
}
.summary-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem; margin-bottom: 1.5rem;
}
.stat-card {
    background: var(--bg-surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 1rem; text-align: center;
}
.stat-card .value { font-size: 2rem; font-weight: 700; color: var(--accent); }
.stat-card .label { font-size: 0.8rem; color: var(--text-muted); }
.content { padding: 0 1rem 1rem; }
"#;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn severity_badge(sev: &impl std::fmt::Display) -> String {
    let s = sev.to_string();
    let cls = match s.to_lowercase().as_str() {
        "critical" => "badge-critical",
        "high" => "badge-high",
        "medium" => "badge-medium",
        "low" => "badge-low",
        _ => "badge-purple",
    };
    format!(r#"<span class="badge {}">{}</span>"#, cls, esc(&s))
}

fn comp_row(c: &Component) -> String {
    format!(
        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
        esc(&c.name), esc(&c.version), esc(&c.ecosystem.to_string())
    )
}

fn section<F: FnOnce(&mut String)>(out: &mut String, title: &str, count: usize, badge_cls: &str, body: F) {
    if count == 0 { return; }
    let _ = write!(out,
        r#"<details><summary><h2>{}</h2> <span class="badge {}">{} item{}</span></summary><div class="content">"#,
        esc(title), badge_cls, count, if count == 1 { "" } else { "s" }
    );
    body(out);
    out.push_str("</div></details>");
}

pub fn render(cs: &ChangeSet, enrichment: &Enrichment) -> String {
    let mut out = String::with_capacity(16384);

    let _ = write!(out, r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BOMdrift Report</title><style>{CSS}</style></head><body>"#);
    out.push_str("<h1>📦 BOMdrift — SBOM Diff Report</h1>");

    // Summary cards
    let total_vulns: usize = enrichment.vulns.values().map(|v| v.len()).sum();
    out.push_str(r#"<div class="summary-grid">"#);
    for (label, value, color) in [
        ("Added", cs.added.len(), "var(--green)"),
        ("Removed", cs.removed.len(), "var(--red)"),
        ("Version Changed", cs.version_changed.len(), "var(--yellow)"),
        ("License Changed", cs.license_changed.len(), "var(--orange)"),
        ("Vulnerabilities", total_vulns, "var(--red)"),
        ("Typosquats", enrichment.typosquats.len(), "var(--purple)"),
        ("VEX Suppressed", enrichment.vex_suppressed_count, "var(--cyan)"),
    ] {
        if value > 0 {
            let _ = write!(out,
                r#"<div class="stat-card"><div class="value" style="color:{color}">{value}</div><div class="label">{label}</div></div>"#
            );
        }
    }
    out.push_str("</div>");

    // Added
    section(&mut out, "Added Components", cs.added.len(), "badge-green", |o| {
        o.push_str("<table><tr><th>Name</th><th>Version</th><th>Ecosystem</th></tr>");
        for c in &cs.added { o.push_str(&comp_row(c)); }
        o.push_str("</table>");
    });

    // Removed
    section(&mut out, "Removed Components", cs.removed.len(), "badge-red", |o| {
        o.push_str("<table><tr><th>Name</th><th>Version</th><th>Ecosystem</th></tr>");
        for c in &cs.removed { o.push_str(&comp_row(c)); }
        o.push_str("</table>");
    });

    // Version Changed
    section(&mut out, "Version Changed", cs.version_changed.len(), "badge-purple", |o| {
        o.push_str("<table><tr><th>Name</th><th>Old Version</th><th>New Version</th><th>Ecosystem</th></tr>");
        for (old, new) in &cs.version_changed {
            let _ = write!(o, "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&old.name), esc(&old.version), esc(&new.version), esc(&old.ecosystem.to_string()));
        }
        o.push_str("</table>");
    });

    // License Changed
    section(&mut out, "License Changed", cs.license_changed.len(), "badge-purple", |o| {
        o.push_str("<table><tr><th>Name</th><th>Old License</th><th>New License</th></tr>");
        for (old, new) in &cs.license_changed {
            let _ = write!(o, "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&old.name), esc(&old.licenses.join(", ")), esc(&new.licenses.join(", ")));
        }
        o.push_str("</table>");
    });

    // Vulnerabilities
    section(&mut out, "Vulnerabilities", total_vulns, "badge-critical", |o| {
        o.push_str("<table><tr><th>Component</th><th>ID</th><th>Severity</th><th>Aliases</th></tr>");
        for (pkg, advisories) in &enrichment.vulns {
            for adv in advisories {
                let _ = write!(o, "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(pkg), esc(&adv.id), severity_badge(&adv.severity),
                    esc(&adv.aliases.join(", ")));
            }
        }
        o.push_str("</table>");
    });

    // Typosquats
    section(&mut out, "Typosquat Candidates", enrichment.typosquats.len(), "badge-critical", |o| {
        o.push_str("<table><tr><th>Component</th><th>Similar To</th><th>Score</th></tr>");
        for t in &enrichment.typosquats {
            let _ = write!(o, "<tr><td>{}</td><td>{}</td><td>{:.2}</td></tr>",
                esc(&t.component.name), esc(&t.closest), t.score);
        }
        o.push_str("</table>");
    });

    // Version Jumps
    section(&mut out, "Version Jumps", enrichment.version_jumps.len(), "badge-high", |o| {
        o.push_str("<table><tr><th>Name</th><th>Old</th><th>New</th><th>Old Major</th><th>New Major</th></tr>");
        for v in &enrichment.version_jumps {
            let _ = write!(o, "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&v.before.name), esc(&v.before.version), esc(&v.after.version), v.before_major, v.after_major);
        }
        o.push_str("</table>");
    });

    // Maintainer Age
    section(&mut out, "Maintainer Age Warnings", enrichment.maintainer_age.len(), "badge-high", |o| {
        o.push_str("<table><tr><th>Component</th><th>Top Contributor</th><th>Days Old</th><th>First Commit</th></tr>");
        for m in &enrichment.maintainer_age {
            let _ = write!(o, "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&m.component.name), esc(&m.top_contributor), m.days_old, esc(&m.first_commit_at));
        }
        o.push_str("</table>");
    });

    // License Violations
    section(&mut out, "License Violations", enrichment.license_violations.len(), "badge-red", |o| {
        o.push_str("<table><tr><th>Component</th><th>License</th><th>Matched Rule</th><th>Kind</th></tr>");
        for lv in &enrichment.license_violations {
            let _ = write!(o, "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:?}</td></tr>",
                esc(&lv.component.name), esc(&lv.license), esc(&lv.matched_rule), lv.kind);
        }
        o.push_str("</table>");
    });

    // Recently Published
    section(&mut out, "Recently Published", enrichment.recently_published.len(), "badge-high", |o| {
        o.push_str("<table><tr><th>Component</th><th>Version</th><th>Published</th><th>Days Old</th></tr>");
        for r in &enrichment.recently_published {
            let _ = write!(o, "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&r.component.name), esc(&r.component.version), esc(&r.published_at), r.days_old);
        }
        o.push_str("</table>");
    });

    // Deprecated
    section(&mut out, "Deprecated Packages", enrichment.deprecated.len(), "badge-red", |o| {
        o.push_str("<table><tr><th>Component</th><th>Version</th><th>Message</th></tr>");
        for r in &enrichment.deprecated {
            let _ = write!(o, "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&r.component.name), esc(&r.component.version),
                esc(r.message.as_deref().unwrap_or("")));
        }
        o.push_str("</table>");
    });

    // Maintainer Set Changed
    section(&mut out, "Maintainer Set Changed", enrichment.maintainer_set_changed.len(), "badge-high", |o| {
        o.push_str("<table><tr><th>Package</th><th>Old Version</th><th>New Version</th><th>Added</th><th>Removed</th></tr>");
        for r in &enrichment.maintainer_set_changed {
            let _ = write!(o, "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&r.before.name), esc(&r.before.version), esc(&r.after.version),
                esc(&r.added.join(", ")), esc(&r.removed.join(", ")));
        }
        o.push_str("</table>");
    });

    // Plugin Findings
    section(&mut out, "Plugin Findings", enrichment.plugin_findings.len(), "badge-purple", |o| {
        o.push_str("<table><tr><th>Plugin</th><th>Component PURL</th><th>Severity</th><th>Message</th></tr>");
        for p in &enrichment.plugin_findings {
            let _ = write!(o, "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&p.plugin_name), esc(&p.component_purl), severity_badge(&format!("{:?}", p.severity)), esc(&p.message));
        }
        o.push_str("</table>");
    });

    // VEX Suppressed
    if enrichment.vex_suppressed_count > 0 {
        let _ = write!(out,
            r#"<details><summary><h2>VEX Suppressed</h2> <span class="badge badge-green">{} suppressed</span></summary><div class="content"><p>{} vulnerabilities were suppressed by VEX annotations.</p></div></details>"#,
            enrichment.vex_suppressed_count, enrichment.vex_suppressed_count
        );
    }

    out.push_str("</body></html>");
    out
}
