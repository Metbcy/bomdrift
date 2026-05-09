use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::enrich::Enrichment;
use crate::plugin::{PluginFinding, PluginSeverity};
use crate::render::markdown::section;

pub fn render(enrichment: &Enrichment) -> String {
    if enrichment.plugin_findings.is_empty() {
        return String::new();
    }

    // Group findings by plugin_name so each plugin gets its own subsection.
    // BTreeMap keeps output stable for byte-identical PR comment upserts.
    let mut by_plugin: BTreeMap<&str, Vec<&PluginFinding>> = BTreeMap::new();
    for f in &enrichment.plugin_findings {
        by_plugin.entry(f.plugin_name.as_str()).or_default().push(f);
    }

    let mut out = String::new();
    let total = enrichment.plugin_findings.len();
    section::open(&mut out, "Plugin findings", total, None);
    out.push_str(
        "External plugins reported the following findings against added \
         or version-changed components. Plugin findings are best-effort \
         — runtime failures (timeout, malformed JSON, non-zero exit) \
         drop findings without failing the diff.\n\n",
    );
    for (name, findings) in &by_plugin {
        let _ = writeln!(out, "**{name}** ({})\n", findings.len());
        for f in findings {
            let prefix = match f.severity {
                PluginSeverity::Info => "ℹ️ info",
                PluginSeverity::Warning => "⚠️ warning",
                PluginSeverity::Error => "❌ error",
            };
            let _ = writeln!(
                out,
                "- {prefix} · `{}` · {} — {} (`{}`)",
                f.component_purl, f.kind, f.message, f.rule_id,
            );
        }
        out.push('\n');
    }
    section::close(&mut out);

    out
}
