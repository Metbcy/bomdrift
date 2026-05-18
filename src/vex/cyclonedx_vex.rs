//! CycloneDX VEX 1.6 parser. Public entry point is `parse(&value, &path)`,
//! called from [`super::load`] after `detect_format` selects this format.

use std::path::Path;

use anyhow::Result;

use super::{VexStatement, VexStatus};

pub(super) fn parse(value: &serde_json::Value, path: &Path) -> Result<Vec<VexStatement>> {
    let vulns = value
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "CycloneDX VEX missing `vulnerabilities` array: {}",
                path.display()
            )
        })?;
    let mut out = Vec::with_capacity(vulns.len());
    for v in vulns {
        let vuln_id = v
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if vuln_id.is_empty() {
            continue;
        }
        let analysis = v.get("analysis");
        let state = analysis
            .and_then(|a| a.get("state"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let Some(status) = VexStatus::from_cyclonedx_state(state) else {
            continue;
        };
        let mut products: Vec<String> = Vec::new();
        if let Some(arr) = v.get("affects").and_then(|v| v.as_array()) {
            for a in arr {
                if let Some(r) = a.get("ref").and_then(|x| x.as_str()) {
                    products.push(r.to_string());
                }
            }
        }
        let justification = analysis
            .and_then(|a| a.get("justification"))
            .and_then(|x| x.as_str())
            .map(str::to_string);
        let status_notes = analysis
            .and_then(|a| a.get("detail"))
            .and_then(|x| x.as_str())
            .map(str::to_string);
        out.push(VexStatement {
            vuln_id,
            products,
            status,
            justification,
            status_notes,
        });
    }
    Ok(out)
}
