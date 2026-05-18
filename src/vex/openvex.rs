//! OpenVEX 0.2.0 parser. Public entry point is `parse(&value, &path)`,
//! called from [`super::load`] after `detect_format` selects this format.

use std::path::Path;

use anyhow::Result;

use super::{VexStatement, VexStatus};

pub(super) fn parse(value: &serde_json::Value, path: &Path) -> Result<Vec<VexStatement>> {
    let stmts = value
        .get("statements")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!("OpenVEX doc missing `statements` array: {}", path.display())
        })?;
    let mut out = Vec::with_capacity(stmts.len());
    for s in stmts {
        let vuln_id = s
            .get("vulnerability")
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                // Older OpenVEX drafts allowed `vulnerability` as a bare string.
                s.get("vulnerability").and_then(|v| v.as_str())
            })
            .unwrap_or("")
            .to_string();
        if vuln_id.is_empty() {
            continue;
        }
        let status_raw = s.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let Some(status) = VexStatus::from_openvex(status_raw) else {
            continue;
        };
        let mut products: Vec<String> = Vec::new();
        if let Some(arr) = s.get("products").and_then(|v| v.as_array()) {
            for p in arr {
                if let Some(s) = p.as_str() {
                    products.push(s.to_string());
                } else if let Some(id) = p.get("@id").and_then(|v| v.as_str()) {
                    products.push(id.to_string());
                } else if let Some(id) = p.get("id").and_then(|v| v.as_str()) {
                    products.push(id.to_string());
                }
            }
        }
        let justification = s
            .get("justification")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let status_notes = s
            .get("status_notes")
            .and_then(|v| v.as_str())
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
