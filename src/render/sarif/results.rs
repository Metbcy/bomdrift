use serde_json::{Value, json};

use crate::diff::ChangeSet;
use crate::enrich::Enrichment;

use super::helpers::{fingerprint, plugin_sarif_level, sarif_level, synthetic_location};

pub(super) fn results(cs: &ChangeSet, e: &Enrichment) -> Value {
    let mut out: Vec<Value> = Vec::new();

    // ---- bomdrift.cve ----
    // Sort vulns by purl key for deterministic output (HashMap iteration is
    // non-deterministic). Inner advisory list is sorted highest-severity
    // first then by id, matching the markdown / term renderers so a SARIF
    // reader and a PR-comment reader see the same priority order.
    let mut vuln_keys: Vec<&String> = e.vulns.keys().collect();
    vuln_keys.sort();
    for purl in vuln_keys {
        let mut advisories: Vec<&crate::enrich::VulnRef> = e.vulns[purl].iter().collect();
        advisories.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
        for advisory in advisories {
            let purl_str: &str = purl;
            let fp = fingerprint(&["bomdrift.cve", purl_str, &advisory.id]);
            let mut props = serde_json::Map::new();
            props.insert("purl".into(), Value::String(purl.clone()));
            props.insert("advisoryId".into(), Value::String(advisory.id.clone()));
            props.insert(
                "severity".into(),
                Value::String(advisory.severity.as_str().into()),
            );
            if let Some(score) = advisory.epss_score {
                props.insert(
                    "epssScore".into(),
                    serde_json::Number::from_f64(score as f64)
                        .map(Value::Number)
                        .unwrap_or(Value::Null),
                );
            }
            if advisory.kev {
                props.insert("kev".into(), Value::Bool(true));
            }
            let vex_key = format!("cve:{purl_str}:{}", advisory.id);
            if let Some(ann) = e.vex_annotations.get(&vex_key) {
                props.insert("vexStatus".into(), Value::String(ann.status.clone()));
                if let Some(j) = &ann.justification {
                    props.insert("vexJustification".into(), Value::String(j.clone()));
                }
            }
            out.push(json!({
                "ruleId": "bomdrift.cve",
                "level": sarif_level(advisory.severity),
                "message": {
                    "text": format!(
                        "{} ({}) affects {purl}. Review the advisory and update \
                         or pin a patched version.",
                        advisory.id,
                        advisory.severity,
                    ),
                },
                "locations": [synthetic_location()],
                "partialFingerprints": { "primaryHash/v1": fp },
                "properties": Value::Object(props),
            }));
        }
    }

    // ---- bomdrift.typosquat ----
    for finding in &e.typosquats {
        let name = &finding.component.name;
        let closest = &finding.closest;
        let purl_or_name = finding.component.purl.as_deref().unwrap_or(name);
        let fp = fingerprint(&["bomdrift.typosquat", purl_or_name, closest]);
        out.push(json!({
            "ruleId": "bomdrift.typosquat",
            "level": "warning",
            "message": {
                "text": format!(
                    "`{name}` is similar to popular package `{closest}` (similarity {:.2}). \
                     Verify the package source before merging.",
                    finding.score,
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":       finding.component.purl,
                "name":       name,
                "version":    finding.component.version,
                "closest":    closest,
                "similarity": finding.score,
            },
        }));
    }

    // ---- bomdrift.version-jump ----
    for finding in &e.version_jumps {
        let name = &finding.after.name;
        let purl_or_name = finding.after.purl.as_deref().unwrap_or(name);
        let fp = fingerprint(&[
            "bomdrift.version-jump",
            purl_or_name,
            &finding.before.version,
            &finding.after.version,
        ]);
        out.push(json!({
            "ruleId": "bomdrift.version-jump",
            "level": "warning",
            "message": {
                "text": format!(
                    "`{name}` jumped from {} to {} (major {} -> {}). Multi-major \
                     bumps deserve extra scrutiny.",
                    finding.before.version,
                    finding.after.version,
                    finding.before_major,
                    finding.after_major,
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":         finding.after.purl,
                "name":         name,
                "beforeVersion": finding.before.version,
                "afterVersion":  finding.after.version,
                "beforeMajor":   finding.before_major,
                "afterMajor":    finding.after_major,
            },
        }));
    }

    // ---- bomdrift.young-maintainer ----
    for finding in &e.maintainer_age {
        let name = &finding.component.name;
        let purl_or_name = finding.component.purl.as_deref().unwrap_or(name);
        let fp = fingerprint(&[
            "bomdrift.young-maintainer",
            purl_or_name,
            &finding.top_contributor,
        ]);
        out.push(json!({
            "ruleId": "bomdrift.young-maintainer",
            "level": "warning",
            "message": {
                "text": format!(
                    "`{name}` top contributor `{}` made their first commit {} day(s) ago \
                     ({}). Investigate maintainer history before merging.",
                    finding.top_contributor,
                    finding.days_old,
                    finding.first_commit_at,
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":           finding.component.purl,
                "name":           name,
                "topContributor": finding.top_contributor,
                "firstCommitAt":  finding.first_commit_at,
                "daysOld":        finding.days_old,
            },
        }));
    }

    // ---- bomdrift.license-change ----
    // license_changed is the suspicious case (license differs at SAME version);
    // version_changed already folds in license-changes-with-version-bumps.
    for (before, after) in &cs.license_changed {
        let name = &after.name;
        let purl_or_name = after.purl.as_deref().unwrap_or(name);
        let mut before_lic = before.licenses.clone();
        before_lic.sort();
        let mut after_lic = after.licenses.clone();
        after_lic.sort();
        let before_join = before_lic.join(",");
        let after_join = after_lic.join(",");
        let fp = fingerprint(&[
            "bomdrift.license-change",
            purl_or_name,
            &before_join,
            &after_join,
        ]);
        out.push(json!({
            "ruleId": "bomdrift.license-change",
            "level": "warning",
            "message": {
                "text": format!(
                    "`{name}` license changed at the same version: {:?} -> {:?}. \
                     Could be a corrected SBOM, a license rug-pull, or a swap.",
                    before.licenses, after.licenses,
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":            after.purl,
                "name":            name,
                "version":         after.version,
                "beforeLicenses":  before.licenses,
                "afterLicenses":   after.licenses,
            },
        }));
    }

    // ---- bomdrift.license-violation ----
    for v in &e.license_violations {
        let name = &v.component.name;
        let purl_or_name = v.component.purl.as_deref().unwrap_or(name);
        let fp = fingerprint(&["bomdrift.license-violation", purl_or_name, &v.license]);
        out.push(json!({
            "ruleId": "bomdrift.license-violation",
            "level": "warning",
            "message": {
                "text": format!(
                    "`{name}` license `{lic}` violates policy ({rule}).",
                    name = name,
                    lic = v.license,
                    rule = v.matched_rule,
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":         v.component.purl,
                "name":         name,
                "version":      v.component.version,
                "license":      v.license,
                "matchedRule":  v.matched_rule,
                "kind":         match v.kind {
                    crate::enrich::LicenseViolationKind::Deny => "deny",
                    crate::enrich::LicenseViolationKind::Ambiguous => "ambiguous",
                    crate::enrich::LicenseViolationKind::NotAllowed => "not-allowed",
                },
            },
        }));
    }

    // ---- bomdrift.recently-published ----
    for f in &e.recently_published {
        let name = &f.component.name;
        let purl_or_name = f.component.purl.as_deref().unwrap_or(name);
        let fp = fingerprint(&["bomdrift.recently-published", purl_or_name, &f.published_at]);
        out.push(json!({
            "ruleId": "bomdrift.recently-published",
            "level": "warning",
            "message": {
                "text": format!(
                    "`{name}` was published {} day(s) ago ({}). Recent publishes correlate with takeover swaps.",
                    f.days_old, f.published_at,
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":         f.component.purl,
                "name":         name,
                "version":      f.component.version,
                "publishedAt":  f.published_at,
                "daysOld":      f.days_old,
            },
        }));
    }

    // ---- bomdrift.deprecated ----
    for f in &e.deprecated {
        let name = &f.component.name;
        let purl_or_name = f.component.purl.as_deref().unwrap_or(name);
        let msg = f.message.as_deref().unwrap_or("(deprecated upstream)");
        let fp = fingerprint(&["bomdrift.deprecated", purl_or_name, msg]);
        out.push(json!({
            "ruleId": "bomdrift.deprecated",
            "level": "error",
            "message": {
                "text": format!("`{name}` is deprecated upstream: {msg}"),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":    f.component.purl,
                "name":    name,
                "version": f.component.version,
                "message": msg,
            },
        }));
    }

    // ---- bomdrift.maintainer-set-changed ----
    for f in &e.maintainer_set_changed {
        let name = &f.after.name;
        let purl_or_name = f.after.purl.as_deref().unwrap_or(name);
        let added = f.added.join(",");
        let removed = f.removed.join(",");
        let fp = fingerprint(&[
            "bomdrift.maintainer-set-changed",
            purl_or_name,
            &added,
            &removed,
        ]);
        out.push(json!({
            "ruleId": "bomdrift.maintainer-set-changed",
            "level": "warning",
            "message": {
                "text": format!(
                    "`{name}` maintainer set changed: +{} / -{}.",
                    if added.is_empty() { "(none)".into() } else { added.clone() },
                    if removed.is_empty() { "(none)".into() } else { removed.clone() },
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":    f.after.purl,
                "name":    name,
                "before":  f.before.version,
                "after":   f.after.version,
                "added":   f.added,
                "removed": f.removed,
            },
        }));
    }

    // ---- bomdrift.plugin ----
    // Plugin findings are pre-ordered by run_plugins() (manifest order
    // outer, cs.added/version_changed inner — both already deterministic
    // since cs.added is BTreeMap-derived and the manifest list is the
    // user's CLI order). Emit verbatim.
    for f in &e.plugin_findings {
        let fp = f.fingerprint();
        out.push(json!({
            "ruleId": "bomdrift.plugin",
            "level": plugin_sarif_level(f.severity),
            "message": {
                "text": format!(
                    "{} ({}): {}",
                    f.plugin_name, f.kind, f.message,
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "pluginName":  f.plugin_name,
                "findingKind": f.kind,
                "ruleId":      f.rule_id,
                "purl":        f.component_purl,
                "severity":    f.severity.as_str(),
            },
        }));
    }

    Value::Array(out)
}
