use serde_json::{Value, json};

pub(super) fn rules() -> Value {
    json!([
        rule(
            "bomdrift.cve",
            "cve",
            "Known CVE / advisory affects this component",
            "OSV.dev returned one or more advisory IDs (CVE, GHSA, MAL, etc.) \
             for the component at this version. Per-advisory severity is \
             populated via /v1/vulns/{id} (GHSA `database_specific.severity`); \
             results map Critical/High to SARIF `error`, lower buckets to \
             `warning`. Advisories with no resolvable severity surface as \
             `warning` and don't trip `--fail-on critical-cve`.",
            "https://metbcy.github.io/bomdrift/enrichers/osv-cve.html",
        ),
        rule(
            "bomdrift.typosquat",
            "typosquat",
            "Newly added component name is similar to a popular package",
            "The added component's name is suspiciously close to a popular \
             package in the same ecosystem. High similarity does not prove \
             malicious intent — investigate the package source before merging. \
             Always informational severity (`warning`).",
            "https://metbcy.github.io/bomdrift/enrichers/typosquat.html",
        ),
        rule(
            "bomdrift.version-jump",
            "version-jump",
            "Multi-major version bump detected",
            "The component's major version increased by 2 or more in a single \
             diff (e.g. 1.x to 4.x). Multi-major bumps correlate with \
             takeover swaps and namespace reuse, not just legitimate \
             refactors. Always informational severity (`warning`).",
            "https://metbcy.github.io/bomdrift/enrichers/version-jump.html",
        ),
        rule(
            "bomdrift.young-maintainer",
            "young-maintainer",
            "Top contributor's first commit is recent",
            "The newly added component is hosted on GitHub, GitLab, or \
             Codeberg and its top contributor's first commit is younger than \
             90 days. The xz / Jia Tan supply-chain-takeover pattern. \
             Always informational severity (`warning`).",
            "https://metbcy.github.io/bomdrift/enrichers/maintainer-age.html",
        ),
        rule(
            "bomdrift.license-change",
            "license-change",
            "License changed without a version bump",
            "The component's license set differs between before and after at \
             the SAME version. Could indicate a corrected SBOM, a \
             license-rug-pull, or a supply-chain swap. Worth a human glance \
             regardless. Always informational severity (`warning`).",
            "https://metbcy.github.io/bomdrift/output-formats.html#sarif-v210",
        ),
        rule(
            "bomdrift.license-violation",
            "license-violation",
            "Component license violates configured allow/deny policy",
            "The component's declared license is on the deny list, doesn't \
             appear on the allow list, or is a compound expression that \
             cannot be safely evaluated against the configured policy (with \
             `allow_ambiguous=false`). Configure via the `[license]` block \
             in `.bomdrift.toml` or the `--allow-licenses` / `--deny-licenses` \
             CLI flags. Severity `error` (this is a policy gate, not an \
             advisory heuristic).",
            "https://metbcy.github.io/bomdrift/license-policy.html",
        ),
        rule(
            "bomdrift.recently-published",
            "recently-published",
            "Newly added component was published to its registry recently",
            "The component's most recent registry publish timestamp is \
             younger than the configured threshold (default 14 days). \
             Recent publishes correlate with takeover swaps and \
             namespace-reuse attacks. Always informational severity \
             (`warning`).",
            "https://metbcy.github.io/bomdrift/enrichers/registry.html",
        ),
        rule(
            "bomdrift.deprecated",
            "deprecated",
            "Component is deprecated or yanked upstream",
            "The component's package registry (npm / PyPI / crates.io) \
             marks this version (or the package) as deprecated, yanked, \
             or inactive. Severity `error` because the upstream signal \
             is unambiguous.",
            "https://metbcy.github.io/bomdrift/enrichers/registry.html",
        ),
        rule(
            "bomdrift.maintainer-set-changed",
            "maintainer-set-changed",
            "npm package's maintainer set changed across the version bump",
            "The set of npm maintainers listed for the new version \
             differs from the maintainer set listed for the old \
             version. New maintainers gaining publish rights is a \
             classic takeover-attack precursor (cf. xz / Jia Tan). \
             Severity `warning`.",
            "https://metbcy.github.io/bomdrift/enrichers/registry.html",
        ),
        rule(
            "bomdrift.plugin",
            "plugin",
            "External plugin reported a finding",
            "An external plugin (loaded via --plugin manifest.toml) \
             reported a finding against an added or version-changed \
             component. The plugin name and finding kind are recorded \
             on the result's `properties` for filtering. Severity is \
             plugin-controlled (info → note, warning → warning, error \
             → error). Plugin findings are best-effort — runtime \
             failures (timeout, malformed JSON, non-zero exit) drop \
             findings without failing the diff.",
            "https://metbcy.github.io/bomdrift/plugins.html",
        ),
    ])
}

fn rule(id: &str, name: &str, short: &str, full: &str, help_uri: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "shortDescription": { "text": short },
        "fullDescription":  { "text": full },
        "helpUri": help_uri,
        "defaultConfiguration": { "level": "warning" },
    })
}
