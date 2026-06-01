//! SARIF v2.1.0 renderer (`--output sarif`).
//!
//! Produces a single-run SARIF document suitable for ingestion by GitHub Code
//! Scanning, GitLab Vulnerability Reports, and any other consumer that speaks
//! SARIF. The schema is hand-built via `serde_json::json!` — pulling a `sarif`
//! crate would add ~30 transitive dependencies for what amounts to ~50 lines
//! of object construction.
//!
//! ## Stable rule IDs (NEVER rename)
//!
//! These IDs surface in GitHub Code Scanning's UI and are the join key for
//! suppressions, so they're load-bearing public API once a finding has been
//! seen by any consumer:
//!
//! - `bomdrift.cve` — one result per `(component, advisory_id)` from
//!   `enrichment.vulns`.
//! - `bomdrift.typosquat` — one per `enrichment.typosquats` finding.
//! - `bomdrift.version-jump` — one per `enrichment.version_jumps` finding.
//! - `bomdrift.young-maintainer` — one per `enrichment.maintainer_age` finding.
//! - `bomdrift.license-change` — one per `cs.license_changed` pair (license
//!   changed without a version bump — the suspicious case).
//!
//! All five rules are always emitted in `tool.driver.rules`, even when the
//! current diff has zero findings of that kind. Code Scanning consumers
//! enumerate the rules independently of the results, so omitting unused
//! rules confuses suppression UIs.
//!
//! ## Severity
//!
//! `bomdrift.cve` results map their per-advisory severity to SARIF `level`:
//! `Critical` and `High` → `"error"`, everything else (including `None`,
//! used when /v1/vulns/{id} couldn't resolve a label) → `"warning"`. The
//! heuristic-enricher rules (typosquat, version-jump, maintainer-age,
//! license-change) stay at `"warning"` — they're intentionally informational.
//!
//! ## Locations
//!
//! SARIF requires `locations` on every `result`. We emit a synthetic
//! `physicalLocation.artifactLocation.uri = "sbom"`, matching the convention
//! used by `trivy` for SBOM-derived findings (no source line numbers exist —
//! the SBOM itself is the artifact).
//!
//! ## Determinism
//!
//! Renderer determinism is the upsert contract for PR comment workflows.
//! `Enrichment::vulns` is a `HashMap` (iteration order non-deterministic), so
//! its entries are sorted by purl key before emission. The other finding
//! collections are already `Vec`s ordered by their enrichers (which iterate
//! the `ChangeSet`'s BTreeMap-derived order), so they need no extra sorting.
//! The render-twice-byte-equal regression test below guards this.

mod document;
mod helpers;
mod results;
mod rules;

#[cfg(test)]
mod tests;

pub use document::render;
#[cfg(test)]
use helpers::fingerprint;

/// SARIF schema URL pinned to v2.1.0. GitHub Code Scanning accepts both
/// `master` and `2.1.0` paths; pin to the version-tagged one for stability.
const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

/// Synthetic artifact URI for all results. SARIF requires a `physicalLocation`
/// on every `result`; an SBOM-derived finding has no source line, so we
/// project all results onto a single virtual `sbom` artifact.
const SARIF_ARTIFACT_URI: &str = "sbom";
