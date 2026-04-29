# Example: axios npm compromise (Mar 31, 2026)

## What this shows

The headline scenario bomdrift was built to surface. On 2026-03-31, an axios
maintainer was socially engineered (fake Slack/Teams call attributed to North
Korean UNC1069), and `axios@1.14.1` + `axios@0.30.4` were briefly published
with a malicious runtime dependency on `plain-crypto-js@4.2.1` — a typosquat
of the legitimate `crypto-js`. The dropper installed the WAVESHAPER.V2 RAT
on Windows, macOS, and Linux.

This diff captures the moment a project's lockfile pulls the compromised
release. Three of bomdrift's signals fire:

1. **Added** — a brand-new transitive dependency `plain-crypto-js@4.2.1`
   appears, which a reviewer should immediately question.
2. **Typosquat** — `plain-crypto-js` scores 0.95 against the legitimate
   `crypto-js` via the suffix-containment boost rule.
3. **Version changed** — `axios` itself bumps `1.14.0 → 1.14.1`, and with
   network access OSV.dev returns the published advisory IDs (`MAL-2026-2306`,
   `GHSA-3p68-rc4w-qgx5`, etc.) on both versions.

## Run it

```bash
# Offline mode — pure local compute, no OSV / GitHub network calls.
bomdrift diff before.json after.json --no-osv --no-maintainer-age

# Live mode — populates the Vulnerabilities section from OSV.dev and the
# "young maintainer" signal from GitHub. Requires network and (for the
# rate-limit headroom) ideally GITHUB_TOKEN.
bomdrift diff before.json after.json
```

## Files

- [`before.json`](./before.json) — pre-incident SBOM (`axios@1.14.0`, etc.).
  Same content as `tests/fixtures/cdx-minimal.json`.
- [`after.json`](./after.json) — post-incident SBOM (`axios@1.14.1` plus the
  newly added `plain-crypto-js@4.2.1`). Same content as
  `tests/fixtures/cdx-after.json`.
- [`expected-output.md`](./expected-output.md) — the exact markdown
  bomdrift produces in offline mode against this pair. Pinned to keep
  this example's output reviewable; `examples/run-all.sh` regenerates and
  diff-checks it.
