# SARIF + GitHub Code Scanning

bomdrift can emit findings in [SARIF v2.1.0] for ingestion by GitHub Code
Scanning, GitLab Vulnerability Reports, and any other consumer that speaks
SARIF.

```bash
bomdrift diff before.cdx.json after.cdx.json \
    --output sarif \
    --output-file bomdrift.sarif
```

## Rule taxonomy

bomdrift emits the following stable rule IDs (load-bearing — never renamed
across releases). All rules are present in `tool.driver.rules` even when
the current diff has zero results of that kind, so Code Scanning UI
suppression flows can enumerate them upfront.

| Rule ID | Surfaces | SARIF level |
|---|---|---|
| `bomdrift.cve` | OSV.dev advisory ID(s) for the component | `error` for High/Critical, else `warning` |
| `bomdrift.typosquat` | Component name similar to a popular package | `warning` |
| `bomdrift.version-jump` | Multi-major version bump | `warning` |
| `bomdrift.young-maintainer` | Top GitHub contributor's first commit < 90 days ago | `warning` |
| `bomdrift.license-change` | License changed at the same version | `warning` |
| `bomdrift.license-violation` | Component license violates configured allow/deny policy | `warning` |

## Fingerprint stability

Each result carries `partialFingerprints.primaryHash/v1` — a SHA-256 digest
of a stable identity tuple per rule:

| Rule | Identity |
|---|---|
| `bomdrift.cve` | `ruleId | purl | advisoryId` (severity excluded — severity changes shouldn't churn alert identity) |
| `bomdrift.typosquat` | `ruleId | purl | closest` |
| `bomdrift.version-jump` | `ruleId | purl | beforeVersion | afterVersion` (full versions, not majors) |
| `bomdrift.young-maintainer` | `ruleId | purl | topContributor` |
| `bomdrift.license-change` | `ruleId | purl | beforeLicensesSorted | afterLicensesSorted` |
| `bomdrift.license-violation` | `ruleId | purl | matchedLicense` |

The `/v1` suffix on the fingerprint key lets bomdrift evolve identity
schemes in future releases without GitHub re-opening every existing alert.
Two distinct CVEs on the same purl produce distinct fingerprints; the
same finding produced across two runs produces a byte-equal fingerprint.

## Wire up GitHub Code Scanning

Set the new action input `upload-to-code-scanning: 'true'` and ensure your
workflow has the `security-events: write` permission. The composite action
runs `github/codeql-action/upload-sarif@v3` after bomdrift writes
`${{ github.workspace }}/bomdrift.sarif`.

```yaml
permissions:
  contents: read
  security-events: write   # required for SARIF upload
  pull-requests: write     # only if you also want PR comments

jobs:
  bomdrift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Metbcy/bomdrift@v1
        with:
          output: sarif
          upload-to-code-scanning: 'true'
```

## Direct CLI use (any CI)

When integrating with GitLab Vulnerability Reports, Bitbucket, or any
arbitrary SARIF consumer, prefer `--output-file` over shell redirection:

```bash
bomdrift diff before.json after.json \
    --output sarif \
    --output-file bomdrift.sarif
```

The `--output-file` form is YAML-quoting-safe (no `>` redirection) and
keeps stdout free for human-readable progress logging.

## Determinism

Renderer output is byte-deterministic across runs for identical inputs.
HashMap-keyed advisory lists are sorted by purl key before emission;
license arrays are sorted before fingerprinting. The
`SOURCE_DATE_EPOCH` environment variable is honored everywhere bomdrift
emits a timestamp (the SARIF document itself currently carries no
timestamps, but related VEX emission in v0.9 will).

## Troubleshooting

- **Alerts don't appear in the Security tab.** Confirm
  `permissions.security-events: write` on the calling workflow AND
  `upload-to-code-scanning: 'true'` on the action input. Check the
  "Upload SARIF to Code Scanning" step in the job log for the API
  response.
- **Same finding appears twice after a re-run.** This is a fingerprint
  bug — file an issue with the SARIF artifact and the inputs that
  produced it. Fingerprints should remain byte-equal across runs.
- **Severity wrong / missing.** Bomdrift maps GHSA's
  `database_specific.severity` text label. Advisories without a label
  surface at SARIF `warning` and the `properties.severity` field reads
  `NONE`.

[SARIF v2.1.0]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
