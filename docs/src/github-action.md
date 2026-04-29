# GitHub Action

The `Metbcy/bomdrift` action is a **composite action** (no Docker), which
keeps PR-comment latency low — typically 5–10s on a warm runner versus
30s+ for a Docker container action.

## Quick start (zero-config, v0.5+)

On a `pull_request` workflow, the action defaults to comparing the PR's
base branch against the PR's head SHA — no checkout step, no Syft step,
no SBOM-path wiring needed:

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  diff:
    runs-on: ubuntu-latest
    steps:
      - uses: Metbcy/bomdrift@v1
```

That's it. The action checks out both refs into opaque sibling paths,
generates CycloneDX-JSON SBOMs via Syft (installed automatically and
cached across job runs), and posts the rendered diff as an upserted PR
comment.

If you already produce SBOMs through a non-Syft toolchain — Trivy,
SPDX-tools, an in-house generator — supply the file paths via the
`before-sbom` / `after-sbom` inputs instead. The advanced flow below
documents that path; both flows continue to be supported in v1.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `before-ref` | no | `${{ github.event.pull_request.base.ref }}` | Git ref / SHA to check out as the "before" side. The default works on `pull_request` events; supply explicitly on other events. Ignored when `before-sbom` is set. |
| `after-ref`  | no | `${{ github.event.pull_request.head.sha }}`  | Git ref / SHA for the "after" side. Same defaulting story. Ignored when `after-sbom` is set. |
| `path`       | no | `.` | Subdirectory of the checked-out ref to scan with Syft. Useful for monorepos (`path: services/api`). Ignored when both `*-sbom` inputs are set. |
| `before-sbom` | no | `` (empty) | Path to the "before" SBOM (CycloneDX, SPDX, or Syft JSON). When set, bypasses the v0.5 zero-config Syft invocation and uses this file directly. The escape hatch for non-Syft toolchains. |
| `after-sbom`  | no | `` (empty) | Path to the "after" SBOM. Same migration story as `before-sbom`. |
| `format`      | no  | `auto` | Force input format detection: `auto`/`cdx`/`spdx`/`syft`. |
| `output`      | no  | `markdown` | Output format: `terminal`/`markdown`/`json`/`sarif`. The PR-comment path requires `markdown`. |
| `comment-on-pr` | no | `true` | Post the rendered diff as a PR comment when the workflow runs on a `pull_request` event. Set to `false` for diff-only / report-only workflows. |
| `fail-on`     | no  | `none` | Exit code 2 on findings of the configured kind: `none`/`cve`/`critical-cve`/`typosquat`/`any`. The PR comment is still posted on a tripped run. |
| `comment-size-limit` | no | `60000` | Bytes. When the rendered diff exceeds this size, bomdrift re-renders with `--summary-only` for the PR comment while keeping the full body in the workflow step summary. Set to `0` to disable the fallback. GitHub's hard cap is 65,536 chars. |
| `verify-signatures` | no | `true` | Whether to install cosign and verify the bomdrift release archive's Sigstore signature. Set to `false` on trusted mirrors / cached runners to skip the cosign-installer step (~15s saved). |
| `baseline` | no | `` (empty) | Path to a previously captured `bomdrift diff --output json` snapshot. Findings present in the baseline are suppressed from the rendered output and the `--fail-on` trip evaluation. See [Baseline & suppression](./baseline.md) for match-key semantics. |
| `github-token` | no | `${{ github.token }}` | Token used to post PR comments. |

## Outputs

The action does not declare formal outputs. Its side effects are:

1. The rendered diff is written to stdout (visible in the workflow run log
   under the `Run bomdrift` step).
2. When `output == markdown` and `GITHUB_STEP_SUMMARY` is set, the rendered
   diff is appended to the step summary so reviewers can see it without a
   PR-comment posting permission.
3. On `pull_request` events with `comment-on-pr: true`, the rendered diff
   is upserted into a single PR comment marked `<!-- bomdrift:diff -->`.
   Subsequent pushes update the same comment instead of accumulating new
   ones (`peter-evans/create-or-update-comment`-style upsert).
4. When `fail-on` trips, the action exits with code 2 — but only **after**
   the PR comment has been posted, so reviewers see the findings even when
   the workflow step fails.

## Common patterns

### Bring your own SBOMs (advanced / pre-v0.5 flow)

When the SBOMs come from a non-Syft toolchain (Trivy, SPDX-tools,
proprietary scanners) or you already generate them in an earlier job
step, supply both paths explicitly. The action skips the in-action
Syft invocation entirely:

```yaml
- uses: actions/checkout@v4
- uses: anchore/sbom-action@v0
  with: { path: ., output-file: after.json }
- uses: actions/checkout@v4
  with: { ref: ${{ github.event.pull_request.base.ref }}, path: base }
- uses: anchore/sbom-action@v0
  with: { path: base, output-file: before.json }
- uses: Metbcy/bomdrift@v1
  with: { before-sbom: before.json, after-sbom: after.json }
```

This is the v0.4-era "manual" pattern. It still works in v0.5 — the
`before-sbom` / `after-sbom` inputs were `required: true` in v0.4 and
became `required: false` in v0.5; nothing else changed about how they
behave. Existing v0.4 workflows continue to function unchanged after a
`@v1` tag bump.

### Block the merge on critical findings

```yaml
- uses: Metbcy/bomdrift@v1
  with:
    before-sbom: before.json
    after-sbom:  after.json
    fail-on:     critical-cve
```

`critical-cve` filters on `severity >= High` per the OSV-fetched severity
(see [OSV.dev CVE lookup](./enrichers/osv-cve.md)). `typosquat` and `any`
are also accepted thresholds — see [`--fail-on`](./cli-reference.md#--fail-on).

### Self-hosted / trusted-mirror runners

```yaml
- uses: Metbcy/bomdrift@v1
  with:
    before-sbom: before.json
    after-sbom:  after.json
    verify-signatures: false   # ~15s faster, skips cosign-installer
```

This is appropriate when:

- You're running on self-hosted runners with a hardened image you control.
- You've pre-pinned the bomdrift archive in your Nexus/Artifactory mirror
  and verified its signature once at mirror time.
- You're running in a network-restricted environment where the public
  Sigstore endpoints aren't reachable.

When `verify-signatures: true` and cosign isn't installed (or the `.sig`/
`.pem` aren't on the release), the action **fails loudly** rather than
silently degrading — that's the whole point of the explicit opt-out.

### Big monorepo with massive SBOMs

If `bomdrift diff` rendered output exceeds GitHub's 65,536-char comment-body
cap, the v0.3 size fallback re-renders with `--summary-only` for the PR
comment and keeps the full body in the workflow step summary:

```yaml
- uses: Metbcy/bomdrift@v1
  with:
    before-sbom: before.json
    after-sbom:  after.json
    comment-size-limit: 60000   # default; tune for GHE with raised limits
```

Set `comment-size-limit: 0` to disable the fallback entirely and let
GitHub return a 422 on oversized comments (rarely what you want).

### Diff-only (no PR comment)

Useful for SARIF uploads, third-party comment posting, or when you just
want the diff in the step summary:

```yaml
- uses: Metbcy/bomdrift@v1
  with:
    before-sbom:    before.json
    after-sbom:     after.json
    output:         sarif
    comment-on-pr:  false

- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: bomdrift.sarif }
```

The `output: sarif` produces SARIF v2.1.0 with stable rule IDs (see
[Output formats](./output-formats.md#sarif-v210)).

## Action permissions

`pull-requests: write` is required when `comment-on-pr: true` (the
default). Without it, the comment-upsert step fails with a 403; the
action's exit code remains the bomdrift exit (so a `fail-on` trip still
fails the workflow correctly).

`contents: read` is required so the action's internal `actions/checkout`
steps (zero-config flow) can fetch both refs. In the bring-your-own-SBOMs
flow it's still required by whichever step generates the SBOMs upstream.

## What the action does (v0.5+)

When the zero-config flow runs (no explicit `before-sbom` / `after-sbom`):

1. **Two sibling checkouts** of `before-ref` and `after-ref` into
   `${{ github.workspace }}/__bomdrift_before` and `__bomdrift_after`.
   Both with `fetch-depth: 1` and `persist-credentials: false`. Skipped
   for whichever side has a pre-supplied SBOM path.
2. **Syft installed** via `anchore/sbom-action/download-syft@v0`. Cached
   across job runs in the runner's tool cache.
3. **`syft scan dir:...` against each checkout's `${path}` subtree**,
   producing CycloneDX-JSON into a tempfile under `$RUNNER_TEMP`. The
   bomdrift parser drops `Ecosystem::Other("file")` pseudo-components
   that Syft's directory cataloger emits — set
   `--include-file-components` (CLI) or pass a pre-generated SBOM via
   `before-sbom` / `after-sbom` to bypass.
4. **`bomdrift diff` runs** as in the v0.4 flow, and the upsert + step
   summary plumbing is unchanged.

The new behavior costs about 30 MB of one-time tool cache and 3–5s of
cold-cache wall time per first invocation. Subsequent runs in the same
job (or in repos that share the runner's tool cache) reuse Syft.
