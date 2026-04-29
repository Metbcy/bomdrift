# GitHub Action

The `Metbcy/bomdrift` action is a **composite action** (no Docker), which
keeps PR-comment latency low — typically 5–10s on a warm runner versus
30s+ for a Docker container action.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `before-sbom` | yes | — | Path to the "before" SBOM (CycloneDX, SPDX, or Syft JSON). |
| `after-sbom`  | yes | — | Path to the "after" SBOM. |
| `format`      | no  | `auto` | Force input format detection: `auto`/`cdx`/`spdx`/`syft`. |
| `output`      | no  | `markdown` | Output format: `terminal`/`markdown`/`json`/`sarif`. The PR-comment path requires `markdown`. |
| `comment-on-pr` | no | `true` | Post the rendered diff as a PR comment when the workflow runs on a `pull_request` event. Set to `false` for diff-only / report-only workflows. |
| `fail-on`     | no  | `none` | Exit code 2 on findings of the configured kind: `none`/`cve`/`critical-cve`/`typosquat`/`any`. The PR comment is still posted on a tripped run. |
| `comment-size-limit` | no | `60000` | Bytes. When the rendered diff exceeds this size, bomdrift re-renders with `--summary-only` for the PR comment while keeping the full body in the workflow step summary. Set to `0` to disable the fallback. GitHub's hard cap is 65,536 chars. |
| `verify-signatures` | no | `true` | Whether to install cosign and verify the bomdrift release archive's Sigstore signature. Set to `false` on trusted mirrors / cached runners to skip the cosign-installer step (~15s saved). |
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

### Generate the SBOMs in the same workflow

The most common pattern: generate before and after SBOMs from the base ref
and the PR head, respectively, then feed both into bomdrift.

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

`contents: read` is required for the SBOM-checkout step, not the action
itself. The action only reads files passed via `before-sbom` / `after-sbom`.
