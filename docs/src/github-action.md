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

For a repo-owned policy, run `bomdrift init` once and commit the generated
`.bomdrift.toml` plus workflows. The action auto-loads `.bomdrift.toml`
from the repo root when present, or you can pass
`config: .bomdrift.toml` explicitly.

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
| `fail-on`     | no  | `none` | Exit code 2 on findings of the configured kind: `none`/`cve`/`critical-cve`/`typosquat`/`license-change`/`any`. The PR comment is still posted on a tripped run. |
| `comment-size-limit` | no | `60000` | Bytes. When the rendered diff exceeds this size, bomdrift re-renders with `--summary-only` for the PR comment while keeping the full body in the workflow step summary. Set to `0` to disable the fallback. GitHub's hard cap is 65,536 chars. |
| `verify-signatures` | no | `true` | Whether to install cosign and verify the bomdrift release archive's Sigstore signature. Set to `false` on trusted mirrors / cached runners to skip the cosign-installer step (~15s saved). |
| `config` | no | `` (empty) | Path to `.bomdrift.toml`. Leave empty to auto-load `.bomdrift.toml` from the repo root when present. |
| `findings-only` | no | `false` | Markdown-only. Keep summary + risk-bearing sections, but omit raw Added / Removed / Version changed detail rows from the PR comment. |
| `max-added` | no | `` (empty) | Exit 2 when more than this many dependencies are added. |
| `max-removed` | no | `` (empty) | Exit 2 when more than this many dependencies are removed. |
| `max-version-changed` | no | `` (empty) | Exit 2 when more than this many dependencies change version. |
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
4. When `fail-on` or a diff budget trips, the action exits with code 2 —
   but only **after** the PR comment has been posted, so reviewers see the
   findings even when the workflow step fails.

## Common patterns

### Repo policy file

Use `.bomdrift.toml` when you want the policy in version control instead
of repeated YAML inputs:

```toml
[diff]
fail_on = "critical-cve"
baseline = ".bomdrift/baseline.json"
findings_only = true
max_added = 25
max_version_changed = 10
```

```yaml
- uses: Metbcy/bomdrift@v1
  with:
    config: .bomdrift.toml
```

Explicit action inputs still override the config-backed defaults for
one-off workflows.

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
(see [OSV.dev CVE lookup](./enrichers/osv-cve.md)). `typosquat`,
`license-change`, and `any` are also accepted thresholds — see
[`--fail-on`](./cli-reference.md#--fail-on).

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
action's exit code remains the bomdrift exit (so a `fail-on` or budget
trip still fails the workflow correctly).

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

## Monorepo setup

When a single repo owns N services with independent dependency trees
(`services/api`, `services/worker`, `apps/web`, ...), running one
bomdrift job per service gives each PR a focused, per-service comment
without merging unrelated diff churn into a single 65k-char wall.

### Pattern A — `path:` per matrix entry

The simplest setup uses a job matrix and the action's `path` input:

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  diff:
    strategy:
      fail-fast: false
      matrix:
        service: [api, worker, web]
    runs-on: ubuntu-latest
    steps:
      - uses: Metbcy/bomdrift@v1
        with:
          path: services/${{ matrix.service }}
          fail-on: critical-cve
```

Each matrix leg posts (or upserts) **its own PR comment**, distinguished
by the rendered title (e.g. "SBOM diff — services/api"). The
`<!-- bomdrift:diff -->` upsert marker is namespaced internally by
`path:`, so leg N's comment doesn't clobber leg N-1's.

`fail-fast: false` is recommended: a vulnerability in `worker` shouldn't
hide an emergent `api` finding from the same PR.

### Pattern B — share a baseline across services

Most monorepos *do* want one shared exception list (the same false
positive will show up in any service that depends on the same
package). Point each leg at the same file:

```yaml
- uses: Metbcy/bomdrift@v1
  with:
    path: services/${{ matrix.service }}
    baseline: .bomdrift/baseline.json
```

The baseline file is keyed by `(purl_with_version, advisory_id)` — see
[Match keys](./baseline.md#match-keys) — so a suppression for
`pkg:npm/colour-print@2.1.0` covers every service that pulls in that
exact version. New versions still surface (intentional; that's the
point of the version-pinned key).

When services pin different versions of the same dep, you'll get
per-version baseline entries. That's working-as-intended — a known-fine
finding at v1.0.0 should still get a fresh review at v1.1.0.

### Pattern C — per-service `.bomdrift.toml`

When the policy itself differs (worker has a stricter `fail-on`,
docs-site has a generous `max-added`), drop a `.bomdrift.toml` per
service:

```yaml
- uses: Metbcy/bomdrift@v1
  with:
    path:   services/${{ matrix.service }}
    config: services/${{ matrix.service }}/.bomdrift.toml
```

The auto-discovery only checks the repo root, so an explicit
`config:` is required for nested files.

### What to scope per service vs. globally

| Setting | Scope | Why |
|---|---|---|
| `fail-on`, `max-*` budgets | Per-service | Worker's risk surface ≠ web's |
| `baseline` | **Shared** | Same false positives across services |
| `comment-on-pr`, `output` | Per-service | Diff-only legs vs. PR-comment legs |
| `verify-signatures` | Global | Runner-image property, not service property |

## Action-broke troubleshooting checklist

When a previously-working bomdrift action job starts failing — typically
right after a merge to your default branch, a token rotation, or a
runner-image upgrade — work through these in order. Each row is **one
symptom, one fix** so you can grep your job log for the symptom and
land on the recipe.

| Symptom (in the job log) | Likely cause | Fix |
|---|---|---|
| `403 Resource not accessible by integration` on the comment-upsert step | `pull-requests: write` permission missing on the workflow / job | Add `permissions: { pull-requests: write, contents: read }` at the workflow or job level. PR comments need `pull-requests: write`; the action's internal checkouts need `contents: read`. |
| `Forks cannot post PR comments` warning, exit 0 | PR is from a fork; default `GITHUB_TOKEN` on `pull_request` events is read-only | Switch the trigger to `pull_request_target` (and harden — see [GitHub's guidance][prtarget]), or accept that fork PRs only get the workflow step summary, not a PR comment. |
| `Could not find SBOM at services/api` after a green earlier run | Default branch protection bumped the merge-base; `before-ref` now points at a commit that predates the `services/api` directory | Either move the `path:` value to match the new layout, or pin `before-ref` explicitly to a known-good commit (`before-ref: main`). |
| `cosign: signature verification failed` after a release-archive rotation | Cached release archive in the runner's tool cache is stale and predates a rotation | Bump to the latest patch tag (e.g. `Metbcy/bomdrift@v1` re-resolves to the floating tag), or set `verify-signatures: false` on a self-hosted runner you've pinned manually. |
| `path: services/api` warning + empty SBOM | The path doesn't exist post-checkout — typo, or the directory was renamed in `before-ref` only | bomdrift v0.7+ surfaces an actionable error pointing at this exact case. See the [monorepo section](#monorepo-setup) for the matrix recipe; double-check `${{ matrix.service }}` substitution. |
| "Comment exceeds 65,536 characters" 422 from GitHub | A massive diff blew past the size cap; the v0.3 fallback to `--summary-only` was disabled (`comment-size-limit: 0`) | Re-enable the fallback (drop `comment-size-limit` to use the default, or set it to `60000`). The full body is preserved in the workflow step summary. |
| Action runs, no PR comment appears, exit 0 | Workflow event isn't `pull_request` (the comment path is gated on PR events), or `comment-on-pr: false` was set explicitly | For `push`/`schedule` events, the comment path is intentionally skipped — use the step summary or upload the markdown as an artifact. |

[prtarget]: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-pull_request_target

If you hit a failure mode not in the table above, please [open an
issue](https://github.com/Metbcy/bomdrift/issues/new?labels=action-broke)
with the failing job log — the troubleshooting table grows from real
reports.
