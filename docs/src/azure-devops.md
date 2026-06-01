# Azure DevOps Pipelines

bomdrift runs in Azure Pipelines and posts a single upserted PR
thread per pull request.

## Quickstart

Copy [`examples/azure-devops/azure-pipelines.yml`](https://github.com/Metbcy/bomdrift/blob/main/examples/azure-devops/azure-pipelines.yml)
to your repo root and add a secret pipeline variable named
`BOMDRIFT_API_TOKEN` containing a PAT with the `Code (Read & Write)`
scope.

## What the job does

1. Installs Rust + bomdrift + Syft on the `ubuntu-latest` agent.
2. Generates a CycloneDX SBOM for the PR target branch and the PR
   head.
3. Renders the diff to markdown with `bomdrift diff --platform
   azure-devops`.
4. Looks up the existing bomdrift PR thread (by the
   `<!-- bomdrift:diff -->` marker) and either creates a new thread
   or updates the existing comment.

## Tokens & permissions

| Variable | Scope | Why |
|---|---|---|
| `BOMDRIFT_API_TOKEN` | PAT, `Code (Read & Write)` | Creating / updating PR threads. |

The default `System.AccessToken` is **not** used because most
organizations don't grant it permission to create PR threads.

## CLI auto-detection

Setting `TF_BUILD=true` (Azure Pipelines sets this on every job)
auto-selects `--platform azure-devops` when the flag is omitted.

`BUILD_REPOSITORY_URI` is honored as a `--repo-url` fallback. Note
that this variable is empty for some local debug runs; passing
`--repo-url` explicitly is fine.

## Suppressions

The supported, no-infrastructure-required flow is the manual baseline
edit: run `bomdrift baseline add` locally and commit the result to
your PR branch.

### Comment-driven suppression (advanced, v0.9.5+)

> **Trade-off up front.** Comment-driven suppression turns a reviewer
> comment like `/bomdrift suppress GHSA-...` into an automatic
> baseline edit. To wire it up safely you need to operate a small
> public webhook handler. The manual flow above is supported and
> lower-risk; reach for the bridge only when the zero-click UX is
> worth running a service.

`examples/azure-devops/comment-bridge/` ships a Cloudflare Worker
reference implementation that enforces five security guards:

1. Webhook secret verification (`X-Bomdrift-Bridge-Secret` custom
   header, constant-time compare).
2. Event-type filter (`ms.vss-code.git-pullrequest-comment-event`
   only).
3. Project-UUID allowlist.
4. Commenter-permission lookup (Contributors team membership).
5. PR-context guard (active PR targeting the protected main branch).

When the guards pass, the worker POSTs to
`/_apis/pipelines/{id}/runs` with `BOMDRIFT_NOTE_BODY` as a template
parameter. The example `azure-pipelines.yml` defines a conditional
`bomdrift_suppress` stage gated on that parameter; it runs
`bomdrift baseline add --from-comment "$BOMDRIFT_NOTE_BODY"` and
pushes the resulting baseline edit back to the PR's source branch.
Normal PR-build runs leave the parameter empty so the suppress stage
is skipped.

The full threat model and deployment guide live in
[`examples/azure-devops/comment-bridge/README.md`](https://github.com/Metbcy/bomdrift/tree/main/examples/azure-devops/comment-bridge#threat-model).
The same logic ports to Vercel / Netlify / AWS Lambda — see
[`vercel-equivalent.md`](https://github.com/Metbcy/bomdrift/blob/main/examples/azure-devops/comment-bridge/vercel-equivalent.md).

## Input reference

The example pipeline exposes optional template parameters that are
forwarded to `bomdrift diff` as CLI flags. Override them at queue
time (Run pipeline, Variables / Parameters dialog) or pin defaults
by editing the `parameters:` block in the YAML; you can also wire a
pipeline variable through a parameter for org-wide defaults. Unset
parameters contribute zero CLI arguments, so the default invocation
matches the bare v0.9 template exactly.

This mirrors the [GitHub Action input
surface](https://github.com/Metbcy/bomdrift/blob/main/action.yml);
descriptions are abridged from `action.yml`.

### VEX

- `vex` (newline-separated paths to OpenVEX documents), each
  forwarded as a repeated `--vex <path>`.
- `emit_vex` (path), write a fresh OpenVEX document derived from
  the diff (`--emit-vex <path>`).
- `vex_author`, author identity recorded on emitted VEX
  (`--vex-author <author>`).
- `vex_default_justification`, default OpenVEX `not_affected`
  justification (`--vex-default-justification <id>`).

### License policy

- `allow_licenses`, comma-separated SPDX expressions to allow
  (`--allow-licenses`).
- `deny_licenses`, comma-separated SPDX expressions to deny
  (`--deny-licenses`).
- `allow_exception`, SPDX exception identifiers to allow inside
  `WITH` clauses (`--allow-exception`).
- `deny_exception`, SPDX exception identifiers to deny
  (`--deny-exception`).
- `allow_ambiguous_licenses` (boolean), set to `true` to treat
  unresolvable expressions as allowed
  (`--allow-ambiguous-licenses`).

### Enrichment toggles

- `no_epss` (boolean), set to `true` to disable EPSS enrichment
  (`--no-epss`).
- `no_kev` (boolean), set to `true` to disable CISA KEV enrichment
  (`--no-kev`).
- `no_registry` (boolean), set to `true` to disable registry and
  maintainer enrichment (`--no-registry`).
- `fail_on_epss`, exit 2 when any new advisory has an EPSS score
  at or above this threshold (0.0 to 1.0,
  `--fail-on-epss <FLOAT>`).

### Calibration

- `recently_published_days`, window (days) for the
  recently-published maintainer-age signal.
- `typosquat_similarity_threshold`, Damerau-Levenshtein similarity
  threshold (0.0 to 1.0).
- `young_maintainer_days`, age threshold (days) below which a
  maintainer is flagged as young.
- `cache_ttl_hours`, TTL (hours) for the on-disk enrichment cache.
- `multi_major_delta`, major-version delta at or above which a
  version jump is flagged as multi-major (default 2, minimum 1).

### Attestation

- `before_attestation`, OCI reference for the cosign attestation
  covering the before SBOM (`--before-attestation <oci-ref>`).
- `after_attestation`, OCI reference for the after SBOM
  (`--after-attestation <oci-ref>`).
- `cosign_identity`, regex matched against the cosign certificate
  identity (`--cosign-identity <regex>`).
- `cosign_issuer`, OIDC issuer URL used for keyless cosign
  verification (`--cosign-issuer <url>`).
- `require_attestation` (boolean), set to `true` to fail the diff
  when either side is missing a verified attestation
  (`--require-attestation`).

### Plugins

- `plugin` (newline-separated paths to plugin manifests, i.e.
  `plugin.toml`), each forwarded as a repeated `--plugin <path>`.

## Troubleshooting

See [`examples/azure-devops/README.md`](https://github.com/Metbcy/bomdrift/blob/main/examples/azure-devops/README.md).
