# Bitbucket Pipelines

bomdrift runs in Bitbucket Cloud Pipelines and posts a single
upserted PR comment per pull request, mirroring the GitHub Action
and GitLab template flow.

## Quickstart

Copy [`examples/bitbucket-pipelines/bitbucket-pipelines.yml`](https://github.com/Metbcy/bomdrift/blob/main/examples/bitbucket-pipelines/bitbucket-pipelines.yml)
to your repo root and add a Repository Variable named
`BOMDRIFT_API_TOKEN` containing a Bitbucket App Password with the
`pullrequest:write` scope.

## What the job does

1. Installs Syft and bomdrift in a `rust:1.88` container.
2. Generates a CycloneDX SBOM for the PR target branch and the PR
   head via `syft dir:`.
3. Renders the diff to markdown with `bomdrift diff --platform
   bitbucket`.
4. Looks up the existing bomdrift comment on the PR (by the
   `<!-- bomdrift:diff -->` marker) and either creates a new comment
   or updates the existing one.

## Tokens & permissions

| Variable | Scope | Why |
|---|---|---|
| `BOMDRIFT_API_TOKEN` | App Password, `pullrequest:write` | Posting / updating PR comments. |

The job never auto-pushes to your branch. Suppression is the manual
`bomdrift baseline add` flow plus a commit on your branch.

## CLI auto-detection

Setting `BITBUCKET_BUILD_NUMBER` in the environment auto-selects
`--platform bitbucket` when the flag is omitted. The Pipelines
runner sets this variable on every build.

`BITBUCKET_GIT_HTTP_ORIGIN` is honored as a `--repo-url` fallback,
so the markdown footer's "Report this finding" link works without
plumbing.

## Suppressions

The supported, no-infrastructure-required flow is the manual baseline edit:

```sh
bomdrift baseline add GHSA-... --reason "audit complete (PR #42)"
git add .bomdrift/baseline.json
git commit -m "baseline: suppress GHSA-..."
```

### Comment-driven suppression (advanced, v0.9.5+)

> **Trade-off up front.** Comment-driven suppression turns a reviewer
> comment like `/bomdrift suppress GHSA-...` into an automatic
> baseline edit. To wire it up safely you need to operate a small
> public webhook handler. The manual flow above is supported and
> lower-risk; reach for the bridge only when the zero-click UX is
> worth running a service.

`examples/bitbucket-pipelines/comment-bridge/` ships a Cloudflare
Worker reference implementation that enforces five security guards:

1. Webhook HMAC verification (`X-Hub-Signature: sha256=…` against the
   byte-exact request body).
2. Event-type filter (`pullrequest:comment_created` only).
3. Repo-full-name allowlist.
4. Commenter-permission lookup (`write` / `admin` / `owner` only).
5. PR-context guard (rejects fork-PR comment-suppress).

When the guards pass, the worker triggers the
`bomdrift-comment-suppress` custom pipeline (defined in the example
`bitbucket-pipelines.yml`) with `BOMDRIFT_NOTE_BODY` set to the raw
comment body. The pipeline runs
`bomdrift baseline add --from-comment "$BOMDRIFT_NOTE_BODY"` and
pushes the resulting baseline edit back to the PR's source branch.

The full threat model and deployment guide live in
[`examples/bitbucket-pipelines/comment-bridge/README.md`](https://github.com/Metbcy/bomdrift/tree/main/examples/bitbucket-pipelines/comment-bridge#threat-model).
The same logic ports to Vercel / Netlify / AWS Lambda — see
[`vercel-equivalent.md`](https://github.com/Metbcy/bomdrift/blob/main/examples/bitbucket-pipelines/comment-bridge/vercel-equivalent.md).

## Input reference

The example pipeline reads optional `BOMDRIFT_*` repository (or
workspace) variables and forwards each as a `bomdrift diff` flag.
Set them under **Repository settings, Repository variables** (or
**Workspace variables** for organization-wide defaults). Unset
variables contribute zero CLI arguments, so the default invocation
matches the bare v0.9 template exactly.

This mirrors the [GitHub Action input
surface](https://github.com/Metbcy/bomdrift/blob/main/action.yml);
descriptions are abridged from `action.yml`.

### VEX

- `BOMDRIFT_VEX` (newline-separated paths to OpenVEX documents),
  each forwarded as a repeated `--vex <path>`.
- `BOMDRIFT_EMIT_VEX` (path), write a fresh OpenVEX document
  derived from the diff (`--emit-vex <path>`).
- `BOMDRIFT_VEX_AUTHOR`, author identity recorded on emitted VEX
  (`--vex-author <author>`).
- `BOMDRIFT_VEX_DEFAULT_JUSTIFICATION`, default OpenVEX
  `not_affected` justification (`--vex-default-justification <id>`).

### License policy

- `BOMDRIFT_ALLOW_LICENSES`, comma-separated SPDX expressions to
  allow (`--allow-licenses`).
- `BOMDRIFT_DENY_LICENSES`, comma-separated SPDX expressions to
  deny (`--deny-licenses`).
- `BOMDRIFT_ALLOW_EXCEPTION`, SPDX exception identifiers to allow
  inside `WITH` clauses (`--allow-exception`).
- `BOMDRIFT_DENY_EXCEPTION`, SPDX exception identifiers to deny
  (`--deny-exception`).
- `BOMDRIFT_ALLOW_AMBIGUOUS_LICENSES`, set to `true` to treat
  unresolvable expressions as allowed (`--allow-ambiguous-licenses`).

### Enrichment toggles

- `BOMDRIFT_NO_EPSS`, set to `true` to disable EPSS enrichment
  (`--no-epss`).
- `BOMDRIFT_NO_KEV`, set to `true` to disable CISA KEV enrichment
  (`--no-kev`).
- `BOMDRIFT_NO_REGISTRY`, set to `true` to disable registry and
  maintainer enrichment (`--no-registry`).
- `BOMDRIFT_FAIL_ON_EPSS`, exit 2 when any new advisory has an
  EPSS score at or above this threshold (0.0 to 1.0,
  `--fail-on-epss <FLOAT>`).

### Calibration

- `BOMDRIFT_RECENTLY_PUBLISHED_DAYS`, window (days) for the
  recently-published maintainer-age signal.
- `BOMDRIFT_TYPOSQUAT_SIMILARITY_THRESHOLD`,
  Damerau-Levenshtein similarity threshold (0.0 to 1.0).
- `BOMDRIFT_YOUNG_MAINTAINER_DAYS`, age threshold (days) below
  which a maintainer is flagged as young.
- `BOMDRIFT_CACHE_TTL_HOURS`, TTL (hours) for the on-disk
  enrichment cache.
- `BOMDRIFT_MULTI_MAJOR_DELTA`, major-version delta at or above
  which a version jump is flagged as multi-major (default 2,
  minimum 1).

### Attestation

- `BOMDRIFT_BEFORE_ATTESTATION`, OCI reference for the cosign
  attestation covering the before SBOM
  (`--before-attestation <oci-ref>`).
- `BOMDRIFT_AFTER_ATTESTATION`, OCI reference for the after SBOM
  (`--after-attestation <oci-ref>`).
- `BOMDRIFT_COSIGN_IDENTITY`, regex matched against the cosign
  certificate identity (`--cosign-identity <regex>`).
- `BOMDRIFT_COSIGN_ISSUER`, OIDC issuer URL used for keyless
  cosign verification (`--cosign-issuer <url>`).
- `BOMDRIFT_REQUIRE_ATTESTATION`, set to `true` to fail the diff
  when either side is missing a verified attestation
  (`--require-attestation`).

### Plugins

- `BOMDRIFT_PLUGIN` (newline-separated paths to plugin manifests,
  i.e. `plugin.toml`), each forwarded as a repeated
  `--plugin <path>`.

## Troubleshooting

See [`examples/bitbucket-pipelines/README.md`](https://github.com/Metbcy/bomdrift/blob/main/examples/bitbucket-pipelines/README.md).
