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

## Troubleshooting

See [`examples/bitbucket-pipelines/README.md`](https://github.com/Metbcy/bomdrift/blob/main/examples/bitbucket-pipelines/README.md).
