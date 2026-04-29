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

Comment-driven suppression is **not** wired up for Bitbucket in
v0.9. The supported flow is:

```sh
bomdrift baseline add GHSA-... --reason "audit complete (PR #42)"
git add .bomdrift/baseline.json
git commit -m "baseline: suppress GHSA-..."
```

## Troubleshooting

See [`examples/bitbucket-pipelines/README.md`](https://github.com/Metbcy/bomdrift/blob/main/examples/bitbucket-pipelines/README.md).
