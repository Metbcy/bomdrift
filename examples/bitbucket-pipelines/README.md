# bomdrift + Bitbucket Pipelines

Drop-in template for running bomdrift on Bitbucket Cloud PRs. The
pipeline runs on every PR build, generates SBOMs with Syft for the
target branch and the PR head, renders the diff to markdown, and
upserts a Bitbucket PR comment marked `<!-- bomdrift:diff -->`.

## Quickstart

1. Copy [`bitbucket-pipelines.yml`](./bitbucket-pipelines.yml) to your
   project root, or `import:` it from a shared template repo.
2. Create a Bitbucket App Password with the `pullrequest:write` scope.
   Expose it as a masked Pipelines repository variable named
   `BOMDRIFT_API_TOKEN`.
3. Open a PR. The `bomdrift:diff` step runs and posts a comment.
   Subsequent pushes update the same comment by the marker.

## Token model

| Step | Token used | Scope |
|---|---|---|
| `bomdrift:diff` | `BOMDRIFT_API_TOKEN` | App Password, `pullrequest:write` |

bomdrift never auto-pushes a baseline change to your branch from a PR
build. To suppress a finding, run `bomdrift baseline add <ID>` locally
and commit `.bomdrift/baseline.json` to your branch — same flow as
GitLab and Azure DevOps.

## Caveats

- Bitbucket's `pullrequest:write` App Password scope is broad on some
  workspaces. Audit your workspace's permission bundles before issuing
  the token.
- Comment-driven `/bomdrift suppress` is **not** wired up for
  Bitbucket in v0.9. The recommended flow is the manual baseline edit.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `401 Unauthorized` from `/2.0/repositories/.../pullrequests/.../comments` | Token lacks `pullrequest:write` | Re-issue App Password with the right scope. |
| Multiple bomdrift comments accrue per PR | Marker stripped by upstream comment renderer | Confirm the marker `<!-- bomdrift:diff -->` survives a round-trip via the API. |

## What v0.9 does NOT ship

- Comment-driven suppression for Bitbucket. Use the manual
  `bomdrift baseline add` flow.
- Pipeline auto-bootstrap (`bomdrift init` does not write a Bitbucket
  YAML in v0.9). Copy this file manually.
