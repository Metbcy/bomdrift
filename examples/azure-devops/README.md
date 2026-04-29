# bomdrift + Azure DevOps Pipelines

Drop-in template for running bomdrift on Azure DevOps Repos PRs.

## Quickstart

1. Copy [`azure-pipelines.yml`](./azure-pipelines.yml) to your repo root.
2. Create a Personal Access Token with **Code (Read & Write)** scope.
   Expose it as a masked pipeline secret variable named
   `BOMDRIFT_API_TOKEN`.
3. Open a PR. The pipeline posts an inline thread.

## Why a PAT and not `System.AccessToken`?

`System.AccessToken`'s scope is too narrow to update PR threads on
most orgs. A maintainer-issued PAT is the most-portable option.

## Token model

| Step | Token used | Scope |
|---|---|---|
| `bomdrift_diff` | `BOMDRIFT_API_TOKEN` | PAT, `Code (Read & Write)` |

## Caveats

- The pipeline reads `System.PullRequest.PullRequestId` and
  `Build.Repository.ID` at runtime. Manual builds outside a PR
  context have neither.
- Comment-driven `/bomdrift suppress` is not wired up for Azure
  DevOps in v0.9.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| 403 from `/_apis/git/repositories/.../threads` | PAT scope too narrow | Re-issue with `Code (Read & Write)`. |
| Multiple threads per PR | Marker not surviving Azure's HTML sanitizer | Confirm the comment body is sent as `commentType: 1` (text). |

## What v0.9 does NOT ship

- Comment-driven suppression.
- Pipeline auto-bootstrap (`bomdrift init` does not write an Azure
  Pipelines YAML in v0.9).
