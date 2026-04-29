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

Comment-driven suppression is not wired up for Azure DevOps in v0.9.
Use `bomdrift baseline add` and commit the result.

## Troubleshooting

See [`examples/azure-devops/README.md`](https://github.com/Metbcy/bomdrift/blob/main/examples/azure-devops/README.md).
