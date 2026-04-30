# Azure DevOps comment-driven suppress bridge

Reference implementation of a Service Hooks handler that turns a
`/bomdrift suppress <ID>` PR comment on Azure DevOps Repos into an
Azure Pipelines run which executes
`bomdrift baseline add --from-comment <body>` on the PR's source
branch.

The bridge is **opt-in advanced infrastructure**. Most teams should
prefer the manual flow in `examples/azure-devops/README.md` (commit
`.bomdrift/baseline.json` directly). Only deploy this if the
zero-click suppression UX is worth operating a small public service.

## Architecture

```
┌───────────────────────────┐  ms.vss-code.git-pullrequest-  ┌─────────────────────┐
│  Azure DevOps PR comment  │  comment-event (Service Hook)  │ Cloudflare Worker   │
│  /bomdrift suppress …     │ ──────────────────────────────▶│ (this directory)    │
└───────────────────────────┘  X-Bomdrift-Bridge-Secret      └─────────┬───────────┘
                                                                       │ 5 guards
                                                                       ▼
                                                             ┌─────────────────────┐
                                                             │ Azure Pipelines     │
                                                             │ POST /_apis/        │
                                                             │  pipelines/{id}/    │
                                                             │  runs               │
                                                             └─────────┬───────────┘
                                                                       ▼
                                                             ┌─────────────────────┐
                                                             │ bomdrift baseline   │
                                                             │  add --from-comment │
                                                             └─────────────────────┘
```

## Threat model

Five guards. Each prevents a distinct class of attack:

| # | Guard | Attack prevented |
|---|---|---|
| 1 | **Webhook secret** (`X-Bomdrift-Bridge-Secret`, constant-time compare against env.`WEBHOOK_SECRET`) | Unauthenticated POSTs from anyone on the internet. Azure DevOps Service Hooks support Basic auth out of the box, but the custom-header approach makes the secret visible to the Worker without `WWW-Authenticate` round-trips. |
| 2 | **Event-type filter** (`eventType === "ms.vss-code.git-pullrequest-comment-event"`) | Type-confusion: a forged work-item-comment event that contains a `/bomdrift suppress` line. |
| 3 | **Project allowlist** (`PROJECT_ALLOWLIST="<uuid>,<uuid>"` matched against `resource.pullRequest.repository.project.id`) | Foreign-project replay. |
| 4 | **Commenter-permission check** — list the project's `Contributors` team members and require the commenter id to be a member | Random outsiders on a public-readable Azure DevOps project commenting `/bomdrift suppress …`. |
| 5 | **PR-context guard** (`pullRequest.status === "active"` AND `pullRequest.targetRefName === MAIN_BRANCH` (default `refs/heads/main`)) | Suppressing findings on side-branches the org doesn't actually ship from. |

Failures return 4xx without invoking the pipeline trigger. Use
`wrangler tail` for live debugging.

## Deployment

1. `npm install -g wrangler`
2. `wrangler secret put` for each of:
   - `WEBHOOK_SECRET` — string the Service Hook will send in
     `X-Bomdrift-Bridge-Secret`.
   - `PROJECT_ALLOWLIST` — comma-separated project UUIDs.
   - `AZDO_ORG_URL` — `https://dev.azure.com/<org>`.
   - `AZDO_API_TOKEN` — PAT with `Code (Read)` and
     `Build (Read & Execute)` scopes.
   - `PIPELINE_ID` — the numeric definition id of the suppress
     pipeline (from
     `https://dev.azure.com/<org>/<project>/_apis/pipelines`).
   - `MAIN_BRANCH` (optional) — defaults to `refs/heads/main`.
3. `wrangler deploy`.
4. Add the suppress stage to `azure-pipelines.yml` (gated on
   `BOMDRIFT_NOTE_BODY` template parameter — see
   [`../azure-pipelines.yml`](../azure-pipelines.yml)).
5. In Azure DevOps → Project Settings → Service hooks: create a
   subscription with:
   - Service: **Web Hooks**
   - Trigger: **Pull request commented on**
   - Filters: target your project / repo
   - URL: the Worker URL
   - HTTP headers: `X-Bomdrift-Bridge-Secret: <WEBHOOK_SECRET>`
   - Resource details to send: **All**
6. Smoke-test by commenting `/bomdrift suppress GHSA-test-1234-aaaa`
   on an active PR. `wrangler tail` should show the guards passing.

## Azure DevOps gotchas

- **PAT lifetime.** Azure DevOps caps PAT lifetime at 1 year. Set a
  calendar reminder to rotate `AZDO_API_TOKEN`; the bridge will start
  401-ing on the membership-lookup call when it expires.
- **Identity descriptors vs. ids.** Azure DevOps surfaces both an
  `id` (UUID) and a `descriptor` (longer string) for identities. The
  Worker accepts either when matching the commenter against team
  members; some Service Hook payloads include only one.
- **`Contributors` team naming.** The default Project Contributors
  team is named `<Project> Team` on some legacy projects rather than
  `Contributors`. The Worker does a case-insensitive
  `/contributors$/` regex; if your org renamed the group, fall back
  to `teams?.value?.[0]` is used as a last resort. Adjust if your
  permission boundary is a custom group.
- **Custom pipeline parameters** are typed in Azure DevOps. The
  receiving pipeline must declare a `parameters:` block accepting
  `BOMDRIFT_NOTE_BODY` as a `string` or the run trigger 400s.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| 401 from worker | `X-Bomdrift-Bridge-Secret` mismatch with `WEBHOOK_SECRET`. |
| 403 "project not allowlisted" | UUID mismatch — copy from `https://dev.azure.com/<org>/_apis/projects?api-version=7.1`. |
| 403 "commenter not Contributor+" | Commenter is in a different group (Readers / Stakeholders). Either grant Contributor or accept the rejection. |
| 502 from worker | Pipeline trigger 4xx — usually the `PIPELINE_ID` is wrong or the pipeline doesn't accept `BOMDRIFT_NOTE_BODY` as a template parameter. |

## Hosting alternatives

See [`vercel-equivalent.md`](./vercel-equivalent.md).
