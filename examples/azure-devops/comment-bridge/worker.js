/* Cloudflare Worker — Azure DevOps comment-driven suppress bridge.
 *
 * Five guards before triggering the bomdrift suppress pipeline:
 *   1. Webhook secret verification: custom header X-Bomdrift-Bridge-Secret
 *      (set in the Service Hooks subscription's "Custom HTTP headers"
 *      field), constant-time compared against env.WEBHOOK_SECRET.
 *   2. Event-type filter (eventType === "ms.vss-code.git-pullrequest-comment-event").
 *   3. Project allowlist (resource.pullRequest.repository.project.id ∈
 *      PROJECT_ALLOWLIST, comma-separated UUIDs).
 *   4. Commenter-permission check via /_apis/projects/{projectId}/teams
 *      and /_apis/identities — require the commenter to be a member
 *      of the project's Contributors group (or above).
 *   5. PR-context guard: pullRequest.status === "active" AND
 *      pullRequest.targetRefName matches MAIN_BRANCH (default
 *      "refs/heads/main"). Rejects spurious comments on draft PRs
 *      targeting non-default branches.
 *
 * Required secrets:
 *   WEBHOOK_SECRET, PROJECT_ALLOWLIST, AZDO_ORG_URL,
 *   AZDO_API_TOKEN (PAT with Code Read + Build Execute),
 *   PIPELINE_ID (the numeric definition id of the suppress pipeline),
 *   MAIN_BRANCH (optional, default refs/heads/main).
 *
 * Reference: https://learn.microsoft.com/en-us/azure/devops/service-hooks/events
 */

// Suppress-comment regex. CANONICAL DEFINITION lives in
// scripts/parse-suppress-comment.sh — keep these in sync.
// CI guard: scripts/check-suppress-regex-sync.sh diffs the two.
const BOMDRIFT_SUPPRESS_REGEX = /^\s*\/bomdrift\s+suppress\s+([A-Za-z0-9-]+)(\s+reason:\s*(.+))?\s*$/m;

export default {
  async fetch(request, env) {
    if (request.method !== "POST") return new Response("method", { status: 405 });

    // Guard 1: webhook secret.
    const provided = request.headers.get("X-Bomdrift-Bridge-Secret") ?? "";
    if (!constantTimeEqual(provided, env.WEBHOOK_SECRET ?? "")) {
      return new Response("forbidden", { status: 401 });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return new Response("bad json", { status: 400 });
    }

    // Guard 2: event-type.
    if (body?.eventType !== "ms.vss-code.git-pullrequest-comment-event") {
      return new Response("ignored", { status: 204 });
    }

    // Guard 3: project allowlist.
    const projectId = body?.resource?.pullRequest?.repository?.project?.id;
    const allow = (env.PROJECT_ALLOWLIST ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    if (!projectId || !allow.includes(projectId)) {
      return new Response("project not allowlisted", { status: 403 });
    }

    // Guard 5: PR-context.
    const pr = body?.resource?.pullRequest;
    const mainBranch = env.MAIN_BRANCH || "refs/heads/main";
    if (!pr || pr.status !== "active") {
      return new Response("not an active PR", { status: 204 });
    }
    if (pr.targetRefName !== mainBranch) {
      return new Response("PR not targeting protected main branch", { status: 403 });
    }

    // Quick parse: comment looks like a directive?
    const text = body?.resource?.comment?.content ?? "";
    if (!BOMDRIFT_SUPPRESS_REGEX.test(text)) {
      return new Response("no directive", { status: 204 });
    }

    // Guard 4: commenter-permission via project membership.
    const commenter =
      body?.resource?.comment?.author?.id ??
      body?.resource?.comment?.author?.descriptor;
    if (!commenter) return new Response("no commenter id", { status: 400 });
    const orgUrl = (env.AZDO_ORG_URL ?? "").replace(/\/$/, "");
    if (!orgUrl) return new Response("AZDO_ORG_URL unset", { status: 500 });
    const authHeader = `Basic ${btoa(`:${env.AZDO_API_TOKEN}`)}`;
    // The simplest "is this a project member" probe is the project teams
    // membership check: list members of the project's Contributors team
    // and look for the commenter's id. On most orgs the Contributors
    // group is exactly the right "can push code / can /bomdrift
    // suppress" privilege boundary.
    const teamUrl = `${orgUrl}/_apis/projects/${encodeURIComponent(projectId)}/teams?api-version=7.1`;
    const teamsResp = await fetch(teamUrl, {
      headers: { Authorization: authHeader, Accept: "application/json" },
    });
    if (!teamsResp.ok) return new Response("teams lookup failed", { status: 403 });
    const teams = await teamsResp.json();
    const contributors =
      teams?.value?.find((t) => /contributors$/i.test(t.name)) ??
      teams?.value?.[0];
    if (!contributors?.id) return new Response("no contributors team", { status: 403 });
    const memberUrl = `${orgUrl}/_apis/projects/${encodeURIComponent(projectId)}/teams/${contributors.id}/members?api-version=7.1`;
    const memberResp = await fetch(memberUrl, {
      headers: { Authorization: authHeader, Accept: "application/json" },
    });
    if (!memberResp.ok) return new Response("member lookup failed", { status: 403 });
    const members = await memberResp.json();
    const isMember = (members?.value ?? []).some(
      (m) => m?.identity?.id === commenter || m?.identity?.descriptor === commenter,
    );
    if (!isMember) {
      return new Response("commenter not Contributor+", { status: 403 });
    }

    // All guards passed. Trigger the suppress pipeline run with
    // BOMDRIFT_NOTE_BODY as a template parameter.
    const projectName = body?.resource?.pullRequest?.repository?.project?.name ?? projectId;
    const pipelineId = env.PIPELINE_ID;
    if (!pipelineId) return new Response("PIPELINE_ID unset", { status: 500 });
    const triggerUrl = `${orgUrl}/${encodeURIComponent(projectName)}/_apis/pipelines/${encodeURIComponent(pipelineId)}/runs?api-version=7.1`;
    const trigPayload = {
      resources: {
        repositories: {
          self: { refName: pr.sourceRefName },
        },
      },
      templateParameters: {
        BOMDRIFT_NOTE_BODY: text,
      },
    };
    const trig = await fetch(triggerUrl, {
      method: "POST",
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(trigPayload),
    });
    if (!trig.ok) return new Response("pipeline trigger failed", { status: 502 });
    return new Response("triggered", { status: 204 });
  },
};

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return acc === 0;
}
