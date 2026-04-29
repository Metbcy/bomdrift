/* Cloudflare Worker — GitLab comment-driven suppress bridge.
 *
 * Five guards before triggering the bomdrift suppress pipeline:
 *   1. Webhook secret (constant-time compare).
 *   2. Event-type filter (Note Hook only).
 *   3. Project-ID allowlist.
 *   4. Commenter access_level >= 30.
 *   5. MR-context guard (state=opened AND target_project_id===project.id).
 *
 * Required secrets:
 *   WEBHOOK_SECRET, PROJECT_ALLOWLIST, GITLAB_API_URL, BOT_API_TOKEN,
 *   PIPELINE_TRIGGER_TOKEN.
 */

export default {
  async fetch(request, env) {
    if (request.method !== "POST") return new Response("method", { status: 405 });

    // Guard 1.
    const provided = request.headers.get("X-Gitlab-Token") ?? "";
    if (!constantTimeEqual(provided, env.WEBHOOK_SECRET ?? "")) {
      return new Response("forbidden", { status: 401 });
    }

    // Guard 2.
    if ((request.headers.get("X-Gitlab-Event") ?? "") !== "Note Hook") {
      return new Response("ignored", { status: 204 });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return new Response("bad json", { status: 400 });
    }

    // Guard 3.
    const projectId = body?.project?.id;
    const allow = (env.PROJECT_ALLOWLIST ?? "").split(",").map((s) => s.trim());
    if (!projectId || !allow.includes(String(projectId))) {
      return new Response("project not allowlisted", { status: 403 });
    }

    // Guard 5.
    const mr = body?.merge_request;
    if (!mr || mr.state !== "opened") {
      return new Response("not an open MR", { status: 204 });
    }
    if (mr.target_project_id !== projectId) {
      return new Response("fork-MR refused", { status: 403 });
    }

    // Quick parse: comment looks like a directive?
    const text = body?.object_attributes?.note ?? "";
    if (!/\/bomdrift\s+suppress\s+\S+/.test(text)) {
      return new Response("no directive", { status: 204 });
    }

    // Guard 4.
    const userId = body?.user?.id ?? body?.object_attributes?.author_id;
    if (!userId) return new Response("no commenter id", { status: 400 });
    const memberUrl = `${env.GITLAB_API_URL}/api/v4/projects/${projectId}/members/all/${userId}`;
    const memberResp = await fetch(memberUrl, {
      headers: { "PRIVATE-TOKEN": env.BOT_API_TOKEN },
    });
    if (!memberResp.ok) return new Response("permission lookup failed", { status: 403 });
    const member = await memberResp.json();
    if ((member.access_level ?? 0) < 30) {
      return new Response("commenter not Developer+", { status: 403 });
    }

    // All guards passed. Trigger the pipeline. The directive body is
    // forwarded as `BOMDRIFT_NOTE_BODY`; the suppress job invokes
    // `bomdrift baseline add --from-comment "$BOMDRIFT_NOTE_BODY"`.
    const triggerUrl = `${env.GITLAB_API_URL}/api/v4/projects/${projectId}/trigger/pipeline`;
    const ref = mr.source_branch ?? "main";
    const form = new FormData();
    form.append("token", env.PIPELINE_TRIGGER_TOKEN);
    form.append("ref", ref);
    form.append("variables[BOMDRIFT_NOTE_BODY]", text);
    const trig = await fetch(triggerUrl, { method: "POST", body: form });
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
