/* Cloudflare Worker — Bitbucket Cloud comment-driven suppress bridge.
 *
 * Five guards before triggering the bomdrift suppress pipeline:
 *   1. Webhook HMAC verification (X-Hub-Signature, sha256=<hex>),
 *      constant-time compared against HMAC_SHA256(WEBHOOK_SECRET, body).
 *   2. Event-type filter (X-Event-Key === "pullrequest:comment_created").
 *   3. Repo-full-name allowlist (REPO_ALLOWLIST="org/repo,org/other").
 *   4. Commenter-permission check via /2.0/workspaces/<ws>/permissions
 *      → require permission ∈ {"write","admin"}.
 *   5. PR-context guard: pullrequest.state === "OPEN" AND
 *      source.repository.full_name === destination.repository.full_name
 *      (rejects fork-PR comment-suppress).
 *
 * Required secrets:
 *   WEBHOOK_SECRET, REPO_ALLOWLIST, BITBUCKET_API_TOKEN,
 *   BITBUCKET_TRIGGER_USER (bot account_id, optional — used only in
 *   logging), SUPPRESS_PIPELINE_REF (branch/ref to run the custom
 *   pipeline on; defaults to the PR source branch).
 *
 * Reference: https://support.atlassian.com/bitbucket-cloud/docs/event-payloads/
 */

// Suppress-comment regex. CANONICAL DEFINITION lives in
// scripts/parse-suppress-comment.sh — keep these in sync.
// CI guard: scripts/check-suppress-regex-sync.sh diffs the two.
const BOMDRIFT_SUPPRESS_REGEX = /^\s*\/bomdrift\s+suppress\s+([A-Za-z0-9-]+)(\s+reason:\s*(.+))?\s*$/m;

export default {
  async fetch(request, env) {
    if (request.method !== "POST") return new Response("method", { status: 405 });

    // Read body as raw bytes — Bitbucket signs the byte-exact request body,
    // so any JSON re-serialization would invalidate the HMAC.
    const rawBody = await request.arrayBuffer();

    // Guard 1: HMAC verification.
    const sigHeader = request.headers.get("X-Hub-Signature") ?? "";
    if (!(await verifyHubSignature(env.WEBHOOK_SECRET ?? "", rawBody, sigHeader))) {
      return new Response("forbidden", { status: 401 });
    }

    // Guard 2: event-type filter.
    if ((request.headers.get("X-Event-Key") ?? "") !== "pullrequest:comment_created") {
      return new Response("ignored", { status: 204 });
    }

    let body;
    try {
      body = JSON.parse(new TextDecoder().decode(rawBody));
    } catch {
      return new Response("bad json", { status: 400 });
    }

    // Guard 3: repo allowlist.
    const repoFull = body?.repository?.full_name ?? "";
    const allow = (env.REPO_ALLOWLIST ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    if (!repoFull || !allow.includes(repoFull)) {
      return new Response("repo not allowlisted", { status: 403 });
    }

    // Guard 5: PR-context.
    const pr = body?.pullrequest;
    if (!pr || pr.state !== "OPEN") {
      return new Response("not an open PR", { status: 204 });
    }
    const srcRepo = pr?.source?.repository?.full_name;
    const dstRepo = pr?.destination?.repository?.full_name;
    if (!srcRepo || !dstRepo || srcRepo !== dstRepo) {
      return new Response("fork-PR refused", { status: 403 });
    }

    // Quick parse: comment looks like a directive?
    const text = body?.comment?.content?.raw ?? "";
    if (!BOMDRIFT_SUPPRESS_REGEX.test(text)) {
      return new Response("no directive", { status: 204 });
    }

    // Guard 4: commenter-permission lookup.
    const commenterId = body?.actor?.account_id ?? body?.actor?.uuid;
    if (!commenterId) return new Response("no commenter id", { status: 400 });
    const [workspace] = repoFull.split("/", 1);
    // The user-permission endpoint accepts q=user.account_id="<id>".
    const permUrl = `https://api.bitbucket.org/2.0/workspaces/${encodeURIComponent(workspace)}/permissions?q=${encodeURIComponent(`user.account_id="${commenterId}"`)}`;
    const permResp = await fetch(permUrl, {
      headers: {
        Authorization: `Basic ${btoa(`x-token-auth:${env.BITBUCKET_API_TOKEN}`)}`,
        Accept: "application/json",
      },
    });
    if (!permResp.ok) return new Response("permission lookup failed", { status: 403 });
    const perm = await permResp.json();
    const permission = perm?.values?.[0]?.permission ?? "";
    if (permission !== "write" && permission !== "admin" && permission !== "owner") {
      return new Response("commenter not write/admin", { status: 403 });
    }

    // All guards passed. Trigger a custom pipeline on the PR source branch
    // with BOMDRIFT_NOTE_BODY set to the raw comment body. The custom
    // pipeline (defined in bitbucket-pipelines.yml) invokes
    // `bomdrift baseline add --from-comment "$BOMDRIFT_NOTE_BODY"`.
    const ref = env.SUPPRESS_PIPELINE_REF || pr?.source?.branch?.name || "main";
    const triggerUrl = `https://api.bitbucket.org/2.0/repositories/${repoFull}/pipelines/`;
    const trigPayload = {
      target: {
        type: "pipeline_ref_target",
        ref_type: "branch",
        ref_name: ref,
        selector: { type: "custom", pattern: "bomdrift-comment-suppress" },
      },
      variables: [
        { key: "BOMDRIFT_NOTE_BODY", value: text, secured: false },
      ],
    };
    const trig = await fetch(triggerUrl, {
      method: "POST",
      headers: {
        Authorization: `Basic ${btoa(`x-token-auth:${env.BITBUCKET_API_TOKEN}`)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(trigPayload),
    });
    if (!trig.ok) return new Response("pipeline trigger failed", { status: 502 });
    return new Response("triggered", { status: 204 });
  },
};

// Verify Bitbucket's X-Hub-Signature header. Format: "sha256=<hex>".
async function verifyHubSignature(secret, body, header) {
  if (!secret || !header) return false;
  const expectedPrefix = "sha256=";
  if (!header.startsWith(expectedPrefix)) return false;
  const providedHex = header.slice(expectedPrefix.length).trim().toLowerCase();
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, body);
  const computedHex = [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return constantTimeEqual(providedHex, computedHex);
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return acc === 0;
}
