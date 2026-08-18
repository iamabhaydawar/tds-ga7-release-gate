// Cloudflare Worker version of the release-gate policy engine.
// Identical logic to release_gate.py. Deploy with:  npx wrangler deploy
// Endpoint: POST /release-gate  ->  {"decision","violations":[...]}

const SHA40 = /^[0-9a-f]{40}$/;
const REQUIRED_PERMISSIONS = { contents: "read", packages: "write", "id-token": "none" };

function permsMatch(perms) {
  if (typeof perms !== "object" || perms === null) return false;
  const keys = Object.keys(perms);
  if (keys.length !== 3) return false;
  return (
    perms.contents === "read" &&
    perms.packages === "write" &&
    perms["id-token"] === "none"
  );
}

function evaluate(body) {
  if (typeof body !== "object" || body === null) body = {};
  const violations = [];
  const { target, event, ref } = body;
  const wf = typeof body.workflow === "object" && body.workflow ? body.workflow : {};
  const img = typeof body.image === "object" && body.image ? body.image : {};

  if (!permsMatch(wf.permissions)) violations.push("EXCESS_PERMISSION");

  if (wf.trigger === "pull_request_target") violations.push("UNSAFE_PR_TRIGGER");

  if (!(wf.testsPassed === true && wf.matrixComplete === true && wf.failFast === false))
    violations.push("TESTS_INCOMPLETE");

  for (const a of wf.actions || []) {
    if (!a || typeof a !== "object") continue;
    if (a.owner === "actions") continue;
    if (!SHA40.test(String(a.ref ?? ""))) {
      violations.push("MUTABLE_ACTION");
      break;
    }
  }

  if (img.multiStage !== true) violations.push("SINGLE_STAGE_IMAGE");
  if (img.runsAsRoot === true) violations.push("ROOT_RUNTIME");
  if (img.secretMode === "arg" || img.secretMode === "copy")
    violations.push("SECRET_IN_LAYER");

  let crit = img.criticalVulnerabilities;
  if (typeof crit !== "number") crit = crit ? 1 : 0;
  if (crit > 0) violations.push("CRITICAL_CVE");

  if (img.digestPinned !== true) violations.push("UNPINNED_IMAGE");

  if (target === "production") {
    if (!(event === "push" && ref === "refs/heads/main"))
      violations.push("INVALID_PRODUCTION_REF");
    if (wf.environmentApproval !== true) violations.push("APPROVAL_REQUIRED");
  }

  return { decision: violations.length ? "block" : "promote", violations };
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS")
      return new Response(null, { status: 204, headers: CORS });

    if (request.method === "GET" && (path === "/" || path === "/health"))
      return Response.json({ status: "ok", service: "release-gate" }, { headers: CORS });

    if (request.method === "POST" && path === "/release-gate") {
      let body;
      try {
        body = await request.json();
      } catch {
        return Response.json({ error: "invalid JSON" }, { status: 400, headers: CORS });
      }
      return Response.json(evaluate(body), { headers: CORS });
    }

    return Response.json({ error: "not found" }, { status: 404, headers: CORS });
  },
};
