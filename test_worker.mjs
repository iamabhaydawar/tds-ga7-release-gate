// Exercises the ACTUAL worker.js fetch handler using Node's built-in
// Request/Response (undici). Run: node test_worker.mjs
import worker from "./worker.js";

let pass = 0, fail = 0;
async function post(body) {
  const req = new Request("https://x/release-gate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const res = await worker.fetch(req);
  return res.json();
}
function eq(name, got, want) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) { pass++; console.log("ok  ", name); }
  else { fail++; console.log("FAIL", name, "\n  got ", g, "\n  want", w); }
}

const safePreview = {
  target: "preview", event: "pull_request", ref: "refs/heads/f",
  workflow: {
    trigger: "pull_request",
    permissions: { contents: "read", packages: "write", "id-token": "none" },
    testsPassed: true, matrixComplete: true, failFast: false,
    actions: [
      { owner: "actions", name: "checkout", ref: "v4" },
      { owner: "docker", name: "bp", ref: "a".repeat(40) },
    ],
  },
  image: { multiStage: true, runsAsRoot: false, secretMode: "buildkit", criticalVulnerabilities: 0, digestPinned: true },
};

const safeProd = {
  target: "production", event: "push", ref: "refs/heads/main",
  workflow: {
    trigger: "push",
    permissions: { contents: "read", packages: "write", "id-token": "none" },
    testsPassed: true, matrixComplete: true, failFast: false, environmentApproval: true,
    actions: [{ owner: "actions", name: "checkout", ref: "v4" }],
  },
  image: { multiStage: true, runsAsRoot: false, secretMode: "none", criticalVulnerabilities: 0, digestPinned: true },
};

const clone = (o) => JSON.parse(JSON.stringify(o));
const sortV = (r) => ({ decision: r.decision, violations: [...r.violations].sort() });

// safe
eq("safe preview promotes", await post(safePreview), { decision: "promote", violations: [] });
eq("safe production promotes", await post(safeProd), { decision: "promote", violations: [] });

// single failures
let p = clone(safePreview); p.workflow.permissions.actions = "read";
eq("excess permission", await post(p), { decision: "block", violations: ["EXCESS_PERMISSION"] });

p = clone(safePreview); p.workflow.permissions = { contents: "write", packages: "write", "id-token": "none" };
eq("wrong perm value", await post(p), { decision: "block", violations: ["EXCESS_PERMISSION"] });

p = clone(safePreview); p.workflow.trigger = "pull_request_target";
eq("unsafe trigger", await post(p), { decision: "block", violations: ["UNSAFE_PR_TRIGGER"] });

p = clone(safePreview); p.workflow.failFast = true;
eq("failFast", await post(p), { decision: "block", violations: ["TESTS_INCOMPLETE"] });

p = clone(safePreview); p.workflow.actions = [{ owner: "docker", name: "x", ref: "v5" }];
eq("mutable tag", await post(p), { decision: "block", violations: ["MUTABLE_ACTION"] });

p = clone(safePreview); p.workflow.actions = [{ owner: "docker", name: "x", ref: "A".repeat(40) }];
eq("uppercase sha mutable", await post(p), { decision: "block", violations: ["MUTABLE_ACTION"] });

p = clone(safePreview); p.image.multiStage = false;
eq("single stage", await post(p), { decision: "block", violations: ["SINGLE_STAGE_IMAGE"] });

p = clone(safePreview); p.image.runsAsRoot = true;
eq("root", await post(p), { decision: "block", violations: ["ROOT_RUNTIME"] });

p = clone(safePreview); p.image.secretMode = "arg";
eq("secret arg", await post(p), { decision: "block", violations: ["SECRET_IN_LAYER"] });

p = clone(safePreview); p.image.criticalVulnerabilities = 2;
eq("cve", await post(p), { decision: "block", violations: ["CRITICAL_CVE"] });

p = clone(safePreview); p.image.digestPinned = false;
eq("unpinned", await post(p), { decision: "block", violations: ["UNPINNED_IMAGE"] });

p = clone(safeProd); p.ref = "refs/heads/release";
eq("invalid prod ref", await post(p), { decision: "block", violations: ["INVALID_PRODUCTION_REF"] });

p = clone(safeProd); p.workflow.environmentApproval = false;
eq("approval required", await post(p), { decision: "block", violations: ["APPROVAL_REQUIRED"] });

// multi
const multi = {
  target: "production", event: "pull_request", ref: "refs/heads/dev",
  workflow: {
    trigger: "pull_request_target", permissions: { contents: "write" },
    testsPassed: false, matrixComplete: true, failFast: true, environmentApproval: false,
    actions: [{ owner: "evil", name: "x", ref: "v1" }],
  },
  image: { multiStage: false, runsAsRoot: true, secretMode: "copy", criticalVulnerabilities: 7, digestPinned: false },
};
eq("all 11", sortV(await post(multi)), {
  decision: "block",
  violations: [
    "APPROVAL_REQUIRED", "CRITICAL_CVE", "EXCESS_PERMISSION", "INVALID_PRODUCTION_REF",
    "MUTABLE_ACTION", "ROOT_RUNTIME", "SECRET_IN_LAYER", "SINGLE_STAGE_IMAGE",
    "TESTS_INCOMPLETE", "UNPINNED_IMAGE", "UNSAFE_PR_TRIGGER",
  ].sort(),
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
