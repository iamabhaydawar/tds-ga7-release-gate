"""Deterministic CI/CD container release-gate policy engine.

Pure decision function `evaluate(body) -> {"decision", "violations"}` plus a
zero-dependency stdlib HTTP server exposing `POST /release-gate`.

Every rule maps to exactly one violation code. `promote` is returned only when
no rule fires; otherwise `block` with the applicable codes (order-insensitive).
"""

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# A third-party action must be pinned to a full 40-char lowercase hex commit SHA.
_SHA40 = re.compile(r"^[0-9a-f]{40}$")

# Exactly-least-privilege permission set required for a release.
_REQUIRED_PERMISSIONS = {"contents": "read", "packages": "write", "id-token": "none"}


def evaluate(body):
    """Apply all release-gate rules to a request body and return the decision."""
    if not isinstance(body, dict):
        body = {}

    violations = []

    target = body.get("target")
    event = body.get("event")
    ref = body.get("ref")
    wf = body.get("workflow") if isinstance(body.get("workflow"), dict) else {}
    img = body.get("image") if isinstance(body.get("image"), dict) else {}

    # 1. Permissions must be EXACTLY contents:read, packages:write, id-token:none.
    #    Any wrong value, missing key, or extra scope is an excess permission.
    perms = wf.get("permissions") if isinstance(wf.get("permissions"), dict) else {}
    if perms != _REQUIRED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # 2. A pull request must use `pull_request`, never `pull_request_target`.
    if wf.get("trigger") == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests must pass, the whole matrix must finish, and failFast must be false.
    if not (
        wf.get("testsPassed") is True
        and wf.get("matrixComplete") is True
        and wf.get("failFast") is False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Every third-party action must be SHA-pinned; `actions`-owned may use a tag.
    for action in wf.get("actions") or []:
        if not isinstance(action, dict):
            continue
        if action.get("owner") == "actions":
            continue
        if not _SHA40.match(str(action.get("ref", ""))):
            violations.append("MUTABLE_ACTION")
            break

    # 5. Image must be multi-stage.
    if img.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Image must run as non-root.
    if img.get("runsAsRoot") is True:
        violations.append("ROOT_RUNTIME")

    # 7. Build secrets: only `none` or `buildkit` mount; `arg`/`copy` bake into a layer.
    if img.get("secretMode") in ("arg", "copy"):
        violations.append("SECRET_IN_LAYER")

    # 8. Zero critical vulnerabilities.
    crit = img.get("criticalVulnerabilities")
    if isinstance(crit, bool) or not isinstance(crit, (int, float)):
        crit = 1 if crit else 0  # non-numeric truthy -> treat as present
    if crit > 0:
        violations.append("CRITICAL_CVE")

    # 9. Image must be referenced by digest.
    if img.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 10 & 11. Production also needs a push on refs/heads/main and env approval.
    if target == "production":
        if not (event == "push" and ref == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")
        if wf.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if not violations else "block"
    return {"decision": decision, "violations": violations}


# --------------------------------------------------------------------------- #
# HTTP server (stdlib only)
# --------------------------------------------------------------------------- #

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(204, {})

    def do_GET(self):
        if self.path.rstrip("/") in ("", "/health"):
            self._send(200, {"status": "ok", "service": "release-gate"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/release-gate":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            body = json.loads(raw or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send(400, {"error": "invalid JSON"})
            return
        self._send(200, evaluate(body))

    def log_message(self, *args):
        pass  # keep stdout quiet for tunnel log polling


def serve(host="0.0.0.0", port=8000):
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"release-gate listening on http://{host}:{port}/release-gate", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    import os

    serve(port=int(os.environ.get("PORT", "8000")))
