# TDS GA7 — CI/CD Container Release Gate

Deterministic policy endpoint that decides whether a GitHub Actions run may
promote a container image.

## Endpoint

`POST /release-gate` → `{"decision": "promote|block", "violations": [...]}`

`promote` only when no rule fires; otherwise `block` with the applicable codes.

## Rules → violation codes

| Rule | Code |
| --- | --- |
| Permissions must be exactly `contents:read`, `packages:write`, `id-token:none` (no extras) | `EXCESS_PERMISSION` |
| PR trigger must be `pull_request`, never `pull_request_target` | `UNSAFE_PR_TRIGGER` |
| `testsPassed` true, `matrixComplete` true, `failFast` false | `TESTS_INCOMPLETE` |
| Third-party actions must be pinned to a 40-char lowercase hex SHA (`actions`-owned may use a tag) | `MUTABLE_ACTION` |
| Image must be multi-stage | `SINGLE_STAGE_IMAGE` |
| Image must run as non-root | `ROOT_RUNTIME` |
| Build secret must be `none` or `buildkit` (not `arg`/`copy`) | `SECRET_IN_LAYER` |
| Zero critical vulnerabilities | `CRITICAL_CVE` |
| Image must be digest-pinned | `UNPINNED_IMAGE` |
| Production needs `push` on `refs/heads/main` | `INVALID_PRODUCTION_REF` |
| Production needs `workflow.environmentApproval: true` | `APPROVAL_REQUIRED` |

## Run locally

```bash
python release_gate.py        # serves on :8000
python -m unittest test_release_gate -v
```

## Deploy options

- **Cloudflare Worker** (always-on): `npx wrangler deploy` (uses `worker.js`, `wrangler.toml`)
- **Local + cloudflared tunnel**: run `release_gate.py`, expose with a quick tunnel.
