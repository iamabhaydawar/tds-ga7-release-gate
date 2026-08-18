"""Tests for the release-gate policy engine, covering safe, single-failure,
and multi-failure payloads."""

import copy
import unittest

from release_gate import evaluate

SAFE_PREVIEW = {
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/heads/feature",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [
            {"owner": "actions", "name": "checkout", "ref": "v4"},
            {"owner": "docker", "name": "build-push-action",
             "ref": "a" * 40},
        ],
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "buildkit",
        "criticalVulnerabilities": 0,
        "digestPinned": True,
    },
}

SAFE_PRODUCTION = {
    "target": "production",
    "event": "push",
    "ref": "refs/heads/main",
    "workflow": {
        "trigger": "push",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "environmentApproval": True,
        "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}],
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "none",
        "criticalVulnerabilities": 0,
        "digestPinned": True,
    },
}


def with_wf(base, **kw):
    d = copy.deepcopy(base)
    d["workflow"].update(kw)
    return d


def with_img(base, **kw):
    d = copy.deepcopy(base)
    d["image"].update(kw)
    return d


class SafeCases(unittest.TestCase):
    def test_safe_preview_promotes(self):
        self.assertEqual(evaluate(SAFE_PREVIEW),
                         {"decision": "promote", "violations": []})

    def test_safe_production_promotes(self):
        self.assertEqual(evaluate(SAFE_PRODUCTION),
                         {"decision": "promote", "violations": []})


class SingleFailure(unittest.TestCase):
    def one(self, payload, code):
        r = evaluate(payload)
        self.assertEqual(r["decision"], "block")
        self.assertEqual(r["violations"], [code])

    def test_excess_permission_extra_scope(self):
        self.one(with_wf(SAFE_PREVIEW, permissions={
            "contents": "read", "packages": "write", "id-token": "none",
            "actions": "read"}), "EXCESS_PERMISSION")

    def test_excess_permission_wrong_value(self):
        self.one(with_wf(SAFE_PREVIEW, permissions={
            "contents": "write", "packages": "write", "id-token": "none"}),
            "EXCESS_PERMISSION")

    def test_unsafe_pr_trigger(self):
        self.one(with_wf(SAFE_PREVIEW, trigger="pull_request_target"),
                 "UNSAFE_PR_TRIGGER")

    def test_tests_not_passed(self):
        self.one(with_wf(SAFE_PREVIEW, testsPassed=False), "TESTS_INCOMPLETE")

    def test_matrix_incomplete(self):
        self.one(with_wf(SAFE_PREVIEW, matrixComplete=False), "TESTS_INCOMPLETE")

    def test_failfast_true(self):
        self.one(with_wf(SAFE_PREVIEW, failFast=True), "TESTS_INCOMPLETE")

    def test_mutable_third_party_tag(self):
        self.one(with_wf(SAFE_PREVIEW, actions=[
            {"owner": "docker", "name": "x", "ref": "v5"}]), "MUTABLE_ACTION")

    def test_mutable_uppercase_sha(self):
        self.one(with_wf(SAFE_PREVIEW, actions=[
            {"owner": "docker", "name": "x", "ref": "A" * 40}]), "MUTABLE_ACTION")

    def test_actions_owner_tag_ok(self):
        self.assertEqual(evaluate(with_wf(SAFE_PREVIEW, actions=[
            {"owner": "actions", "name": "checkout", "ref": "v4"}]))["violations"],
            [])

    def test_single_stage(self):
        self.one(with_img(SAFE_PREVIEW, multiStage=False), "SINGLE_STAGE_IMAGE")

    def test_root_runtime(self):
        self.one(with_img(SAFE_PREVIEW, runsAsRoot=True), "ROOT_RUNTIME")

    def test_secret_arg(self):
        self.one(with_img(SAFE_PREVIEW, secretMode="arg"), "SECRET_IN_LAYER")

    def test_secret_copy(self):
        self.one(with_img(SAFE_PREVIEW, secretMode="copy"), "SECRET_IN_LAYER")

    def test_critical_cve(self):
        self.one(with_img(SAFE_PREVIEW, criticalVulnerabilities=3), "CRITICAL_CVE")

    def test_unpinned_image(self):
        self.one(with_img(SAFE_PREVIEW, digestPinned=False), "UNPINNED_IMAGE")

    def test_invalid_production_ref_wrong_ref(self):
        p = copy.deepcopy(SAFE_PRODUCTION)
        p["ref"] = "refs/heads/release"
        self.one(p, "INVALID_PRODUCTION_REF")

    def test_invalid_production_ref_wrong_event(self):
        p = copy.deepcopy(SAFE_PRODUCTION)
        p["event"] = "pull_request"
        self.one(p, "INVALID_PRODUCTION_REF")

    def test_approval_required(self):
        self.one(with_wf(SAFE_PRODUCTION, environmentApproval=False),
                 "APPROVAL_REQUIRED")


class MultiFailure(unittest.TestCase):
    def test_many(self):
        payload = {
            "target": "production",
            "event": "pull_request",
            "ref": "refs/heads/dev",
            "workflow": {
                "trigger": "pull_request_target",
                "permissions": {"contents": "write"},
                "testsPassed": False,
                "matrixComplete": True,
                "failFast": True,
                "environmentApproval": False,
                "actions": [{"owner": "evil", "name": "x", "ref": "v1"}],
            },
            "image": {
                "multiStage": False,
                "runsAsRoot": True,
                "secretMode": "copy",
                "criticalVulnerabilities": 7,
                "digestPinned": False,
            },
        }
        r = evaluate(payload)
        self.assertEqual(r["decision"], "block")
        self.assertEqual(set(r["violations"]), {
            "EXCESS_PERMISSION", "UNSAFE_PR_TRIGGER", "TESTS_INCOMPLETE",
            "MUTABLE_ACTION", "SINGLE_STAGE_IMAGE", "ROOT_RUNTIME",
            "SECRET_IN_LAYER", "CRITICAL_CVE", "UNPINNED_IMAGE",
            "INVALID_PRODUCTION_REF", "APPROVAL_REQUIRED",
        })

    def test_production_safe_but_root(self):
        r = evaluate(with_img(SAFE_PRODUCTION, runsAsRoot=True))
        self.assertEqual(r["violations"], ["ROOT_RUNTIME"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
