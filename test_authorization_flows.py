#!/usr/bin/env python3
"""Authorization receipt and reference-probe flow tests."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from constants import (
    CONTRADICTED,
    SUPPORTED,
    UNKNOWN,
)

from test_support import (
    ENV,
    PYTHON,
    ROOT,
    assert_receipt,
    run_ashiba_process,
    run_compile_process,
)


def test_authorization_decision_id_mismatch_cannot_support() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "authorization.json").write_text(
            json.dumps({
                "authorization": {
                    "grant_id": "grant-decision-mismatch",
                    "grant_valid_from": "2026-05-14T16:00:00Z",
                    "grant_valid_until": "2026-05-14T18:00:00Z",
                    "revoked_at": None,
                    "render_time_grant_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "execution_time_decision_id": "decision-expected",
                    "grant_active_at_execution": True,
                }
            }),
            encoding="utf-8",
        )
        (root / "parsed_actions.json").write_text(
            json.dumps({
                "parsed_actions": [
                    {
                        "action_id": "act-decision-mismatch",
                        "tool": "lambda.amazonaws.com:Invoke",
                        "executed_at": "2026-05-14T17:01:30Z",
                        "source_kind": "cloudtrail_event",
                    }
                ]
            }),
            encoding="utf-8",
        )
        (root / "tool_call.json").write_text(
            json.dumps({
                "tool_call": {
                    "action_id": "act-decision-mismatch",
                    "tool_name": "lambda.amazonaws.com:Invoke",
                    "invocation_context": {
                        "decision_id": "decision-other",
                    },
                }
            }),
            encoding="utf-8",
        )

        receipt = run_compile_process(str(root), "--claim-type", "authorization_bound_action")
        assert receipt.returncode == 0, receipt.stderr
        data = json.loads(receipt.stdout)
        assert data["verdict"]["status"] == CONTRADICTED
        assert data["verdict"]["status"] != SUPPORTED
        assert "grant binding decision mismatch" in data["verdict"]["basis"]

def test_authorization_missing_runtime_decision_id_cannot_support() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "authorization.json").write_text(
            json.dumps({
                "authorization": {
                    "grant_id": "grant-missing-runtime-decision",
                    "grant_valid_from": "2026-05-14T16:00:00Z",
                    "grant_valid_until": "2026-05-14T18:00:00Z",
                    "revoked_at": None,
                    "render_time_grant_hash": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "execution_time_decision_id": "decision-expected",
                    "grant_active_at_execution": True,
                }
            }),
            encoding="utf-8",
        )
        (root / "parsed_actions.json").write_text(
            json.dumps({
                "parsed_actions": [
                    {
                        "action_id": "act-missing-runtime-decision",
                        "tool": "lambda.amazonaws.com:Invoke",
                        "executed_at": "2026-05-14T17:01:30Z",
                        "source_kind": "cloudtrail_event",
                    }
                ]
            }),
            encoding="utf-8",
        )
        (root / "tool_call.json").write_text(
            json.dumps({
                "tool_call": {
                    "action_id": "act-missing-runtime-decision",
                    "tool_name": "lambda.amazonaws.com:Invoke",
                    "invocation_context": {
                        "source": "cloudtrail",
                    },
                }
            }),
            encoding="utf-8",
        )

        receipt = run_compile_process(str(root), "--claim-type", "authorization_bound_action")
        assert receipt.returncode == 0, receipt.stderr
        data = json.loads(receipt.stdout)
        assert data["verdict"]["status"] == UNKNOWN
        assert data["verdict"]["status"] != SUPPORTED
        assert "missing tool-call field: side_effects.0.invocation.decision_id" in data["verdict"]["basis"]
        gaps = run_compile_process(str(root), "--claim-type", "authorization_bound_action", "--gaps")
        assert gaps.returncode == 0, gaps.stderr
        assert "missing expected path: side_effects.0.invocation.decision_id" in gaps.stdout

def test_hero_authorization_demo_packets() -> None:
    before = run_ashiba_process(
        "scan",
        "readiness_packets/hero_authz_before_2026-05-26/logs",
        "--policy",
        "readiness_packets/hero_authz_before_2026-05-26/policy.json",
        "--json",
    )
    assert before.returncode == 0, before.stderr
    before_result = json.loads(before.stdout)
    assert before_result["summary"]["actions_found"] == 1
    assert before_result["summary"]["actions_decidable"] == 0
    assert before_result["summary"]["actions_blocked"] == 1
    assert before_result["can_decide"] == []
    blocked_claims = {item["claim"]: item["missing"] for item in before_result["cannot_decide"]}
    assert blocked_claims["authorization_bound_action"] == [
        "authorization.revoked_at",
        "authorization-to-action binding",
    ]
    before_action = before_result["actions"][0]
    assert before_action["action_id"] == "hero-authz-charge-001"
    assert before_action["decidable"] is False
    assert before_action["can_decide"] == []
    assert before_action["cannot_decide"][0]["missing"] == [
        "authorization.revoked_at",
        "authorization-to-action binding",
    ]

    after = run_ashiba_process(
        "scan",
        "readiness_packets/hero_authz_after_2026-05-26/logs",
        "--policy",
        "readiness_packets/hero_authz_after_2026-05-26/policy.json",
        "--json",
    )
    assert after.returncode == 0, after.stderr
    after_result = json.loads(after.stdout)
    assert after_result["summary"]["actions_found"] == 1
    assert after_result["summary"]["actions_decidable"] == 1
    assert after_result["summary"]["actions_blocked"] == 0
    assert "authorization_bound_action" in after_result["can_decide"]
    assert after_result["cannot_decide"] == []
    after_action = after_result["actions"][0]
    assert after_action["action_id"] == "hero-authz-charge-001"
    assert after_action["decidable"] is True
    assert "authorization_bound_action" in after_action["can_decide"]

    receipt = run_compile_process(
        "readiness_packets/hero_authz_supported_2026-05-26/artifacts",
        "--claim-type",
        "authorization_bound_action",
    )
    assert receipt.returncode == 0, receipt.stderr
    receipt_data = json.loads(receipt.stdout)
    assert_receipt(receipt_data, SUPPORTED, 7, 0)
    assert receipt_data["artifacts"]["tool_call"]["action_id"] == "hero-authz-charge-001"
    assert (
        receipt_data["artifacts"]["tool_call"]["invocation_context"]["decision_id"]
        == receipt_data["artifacts"]["authorization"]["execution_time_decision_id"]
    )

def test_reference_authorization_boundary_probe_fills_hero_evidence_gap() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "probe_packet"
        probe = subprocess.run(
            [
                PYTHON,
                "examples/probes/authorization_boundary_probe.py",
                "--policy",
                "readiness_packets/hero_authz_before_2026-05-26/policy.json",
                "--cloudtrail",
                "readiness_packets/hero_authz_before_2026-05-26/logs/cloudtrail_lambda_invoke.json",
                "--out",
                str(out_dir),
            ],
            cwd=ROOT,
            env=ENV,
            text=True,
            capture_output=True,
        )
        assert probe.returncode == 0, probe.stderr
        assert "Authorization boundary probe emitted boundary evidence" in probe.stdout
        assert "grant_active_at_execution: true" in probe.stdout

        scan = run_ashiba_process("scan", str(out_dir / "logs"), "--policy", str(out_dir / "policy.json"), "--json")
        assert scan.returncode == 0, scan.stderr
        scan_result = json.loads(scan.stdout)
        assert scan_result["summary"]["actions_found"] == 1
        assert scan_result["summary"]["actions_decidable"] == 1
        assert scan_result["summary"]["actions_blocked"] == 0
        assert scan_result["can_decide"] == ["authorization_bound_action"]
        assert scan_result["cannot_decide"] == []

        receipt = run_compile_process(
            str(out_dir / "artifacts"),
            "--claim-type",
            "authorization_bound_action",
        )
        assert receipt.returncode == 0, receipt.stderr
        receipt_data = json.loads(receipt.stdout)
        assert_receipt(receipt_data, SUPPORTED, 7, 0)
        assert (
            receipt_data["artifacts"]["tool_call"]["invocation_context"]["decision_id"]
            == receipt_data["artifacts"]["authorization"]["execution_time_decision_id"]
        )

def test_reference_authorization_boundary_probe_preserves_contradiction() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "revoked_probe_packet"
        probe = subprocess.run(
            [
                PYTHON,
                "examples/probes/authorization_boundary_probe.py",
                "--policy",
                "readiness_packets/hero_authz_before_2026-05-26/policy.json",
                "--cloudtrail",
                "readiness_packets/hero_authz_before_2026-05-26/logs/cloudtrail_lambda_invoke.json",
                "--revoked-at",
                "2026-05-14T17:00:30Z",
                "--out",
                str(out_dir),
            ],
            cwd=ROOT,
            env=ENV,
            text=True,
            capture_output=True,
        )
        assert probe.returncode == 0, probe.stderr
        assert "grant_active_at_execution: false" in probe.stdout

        scan = run_ashiba_process("scan", str(out_dir / "logs"), "--policy", str(out_dir / "policy.json"), "--json")
        assert scan.returncode == 0, scan.stderr
        scan_result = json.loads(scan.stdout)
        assert scan_result["summary"]["actions_decidable"] == 1
        assert scan_result["summary"]["actions_blocked"] == 0
        assert scan_result["can_decide"] == ["authorization_bound_action"]

        receipt = run_compile_process(
            str(out_dir / "artifacts"),
            "--claim-type",
            "authorization_bound_action",
            "--verdict",
        )
        assert receipt.returncode == 0, receipt.stderr
        assert receipt.stdout.strip() == "CONTRADICTED"

def test_reference_authorization_boundary_probe_fails_closed_on_bad_revocation_time() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "bad_revocation_packet"
        probe = subprocess.run(
            [
                PYTHON,
                "examples/probes/authorization_boundary_probe.py",
                "--policy",
                "readiness_packets/hero_authz_before_2026-05-26/policy.json",
                "--cloudtrail",
                "readiness_packets/hero_authz_before_2026-05-26/logs/cloudtrail_lambda_invoke.json",
                "--revoked-at",
                "yesterday",
                "--out",
                str(out_dir),
            ],
            cwd=ROOT,
            env=ENV,
            text=True,
            capture_output=True,
        )
        assert probe.returncode == 1
        assert "revoked_at must be ISO 8601" in probe.stderr
        assert not out_dir.exists()


def run_authorization_flow_tests() -> None:
    test_authorization_decision_id_mismatch_cannot_support()
    test_authorization_missing_runtime_decision_id_cannot_support()
    test_hero_authorization_demo_packets()
    test_reference_authorization_boundary_probe_fills_hero_evidence_gap()
    test_reference_authorization_boundary_probe_preserves_contradiction()
    test_reference_authorization_boundary_probe_fails_closed_on_bad_revocation_time()
