#!/usr/bin/env python3
"""Readiness scanner tests."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from test_support import (
    ENV,
    ROOT,
    run_ashiba_process,
    run_compile_process,
    run_import_cloudtrail_process,
)


def test_ashiba_scan_readiness_gaps() -> None:
    root = Path("readiness_packets/deployment_ready_auth_gaps_2026-05-18")
    proc = run_ashiba_process("scan", str(root / "logs"), "--policy", str(root / "policy.json"))
    assert proc.returncode == 0, proc.stderr
    assert "Ashiba scan" in proc.stdout
    assert "Summary:\n- Files scanned: 2\n- Side-effect actions found: 1" in proc.stdout
    assert "- Receipt-ready actions: 0" in proc.stdout
    assert "- Blocked actions: 1" in proc.stdout
    assert "Action groups:\n- 0 receipt-ready, 1 blocked" in proc.stdout
    assert "Top missing evidence:" in proc.stdout
    assert "Punch list:\n- add revocation_state export (1 action blocked)" in proc.stdout
    assert "- Claim families ready: deployment_matches_reviewed_commit" in proc.stdout
    assert "- Claim families blocked: authorization_bound_action" in proc.stdout
    assert "authorization.revoked_at: 1 action blocked -> add revocation_state export" in proc.stdout
    assert (
        "authorization-to-action binding: 1 action blocked -> "
        "carry authorization execution_time_decision_id into the tool call"
    ) in proc.stdout

def test_ashiba_scan_readiness_json_packets() -> None:
    auth_ready = Path("readiness_packets/authorization_ready_no_deployment_2026-05-18")
    proc = run_ashiba_process("scan", str(auth_ready / "logs"), "--policy", str(auth_ready / "policy.json"), "--json")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert "authorization_bound_action" in result["can_decide"]
    assert "human_approval_before_external_side_effect" in result["can_decide"]
    assert "deployment_matches_reviewed_commit" not in result["can_decide"]
    assert all(c["claim"] != "deployment_matches_reviewed_commit" for c in result["cannot_decide"])

    decidable_negative = Path("readiness_packets/authorization_revoked_deployment_mismatch_2026-05-18")
    proc = run_ashiba_process(
        "scan",
        str(decidable_negative / "logs"),
        "--policy",
        str(decidable_negative / "policy.json"),
        "--json",
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert "deployment_matches_reviewed_commit" in result["can_decide"]
    assert "authorization_bound_action" in result["can_decide"]
    assert result["cannot_decide"] == []
    assert result["probeable_next"] == []

def test_ashiba_scan_action_readiness_json() -> None:
    root = Path("readiness_packets/two_action_approval_gap_2026-05-18")
    proc = run_ashiba_process("scan", str(root / "logs"), "--policy", str(root / "policy.json"), "--json")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)

    actions = {action["action_id"]: action for action in result["actions"]}
    assert set(actions) == {"cloudtrail-evt-approved", "cloudtrail-evt-missing-approval"}

    approved = actions["cloudtrail-evt-approved"]
    assert approved["decidable"] is True
    assert approved["source_kind"] == "cloudtrail"
    assert "authorization_bound_action" in approved["can_decide"]
    assert approved["cannot_decide"] == []

    missing_authorization_binding = actions["cloudtrail-evt-missing-approval"]
    assert missing_authorization_binding["decidable"] is False
    assert missing_authorization_binding["can_decide"] == []
    blocked_claims = {c["claim"] for c in missing_authorization_binding["cannot_decide"]}
    assert "authorization_bound_action" in blocked_claims
    assert (
        "carry authorization execution_time_decision_id into the tool call"
        in missing_authorization_binding["probeable_next"]
    )
    assert result["summary"]["actions_found"] == 2
    assert result["summary"]["actions_decidable"] == 1
    assert result["summary"]["actions_blocked"] == 1
    assert "CloudTrail" in result["summary"]["input_kinds"]
    assert (
        "carry authorization execution_time_decision_id into the tool call (1 action blocked)"
        in result["punch_list"]
    )

def test_ashiba_scan_uses_claim_pack_roots_for_file_shaped_artifacts() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "parser.json").write_text(
            json.dumps({
                "repair_events": [
                    {
                        "repair_id": "repair-scan-root",
                        "repair_function": "normalize_json",
                        "before_hash": "sha256:before",
                        "after_hash": "sha256:after",
                        "writeback_to_model_history": False,
                    }
                ]
            }),
            encoding="utf-8",
        )

        proc = run_ashiba_process("scan", str(root), "--json")
        assert proc.returncode == 0, proc.stderr
        result = json.loads(proc.stdout)
        assert "parser_repair_visibility" in result["can_decide"]
        assert result["cannot_decide"] == []
        assert result["summary"]["input_kinds"]["Ashiba/evidence artifact"] == 1
        assert result["detected_inputs"][0]["evidence"] == ["parser"]

def test_ashiba_scan_claim_packs_dir_extends_artifact_roots() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        pack_dir = root / "claim_packs"
        pack_dir.mkdir()
        logs = root / "logs"
        logs.mkdir()
        (pack_dir / "external_scan_pack.json").write_text(
            json.dumps({
                "schema_version": "receipt-claim-pack-v0.1",
                "name": "external_scan_pack",
                "renderer_family": "agent_trace_integrity",
                "claim": {
                    "id": "claim.external_scan_pack",
                    "text": "External scanner claim pack evidence was present.",
                },
                "expected_evidence": ["external_scan_marker.value"],
                "applicability_evidence": ["external_scan_marker"],
                "passes": [
                    "utc_timestamp_format",
                    "expected_evidence_absence",
                    "no_future_evidence",
                ],
                "pass_params": {},
            }),
            encoding="utf-8",
        )
        (logs / "external_scan_marker.json").write_text(
            json.dumps({"value": "present"}),
            encoding="utf-8",
        )

        default_scan = run_ashiba_process("scan", str(logs), "--json")
        assert default_scan.returncode == 0, default_scan.stderr
        default_result = json.loads(default_scan.stdout)
        assert "external_scan_pack" not in default_result["can_decide"]
        assert default_result["detected_inputs"][0]["kinds"] == ["unrecognized JSON"]

        external_scan = run_ashiba_process(
            "scan",
            str(logs),
            "--claim-packs-dir",
            str(pack_dir),
            "--json",
        )
        assert external_scan.returncode == 0, external_scan.stderr
        external_result = json.loads(external_scan.stdout)
        assert "external_scan_pack" in external_result["can_decide"]
        assert external_result["cannot_decide"] == []
        assert external_result["detected_inputs"][0]["evidence"] == ["external_scan_marker"]

def test_ashiba_scan_requires_cross_boundary_authorization_decision_id() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        logs = root / "logs"
        logs.mkdir()
        policy = root / "policy.json"
        policy.write_text(
            json.dumps({
                "grant_id": "grant-cross-boundary",
                "grant_valid_from": "2026-05-14T16:00:00Z",
                "grant_valid_until": "2026-05-14T18:00:00Z",
                "revoked_at": None,
                "render_time_grant_hash": "sha256:crossboundarygrant",
                "execution_time_decision_id": "authz-decision-123",
                "grant_active_at_execution": True,
            }),
            encoding="utf-8",
        )
        (logs / "cloudtrail.json").write_text(
            json.dumps({
                "Records": [
                    {
                        "eventID": "act-matched-authz",
                        "eventSource": "lambda.amazonaws.com",
                        "eventName": "Invoke",
                        "eventTime": "2026-05-14T17:01:30Z",
                        "requestParameters": {"decision_id": "authz-decision-123"},
                    },
                    {
                        "eventID": "act-approval-only",
                        "eventSource": "lambda.amazonaws.com",
                        "eventName": "Invoke",
                        "eventTime": "2026-05-14T17:02:30Z",
                    },
                    {
                        "eventID": "act-mismatched-authz",
                        "eventSource": "lambda.amazonaws.com",
                        "eventName": "Invoke",
                        "eventTime": "2026-05-14T17:03:30Z",
                        "requestParameters": {"decision_id": "authz-decision-999"},
                    },
                ]
            }),
            encoding="utf-8",
        )
        (logs / "approval.json").write_text(
            json.dumps({
                "approval": {
                    "approval_id": "approval-for-human-claim",
                    "tool_call_id": "act-approval-only",
                    "approved_at": "2026-05-14T17:00:00Z",
                    "decision": "approved",
                    "actor": "ops@example.com",
                }
            }),
            encoding="utf-8",
        )

        proc = run_ashiba_process("scan", str(logs), "--policy", str(policy), "--json")
        assert proc.returncode == 0, proc.stderr
        result = json.loads(proc.stdout)
        actions = {action["action_id"]: action for action in result["actions"]}

        assert "authorization_bound_action" in actions["act-matched-authz"]["can_decide"]

        approval_only = actions["act-approval-only"]
        assert "human_approval_before_external_side_effect" in approval_only["can_decide"]
        assert "authorization_bound_action" in {
            item["claim"] for item in approval_only["cannot_decide"]
        }
        assert (
            "carry authorization execution_time_decision_id into the tool call"
            in approval_only["probeable_next"]
        )

        mismatched = actions["act-mismatched-authz"]
        assert "authorization_bound_action" in {
            item["claim"] for item in mismatched["cannot_decide"]
        }
        assert (
            "carry authorization execution_time_decision_id into the tool call"
            in mismatched["probeable_next"]
        )

def test_ashiba_scan_compile_authorization_invariant() -> None:
    scan = run_ashiba_process(
        "scan",
        "examples/cloudtrail_sample.json",
        "--policy",
        "examples/real_world_policy_sample.json",
        "--json",
    )
    assert scan.returncode == 0, scan.stderr
    scan_result = json.loads(scan.stdout)
    blocked_claims = {item["claim"] for item in scan_result["cannot_decide"]}
    assert "authorization_bound_action" in blocked_claims

    imported = run_import_cloudtrail_process(
        "examples/cloudtrail_sample.json",
        "--policy",
        "examples/real_world_policy_sample.json",
    )
    assert imported.returncode == 0, imported.stderr
    compiled = run_compile_process("-", "-v", input_text=imported.stdout)
    assert compiled.returncode == 0, compiled.stderr
    assert compiled.stdout.strip() != "SUPPORTED"
    assert compiled.stdout.strip() == "UNKNOWN"

def test_importer_preserves_scanner_ready_authorization_binding() -> None:
    root = Path("readiness_packets/authorization_ready_no_deployment_2026-05-18")

    scan = run_ashiba_process("scan", str(root / "logs"), "--policy", str(root / "policy.json"), "--json")
    assert scan.returncode == 0, scan.stderr
    assert "authorization_bound_action" in json.loads(scan.stdout)["can_decide"]

    imported = run_import_cloudtrail_process(
        str(root / "logs" / "cloudtrail_lambda_invoke.json"),
        "--policy",
        str(root / "policy.json"),
    )
    assert imported.returncode == 0, imported.stderr
    artifacts = json.loads(imported.stdout)
    assert artifacts["authorization"]["render_time_grant_hash"] == "sha256:authorizationreadygrant"
    assert artifacts["authorization"]["execution_time_decision_id"] == "authz-decision-approved-charge"
    assert artifacts["authorization"]["grant_active_at_execution"] is True
    assert artifacts["tool_call"]["invocation_context"]["decision_id"] == "authz-decision-approved-charge"

    compiled = run_compile_process("-", "--claim-type", "authorization_bound_action", "--verdict", input_text=imported.stdout)
    assert compiled.returncode == 0, compiled.stderr
    assert compiled.stdout.strip() == "SUPPORTED"

def test_ashiba_scan_does_not_infer_human_approval_from_actions_only() -> None:
    proc = run_ashiba_process(
        "scan",
        "examples/cloudtrail_sample.json",
        "--policy",
        "examples/real_world_policy_sample.json",
        "--json",
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert "human_approval_before_external_side_effect" not in result["can_decide"]
    assert all(
        item["claim"] != "human_approval_before_external_side_effect"
        for item in result["cannot_decide"]
    )
    assert all(
        item["claim"] != "human_approval_before_external_side_effect"
        for action in result["actions"]
        for item in action["cannot_decide"]
    )

def test_ashiba_scan_punch_list_includes_missing_approval_probes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        logs = root / "logs"
        logs.mkdir()
        policy = root / "policy.json"
        policy.write_text(
            json.dumps({
                "grant_id": "grant-approval-probe",
                "grant_valid_from": "2026-05-14T16:00:00Z",
                "grant_valid_until": "2026-05-14T18:00:00Z",
                "revoked_at": None,
            }),
            encoding="utf-8",
        )
        (logs / "cloudtrail.json").write_text(
            json.dumps({
                "Records": [
                    {
                        "eventID": "act-missing-approval-fields",
                        "eventSource": "lambda.amazonaws.com",
                        "eventName": "Invoke",
                        "eventTime": "2026-05-14T17:01:30Z",
                    }
                ]
            }),
            encoding="utf-8",
        )
        (logs / "approval.json").write_text(
            json.dumps({
                "approval": {
                    "approval_id": "approval-missing-fields",
                    "tool_call_id": "act-missing-approval-fields",
                }
            }),
            encoding="utf-8",
        )

        proc = run_ashiba_process("scan", str(logs), "--policy", str(policy), "--json")
        assert proc.returncode == 0, proc.stderr
        result = json.loads(proc.stdout)
        assert "human_approval_before_external_side_effect" in {
            item["claim"] for item in result["cannot_decide"]
        }
        assert "log human approval timestamp as UTC (1 action blocked)" in result["punch_list"]
        assert "log approval decision (approved/rejected) (1 action blocked)" in result["punch_list"]
        assert "log the identity of the human approver (1 action blocked)" in result["punch_list"]

def test_ashiba_scan_surfaces_conflicting_scalar_evidence() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        logs = root / "logs"
        logs.mkdir()
        policy = root / "policy.json"
        policy.write_text(
            json.dumps({
                "grant_id": "grant-conflict",
                "grant_valid_from": "2026-05-14T16:00:00Z",
                "grant_valid_until": "2026-05-14T18:00:00Z",
                "revoked_at": None,
                "render_time_grant_hash": "sha256:conflict-grant",
                "execution_time_decision_id": "authz-decision-123",
                "grant_active_at_execution": True,
            }),
            encoding="utf-8",
        )
        (logs / "cloudtrail.json").write_text(
            json.dumps({
                "Records": [
                    {
                        "eventID": "act-conflicting-authz",
                        "eventSource": "lambda.amazonaws.com",
                        "eventName": "Invoke",
                        "eventTime": "2026-05-14T17:01:30Z",
                        "requestParameters": {"decision_id": "authz-decision-123"},
                    }
                ]
            }),
            encoding="utf-8",
        )
        (logs / "authorization_conflict.json").write_text(
            json.dumps({
                "authorization": {
                    "execution_time_decision_id": "authz-decision-999",
                }
            }),
            encoding="utf-8",
        )

        proc = run_ashiba_process("scan", str(logs), "--policy", str(policy), "--json")
        assert proc.returncode == 0, proc.stderr
        result = json.loads(proc.stdout)
        assert result["evidence_conflicts"]
        conflict = result["evidence_conflicts"][0]
        assert conflict["path"] == "authorization.execution_time_decision_id"
        assert conflict["existing"] == "authz-decision-123"
        assert conflict["incoming"] == "authz-decision-999"
        assert "authorization_bound_action" in {item["claim"] for item in result["cannot_decide"]}
        auth_gap = [item for item in result["cannot_decide"] if item["claim"] == "authorization_bound_action"][0]
        assert auth_gap["missing"] == []
        assert auth_gap["conflicts"] == ["authorization.execution_time_decision_id"]
        action_gap = [
            item
            for item in result["actions"][0]["cannot_decide"]
            if item["claim"] == "authorization_bound_action"
        ][0]
        assert action_gap["conflicts"] == ["authorization.execution_time_decision_id"]

        text = run_ashiba_process("scan", str(logs), "--policy", str(policy))
        assert text.returncode == 0, text.stderr
        assert "Evidence conflicts:" in text.stdout
        assert "authorization.execution_time_decision_id" in text.stdout

def test_ashiba_scan_detects_common_action_formats() -> None:
    cases = [
        ("examples/otel_span_sample.jsonl", "OpenTelemetry", "opentelemetry", "otel_call_01HXstripeCharge"),
        ("examples/event_log_sample.jsonl", "agent event log", "agent_event_log", "evt_call_01HXstripeCharge"),
        ("examples/event_log_array_sample.json", "agent event log", "agent_event_log", "evt_call_01HXarrayStripeCharge"),
        ("examples/kubernetes_audit_sample.jsonl", "Kubernetes audit", "kubernetes_audit", "k8s-audit-01HXexec"),
        ("examples/siem_sample.jsonl", "SIEM JSONL", "siem_jsonl", "siem-evt-01HX"),
    ]
    for path, input_kind, source_kind, action_id in cases:
        proc = run_ashiba_process("scan", path, "--json")
        assert proc.returncode == 0, proc.stderr
        result = json.loads(proc.stdout)
        assert result["summary"]["actions_found"] == 1
        assert result["summary"]["input_kinds"][input_kind] == 1
        assert result["actions"][0]["source_kind"] == source_kind
        assert result["actions"][0]["action_id"] == action_id

def test_ashiba_scan_invalid_inputs_exit_nonzero() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "bad.json").write_text("{bad json", encoding="utf-8")

        proc = run_ashiba_process("scan", str(root))
        assert proc.returncode == 1
        assert "Traceback" not in proc.stderr
        assert "input status: no_parseable_inputs" in proc.stdout
        assert "problem: no usable log files were parsed" in proc.stdout
        assert "skipped invalid or unrecognized JSON file" in proc.stdout

        proc = run_ashiba_process("scan", str(root), "--json")
        assert proc.returncode == 1
        assert "Traceback" not in proc.stderr
        result = json.loads(proc.stdout)
        assert result["input_status"] == "no_parseable_inputs"
        assert result["summary"]["input_status"] == "no_parseable_inputs"
        assert result["warnings"]

    with tempfile.TemporaryDirectory() as tmp:
        proc = run_ashiba_process("scan", tmp, "--json")
        assert proc.returncode == 1
        result = json.loads(proc.stdout)
        assert result["input_status"] == "no_parseable_inputs"
        assert any("no candidate log files found" in warning for warning in result["warnings"])

def test_demo_30s_script() -> None:
    proc = subprocess.run(
        ["bash", "demo_30s.sh"],
        cwd=ROOT,
        env=ENV,
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "== 1. Before: scan missing authorization boundary telemetry ==" in proc.stdout
    assert "== 2. After: scan with revocation state and action binding ==" in proc.stdout
    assert "== 3. Compile a bounded receipt card for the same action ==" in proc.stdout
    assert "== 4. Bad input fails closed ==" in proc.stdout
    assert "BLOCKED hero-authz-charge-001" in proc.stdout
    assert "missing authorization.revoked_at, authorization-to-action binding" in proc.stdout
    assert "READY hero-authz-charge-001" in proc.stdout
    assert "Claim families ready: authorization_bound_action, human_approval_before_external_side_effect" in proc.stdout
    assert "Report preview:" in proc.stdout
    assert "Ashiba Evidence Readiness Report" in proc.stdout
    assert "Receipt Card" in proc.stdout
    assert "Verdict: supported" in proc.stdout
    assert "Bad input produced nonzero exit as expected." in proc.stdout

def test_demo_reference_probe_script() -> None:
    proc = subprocess.run(
        ["bash", "demo_reference_probe.sh"],
        cwd=ROOT,
        env=ENV,
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "== 1. Existing logs: authorization claim is blocked ==" in proc.stdout
    assert "== 2. Run reference authorization-boundary probe ==" in proc.stdout
    assert "== 3. Probe output: authorization claim is receipt-ready ==" in proc.stdout
    assert "== 4. Compile bounded receipt from probe artifacts ==" in proc.stdout
    assert "== 5. Epistemic check: decidable does not mean supported ==" in proc.stdout
    assert "BLOCKED hero-authz-charge-001" in proc.stdout
    assert "READY hero-authz-charge-001" in proc.stdout
    assert "Verdict: supported" in proc.stdout
    assert proc.stdout.rstrip().endswith("CONTRADICTED")

def test_ashiba_scan_report_mode() -> None:
    root = Path("readiness_packets/deployment_ready_auth_gaps_2026-05-18")
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "report"
        proc = run_ashiba_process(
            "scan",
            str(root / "logs"),
            "--policy",
            str(root / "policy.json"),
            "--report",
            "--out",
            str(out_dir),
        )
        assert proc.returncode == 0, proc.stderr
        assert "Report written:" in proc.stdout

        md_path = out_dir / "ashiba_report.md"
        json_path = out_dir / "ashiba_report.json"
        assert md_path.exists()
        assert json_path.exists()

        markdown = md_path.read_text(encoding="utf-8")
        assert "# Ashiba Evidence Readiness Report" in markdown
        assert "authorization.revoked_at" in markdown
        assert "authorization-to-action binding" in markdown
        assert "Suggested log shape:" in markdown
        assert "This report is a readiness scan, not a receipt verdict." in markdown

        report = json.loads(json_path.read_text(encoding="utf-8"))
        assert report["schema_version"] == "ashiba-scan-report-v0.1"
        assert report["summary"]["input_status"] == "ok"
        missing = {item["missing"]: item for item in report["missing_evidence"]}
        assert "authorization.revoked_at" in missing
        assert "authorization-to-action binding" in missing
        assert missing["authorization-to-action binding"]["action_count"] == 1


def run_scan_tests() -> None:
    test_ashiba_scan_readiness_gaps()
    test_ashiba_scan_readiness_json_packets()
    test_ashiba_scan_action_readiness_json()
    test_ashiba_scan_uses_claim_pack_roots_for_file_shaped_artifacts()
    test_ashiba_scan_claim_packs_dir_extends_artifact_roots()
    test_ashiba_scan_requires_cross_boundary_authorization_decision_id()
    test_ashiba_scan_compile_authorization_invariant()
    test_importer_preserves_scanner_ready_authorization_binding()
    test_ashiba_scan_does_not_infer_human_approval_from_actions_only()
    test_ashiba_scan_punch_list_includes_missing_approval_probes()
    test_ashiba_scan_surfaces_conflicting_scalar_evidence()
    test_ashiba_scan_detects_common_action_formats()
    test_ashiba_scan_invalid_inputs_exit_nonzero()
    test_demo_30s_script()
    test_demo_reference_probe_script()
    test_ashiba_scan_report_mode()
