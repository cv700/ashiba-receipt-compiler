#!/usr/bin/env python3
"""Core receipt compiler smoke tests."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from constants import (
    CONTRADICTED,
    NOT_APPLICABLE,
    SUPPORTED,
    UNKNOWN,
)

from receipt_compile import (
    compile_claim,
    load_artifacts_dir_bound,
    load_artifacts_dir_with_manifest,
)

from receipt_validate import validate_receipt

from side_effect_envelope import SIDE_EFFECT_ACTION_ID_PATH

from test_support import (
    ENV,
    PYTHON,
    ROOT,
    assert_receipt,
    run_compile_process,
    run_json,
    run_process,
    run_text,
)


def test_v1_bundles() -> None:
    supported = run_json("--bundle", "examples/auth_grant_supported.json")
    assert_receipt(supported, SUPPORTED, 7, 0)
    assert supported["artifact_manifest"][0]["source"] == "bundle"
    assert supported["artifact_manifest"][0]["filename"] == "auth_grant_supported.json"
    assert supported["artifact_manifest"][0]["relative_path"] == "auth_grant_supported.json"
    assert validate_receipt(supported, source_root=ROOT / "examples") == []
    assert_receipt(run_json("--bundle", "examples/auth_grant_contradicted.json"), CONTRADICTED, 7, 0)
    assert_receipt(run_json("--bundle", "examples/auth_grant_unknown.json"), UNKNOWN, 7, 2)

    no_binding_bundle = json.loads((ROOT / "examples" / "auth_grant_supported.json").read_text(encoding="utf-8"))
    authorization = no_binding_bundle["artifacts"]["authorization"]
    authorization.pop("render_time_grant_hash")
    authorization.pop("execution_time_decision_id")
    authorization.pop("grant_active_at_execution")
    no_binding_bundle["artifacts"]["tool_call"].pop("invocation_context")
    with tempfile.TemporaryDirectory() as tmp:
        no_binding_path = Path(tmp) / "no_binding_bundle.json"
        no_binding_path.write_text(json.dumps(no_binding_bundle), encoding="utf-8")
        no_binding = run_json("--bundle", str(no_binding_path))
    assert_receipt(no_binding, UNKNOWN, 7, 0)
    binding_pass = [result for result in no_binding["pass_results"] if result["pass_id"] == "grant_binding_present"][0]
    assert binding_pass["status"] == UNKNOWN
    assert "missing authorization field" in binding_pass["detail"]

def test_v2_explicit_claim_types() -> None:
    assert_receipt(
        run_json("--artifacts-dir", "examples/auth_grant_dir_supported", "--claim-type", "authorization_bound_action"),
        SUPPORTED,
        7,
        0,
    )
    assert_receipt(
        run_json("--artifacts-dir", "examples/parser_repair_supported", "--claim-type", "parser_repair_visibility"),
        SUPPORTED,
        5,
        0,
    )
    assert_receipt(
        run_json("--artifacts-dir", "examples/parser_repair_unknown", "--claim-type", "parser_repair_visibility"),
        UNKNOWN,
        5,
        2,
    )
    assert_receipt(
        run_json("--artifacts-dir", "examples/prefix_continuity_supported", "--claim-type", "prefix_continuity"),
        SUPPORTED,
        4,
        0,
    )
    assert_receipt(
        run_json("--artifacts-dir", "examples/prefix_continuity_contradicted", "--claim-type", "prefix_continuity"),
        CONTRADICTED,
        4,
        0,
    )

def test_v2_auto_detect_and_out_dir() -> None:
    multi = run_json("--artifacts-dir", "examples/realistic_incident_001")
    receipts = multi["receipts"]
    assert len(receipts) == 2, receipts
    by_type = {receipt["claim_type"]: receipt for receipt in receipts}
    assert_receipt(by_type["authorization_bound_action"], SUPPORTED, 7, 0)
    assert_receipt(by_type["parser_repair_visibility"], SUPPORTED, 5, 0)

    with tempfile.TemporaryDirectory() as tmp:
        proc = subprocess.run(
            [PYTHON, "receipt_compile.py", "--artifacts-dir", "examples/realistic_incident_001", "--out", tmp],
            cwd=ROOT,
            env=ENV,
            check=True,
            text=True,
            capture_output=True,
        )
        assert "wrote" in proc.stdout
        assert len(list(Path(tmp).glob("*.json"))) == 2

def test_v4_adversarial_controls_and_not_applicable() -> None:
    adversarial = [
        ("adv_malformed_timestamp_unknown", UNKNOWN),
        ("adv_offset_timestamp_unknown", UNKNOWN),
        ("adv_natural_language_timestamp_unknown", UNKNOWN),
        ("adv_revoked_equal_executed_contradicted", CONTRADICTED),
        ("adv_grant_expires_equal_executed_supported", SUPPORTED),
    ]
    for directory, expected_verdict in adversarial:
        receipt = run_json(
            "--artifacts-dir",
            f"examples/{directory}",
            "--claim-type",
            "authorization_bound_action",
        )
        assert_receipt(receipt, expected_verdict, 7, 0)

    # Existing v3 adversarial controls now compile per side effect.
    mixed = run_json("--artifacts-dir", "examples/mixed_actions_incident", "--claim-type", "authorization_bound_action")
    assert [receipt["verdict"]["status"] for receipt in mixed["receipts"]] == [UNKNOWN, CONTRADICTED]
    assert [len(receipt["absence"]) for receipt in mixed["receipts"]] == [0, 0]
    assert_receipt(
        run_json("--artifacts-dir", "examples/parser_repair_unknown", "--claim-type", "parser_repair_visibility"),
        UNKNOWN,
        5,
        2,
    )

    not_applicable = run_json(
        "--artifacts-dir",
        "examples/adv_not_applicable_parser_only",
        "--claim-type",
        "authorization_bound_action",
    )
    assert_receipt(not_applicable, NOT_APPLICABLE, 1, 0)
    assert not_applicable["pass_results"][0]["pass_id"] == "claim_applicability"

    auto_detect = run_process("--artifacts-dir", "examples/adv_not_applicable_parser_only")
    assert auto_detect.returncode == 1
    assert "Traceback" not in auto_detect.stdout
    assert "Traceback" not in auto_detect.stderr
    auto_error = json.loads(auto_detect.stdout)
    assert auto_error["verdict"]["status"] == UNKNOWN
    assert "no applicable claim types detected" in auto_error["compiler_errors"][0]["detail"]

def test_source_file_binding_verification() -> None:
    v1 = run_json("--bundle", "examples/auth_grant_supported.json")
    assert validate_receipt(v1, source_root=ROOT / "examples") == []

    tampered = json.loads(json.dumps(v1))
    tampered["artifact_manifest"][0]["sha256"] = "0" * 64
    tampered_errors = validate_receipt(tampered, source_root=ROOT / "examples")
    assert "input_set_hash must match the ordered artifact_manifest records" in tampered_errors
    assert "artifact_manifest.0.sha256 does not match source file" in tampered_errors

    size_tampered = json.loads(json.dumps(v1))
    size_tampered["artifact_manifest"][0]["byte_size"] += 1
    size_errors = validate_receipt(size_tampered, source_root=ROOT / "examples")
    assert "input_set_hash must match the ordered artifact_manifest records" in size_errors
    assert "artifact_manifest.0.byte_size does not match source file" in size_errors

    artifacts, artifact_manifest, input_hash = load_artifacts_dir_with_manifest(
        ROOT / "examples" / "realistic_incident_001"
    )
    v2 = compile_claim(
        artifacts,
        "authorization_bound_action",
        artifact_manifest=artifact_manifest,
        input_set_hash=input_hash,
    ).to_dict()
    assert validate_receipt(v2, source_root=ROOT / "examples" / "realistic_incident_001") == []

    with tempfile.TemporaryDirectory() as tmp:
        receipt_path = Path(tmp) / "receipt.json"
        receipt_path.write_text(json.dumps(v2), encoding="utf-8")
        proc = subprocess.run(
            [
                PYTHON,
                "receipt_validate.py",
                "--source-root",
                "examples/realistic_incident_001",
                str(receipt_path),
            ],
            cwd=ROOT,
            env=ENV,
            check=True,
            text=True,
            capture_output=True,
        )
        assert "valid" in proc.stdout

def test_v5_incident_manifest_and_explain_output() -> None:
    example_dir = ROOT / "examples" / "cyber_renderer_authz_supported"
    loaded = load_artifacts_dir_bound(example_dir)
    assert loaded.incident_manifest["incident_id"] == "cyber-renderer-authz-001"
    assert loaded.incident_manifest["claim_types"] == ["authorization_bound_action"]
    assert sorted(loaded.artifacts) == [
        "authorization",
        "parsed_actions",
        "raw_tool_runtime_log",
        "rendered_observation",
        "tool_call",
    ]
    assert loaded.artifact_manifest[0]["source"] == "incident_manifest"
    assert any(record.get("role") == "agent_observation" for record in loaded.artifact_manifest)
    assert any(record.get("role") == "hidden_evidence" for record in loaded.artifact_manifest)

    receipt = run_json("--artifacts-dir", "examples/cyber_renderer_authz_supported")
    assert_receipt(receipt, SUPPORTED, 7, 0)
    assert receipt["incident_manifest"]["renderer"]["name"] == "prime-intellect-style-cyber-renderer-sim"
    assert validate_receipt(receipt, source_root=example_dir) == []

    explanation = run_text("--artifacts-dir", "examples/cyber_renderer_authz_supported", "--explain")
    assert "Receipt Explanation" in explanation
    assert "renderer: prime-intellect-style-cyber-renderer-sim 0.1" in explanation
    assert "role=agent_observation" in explanation
    assert "role=hidden_evidence" in explanation
    assert "Verdict: supported" in explanation

def test_one_line_compile_wrapper() -> None:
    proc = run_compile_process("examples/stripe_trick_bundle", "-v")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "CONTRADICTED"

    explained = run_compile_process("examples/stripe_trick_bundle", "-e")
    assert explained.returncode == 0, explained.stderr
    assert "CONTRADICTED: execution time" in explained.stdout
    assert "[grant_active_at_event_time]" in explained.stdout

    bundle = run_compile_process("examples/auth_grant_contradicted.json", "-v")
    assert bundle.returncode == 0, bundle.stderr
    assert bundle.stdout.strip() == "CONTRADICTED"

    with tempfile.TemporaryDirectory() as tmp:
        merged_path = Path(tmp) / "merged.json"
        merged = {}
        for path in sorted((ROOT / "examples" / "stripe_trick_bundle").glob("*.json")):
            merged.update(json.loads(path.read_text(encoding="utf-8")))
        merged_path.write_text(json.dumps(merged), encoding="utf-8")

        single_file = run_compile_process(str(merged_path), "-v")
        assert single_file.returncode == 0, single_file.stderr
        assert single_file.stdout.strip() == "CONTRADICTED"

        piped = run_compile_process("-", "-v", input_text=json.dumps(merged))
        assert piped.returncode == 0, piped.stderr
        assert piped.stdout.strip() == "CONTRADICTED"

    multi = run_compile_process("examples/realistic_incident_001", "-v")
    assert multi.returncode == 0, multi.stderr
    assert multi.stdout.splitlines() == [
        "authorization_bound_action: SUPPORTED",
        "parser_repair_visibility: SUPPORTED",
    ]

    multi_json = run_compile_process("examples/realistic_incident_001")
    assert multi_json.returncode == 0, multi_json.stderr
    receipts = json.loads(multi_json.stdout)["receipts"]
    assert sorted(receipt["claim_type"] for receipt in receipts) == [
        "authorization_bound_action",
        "parser_repair_visibility",
    ]

    renderer = run_compile_process("examples/cyber_renderer_authz_supported")
    assert renderer.returncode == 0, renderer.stderr
    renderer_receipt = json.loads(renderer.stdout)
    assert renderer_receipt["incident_manifest"]["incident_id"] == "cyber-renderer-authz-001"
    assert renderer_receipt["incident_manifest"]["renderer"]["name"] == "prime-intellect-style-cyber-renderer-sim"

def test_one_line_compile_directory_errors_do_not_traceback() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "authorization.json").write_text("{bad json", encoding="utf-8")
        malformed = run_compile_process(str(root), "--card")
        assert malformed.returncode != 0
        assert "ERROR:" in malformed.stderr
        assert "Traceback" not in malformed.stdout
        assert "Traceback" not in malformed.stderr

    with tempfile.TemporaryDirectory() as tmp:
        empty = run_compile_process(tmp, "--card")
        assert empty.returncode != 0
        assert "ERROR:" in empty.stderr
        assert "Traceback" not in empty.stdout
        assert "Traceback" not in empty.stderr

def test_gap_card_and_ci_outputs() -> None:
    missing_grant_window = run_compile_process("examples/auth_grant_unknown.json", "--gaps")
    assert missing_grant_window.returncode == 0, missing_grant_window.stderr
    assert "missing expected path: authorization.grant_valid_from" in missing_grant_window.stdout
    assert "missing expected path: authorization.grant_valid_until" in missing_grant_window.stdout
    assert "verdict effect: unknown, not contradicted" in missing_grant_window.stdout

    parser_gap = run_compile_process("examples/parser_repair_unknown", "--gaps")
    assert parser_gap.returncode == 0, parser_gap.stderr
    assert "missing expected path: parser.repair_events.0.after_hash" in parser_gap.stdout
    assert "writeback_to_model_history" in parser_gap.stdout

    explained = run_compile_process("examples/auth_grant_unknown.json", "--explain")
    assert explained.returncode == 0, explained.stderr
    assert "Missing-evidence guidance" in explained.stdout
    assert "authorization.grant_valid_from" in explained.stdout

    invalid_timestamp = run_compile_process("examples/adv_malformed_timestamp_unknown", "--gaps")
    assert invalid_timestamp.returncode == 0, invalid_timestamp.stderr
    assert "missing expected path: authorization.grant_valid_from" in invalid_timestamp.stdout
    assert "Log grant_valid_from as an ISO 8601 UTC field" in invalid_timestamp.stdout

    card = run_compile_process("examples/auth_grant_unknown.json", "--card")
    assert card.returncode == 0, card.stderr
    assert "Receipt Card" in card.stdout
    assert "Evidence present:" in card.stdout
    assert "Evidence missing:" in card.stdout
    assert "Boundary / does-not-support:" in card.stdout
    assert "Unsupported inferences:" in card.stdout

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "authorization.json").write_text(
            json.dumps({
                "authorization": {
                    "grant_id": "grant-missing-revocation-state",
                    "grant_valid_from": "2026-05-14T16:00:00Z",
                    "grant_valid_until": "2026-05-14T18:00:00Z",
                }
            }),
            encoding="utf-8",
        )
        (root / "parsed_actions.json").write_text(
            json.dumps({
                "parsed_actions": [
                    {
                        "action_id": "act-missing-revocation-state",
                        "tool": "stripe.charges.create",
                        "executed_at": "2026-05-14T17:01:30Z",
                        "source_kind": "model_output",
                    }
                ]
            }),
            encoding="utf-8",
        )
        (root / "tool_call.json").write_text(
            json.dumps({
                "tool_call": {
                    "action_id": "act-missing-revocation-state",
                    "tool_name": "stripe.charges.create",
                }
            }),
            encoding="utf-8",
        )

        revocation_gap = run_compile_process(str(root), "--gaps")
        assert revocation_gap.returncode == 0, revocation_gap.stderr
        assert "missing expected path: authorization.revoked_at" in revocation_gap.stdout
        assert "explicit null when checked and not revoked" in revocation_gap.stdout

        ci_unknown = run_compile_process(str(root), "--ci")
        assert ci_unknown.returncode == 0
        assert "UNKNOWN" in ci_unknown.stdout
        assert "CI WARNING: unknown receipt present" in ci_unknown.stderr

        ci_strict = run_compile_process(str(root), "--ci", "--strict-unknown")
        assert ci_strict.returncode == 1
        assert "CI ERROR: unknown receipt present" in ci_strict.stderr

        (root / "authorization.json").write_text(
            json.dumps({
                "authorization": {
                    "grant_id": "grant-missing-tool-binding",
                    "grant_valid_from": "2026-05-14T16:00:00Z",
                    "grant_valid_until": "2026-05-14T18:00:00Z",
                    "revoked_at": None,
                }
            }),
            encoding="utf-8",
        )
        (root / "parsed_actions.json").write_text(
            json.dumps({
                "parsed_actions": [
                    {
                        "tool": "stripe.charges.create",
                        "executed_at": "2026-05-14T17:01:30Z",
                        "source_kind": "model_output",
                    }
                ]
            }),
            encoding="utf-8",
        )
        (root / "tool_call.json").write_text(json.dumps({"tool_call": {}}), encoding="utf-8")
        tool_gap = run_compile_process(str(root), "--gaps")
        assert tool_gap.returncode == 0, tool_gap.stderr
        assert f"missing expected path: {SIDE_EFFECT_ACTION_ID_PATH}" in tool_gap.stdout

    ci_unknown = run_compile_process("examples/auth_grant_unknown.json", "--ci")
    assert ci_unknown.returncode == 0, ci_unknown.stderr
    assert "UNKNOWN" in ci_unknown.stdout
    assert "CI WARNING: unknown receipt present" in ci_unknown.stderr

    ci_contradicted = run_compile_process("examples/stripe_trick_bundle", "--ci")
    assert ci_contradicted.returncode == 1
    assert "CONTRADICTED" in ci_contradicted.stdout
    assert "CI ERROR: contradicted receipt present" in ci_contradicted.stderr


def run_receipt_core_tests() -> None:
    test_v1_bundles()
    test_v2_explicit_claim_types()
    test_v2_auto_detect_and_out_dir()
    test_v4_adversarial_controls_and_not_applicable()
    test_source_file_binding_verification()
    test_v5_incident_manifest_and_explain_output()
    test_one_line_compile_wrapper()
    test_one_line_compile_directory_errors_do_not_traceback()
    test_gap_card_and_ci_outputs()
