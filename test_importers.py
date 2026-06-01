#!/usr/bin/env python3
"""Importer bridge and hardening tests."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from test_support import (
    ENV,
    PYTHON,
    ROOT,
    run_compile_process,
    run_import_anthropic_process,
    run_import_cloudtrail_process,
    run_import_eventlog_process,
    run_import_github_actions_process,
    run_import_kubernetes_process,
    run_import_langsmith_process,
    run_import_openai_process,
    run_import_otel_process,
    run_import_siem_process,
)


def test_anthropic_importer_bridge() -> None:
    response_path = ROOT / "examples" / "anthropic_response_sample.json"
    policy_arg = ("--policy", "examples/policy_sample.json")

    imported = run_import_anthropic_process("examples/anthropic_response_sample.json", *policy_arg)
    assert imported.returncode == 0, imported.stderr
    artifacts = json.loads(imported.stdout)
    assert sorted(artifacts) == ["authorization", "parsed_actions", "tool_call"]
    assert artifacts["parsed_actions"][0]["executed_at"] == "2026-05-14T17:01:30Z"

    verdict = run_compile_process("-", "-v", input_text=imported.stdout)
    assert verdict.returncode == 0, verdict.stderr
    assert verdict.stdout.strip() == "CONTRADICTED"

    from_stdin = run_import_anthropic_process(
        "-",
        *policy_arg,
        input_text=response_path.read_text(encoding="utf-8"),
    )
    assert from_stdin.returncode == 0, from_stdin.stderr
    stdin_verdict = run_compile_process("-", "-v", input_text=from_stdin.stdout)
    assert stdin_verdict.returncode == 0, stdin_verdict.stderr
    assert stdin_verdict.stdout.strip() == "CONTRADICTED"

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "anthropic_artifacts"
        written = run_import_anthropic_process(
            "examples/anthropic_response_sample.json",
            *policy_arg,
            "--out",
            str(out_dir),
        )
        assert written.returncode == 0, written.stderr
        assert (out_dir / "authorization.json").is_file()
        assert (out_dir / "parsed_actions.json").is_file()
        assert (out_dir / "tool_call.json").is_file()
        out_verdict = run_compile_process(str(out_dir), "-v")
        assert out_verdict.returncode == 0, out_verdict.stderr
        assert out_verdict.stdout.strip() == "CONTRADICTED"

        out_receipt = run_compile_process(str(out_dir), "--pretty")
        assert out_receipt.returncode == 0, out_receipt.stderr
        receipt_path = Path(tmp) / "receipt.json"
        receipt_path.write_text(out_receipt.stdout, encoding="utf-8")
        validate = subprocess.run(
            [PYTHON, "receipt_validate.py", "--source-root", str(out_dir), str(receipt_path)],
            cwd=ROOT,
            env=ENV,
            check=True,
            text=True,
            capture_output=True,
        )
        assert "valid" in validate.stdout

def test_anthropic_importer_missing_timestamp_fails_closed() -> None:
    response = json.loads((ROOT / "examples" / "anthropic_response_sample.json").read_text(encoding="utf-8"))
    response.pop("created_at", None)
    input_text = json.dumps(response)

    missing_time = run_import_anthropic_process(
        "-",
        "--policy",
        "examples/policy_sample.json",
        input_text=input_text,
    )
    assert missing_time.returncode == 1
    assert missing_time.stdout == ""
    assert "no execution timestamp found" in missing_time.stderr

    supplied_time = run_import_anthropic_process(
        "-",
        "--policy",
        "examples/policy_sample.json",
        "--executed-at",
        "2026-05-14T16:59:00Z",
        input_text=input_text,
    )
    assert supplied_time.returncode == 0, supplied_time.stderr
    verdict = run_compile_process("-", "-v", input_text=supplied_time.stdout)
    assert verdict.returncode == 0, verdict.stderr
    assert verdict.stdout.strip() == "UNKNOWN"

def test_openai_importer_bridge() -> None:
    policy_arg = ("--policy", "examples/policy_sample.json")

    imported = run_import_openai_process("examples/openai_response_sample.json", *policy_arg)
    assert imported.returncode == 0, imported.stderr
    artifacts = json.loads(imported.stdout)
    assert sorted(artifacts) == ["authorization", "parsed_actions", "tool_call"]
    assert artifacts["parsed_actions"][0]["action_id"] == "call_01HXopenaiStripeCharge"
    assert artifacts["parsed_actions"][0]["executed_at"] == "2026-05-14T17:01:30Z"
    assert artifacts["tool_call"]["tool_version"] == "openai-responses-api"

    verdict = run_compile_process("-", "-v", input_text=imported.stdout)
    assert verdict.returncode == 0, verdict.stderr
    assert verdict.stdout.strip() == "CONTRADICTED"

    chat_imported = run_import_openai_process("examples/openai_chat_completion_sample.json", *policy_arg)
    assert chat_imported.returncode == 0, chat_imported.stderr
    chat_artifacts = json.loads(chat_imported.stdout)
    assert chat_artifacts["parsed_actions"][0]["action_id"] == "call_01HXchatStripeCharge"
    assert chat_artifacts["parsed_actions"][0]["executed_at"] == "2026-05-14T17:01:30Z"
    assert chat_artifacts["tool_call"]["tool_version"] == "openai-chat-completions"
    chat_verdict = run_compile_process("-", "-v", input_text=chat_imported.stdout)
    assert chat_verdict.returncode == 0, chat_verdict.stderr
    assert chat_verdict.stdout.strip() == "CONTRADICTED"

    response_path = ROOT / "examples" / "openai_response_sample.json"
    from_stdin = run_import_openai_process(
        "-",
        *policy_arg,
        input_text=response_path.read_text(encoding="utf-8"),
    )
    assert from_stdin.returncode == 0, from_stdin.stderr
    stdin_verdict = run_compile_process("-", "-v", input_text=from_stdin.stdout)
    assert stdin_verdict.returncode == 0, stdin_verdict.stderr
    assert stdin_verdict.stdout.strip() == "CONTRADICTED"

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "openai_artifacts"
        written = run_import_openai_process(
            "examples/openai_response_sample.json",
            *policy_arg,
            "--out",
            str(out_dir),
        )
        assert written.returncode == 0, written.stderr
        assert (out_dir / "authorization.json").is_file()
        assert (out_dir / "parsed_actions.json").is_file()
        assert (out_dir / "tool_call.json").is_file()
        out_verdict = run_compile_process(str(out_dir), "-v")
        assert out_verdict.returncode == 0, out_verdict.stderr
        assert out_verdict.stdout.strip() == "CONTRADICTED"

def test_openai_importer_missing_timestamp_fails_closed() -> None:
    response = json.loads((ROOT / "examples" / "openai_response_sample.json").read_text(encoding="utf-8"))
    response.pop("created_at", None)
    input_text = json.dumps(response)

    missing_time = run_import_openai_process(
        "-",
        "--policy",
        "examples/policy_sample.json",
        input_text=input_text,
    )
    assert missing_time.returncode == 1
    assert missing_time.stdout == ""
    assert "no execution timestamp found" in missing_time.stderr

    supplied_time = run_import_openai_process(
        "-",
        "--policy",
        "examples/policy_sample.json",
        "--executed-at",
        "2026-05-14T16:59:00Z",
        input_text=input_text,
    )
    assert supplied_time.returncode == 0, supplied_time.stderr
    verdict = run_compile_process("-", "-v", input_text=supplied_time.stdout)
    assert verdict.returncode == 0, verdict.stderr
    assert verdict.stdout.strip() == "UNKNOWN"

def test_eventlog_importer_bridge() -> None:
    policy_arg = ("--policy", "examples/policy_sample.json")

    imported = run_import_eventlog_process("examples/event_log_sample.jsonl", *policy_arg)
    assert imported.returncode == 0, imported.stderr
    artifacts = json.loads(imported.stdout)
    assert sorted(artifacts) == ["authorization", "parsed_actions", "tool_call"]
    assert artifacts["parsed_actions"][0]["action_id"] == "evt_call_01HXstripeCharge"
    assert artifacts["parsed_actions"][0]["executed_at"] == "2026-05-14T17:01:30Z"
    assert artifacts["tool_call"]["tool_version"] == "generic-event-log"
    verdict = run_compile_process("-", "-v", input_text=imported.stdout)
    assert verdict.returncode == 0, verdict.stderr
    assert verdict.stdout.strip() == "CONTRADICTED"

    array_imported = run_import_eventlog_process("examples/event_log_array_sample.json", *policy_arg)
    assert array_imported.returncode == 0, array_imported.stderr
    array_artifacts = json.loads(array_imported.stdout)
    assert array_artifacts["parsed_actions"][0]["action_id"] == "evt_call_01HXarrayStripeCharge"
    assert array_artifacts["parsed_actions"][0]["executed_at"] == "2026-05-14T17:01:30Z"

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "eventlog_artifacts"
        written = run_import_eventlog_process("examples/event_log_sample.jsonl", *policy_arg, "--out", str(out_dir))
        assert written.returncode == 0, written.stderr
        assert (out_dir / "authorization.json").is_file()
        assert (out_dir / "parsed_actions.json").is_file()
        assert (out_dir / "tool_call.json").is_file()
        out_verdict = run_compile_process(str(out_dir), "-v")
        assert out_verdict.returncode == 0, out_verdict.stderr
        assert out_verdict.stdout.strip() == "CONTRADICTED"

def test_eventlog_importer_missing_timestamp_fails_closed() -> None:
    event = {
        "type": "tool_call",
        "tool_call_id": "evt_call_missing_time",
        "tool_name": "stripe.charges.create",
        "arguments": {"amount": 2499},
    }
    input_text = json.dumps({"events": [event]})
    missing_time = run_import_eventlog_process(
        "-",
        "--policy",
        "examples/policy_sample.json",
        input_text=input_text,
    )
    assert missing_time.returncode == 1
    assert missing_time.stdout == ""
    assert "no execution timestamp found" in missing_time.stderr

    supplied_time = run_import_eventlog_process(
        "-",
        "--policy",
        "examples/policy_sample.json",
        "--executed-at",
        "2026-05-14T16:59:00Z",
        input_text=input_text,
    )
    assert supplied_time.returncode == 0, supplied_time.stderr
    verdict = run_compile_process("-", "-v", input_text=supplied_time.stdout)
    assert verdict.returncode == 0, verdict.stderr
    assert verdict.stdout.strip() == "UNKNOWN"

def test_langsmith_importer_bridge() -> None:
    policy_arg = ("--policy", "examples/policy_sample.json")

    imported = run_import_langsmith_process("examples/langsmith_trace_sample.json", *policy_arg)
    assert imported.returncode == 0, imported.stderr
    artifacts = json.loads(imported.stdout)
    assert sorted(artifacts) == ["authorization", "parsed_actions", "tool_call"]
    assert artifacts["parsed_actions"][0]["action_id"] == "run_tool_01HXstripeCharge"
    assert artifacts["parsed_actions"][0]["executed_at"] == "2026-05-14T17:01:30Z"
    assert artifacts["tool_call"]["tool_version"] == "langsmith-trace-export"
    verdict = run_compile_process("-", "-v", input_text=imported.stdout)
    assert verdict.returncode == 0, verdict.stderr
    assert verdict.stdout.strip() == "CONTRADICTED"

    trace_path = ROOT / "examples" / "langsmith_trace_sample.json"
    from_stdin = run_import_langsmith_process(
        "-",
        *policy_arg,
        input_text=trace_path.read_text(encoding="utf-8"),
    )
    assert from_stdin.returncode == 0, from_stdin.stderr
    stdin_verdict = run_compile_process("-", "-v", input_text=from_stdin.stdout)
    assert stdin_verdict.returncode == 0, stdin_verdict.stderr
    assert stdin_verdict.stdout.strip() == "CONTRADICTED"

def test_langsmith_importer_missing_timestamp_fails_closed() -> None:
    trace = {
        "id": "run_root_missing_time",
        "run_type": "chain",
        "child_runs": [
            {
                "id": "run_tool_missing_time",
                "name": "stripe.charges.create",
                "run_type": "tool",
                "inputs": {"amount": 2499},
            }
        ],
    }
    input_text = json.dumps(trace)
    missing_time = run_import_langsmith_process(
        "-",
        "--policy",
        "examples/policy_sample.json",
        input_text=input_text,
    )
    assert missing_time.returncode == 1
    assert missing_time.stdout == ""
    assert "no execution timestamp found" in missing_time.stderr

    supplied_time = run_import_langsmith_process(
        "-",
        "--policy",
        "examples/policy_sample.json",
        "--executed-at",
        "2026-05-14T16:59:00Z",
        input_text=input_text,
    )
    assert supplied_time.returncode == 0, supplied_time.stderr
    verdict = run_compile_process("-", "-v", input_text=supplied_time.stdout)
    assert verdict.returncode == 0, verdict.stderr
    assert verdict.stdout.strip() == "UNKNOWN"

def test_real_world_importers_bridge_to_compile() -> None:
    policy_arg = ("--policy", "examples/real_world_policy_sample.json")

    importer_cases = [
        (
            run_import_otel_process,
            ("examples/otel_span_sample.jsonl", *policy_arg),
            "opentelemetry-span",
            "otel_call_01HXstripeCharge",
        ),
        (
            run_import_cloudtrail_process,
            ("examples/cloudtrail_sample.json", *policy_arg),
            "aws-cloudtrail",
            "cloudtrail-evt-01HXstripeCharge",
        ),
        (
            run_import_kubernetes_process,
            ("examples/kubernetes_audit_sample.jsonl", *policy_arg),
            "kubernetes-audit",
            "k8s-audit-01HXexec",
        ),
        (
            run_import_siem_process,
            ("examples/siem_sample.jsonl", *policy_arg),
            "generic-siem-jsonl",
            "siem-evt-01HX",
        ),
    ]
    for runner, args, tool_version, action_id in importer_cases:
        imported = runner(*args)
        assert imported.returncode == 0, imported.stderr
        artifacts = json.loads(imported.stdout)
        assert artifacts["authorization"]["grant_id"] == "grant-real-world-20260514"
        assert artifacts["tool_call"]["tool_version"] == tool_version
        assert artifacts["tool_call"]["action_id"] == action_id
        verdict = run_compile_process("-", "-v", input_text=imported.stdout)
        assert verdict.returncode == 0, verdict.stderr
        assert verdict.stdout.strip() == "UNKNOWN"

    no_policy = run_import_otel_process("examples/otel_span_sample.jsonl")
    assert no_policy.returncode == 0, no_policy.stderr
    no_policy_gaps = run_compile_process("-", "--gaps", input_text=no_policy.stdout)
    assert no_policy_gaps.returncode == 0, no_policy_gaps.stderr
    assert "missing expected path: authorization.grant_id" in no_policy_gaps.stdout
    assert "missing expected path: authorization.revoked_at" in no_policy_gaps.stdout

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "cloudtrail_artifacts"
        written = run_import_cloudtrail_process(
            "examples/cloudtrail_sample.json",
            *policy_arg,
            "--out",
            str(out_dir),
        )
        assert written.returncode == 0, written.stderr
        assert (out_dir / "authorization.json").is_file()
        assert (out_dir / "parsed_actions.json").is_file()
        assert (out_dir / "tool_call.json").is_file()
        out_receipt = run_compile_process(str(out_dir), "--pretty")
        assert out_receipt.returncode == 0, out_receipt.stderr
        receipt_path = Path(tmp) / "cloudtrail_receipt.json"
        receipt_path.write_text(out_receipt.stdout, encoding="utf-8")
        validate = subprocess.run(
            [PYTHON, "receipt_validate.py", "--source-root", str(out_dir), str(receipt_path)],
            cwd=ROOT,
            env=ENV,
            check=True,
            text=True,
            capture_output=True,
        )
        assert "valid" in validate.stdout

def test_github_actions_importer_and_deployment_claim_pack() -> None:
    imported = run_import_github_actions_process("examples/github_actions_deployment_sample.json")
    assert imported.returncode == 0, imported.stderr
    artifacts = json.loads(imported.stdout)
    assert sorted(artifacts) == ["deployment", "review"]
    assert artifacts["deployment"]["commit_sha"] == artifacts["review"]["commit_sha"]
    verdict = run_compile_process("-", "-v", input_text=imported.stdout)
    assert verdict.returncode == 0, verdict.stderr
    assert verdict.stdout.strip() == "SUPPORTED"

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        missing_review = {
            "deployment": {
                "deployment_id": "deploy-missing-review",
                "commit_sha": "abc123",
                "deployed_at": "2026-05-14T17:20:00Z",
            }
        }
        (root / "deployment.json").write_text(json.dumps(missing_review), encoding="utf-8")
        gaps = run_compile_process(str(root), "--claim-type", "deployment_matches_reviewed_commit", "--gaps")
        assert gaps.returncode == 0, gaps.stderr
        assert "missing expected path: review.commit_sha" in gaps.stdout
        assert "missing expected path: review.decision" in gaps.stdout

def test_human_approval_claim_pack() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "approval.json").write_text(
            json.dumps({
                "approval": {
                    "tool_call_id": "approved-action-1",
                    "approved_at": "2026-05-14T17:00:00Z",
                    "decision": "approved",
                    "actor": "ops@example.com",
                }
            }),
            encoding="utf-8",
        )
        (root / "parsed_actions.json").write_text(
            json.dumps({
                "parsed_actions": [
                    {
                        "action_id": "approved-action-1",
                        "tool": "stripe.charges.create",
                        "executed_at": "2026-05-14T17:01:30Z",
                        "source_kind": "model_output",
                    }
                ]
            }),
            encoding="utf-8",
        )
        (root / "tool_call.json").write_text(
            json.dumps({"tool_call": {"action_id": "approved-action-1", "tool_name": "stripe.charges.create"}}),
            encoding="utf-8",
        )
        verdict = run_compile_process(str(root), "--claim-type", "human_approval_before_external_side_effect", "-v")
        assert verdict.returncode == 0, verdict.stderr
        assert verdict.stdout.strip() == "SUPPORTED"

        (root / "approval.json").write_text(
            json.dumps({
                "approval": {
                    "tool_call_id": "approved-action-1",
                    "approved_at": "2026-05-14T17:02:00Z",
                    "decision": "approved",
                    "actor": "ops@example.com",
                }
            }),
            encoding="utf-8",
        )
        contradicted = run_compile_process(
            str(root),
            "--claim-type",
            "human_approval_before_external_side_effect",
            "--ci",
        )
        assert contradicted.returncode == 1
        assert "CONTRADICTED" in contradicted.stdout

        (root / "approval.json").write_text(
            json.dumps({
                "approval": {
                    "tool_call_id": "different-action",
                    "approved_at": "2026-05-14T17:00:00Z",
                    "decision": "approved",
                    "actor": "ops@example.com",
                }
            }),
            encoding="utf-8",
        )
        mismatched = run_compile_process(
            str(root),
            "--claim-type",
            "human_approval_before_external_side_effect",
            "--ci",
        )
        assert mismatched.returncode == 1
        assert "CONTRADICTED" in mismatched.stdout

def test_new_importers_missing_timestamps_fail_closed() -> None:
    policy_arg = ("--policy", "examples/real_world_policy_sample.json")
    cases = [
        (
            run_import_otel_process,
            {"spanId": "span_missing_time", "name": "stripe.charges.create", "attributes": {"tool.name": "stripe.charges.create"}},
        ),
        (
            run_import_cloudtrail_process,
            {"Records": [{"eventSource": "lambda.amazonaws.com", "eventName": "Invoke", "eventID": "missing-time"}]},
        ),
        (
            run_import_github_actions_process,
            {"deployment": {"id": "deploy-missing-time", "commit_sha": "abc123"}, "review": {"commit_sha": "abc123"}},
        ),
        (
            run_import_kubernetes_process,
            {"auditID": "audit-missing-time", "verb": "create", "objectRef": {"resource": "pods"}},
        ),
        (
            run_import_siem_process,
            {"event_id": "siem-missing-time", "actor": "agent", "action": "write", "resource": "system"},
        ),
    ]
    for runner, payload in cases:
        input_text = json.dumps(payload)
        proc = runner("-", *policy_arg, input_text=input_text)
        assert proc.returncode == 1
        assert proc.stdout == ""
        assert "timestamp" in proc.stderr or "time" in proc.stderr

def test_real_world_importer_hardening_edges() -> None:
    policy_arg = ("--policy", "examples/real_world_policy_sample.json")

    negative_index_cases = [
        (run_import_otel_process, ("examples/otel_span_sample.jsonl", *policy_arg, "--action-index", "-1")),
        (run_import_cloudtrail_process, ("examples/cloudtrail_sample.json", *policy_arg, "--action-index", "-1")),
        (run_import_kubernetes_process, ("examples/kubernetes_audit_sample.jsonl", *policy_arg, "--action-index", "-1")),
        (run_import_siem_process, ("examples/siem_sample.jsonl", *policy_arg, "--action-index", "-1")),
    ]
    for runner, args in negative_index_cases:
        proc = runner(*args)
        assert proc.returncode == 1
        assert "action_index -1" in proc.stderr

    with tempfile.TemporaryDirectory() as tmp:
        out_root = Path(tmp) / "otel_all"
        written = run_import_otel_process(
            "examples/otel_span_sample.jsonl",
            *policy_arg,
            "--all",
            "--out",
            str(out_root),
        )
        assert written.returncode == 0, written.stderr
        assert (out_root / "action_0" / "authorization.json").is_file()
        verdict = run_compile_process(str(out_root / "action_0"), "-v")
        assert verdict.returncode == 0, verdict.stderr
        assert verdict.stdout.strip() == "UNKNOWN"

        kv_log = Path(tmp) / "github_job.log"
        kv_log.write_text(
            "\n".join([
                "deployment_id=deploy-kv-1",
                "github_sha=abc123",
                "deployed_at=2026-05-14T17:20:00Z",
                "review_commit_sha=abc123",
                "review_decision=approved",
                "review_approved_at=2026-05-14T17:00:00Z",
            ]),
            encoding="utf-8",
        )
        imported = run_import_github_actions_process(str(kv_log))
        assert imported.returncode == 0, imported.stderr
        verdict = run_compile_process("-", "-v", input_text=imported.stdout)
        assert verdict.returncode == 0, verdict.stderr
        assert verdict.stdout.strip() == "SUPPORTED"

        mismatch_log = Path(tmp) / "github_mismatch.log"
        mismatch_log.write_text(
            "\n".join([
                "deployment_id=deploy-kv-2",
                "github_sha=abc123",
                "deployed_at=2026-05-14T17:20:00Z",
                "review_commit_sha=def456",
                "review_decision=approved",
                "review_approved_at=2026-05-14T17:00:00Z",
            ]),
            encoding="utf-8",
        )
        mismatch = run_import_github_actions_process(str(mismatch_log))
        assert mismatch.returncode == 0, mismatch.stderr
        ci = run_compile_process("-", "--ci", input_text=mismatch.stdout)
        assert ci.returncode == 1
        assert "CONTRADICTED" in ci.stdout
        assert "does not match reviewed commit" in ci.stdout

        incomplete_policy = Path(tmp) / "incomplete_policy.json"
        incomplete_policy.write_text(
            json.dumps({
                "grant_id": "grant-incomplete-only",
                "grant_valid_from": "2026-05-14T16:00:00Z",
                "grant_valid_until": "2026-05-14T18:00:00Z",
            }),
            encoding="utf-8",
        )
        imported = run_import_siem_process("examples/siem_sample.jsonl", "--policy", str(incomplete_policy))
        assert imported.returncode == 0, imported.stderr
        gaps = run_compile_process("-", "--gaps", input_text=imported.stdout)
        assert gaps.returncode == 0, gaps.stderr
        assert "missing expected path: authorization.revoked_at" in gaps.stdout

def test_demo_real_world_importers() -> None:
    proc = subprocess.run(
        [PYTHON, "demo_real_world_importers.py"],
        cwd=ROOT,
        env=ENV,
        check=True,
        text=True,
        capture_output=True,
    )
    assert "source | claim | verdict | missing evidence | receipt valid" in proc.stdout
    assert (
        "opentelemetry | authorization_bound_action | unknown | "
        "authorization.execution_time_decision_id,authorization.grant_active_at_execution,"
        "authorization.render_time_grant_hash | yes"
    ) in proc.stdout
    assert "github_actions | deployment_matches_reviewed_commit | supported | none | yes" in proc.stdout
    assert "opentelemetry_no_policy | authorization_bound_action | unknown | authorization.grant_id" in proc.stdout


def run_importer_tests() -> None:
    test_anthropic_importer_bridge()
    test_anthropic_importer_missing_timestamp_fails_closed()
    test_openai_importer_bridge()
    test_openai_importer_missing_timestamp_fails_closed()
    test_eventlog_importer_bridge()
    test_eventlog_importer_missing_timestamp_fails_closed()
    test_langsmith_importer_bridge()
    test_langsmith_importer_missing_timestamp_fails_closed()
    test_real_world_importers_bridge_to_compile()
    test_github_actions_importer_and_deployment_claim_pack()
    test_human_approval_claim_pack()
    test_new_importers_missing_timestamps_fail_closed()
    test_real_world_importer_hardening_edges()
    test_demo_real_world_importers()
