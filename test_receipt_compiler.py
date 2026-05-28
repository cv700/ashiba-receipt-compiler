#!/usr/bin/env python3
"""Standard-library smoke tests for receipt_compile.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from claim_contracts import claim_conflicts, claim_has_action_scope, claim_missing
from constants import (
    CONTRADICTED,
    NOT_APPLICABLE,
    PASS_CONTRADICTED,
    PASS_OK,
    PASS_SATISFIED,
    PASS_SKIPPED,
    PASS_UNKNOWN,
    SUPPORTED,
    UNKNOWN,
    VERDICT_STATUSES,
)
from demo_gallery import run_gallery
from passes import (
    dcgm_diag_result,
    ecc_threshold_check,
    get_pass_spec,
    grant_binding_present,
    gpu_node_id_match,
    gpu_not_mig_sliced,
    gpu_serial_cross_reference,
    gpu_serial_set_match,
    gpu_sku_count_match,
)
from receipt_compile import (
    build_claim_registry,
    compile_bundle,
    compile_claim,
    compile_claims,
    detect_applicable_claim_types,
    load_artifacts_dir_bound,
    load_artifacts_dir_with_manifest,
)
from receipt_ir import ReceiptIR
from receipt_validate import validate_receipt
from side_effect_envelope import (
    SIDE_EFFECT_ACTION_ID_PATH,
    SIDE_EFFECT_DECISION_ID_PATH,
    SIDE_EFFECT_EXECUTED_AT_PATH,
    SIDE_EFFECTS_KEY,
)


ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable
ENV = {"PYTHONDONTWRITEBYTECODE": "1"}
VERDICT_WORDS = set(VERDICT_STATUSES)


def run_json(*args: str) -> dict:
    proc = subprocess.run(
        [PYTHON, "receipt_compile.py", *args],
        cwd=ROOT,
        env=ENV,
        check=True,
        text=True,
        capture_output=True,
    )
    return json.loads(proc.stdout)


def run_text(*args: str) -> str:
    proc = subprocess.run(
        [PYTHON, "receipt_compile.py", *args],
        cwd=ROOT,
        env=ENV,
        check=True,
        text=True,
        capture_output=True,
    )
    return proc.stdout


def run_process(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "receipt_compile.py", *args],
        cwd=ROOT,
        env=ENV,
        text=True,
        capture_output=True,
    )


def run_compile_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "compile", *args],
        cwd=ROOT,
        env=ENV,
        input=input_text,
        text=True,
        capture_output=True,
    )


def run_import_anthropic_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "import_anthropic", *args],
        cwd=ROOT,
        env=ENV,
        input=input_text,
        text=True,
        capture_output=True,
    )


def run_import_openai_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "import_openai", *args],
        cwd=ROOT,
        env=ENV,
        input=input_text,
        text=True,
        capture_output=True,
    )


def run_import_eventlog_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "import_eventlog", *args],
        cwd=ROOT,
        env=ENV,
        input=input_text,
        text=True,
        capture_output=True,
    )


def run_import_langsmith_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "import_langsmith", *args],
        cwd=ROOT,
        env=ENV,
        input=input_text,
        text=True,
        capture_output=True,
    )


def run_import_otel_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "import_otel", *args],
        cwd=ROOT,
        env=ENV,
        input=input_text,
        text=True,
        capture_output=True,
    )


def run_import_cloudtrail_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "import_cloudtrail", *args],
        cwd=ROOT,
        env=ENV,
        input=input_text,
        text=True,
        capture_output=True,
    )


def run_import_github_actions_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "import_github_actions", *args],
        cwd=ROOT,
        env=ENV,
        input=input_text,
        text=True,
        capture_output=True,
    )


def run_import_kubernetes_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "import_kubernetes_audit", *args],
        cwd=ROOT,
        env=ENV,
        input=input_text,
        text=True,
        capture_output=True,
    )


def run_ashiba_process(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "ashiba", *args],
        cwd=ROOT,
        env=ENV,
        text=True,
        capture_output=True,
    )


def run_import_siem_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "import_siem_jsonl", *args],
        cwd=ROOT,
        env=ENV,
        input=input_text,
        text=True,
        capture_output=True,
    )


def run_import_nvidia_smi_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "import_nvidia_smi", *args],
        cwd=ROOT,
        env=ENV,
        input=input_text,
        text=True,
        capture_output=True,
    )


def assert_receipt(receipt: dict, status: str, pass_count: int | None = None, absence_count: int = 0) -> None:
    assert receipt["verdict"]["status"] == status, receipt
    assert len(receipt.get("absence", [])) == absence_count, receipt
    assert len(receipt.get("compiler_errors", [])) == 0, receipt
    assert receipt.get("artifact_manifest"), receipt
    assert isinstance(receipt.get("input_set_hash"), str) and len(receipt["input_set_hash"]) == 64, receipt
    assert validate_receipt(receipt) == [], receipt
    for record in receipt["artifact_manifest"]:
        assert record.get("relative_path"), receipt
    if pass_count is not None:
        assert len(receipt.get("pass_results", [])) == pass_count, receipt


def load_manifest() -> dict:
    return json.loads((ROOT / "gallery_manifest.json").read_text(encoding="utf-8"))


def verdict_word_in_directory(directory: str) -> str | None:
    tokens = set(directory.split("_"))
    found = sorted(tokens & VERDICT_WORDS)
    assert len(found) <= 1, f"ambiguous verdict words in directory name: {directory}"
    return found[0] if found else None


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


def test_v6_external_claim_pack_registry() -> None:
    default_pack_list = run_text("--list-claim-types", "--claim-packs-dir", "claim_packs")
    assert "authorization_bound_action" in default_pack_list

    auth_pack = build_claim_registry()["authorization_bound_action"]
    assert auth_pack["renderer_family"] == "cyber_tool_use"
    support_requirements = {item["id"]: item for item in auth_pack["support_requirements"]}
    assert support_requirements["authorization.revoked_at"]["presence"] == "path_exists"
    binding = support_requirements["authorization-to-action binding"]
    assert binding["all_of"] == [
        "authorization.render_time_grant_hash",
        "authorization.execution_time_decision_id",
        "authorization.grant_active_at_execution",
        SIDE_EFFECT_DECISION_ID_PATH,
    ]
    assert binding["same_value"] == [
        "authorization.execution_time_decision_id",
        SIDE_EFFECT_DECISION_ID_PATH,
    ]
    binding_spec = get_pass_spec("grant_binding_present")
    assert binding_spec.family == "authorization"
    assert binding_spec.scope == "action"
    assert set(binding_spec.required_paths) <= set(binding["all_of"])
    assert "authorization.grant_active_at_execution" in binding_spec.contradiction_paths

    external_pack = {
        "schema_version": "receipt-claim-pack-v0.1",
        "name": "authz_external_pack",
        "renderer_family": "cyber_tool_use",
        "claim": {
            "id": "claim.authz_external_pack",
            "text": "The external pack claim is supported by active authorization evidence.",
        },
        "expected_evidence": [
            "authorization.grant_id",
            "authorization.grant_valid_from",
            "authorization.grant_valid_until",
            SIDE_EFFECT_EXECUTED_AT_PATH,
            SIDE_EFFECT_ACTION_ID_PATH,
        ],
        "applicability_evidence": [
            "authorization",
            SIDE_EFFECTS_KEY,
        ],
        "support_requirements": [
            {
                "id": "authorization.revoked_at",
                "path": "authorization.revoked_at",
                "presence": "path_exists",
            }
        ],
        "passes": [
            "utc_timestamp_format",
            "expected_evidence_absence",
            "grant_active_at_event_time",
            "revocation_before_action",
            "no_future_evidence",
        ],
        "pass_params": {},
    }

    with tempfile.TemporaryDirectory() as tmp:
        pack_dir = Path(tmp)
        (pack_dir / "authz_external_pack.json").write_text(json.dumps(external_pack), encoding="utf-8")
        registry = build_claim_registry(pack_dir)
        assert "authorization_bound_action" in registry
        assert "authz_external_pack" in registry

        artifacts, artifact_manifest, input_hash = load_artifacts_dir_with_manifest(
            ROOT / "examples" / "auth_grant_dir_supported"
        )
        receipt = compile_claim(
            artifacts,
            "authz_external_pack",
            artifact_manifest=artifact_manifest,
            input_set_hash=input_hash,
            claim_types=registry,
        ).to_dict()
        assert_receipt(receipt, SUPPORTED, 5, 0)

        listed = run_text("--list-claim-types", "--claim-packs-dir", str(pack_dir))
        assert "authz_external_pack" in listed
        cli_receipt = run_json(
            "--artifacts-dir",
            "examples/auth_grant_dir_supported",
            "--claim-type",
            "authz_external_pack",
            "--claim-packs-dir",
            str(pack_dir),
        )
        assert_receipt(cli_receipt, SUPPORTED, 5, 0)

    invalid_pack = {
        "schema_version": "receipt-claim-pack-v0.1",
        "name": "invalid_unknown_pass",
        "renderer_family": "cyber_tool_use",
        "claim": {
            "id": "claim.invalid_unknown_pass",
            "text": "This invalid pack references a missing deterministic pass.",
        },
        "expected_evidence": ["authorization.grant_id"],
        "applicability_evidence": ["authorization"],
        "passes": ["definitely_not_a_registered_pass"],
        "pass_params": {},
    }
    with tempfile.TemporaryDirectory() as tmp:
        pack_dir = Path(tmp)
        (pack_dir / "invalid_unknown_pass.json").write_text(json.dumps(invalid_pack), encoding="utf-8")

        # Bundle mode now resolves through claim packs, so invalid packs fail closed here too.
        bundle_proc = run_process(
            "--bundle",
            "examples/auth_grant_supported.json",
            "--claim-packs-dir",
            str(pack_dir),
        )
        assert bundle_proc.returncode == 1
        assert "Traceback" not in bundle_proc.stdout
        assert "Traceback" not in bundle_proc.stderr
        bundle_error = json.loads(bundle_proc.stdout)
        assert bundle_error["verdict"]["status"] == UNKNOWN
        assert "definitely_not_a_registered_pass" in bundle_error["compiler_errors"][0]["detail"]

        # Claim-pack failures produce structured compiler errors, not Python tracebacks.
        proc = run_process("--list-claim-types", "--claim-packs-dir", str(pack_dir))
        assert proc.returncode == 1
        assert "Traceback" not in proc.stdout
        assert "Traceback" not in proc.stderr
        error = json.loads(proc.stdout)
        assert error["verdict"]["status"] == UNKNOWN
        assert "definitely_not_a_registered_pass" in error["compiler_errors"][0]["detail"]

    missing_renderer_family = dict(external_pack)
    missing_renderer_family.pop("renderer_family")
    missing_renderer_family["name"] = "missing_renderer_family"
    missing_renderer_family["claim"] = {
        "id": "claim.missing_renderer_family",
        "text": "This invalid pack omits the renderer-family contract.",
    }
    with tempfile.TemporaryDirectory() as tmp:
        pack_dir = Path(tmp)
        (pack_dir / "missing_renderer_family.json").write_text(
            json.dumps(missing_renderer_family),
            encoding="utf-8",
        )
        proc = run_process("--list-claim-types", "--claim-packs-dir", str(pack_dir))
        assert proc.returncode == 1
        assert "Traceback" not in proc.stdout
        assert "Traceback" not in proc.stderr
        error = json.loads(proc.stdout)
        assert error["verdict"]["status"] == UNKNOWN
        assert "renderer_family" in error["compiler_errors"][0]["detail"]

    unknown_renderer_family = dict(external_pack)
    unknown_renderer_family["name"] = "unknown_renderer_family"
    unknown_renderer_family["renderer_family"] = "gpu_colateral"
    unknown_renderer_family["claim"] = {
        "id": "claim.unknown_renderer_family",
        "text": "This invalid pack misspells a registered renderer family.",
    }
    with tempfile.TemporaryDirectory() as tmp:
        pack_dir = Path(tmp)
        (pack_dir / "unknown_renderer_family.json").write_text(
            json.dumps(unknown_renderer_family),
            encoding="utf-8",
        )
        proc = run_process("--list-claim-types", "--claim-packs-dir", str(pack_dir))
        assert proc.returncode == 1
        assert "Traceback" not in proc.stdout
        assert "Traceback" not in proc.stderr
        error = json.loads(proc.stdout)
        assert error["verdict"]["status"] == UNKNOWN
        assert "gpu_colateral" in error["compiler_errors"][0]["detail"]
        assert "is not registered" in error["compiler_errors"][0]["detail"]

    missing_binding_contract = dict(external_pack)
    missing_binding_contract["name"] = "missing_binding_contract"
    missing_binding_contract["claim"] = {
        "id": "claim.missing_binding_contract",
        "text": "This invalid pack names the binding pass but omits its evidence contract.",
    }
    missing_binding_contract["passes"] = [
        "utc_timestamp_format",
        "expected_evidence_absence",
        "grant_binding_present",
    ]
    with tempfile.TemporaryDirectory() as tmp:
        pack_dir = Path(tmp)
        (pack_dir / "missing_binding_contract.json").write_text(
            json.dumps(missing_binding_contract),
            encoding="utf-8",
        )
        proc = run_process("--list-claim-types", "--claim-packs-dir", str(pack_dir))
        assert proc.returncode == 1
        assert "Traceback" not in proc.stdout
        assert "Traceback" not in proc.stderr
        error = json.loads(proc.stdout)
        assert error["verdict"]["status"] == UNKNOWN
        assert "grant_binding_present" in error["compiler_errors"][0]["detail"]
        assert "authorization.execution_time_decision_id" in error["compiler_errors"][0]["detail"]

    duplicate_pack = dict(external_pack)
    duplicate_pack["name"] = "authorization_bound_action"
    duplicate_pack["claim"] = {
        "id": "claim.authorization_bound_action.duplicate",
        "text": "Duplicate built-in claim pack fixture.",
    }
    with tempfile.TemporaryDirectory() as tmp:
        pack_dir = Path(tmp)
        (pack_dir / "authorization_bound_action.json").write_text(json.dumps(duplicate_pack), encoding="utf-8")
        proc = run_process("--list-claim-types", "--claim-packs-dir", str(pack_dir))
        assert proc.returncode == 1
        assert "Traceback" not in proc.stdout
        assert "Traceback" not in proc.stderr
        error = json.loads(proc.stdout)
        assert error["verdict"]["status"] == UNKNOWN
        assert "duplicate existing claim type" in error["compiler_errors"][0]["detail"]


def test_claim_contract_helpers_drive_readiness_semantics() -> None:
    registry = build_claim_registry()
    auth_pack = registry["authorization_bound_action"]
    deployment_pack = registry["deployment_matches_reviewed_commit"]

    assert claim_has_action_scope(auth_pack)
    assert not claim_has_action_scope(deployment_pack)

    artifacts = {
        "authorization": {
            "grant_id": "grant-contract",
            "grant_valid_from": "2026-05-14T16:00:00Z",
            "grant_valid_until": "2026-05-14T18:00:00Z",
            "revoked_at": None,
            "render_time_grant_hash": "sha256:contract",
            "execution_time_decision_id": "authz-decision-contract",
            "grant_active_at_execution": True,
        },
        SIDE_EFFECTS_KEY: [
            {
                "action_id": "act-contract",
                "tool": "lambda.amazonaws.com:Invoke",
                "executed_at": "2026-05-14T17:01:30Z",
                "invocation": {"decision_id": "authz-decision-contract"},
            }
        ],
    }
    assert claim_missing(artifacts, auth_pack) == []

    no_revocation_state = dict(artifacts)
    no_revocation_state["authorization"] = dict(artifacts["authorization"])
    no_revocation_state["authorization"].pop("revoked_at")
    assert claim_missing(no_revocation_state, auth_pack) == ["authorization.revoked_at"]

    mismatched_binding = dict(artifacts)
    mismatched_binding[SIDE_EFFECTS_KEY] = [{
        "action_id": "act-contract",
        "tool": "lambda.amazonaws.com:Invoke",
        "executed_at": "2026-05-14T17:01:30Z",
        "invocation": {"decision_id": "authz-decision-other"},
    }]
    assert claim_missing(mismatched_binding, auth_pack) == ["authorization-to-action binding"]
    assert claim_conflicts(
        auth_pack,
        [{"path": "authorization.execution_time_decision_id"}],
    ) == ["authorization.execution_time_decision_id"]
    assert claim_conflicts(auth_pack, [{"path": "deployment.commit_sha"}]) == []


def test_claim_contract_discovery_surfaces_minimum_runtime_facts() -> None:
    proc = subprocess.run(
        [PYTHON, "scripts/discover_claim_contract.py", "--json"],
        cwd=ROOT,
        env=ENV,
        check=True,
        text=True,
        capture_output=True,
    )
    discovery = json.loads(proc.stdout)
    assert discovery["schema_version"] == "ashiba-claim-contract-discovery-v0.1"
    side_effect_minimum = discovery["side_effect_envelope_v1_minimum"]
    assert side_effect_minimum["required_by_current_claims"] == [
        "action_id",
        "executed_at",
        "invocation.decision_id",
    ]
    assert "action_id" in side_effect_minimum["contradiction_relevant"]
    assert "source_kind" in side_effect_minimum["contradiction_relevant"]
    for unclaimed in ("episode_id", "parent_action_id", "principal", "agent_id", "evidence_refs"):
        assert unclaimed in side_effect_minimum["proposed_but_unclaimed"]

    claims = {claim["name"]: claim for claim in discovery["claims"]}
    auth_binding = claims["authorization_bound_action"]["binding_requirements"]
    assert auth_binding == [{
        "id": "authorization-to-action binding",
        "same_value": [
            "authorization.execution_time_decision_id",
            SIDE_EFFECT_DECISION_ID_PATH,
        ],
    }]

    approval_binding = claims["human_approval_before_external_side_effect"]["binding_requirements"]
    assert approval_binding == [{
        "id": "approval-to-action binding",
        "same_value": [
            "approval.tool_call_id",
            SIDE_EFFECT_ACTION_ID_PATH,
        ],
    }]
    assert "discovered_gaps" not in claims["human_approval_before_external_side_effect"]
    assert discovery["discovered_gaps"] == []

    text = subprocess.run(
        [PYTHON, "scripts/discover_claim_contract.py"],
        cwd=ROOT,
        env=ENV,
        check=True,
        text=True,
        capture_output=True,
    )
    assert "SideEffectEnvelope v1 minimum required by current claims" in text.stdout
    assert "approval-to-action binding" in proc.stdout


def test_side_effect_envelope_v1_compiles_and_scans() -> None:
    authorization = {
        "grant_id": "grant-envelope",
        "grant_valid_from": "2026-05-14T16:00:00Z",
        "grant_valid_until": "2026-05-14T18:00:00Z",
        "revoked_at": None,
        "render_time_grant_hash": "sha256:envelope",
        "execution_time_decision_id": "authz-decision-envelope",
        "grant_active_at_execution": True,
    }
    side_effect = {
        "schema_version": "side_effect_envelope_v1",
        "action_id": "act-envelope",
        "tool": "stripe.charges.create",
        "executed_at": "2026-05-14T17:01:30Z",
        "source_kind": "event_log",
        "invocation": {"decision_id": "authz-decision-envelope"},
    }
    artifacts = {
        "authorization": authorization,
        SIDE_EFFECTS_KEY: [side_effect],
    }

    receipt = compile_claim(artifacts, "authorization_bound_action").to_dict()
    assert receipt["verdict"]["status"] == SUPPORTED
    assert SIDE_EFFECT_EXECUTED_AT_PATH in receipt["expected_evidence"]
    assert receipt["artifacts"][SIDE_EFFECTS_KEY][0]["action_id"] == "act-envelope"
    assert receipt["artifacts"]["parsed_actions"][0]["action_id"] == "act-envelope"

    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "side_effect.json"
        log_path.write_text(json.dumps(artifacts), encoding="utf-8")
        proc = run_ashiba_process("scan", str(log_path), "--json")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert "authorization_bound_action" in result["can_decide"]
    assert result["actions"][0]["action_id"] == "act-envelope"
    assert "authorization_bound_action" in result["actions"][0]["can_decide"]


def test_action_scoped_side_effect_envelopes_compile_independently() -> None:
    authorization = {
        "grant_id": "grant-envelope",
        "grant_valid_from": "2026-05-14T16:00:00Z",
        "grant_valid_until": "2026-05-14T18:00:00Z",
        "revoked_at": None,
        "render_time_grant_hash": "sha256:envelope",
        "execution_time_decision_id": "authz-decision-envelope",
        "grant_active_at_execution": True,
    }
    artifacts = {
        "authorization": authorization,
        SIDE_EFFECTS_KEY: [
            {
                "action_id": "act-supported",
                "tool": "stripe.charges.create",
                "executed_at": "2026-05-14T17:01:30Z",
                "source_kind": "event_log",
                "invocation": {"decision_id": "authz-decision-envelope"},
            },
            {
                "action_id": "act-blocked",
                "tool": "stripe.charges.create",
                "executed_at": "2026-05-14T17:02:30Z",
                "source_kind": "event_log",
                "invocation": {"decision_id": "other-decision"},
            },
        ],
    }

    receipts = [receipt.to_dict() for receipt in compile_claims(artifacts, "authorization_bound_action")]
    assert [receipt["artifacts"][SIDE_EFFECTS_KEY][0]["action_id"] for receipt in receipts] == [
        "act-supported",
        "act-blocked",
    ]
    assert [receipt["verdict"]["status"] for receipt in receipts] == [SUPPORTED, CONTRADICTED]
    assert all(len(receipt["artifacts"][SIDE_EFFECTS_KEY]) == 1 for receipt in receipts)
    try:
        compile_claim(artifacts, "authorization_bound_action")
    except ValueError as exc:
        assert "use compile_claims for multi-action artifacts" in str(exc)
    else:
        raise AssertionError("compile_claim should reject multi-action action-scoped artifacts")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "authorization.json").write_text(json.dumps({"authorization": authorization}), encoding="utf-8")
        (root / "side_effects.json").write_text(json.dumps({SIDE_EFFECTS_KEY: artifacts[SIDE_EFFECTS_KEY]}), encoding="utf-8")
        proc = run_compile_process(str(root), "--claim-type", "authorization_bound_action")
    assert proc.returncode == 0, proc.stderr
    compiled = json.loads(proc.stdout)
    assert [receipt["artifacts"][SIDE_EFFECTS_KEY][0]["action_id"] for receipt in compiled["receipts"]] == [
        "act-supported",
        "act-blocked",
    ]


def test_v6_incident_manifest_path_boundaries() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = {
            "schema_version": "receipt-incident-manifest-v0.1",
            "incident_id": "bad-path-incident",
            "claim_types": ["authorization_bound_action"],
            "artifact_roles": [
                {
                    "path": "../outside.json",
                    "artifact_key": "authorization",
                    "role": "hidden_evidence",
                }
            ],
        }
        (root / "incident_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        proc = run_process("--artifacts-dir", str(root))
        assert proc.returncode == 1
        assert "Traceback" not in proc.stdout
        assert "Traceback" not in proc.stderr
        error = json.loads(proc.stdout)
        assert error["verdict"]["status"] == UNKNOWN
        assert "must be relative and stay under the incident directory" in error["compiler_errors"][0]["detail"]


def _supported_authorization_fixture() -> tuple[dict, list[dict], str]:
    loaded = load_artifacts_dir_bound(ROOT / "examples" / "execution_context_gpu_disclosure")
    return loaded.artifacts, loaded.artifact_manifest, loaded.input_set_hash


def _complete_gpu_context() -> dict:
    return {
        "schema_id": "gpu_goodput_context_v0",
        "topology_manifest": {
            "node_guids": ["0xaaa"],
            "switch_guids": ["0xbbb"],
            "gpu_serials": ["GPU-aaa"],
            "nodes_tested": 4,
            "nodes_provisioned": 4,
            "coverage_ratio": 1.0,
        },
        "system_state": {
            "uptimes_seconds": [172800],
            "ecc_volatile": [0],
            "ecc_aggregate": [0],
            "thermal_history_c": [72.5],
            "freshly_rebooted_nodes": 0,
            "ecc_reboot_suspects": 0,
        },
        "probe_manifest_commitment": {
            "committed_at": "2026-05-20T14:00:00Z",
            "committed_by": "customer",
            "probe_ids": ["nccl_allreduce", "ecc_check"],
            "commitment_hash": "sha256:abc123",
        },
        "challenge_nonce": "a3f7c9e2b1d04568",
        "ambient_load": {
            "test_window_start": "2026-05-20T03:00:00Z",
            "test_window_end": "2026-05-20T03:32:00Z",
            "fabric_utilization_pct": 31.0,
            "congestion_events": 2,
            "ambient_load_level": "moderate",
            "port_counter_samples": [],
        },
        "software_stack": {
            "nvidia_driver": "545.23.08",
            "cuda_version": "12.4",
            "nccl_version": "2.20.5",
            "connectx_firmware": "28.39.1002",
            "os_kernel": "5.15.0-91-generic",
            "ib_driver": "23.10-1.1.9.0",
            "nccl_env_hash": "sha256:def456",
            "stack_fingerprint": "sha256:789abc",
        },
    }


def test_v7_execution_context_absent_is_noop() -> None:
    receipt = run_json("--bundle", "examples/auth_grant_supported.json")
    assert_receipt(receipt, SUPPORTED, 7, 0)
    assert "execution_context" not in receipt
    assert all(result["pass_id"] != "execution_context_disclosure" for result in receipt["pass_results"])
    assert not any("Execution context" in line for line in receipt["boundary"]["does_not_support"])


def test_v7_execution_context_round_trip_and_unknown_schema() -> None:
    bundle = json.loads((ROOT / "examples" / "auth_grant_supported.json").read_text(encoding="utf-8"))
    bundle["execution_context"] = {"schema_id": "future_thing_v0", "data": {"field": "value"}}
    receipt = compile_bundle(bundle).to_dict()
    assert receipt["execution_context"] == bundle["execution_context"]
    assert receipt["verdict"]["status"] == SUPPORTED
    assert len(receipt["pass_results"]) == 8
    assert len(receipt.get("absence", [])) == 0
    assert len(receipt.get("compiler_errors", [])) == 0

    context_passes = [result for result in receipt["pass_results"] if result["pass_id"] == "execution_context_disclosure"]
    assert len(context_passes) == 1
    assert context_passes[0]["status"] == PASS_OK
    assert context_passes[0].get("verdict_effect") is None
    assert any("future_thing_v0" in line for line in receipt["boundary"]["does_not_support"])


def test_v7_gpu_execution_context_disclosures() -> None:
    artifacts, artifact_manifest, input_hash = _supported_authorization_fixture()
    context = {
        "schema_id": "gpu_goodput_context_v0",
        "topology_manifest": {
            "nodes_tested": 64,
            "nodes_provisioned": 256,
            "coverage_ratio": 0.25,
        },
        "system_state": {
            "freshly_rebooted_nodes": 3,
            "ecc_reboot_suspects": 2,
        },
        "ambient_load": {
            "ambient_load_level": "negligible",
        },
    }
    receipt = compile_claim(
        artifacts,
        "authorization_bound_action",
        artifact_manifest=artifact_manifest,
        input_set_hash=input_hash,
        execution_context=context,
    ).to_dict()

    assert_receipt(receipt, SUPPORTED, 8, 0)
    assert receipt["execution_context"] == context
    boundary = "\n".join(receipt["boundary"]["does_not_support"])
    assert "Receipt covers 64/256 provisioned nodes (25.0% coverage)" in boundary
    assert "3 nodes were rebooted within 1 hour of test" in boundary
    assert "2 nodes show zero volatile ECC errors but nonzero aggregate" in boundary
    assert "negligible fabric load" in boundary
    assert "Software stack not captured" in boundary
    assert "No challenge nonce" in boundary
    assert "No pre-committed probe manifest" in boundary

    context_pass = [result for result in receipt["pass_results"] if result["pass_id"] == "execution_context_disclosure"][0]
    assert context_pass["status"] == PASS_OK
    assert context_pass.get("verdict_effect") is None


def test_v7_complete_gpu_execution_context_adds_no_negative_context_disclosures() -> None:
    artifacts, artifact_manifest, input_hash = _supported_authorization_fixture()
    receipt = compile_claim(
        artifacts,
        "authorization_bound_action",
        artifact_manifest=artifact_manifest,
        input_set_hash=input_hash,
        execution_context=_complete_gpu_context(),
    ).to_dict()

    assert_receipt(receipt, SUPPORTED, 8, 0)
    boundary = "\n".join(receipt["boundary"]["does_not_support"])
    assert "Receipt covers" not in boundary
    assert "rebooted within 1 hour" not in boundary
    assert "possible reboot to clear errors" not in boundary
    assert "negligible fabric load" not in boundary
    assert "Software stack not captured" not in boundary
    assert "No challenge nonce" not in boundary
    assert "No pre-committed probe manifest" not in boundary


def test_v7_execution_context_file_loaded_outside_artifacts() -> None:
    receipt = run_json(
        "--artifacts-dir",
        "examples/execution_context_gpu_disclosure",
        "--claim-type",
        "authorization_bound_action",
    )
    assert_receipt(receipt, SUPPORTED, 8, 0)
    assert receipt["execution_context"]["schema_id"] == "gpu_goodput_context_v0"
    assert "execution_context" not in receipt["artifacts"]
    assert any(record.get("artifact_key") == "execution_context" for record in receipt["artifact_manifest"])
    assert any("Receipt covers 64/256" in line for line in receipt["boundary"]["does_not_support"])


def test_gpu_collateral_gallery_fixtures() -> None:
    cases = [
        (
            "gpu_serial_match_supported",
            "gpu_serial_collateral_match",
            SUPPORTED,
            0,
            {"gpu_serial_set_match", "gpu_node_id_match"},
        ),
        (
            "gpu_serial_match_unknown",
            "gpu_serial_collateral_match",
            UNKNOWN,
            3,
            {"gpu_serial_set_match", "gpu_node_id_match"},
        ),
        (
            "gpu_serial_match_contradicted",
            "gpu_serial_collateral_match",
            CONTRADICTED,
            0,
            {"gpu_serial_set_match", "gpu_node_id_match"},
        ),
        (
            "gpu_node_health_supported",
            "gpu_node_health_diagnostic",
            SUPPORTED,
            0,
            {"dcgm_diag_result", "ecc_threshold_check", "gpu_serial_cross_reference"},
        ),
        (
            "gpu_node_health_unknown",
            "gpu_node_health_diagnostic",
            UNKNOWN,
            4,
            {"dcgm_diag_result", "ecc_threshold_check", "gpu_serial_cross_reference"},
        ),
        (
            "gpu_node_health_contradicted",
            "gpu_node_health_diagnostic",
            CONTRADICTED,
            0,
            {"dcgm_diag_result", "ecc_threshold_check", "gpu_serial_cross_reference"},
        ),
        (
            "gpu_node_health_supported_weak_conditions",
            "gpu_node_health_diagnostic",
            SUPPORTED,
            0,
            {
                "dcgm_diag_result",
                "ecc_threshold_check",
                "gpu_serial_cross_reference",
                "execution_context_disclosure",
            },
        ),
    ]

    for directory, claim_type, verdict, absence_count, expected_passes in cases:
        receipt = run_json("--artifacts-dir", f"examples/{directory}", "--claim-type", claim_type)
        assert receipt["verdict"]["status"] == verdict, (directory, receipt)
        assert len(receipt.get("absence", [])) == absence_count, (directory, receipt)
        pass_ids = {result["pass_id"] for result in receipt["pass_results"]}
        assert expected_passes <= pass_ids, (directory, pass_ids)
        if verdict == CONTRADICTED:
            assert any(result.get("verdict_effect") == CONTRADICTED for result in receipt["pass_results"])
        if verdict == UNKNOWN:
            assert receipt.get("absence"), directory

    weak = run_json(
        "--artifacts-dir",
        "examples/gpu_node_health_supported_weak_conditions",
        "--claim-type",
        "gpu_node_health_diagnostic",
    )
    assert weak["verdict"]["status"] == SUPPORTED
    context_passes = [
        result for result in weak["pass_results"] if result["pass_id"] == "execution_context_disclosure"
    ]
    assert len(context_passes) == 1
    assert len(context_passes[0]["metadata"]["boundary_disclosures"]) >= 3
    gpu_boundary = "\n".join(weak["boundary"]["does_not_support"])
    assert "representative production load" in gpu_boundary
    assert "recently rebooted" in gpu_boundary
    assert "No challenge nonce" in gpu_boundary

    explained = run_compile_process(
        "examples/gpu_node_health_supported_weak_conditions",
        "--claim-type",
        "gpu_node_health_diagnostic",
        "--explain",
    )
    assert explained.returncode == 0, explained.stderr
    assert "Execution-context disclosures:" in explained.stdout
    assert "No challenge nonce" in explained.stdout


def test_gpu_capacity_acceptance_gallery_fixtures() -> None:
    cases = [
        (
            "gpu_acceptance_supported",
            SUPPORTED,
            0,
            {"gpu_sku_count_match": PASS_SATISFIED, "gpu_not_mig_sliced": PASS_SATISFIED},
        ),
        (
            "gpu_acceptance_mig_contradicted",
            CONTRADICTED,
            0,
            {"gpu_sku_count_match": PASS_SATISFIED, "gpu_not_mig_sliced": PASS_CONTRADICTED},
        ),
        (
            "gpu_acceptance_unknown",
            UNKNOWN,
            1,
            {"gpu_sku_count_match": PASS_UNKNOWN, "gpu_not_mig_sliced": PASS_SATISFIED},
        ),
    ]

    for directory, verdict, absence_count, expected_pass_statuses in cases:
        receipt = run_json("--artifacts-dir", f"examples/{directory}", "--claim-type", "gpu_capacity_acceptance")
        assert receipt["verdict"]["status"] == verdict, (directory, receipt)
        assert len(receipt.get("absence", [])) == absence_count, (directory, receipt)
        pass_results = {result["pass_id"]: result for result in receipt["pass_results"]}
        for pass_id, expected_status in expected_pass_statuses.items():
            assert pass_results[pass_id]["status"] == expected_status, (directory, pass_results[pass_id])
        if directory == "gpu_acceptance_mig_contradicted":
            mig_result = pass_results["gpu_not_mig_sliced"]
            assert mig_result["verdict_effect"] == CONTRADICTED
            assert "MIG enabled" in mig_result["detail"]
        if directory == "gpu_acceptance_unknown":
            missing = {record["expected_path"] for record in receipt["absence"]}
            assert "gpu_inventory.declared_sku" in missing


def test_gpu_boundary_uses_renderer_family_not_claim_id_prefix() -> None:
    custom_gpu_pack = {
        "schema_version": "receipt-claim-pack-v0.1",
        "name": "collateral_schedule_attestation",
        "description": "GPU-family claim with a deliberately non-GPU claim id.",
        "renderer_family": "gpu_collateral",
        "claim": {
            "id": "claim.collateral_schedule_attestation",
            "text": "The collateral schedule matched observed hardware.",
        },
        "expected_evidence": [
            "gpu_inventory.declared_serials",
            "gpu_inventory.declared_node_id",
            "gpu_probe_observation.observed_serials",
            "gpu_probe_observation.observed_node_id",
            "gpu_probe_observation.observed_at",
            "probe_manifest.probe_id",
            "probe_manifest.probe_hash",
            "probe_manifest.committed_at",
        ],
        "applicability_evidence": [
            "gpu_inventory",
            "gpu_probe_observation",
        ],
        "passes": [
            "utc_timestamp_format",
            "expected_evidence_absence",
            "no_future_evidence",
            "gpu_serial_set_match",
            "gpu_node_id_match",
        ],
        "pass_params": {},
    }

    with tempfile.TemporaryDirectory() as tmp:
        pack_dir = Path(tmp)
        (pack_dir / "collateral_schedule_attestation.json").write_text(
            json.dumps(custom_gpu_pack),
            encoding="utf-8",
        )
        registry = build_claim_registry(pack_dir)
        artifacts, artifact_manifest, input_hash = load_artifacts_dir_with_manifest(
            ROOT / "examples" / "gpu_serial_match_supported"
        )
        receipt = compile_claim(
            artifacts,
            "collateral_schedule_attestation",
            artifact_manifest=artifact_manifest,
            input_set_hash=input_hash,
            claim_types=registry,
        ).to_dict()

    assert receipt["verdict"]["status"] == SUPPORTED
    assert receipt["claim"]["id"] == "claim.collateral_schedule_attestation"
    assert receipt["renderer_family"] == "gpu_collateral"
    gpu_boundary = "\n".join(receipt["boundary"]["does_not_support"])
    assert "representative production load" in gpu_boundary
    assert "residual economic value" in gpu_boundary
    assert "That the collateral is worth any specific dollar amount." in receipt["unsupported_inferences"]


def _pass_ir(artifacts: dict) -> ReceiptIR:
    return ReceiptIR(claim={"id": "claim.test", "text": "test"}, expected_evidence=[], artifacts=artifacts)


def test_grant_binding_cross_boundary_pass_units() -> None:
    matched = _pass_ir({
        "authorization": {
            "render_time_grant_hash": "sha256:test-grant",
            "execution_time_decision_id": "decision-123",
            "grant_active_at_execution": True,
        },
        SIDE_EFFECTS_KEY: [{"invocation": {"decision_id": "decision-123"}}],
    })
    assert grant_binding_present(matched).status == PASS_SATISFIED

    missing_tool_side = _pass_ir({
        "authorization": {
            "render_time_grant_hash": "sha256:test-grant",
            "execution_time_decision_id": "decision-123",
            "grant_active_at_execution": True,
        },
        SIDE_EFFECTS_KEY: [{"invocation": {}}],
    })
    missing_result = grant_binding_present(missing_tool_side)
    assert missing_result.status == UNKNOWN
    assert missing_result.verdict_effect == UNKNOWN
    assert missing_result.metadata["missing_expected_paths"] == [SIDE_EFFECT_DECISION_ID_PATH]

    missing_active = _pass_ir({
        "authorization": {
            "render_time_grant_hash": "sha256:test-grant",
            "execution_time_decision_id": "decision-123",
        },
        SIDE_EFFECTS_KEY: [{"invocation": {"decision_id": "decision-123"}}],
    })
    missing_active_result = grant_binding_present(missing_active)
    assert missing_active_result.status == UNKNOWN
    assert missing_active_result.verdict_effect == UNKNOWN
    assert missing_active_result.metadata["missing_expected_paths"] == ["authorization.grant_active_at_execution"]

    inactive = _pass_ir({
        "authorization": {
            "render_time_grant_hash": "sha256:test-grant",
            "execution_time_decision_id": "decision-123",
            "grant_active_at_execution": False,
        },
        SIDE_EFFECTS_KEY: [{"invocation": {"decision_id": "decision-123"}}],
    })
    inactive_result = grant_binding_present(inactive)
    assert inactive_result.status == PASS_CONTRADICTED
    assert inactive_result.verdict_effect == CONTRADICTED
    assert inactive_result.metadata["field"] == "authorization.grant_active_at_execution"

    mismatched = _pass_ir({
        "authorization": {
            "render_time_grant_hash": "sha256:test-grant",
            "execution_time_decision_id": "decision-123",
            "grant_active_at_execution": True,
        },
        SIDE_EFFECTS_KEY: [{"invocation": {"decision_id": "decision-999"}}],
    })
    mismatch_result = grant_binding_present(mismatched)
    assert mismatch_result.status == PASS_CONTRADICTED
    assert mismatch_result.verdict_effect == CONTRADICTED


def test_inactive_grant_execution_flag_contradicts_authorization_claim() -> None:
    receipt = compile_claim(
        {
            "authorization": {
                "grant_id": "grant-inactive-at-execution",
                "grant_valid_from": "2026-05-14T16:00:00Z",
                "grant_valid_until": "2026-05-14T18:00:00Z",
                "revoked_at": None,
                "render_time_grant_hash": "sha256:test-grant",
                "execution_time_decision_id": "decision-inactive",
                "grant_active_at_execution": False,
            },
            "parsed_actions": [
                {
                    "action_id": "action-inactive",
                    "tool": "stripe.charges.create",
                    "executed_at": "2026-05-14T17:01:30Z",
                    "source_kind": "model_output",
                }
            ],
            "tool_call": {
                "action_id": "action-inactive",
                "tool_name": "stripe.charges.create",
                "invocation_context": {"decision_id": "decision-inactive"},
            },
        },
        "authorization_bound_action",
    )
    assert receipt.verdict["status"] == CONTRADICTED
    binding_pass = [result for result in receipt.pass_results if result["pass_id"] == "grant_binding_present"][0]
    assert binding_pass["status"] == PASS_CONTRADICTED
    assert binding_pass["verdict_effect"] == CONTRADICTED
    assert "grant_active_at_execution is false" in binding_pass["detail"]


def test_gpu_collateral_pass_units() -> None:
    serial_ir = _pass_ir({
        "gpu_inventory": {
            "declared_serials": ["GPU-A", "GPU-B"],
            "declared_node_id": "node-1",
        },
        "gpu_probe_observation": {
            "observed_serials": ["GPU-B", "GPU-A"],
            "observed_node_id": "node-1",
        },
    })
    assert gpu_serial_set_match(serial_ir).status == PASS_SATISFIED
    assert gpu_node_id_match(serial_ir).status == PASS_SATISFIED

    serial_bad = _pass_ir({
        "gpu_inventory": {
            "declared_serials": ["GPU-A", "GPU-B"],
            "declared_node_id": "node-1",
        },
        "gpu_probe_observation": {
            "observed_serials": ["GPU-A", "GPU-Z"],
            "observed_node_id": "node-2",
        },
    })
    assert gpu_serial_set_match(serial_bad).status == PASS_CONTRADICTED
    assert gpu_node_id_match(serial_bad).status == PASS_CONTRADICTED
    assert gpu_serial_set_match(_pass_ir({})).status == PASS_SKIPPED
    assert gpu_node_id_match(_pass_ir({})).status == PASS_SKIPPED

    health_ir = _pass_ir({
        "dcgm_diag": {
            "gpu_serial": "GPU-A",
            "overall_result": "Pass",
            "test_results": [{"test_name": "memory_stress", "result": "Pass"}],
        },
        "xid_ecc_log": {
            "gpu_serial": "GPU-A",
            "volatile_dbe_errors": 0,
            "total_retired_pages": 2,
            "page_retirement_limit": 512,
        },
        "nvidia_smi": {"gpu_serial": "GPU-A"},
    })
    assert dcgm_diag_result(health_ir).status == PASS_SATISFIED
    assert ecc_threshold_check(health_ir).status == PASS_SATISFIED
    assert gpu_serial_cross_reference(health_ir).status == PASS_SATISFIED

    health_bad = _pass_ir({
        "dcgm_diag": {
            "gpu_serial": "GPU-A",
            "overall_result": "Fail",
            "test_results": [{"test_name": "memory_stress", "result": "Fail"}],
        },
        "xid_ecc_log": {
            "gpu_serial": "GPU-B",
            "volatile_dbe_errors": 1,
            "total_retired_pages": 512,
            "page_retirement_limit": 512,
        },
        "nvidia_smi": {"gpu_serial": "GPU-A"},
    })
    assert dcgm_diag_result(health_bad).status == PASS_CONTRADICTED
    assert ecc_threshold_check(health_bad).status == PASS_CONTRADICTED
    assert gpu_serial_cross_reference(health_bad).status == PASS_CONTRADICTED
    assert dcgm_diag_result(_pass_ir({})).status == PASS_SKIPPED
    assert ecc_threshold_check(_pass_ir({})).status == PASS_SKIPPED
    assert gpu_serial_cross_reference(_pass_ir({})).status == PASS_SKIPPED


def test_gpu_capacity_acceptance_pass_units() -> None:
    supported = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 8,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H100 80GB HBM3"] * 8,
            "observed_count": 8,
            "observed_mig_modes": ["Disabled"] * 8,
        },
    })
    assert gpu_sku_count_match(supported).status == PASS_SATISFIED
    assert gpu_not_mig_sliced(supported).status == PASS_SATISFIED

    wrong_sku = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 8,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H100 80GB HBM3"] * 7 + ["NVIDIA A100 80GB PCIe"],
            "observed_count": 8,
        },
    })
    assert gpu_sku_count_match(wrong_sku).status == PASS_CONTRADICTED

    short_count = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 8,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H100 80GB HBM3"] * 7,
            "observed_count": 7,
        },
    })
    assert gpu_sku_count_match(short_count).status == PASS_CONTRADICTED

    over_count = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 8,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H100 80GB HBM3"] * 9,
            "observed_count": 9,
        },
    })
    over_count_result = gpu_sku_count_match(over_count)
    assert over_count_result.status == PASS_SATISFIED
    assert "additional observed GPU" in over_count_result.detail

    partial_names = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 8,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H100 80GB HBM3"],
            "observed_count": 8,
        },
    })
    assert gpu_sku_count_match(partial_names).status == PASS_UNKNOWN

    misleading_name = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 1,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H1000 test fixture"],
            "observed_count": 1,
        },
    })
    assert gpu_sku_count_match(misleading_name).status == PASS_CONTRADICTED

    mig_na = _pass_ir({"gpu_probe_observation": {"observed_mig_modes": ["N/A", "Disabled"], "observed_count": 2}})
    assert gpu_not_mig_sliced(mig_na).status == PASS_SATISFIED

    mig_enabled = _pass_ir({"gpu_probe_observation": {"observed_mig_modes": ["Disabled", "Enabled"], "observed_count": 2}})
    assert gpu_not_mig_sliced(mig_enabled).status == PASS_CONTRADICTED

    partial_mig = _pass_ir({"gpu_probe_observation": {"observed_mig_modes": ["Disabled"], "observed_count": 8}})
    assert gpu_not_mig_sliced(partial_mig).status == PASS_UNKNOWN

    assert gpu_not_mig_sliced(_pass_ir({"gpu_probe_observation": {"observed_mig_modes": []}})).status == PASS_UNKNOWN
    assert gpu_sku_count_match(_pass_ir({})).status == PASS_UNKNOWN


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


def test_nvidia_smi_importer_bridge() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        reservation_path = tmp_path / "reservation.json"
        reservation_path.write_text(
            json.dumps({
                "declared_sku": "H100-SXM5-80GB",
                "declared_count": 8,
                "declared_topology_class": "HGX H100 NVL8",
                "declared_region": "us-east",
            }),
            encoding="utf-8",
        )
        csv_path = tmp_path / "nvidia_smi_query.csv"
        rows = [
            "index,uuid,name,mig.mode.current,timestamp",
            *[
                f"{index},GPU-{index:04d},NVIDIA H100 80GB HBM3,Disabled,2026/05/26 14:02:46.123"
                for index in range(8)
            ],
        ]
        csv_path.write_text("\n".join(rows), encoding="utf-8")

        imported = run_import_nvidia_smi_process(str(csv_path), "--reservation", str(reservation_path))
        assert imported.returncode == 0, imported.stderr
        artifacts = json.loads(imported.stdout)
        assert artifacts["gpu_inventory"]["declared_sku"] == "H100-SXM5-80GB"
        assert artifacts["gpu_probe_observation"]["observed_count"] == 8
        assert artifacts["gpu_probe_observation"]["observed_at"] == "2026-05-26T14:02:46Z"

        piped = run_compile_process(
            "-",
            "--claim-type",
            "gpu_capacity_acceptance",
            "-v",
            input_text=imported.stdout,
        )
        assert piped.returncode == 0, piped.stderr
        assert piped.stdout.strip() == "SUPPORTED"

        out_dir = tmp_path / "artifacts"
        written = run_import_nvidia_smi_process(str(csv_path), "--reservation", str(reservation_path), "--out", str(out_dir))
        assert written.returncode == 0, written.stderr
        assert (out_dir / "gpu_inventory.json").is_file()
        assert (out_dir / "gpu_probe_observation.json").is_file()
        compiled = run_compile_process(str(out_dir), "--claim-type", "gpu_capacity_acceptance", "-v")
        assert compiled.returncode == 0, compiled.stderr
        assert compiled.stdout.strip() == "SUPPORTED"

        bad_timestamp_path = tmp_path / "bad_timestamp.csv"
        bad_timestamp_path.write_text(
            "\n".join([
                "index,uuid,name,mig.mode.current,timestamp",
                "0,GPU-0000,NVIDIA H100 80GB HBM3,Disabled,yesterday",
            ]),
            encoding="utf-8",
        )
        bad_timestamp = run_import_nvidia_smi_process(str(bad_timestamp_path), "--reservation", str(reservation_path))
        assert bad_timestamp.returncode == 1
        assert bad_timestamp.stdout == ""
        assert "could not normalize timestamp" in bad_timestamp.stderr


def test_capture_acceptance_fails_closed_when_nvidia_smi_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        fake_nvidia_smi = bin_dir / "nvidia-smi"
        fake_nvidia_smi.write_text("#!/usr/bin/env bash\nexit 42\n", encoding="utf-8")
        fake_nvidia_smi.chmod(0o755)

        env = {**ENV, "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin"}
        proc = subprocess.run(
            ["/bin/bash", "capture_acceptance.sh", str(tmp_path / "packet")],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        assert proc.returncode == 42
        assert "wrote" not in proc.stdout


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


def test_gallery_manifest_outputs() -> None:
    manifest = load_manifest()
    examples = manifest["examples"]
    expected_dirs = {entry["directory"] for entry in examples}
    actual_dirs = {
        path.name
        for path in (ROOT / "examples").iterdir()
        if path.is_dir() and list(path.glob("*.json"))
    }
    assert actual_dirs == expected_dirs

    total_receipts = 0
    verdict_counts: dict[str, int] = {}
    compiler_errors = 0

    for entry in examples:
        directory = entry["directory"]
        expected_receipts = entry["expected_receipts"]
        loaded = load_artifacts_dir_bound(ROOT / "examples" / directory)
        artifacts = loaded.artifacts
        artifact_manifest = loaded.artifact_manifest
        input_hash = loaded.input_set_hash
        incident_manifest = loaded.incident_manifest
        manifest_claim_types = sorted({receipt["claim_type"] for receipt in expected_receipts})
        detected_claim_types = detect_applicable_claim_types(artifacts)
        if expected_receipts and expected_receipts[0]["verdict"] == NOT_APPLICABLE:
            assert detected_claim_types == [], directory
        else:
            assert detected_claim_types == manifest_claim_types, directory

        compiled_receipts = []
        for claim_type in manifest_claim_types:
            compiled_receipts.extend(
                receipt.to_dict()
                for receipt in compile_claims(
                    artifacts,
                    claim_type,
                    artifact_manifest=artifact_manifest,
                    input_set_hash=input_hash,
                    incident_manifest=incident_manifest,
                    execution_context=loaded.execution_context,
                )
            )

        expected_signatures = sorted(
            (
                expected["claim_type"],
                expected["verdict"],
                expected["absence_count"],
                expected["compiler_error_count"],
            )
            for expected in expected_receipts
        )
        actual_signatures = sorted(
            (
                receipt["claim_type"],
                receipt["verdict"]["status"],
                len(receipt.get("absence", [])),
                len(receipt.get("compiler_errors", [])),
            )
            for receipt in compiled_receipts
        )
        assert actual_signatures == expected_signatures, (directory, actual_signatures, expected_signatures)

        for expected in expected_receipts:
            name_verdict = verdict_word_in_directory(directory)
            if name_verdict and name_verdict != expected["verdict"]:
                assert expected.get("directory_verdict_rationale"), (
                    f"{directory} names {name_verdict} but manifest expects {expected['verdict']}"
                )
            assert expected.get("rationale"), directory

        for receipt in compiled_receipts:
            validation_errors = validate_receipt(receipt)
            assert validation_errors == [], (directory, receipt["claim_type"], validation_errors)
            assert receipt.get("artifact_manifest"), (directory, receipt)
            assert len(receipt.get("input_set_hash", "")) == 64, (directory, receipt)

            total_receipts += 1
            verdict = receipt["verdict"]["status"]
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            compiler_errors += len(receipt.get("compiler_errors", []))

    summary = manifest["summary"]
    assert len(examples) == summary["expected_directories"]
    assert total_receipts == summary["expected_receipts"]
    assert compiler_errors == summary["expected_compiler_errors"]
    for verdict, expected_count in summary["expected_verdict_counts"].items():
        assert verdict_counts.get(verdict, 0) == expected_count, verdict


def test_gallery_summary_and_json_output() -> None:
    manifest = load_manifest()
    _, summary = run_gallery()
    expected = manifest["summary"]
    assert summary["directories"] == expected["expected_directories"]
    assert summary["receipts"] == expected["expected_receipts"]
    assert summary["compiler_errors"] == expected["expected_compiler_errors"]
    assert summary["validation_errors"] == 0
    for verdict, expected_count in expected["expected_verdict_counts"].items():
        assert summary["verdict_counts"].get(verdict, 0) == expected_count, verdict

    proc = subprocess.run(
        [PYTHON, "demo_gallery.py", "--json"],
        cwd=ROOT,
        env=ENV,
        check=True,
        text=True,
        capture_output=True,
    )
    data = json.loads(proc.stdout)
    assert data["summary"] == summary


def main() -> int:
    test_v1_bundles()
    test_v2_explicit_claim_types()
    test_v2_auto_detect_and_out_dir()
    test_v4_adversarial_controls_and_not_applicable()
    test_source_file_binding_verification()
    test_v5_incident_manifest_and_explain_output()
    test_v6_external_claim_pack_registry()
    test_claim_contract_helpers_drive_readiness_semantics()
    test_claim_contract_discovery_surfaces_minimum_runtime_facts()
    test_side_effect_envelope_v1_compiles_and_scans()
    test_action_scoped_side_effect_envelopes_compile_independently()
    test_v6_incident_manifest_path_boundaries()
    test_v7_execution_context_absent_is_noop()
    test_v7_execution_context_round_trip_and_unknown_schema()
    test_v7_gpu_execution_context_disclosures()
    test_v7_complete_gpu_execution_context_adds_no_negative_context_disclosures()
    test_v7_execution_context_file_loaded_outside_artifacts()
    test_gpu_collateral_gallery_fixtures()
    test_gpu_capacity_acceptance_gallery_fixtures()
    test_gpu_boundary_uses_renderer_family_not_claim_id_prefix()
    test_grant_binding_cross_boundary_pass_units()
    test_gpu_collateral_pass_units()
    test_gpu_capacity_acceptance_pass_units()
    test_inactive_grant_execution_flag_contradicts_authorization_claim()
    test_one_line_compile_wrapper()
    test_one_line_compile_directory_errors_do_not_traceback()
    test_gap_card_and_ci_outputs()
    test_authorization_decision_id_mismatch_cannot_support()
    test_authorization_missing_runtime_decision_id_cannot_support()
    test_hero_authorization_demo_packets()
    test_reference_authorization_boundary_probe_fills_hero_evidence_gap()
    test_reference_authorization_boundary_probe_preserves_contradiction()
    test_reference_authorization_boundary_probe_fails_closed_on_bad_revocation_time()
    test_anthropic_importer_bridge()
    test_anthropic_importer_missing_timestamp_fails_closed()
    test_nvidia_smi_importer_bridge()
    test_capture_acceptance_fails_closed_when_nvidia_smi_fails()
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
    test_ashiba_scan_readiness_gaps()
    test_ashiba_scan_readiness_json_packets()
    test_ashiba_scan_action_readiness_json()
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
    test_gallery_manifest_outputs()
    test_gallery_summary_and_json_output()
    print("receipt compiler smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
