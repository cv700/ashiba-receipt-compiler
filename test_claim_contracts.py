#!/usr/bin/env python3
"""Claim-pack and SideEffectEnvelope contract tests."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from claim_contracts import (
    claim_artifact_roots,
    claim_conflicts,
    claim_has_action_scope,
    claim_missing,
)

from constants import (
    CONTRADICTED,
    SUPPORTED,
    UNKNOWN,
)

from passes import get_pass_spec

from receipt_compile import (
    build_claim_registry,
    compile_claim,
    compile_claims,
    load_artifacts_dir_with_manifest,
)

from side_effect_envelope import (
    SIDE_EFFECT_ACTION_ID_PATH,
    SIDE_EFFECT_DECISION_ID_PATH,
    SIDE_EFFECT_EXECUTED_AT_PATH,
    SIDE_EFFECTS_KEY,
)

from test_support import (
    ENV,
    PYTHON,
    ROOT,
    assert_receipt,
    run_ashiba_process,
    run_compile_process,
    run_json,
    run_process,
    run_text,
)


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
    artifact_roots = set(claim_artifact_roots(registry))

    assert {
        SIDE_EFFECTS_KEY,
        "authorization",
        "approval",
        "deployment",
        "review",
        "gpu_inventory",
        "gpu_probe_observation",
        "dcgm_diag",
        "xid_ecc_log",
        "nvidia_smi",
        "probe_manifest",
    } <= artifact_roots
    assert "parsed_actions" not in artifact_roots
    assert "tool_call" not in artifact_roots

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


def run_claim_contract_tests() -> None:
    test_v6_external_claim_pack_registry()
    test_claim_contract_helpers_drive_readiness_semantics()
    test_claim_contract_discovery_surfaces_minimum_runtime_facts()
    test_side_effect_envelope_v1_compiles_and_scans()
    test_action_scoped_side_effect_envelopes_compile_independently()
    test_v6_incident_manifest_path_boundaries()
