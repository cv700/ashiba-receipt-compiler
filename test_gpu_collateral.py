#!/usr/bin/env python3
"""GPU collateral and low-level pass tests."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from constants import (
    CONTRADICTED,
    PASS_CONTRADICTED,
    PASS_SATISFIED,
    PASS_SKIPPED,
    PASS_UNKNOWN,
    SUPPORTED,
    UNKNOWN,
)

from passes import (
    dcgm_diag_result,
    ecc_threshold_check,
    gpu_attestation_binding,
    grant_binding_present,
    gpu_node_id_match,
    gpu_serial_cross_reference,
    gpu_serial_set_match,
)

from receipt_compile import (
    build_claim_registry,
    compile_claim,
    load_artifacts_dir_with_manifest,
)

from receipt_ir import ReceiptIR

from side_effect_envelope import (
    SIDE_EFFECT_DECISION_ID_PATH,
    SIDE_EFFECTS_KEY,
)

from test_support import (
    ROOT,
    run_compile_process,
    run_json,
)


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
        (
            "gpu_serial_report_vs_attestation_planted_fraud",
            "gpu_serial_collateral_match",
            SUPPORTED,
            0,
            {"gpu_serial_set_match", "gpu_node_id_match"},
        ),
        (
            "gpu_serial_report_vs_attestation_planted_fraud",
            "gpu_attested_identity_window",
            CONTRADICTED,
            0,
            {"gpu_attestation_binding"},
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


def test_gpu_attestation_binding_pass_units() -> None:
    challenge = "a1b2c3d4e5f6a7b8"
    eat_nonce = challenge + "0" * 50
    ueid_a = "UEID-AAAA"
    ueid_b = "UEID-BBBB"

    def artifacts(**overrides):
        base = {
            "probe_manifest": {
                "challenge_nonce": challenge,
                "declared_gpu_ids": ["GPU-1", "GPU-2"],
                "window_start": "2026-06-01T00:00:00Z",
                "window_end": "2026-06-08T00:00:00Z",
            },
            "gpu_attestation": {
                "attested_ueids": [ueid_a, ueid_b],
                "attestation_nonce": eat_nonce,
                "nonce_match": True,
                "cert_chain_verified": True,
                "collected_at": "2026-06-01T10:00:00Z",
            },
            "identity_bridge": {
                "schedule_id": "UCC1-2026-0042",
                "mapping_source": "provider asset register export",
                "mapping_time": "2026-05-30T09:00:00Z",
                "mapper": "lender-ops@example.com",
                "mappings": [
                    {"contract_gpu_id": "GPU-1", "ueid": ueid_a},
                    {"contract_gpu_id": "GPU-2", "ueid": ueid_b},
                ],
            },
        }
        for key, value in overrides.items():
            if value is None:
                base.pop(key, None)
            else:
                base[key] = {**base[key], **value}
        return base

    # fresh, bridged, in-window evidence satisfies the binding
    good = gpu_attestation_binding(_pass_ir(artifacts()))
    assert good.status == PASS_SATISFIED, good.detail

    # the EAT nonce may equal the challenge exactly (no padding)
    exact = artifacts(gpu_attestation={"attestation_nonce": challenge})
    assert gpu_attestation_binding(_pass_ir(exact)).status == PASS_SATISFIED

    # missing attestation -> UNKNOWN
    missing_att = gpu_attestation_binding(_pass_ir(artifacts(gpu_attestation=None)))
    assert missing_att.status == PASS_UNKNOWN
    assert "gpu_attestation.attested_ueids" in missing_att.metadata["missing_expected_paths"]

    # missing identity bridge -> UNKNOWN, never SUPPORTED
    missing_bridge = gpu_attestation_binding(_pass_ir(artifacts(identity_bridge=None)))
    assert missing_bridge.status == PASS_UNKNOWN
    assert "identity_bridge.mappings" in missing_bridge.metadata["missing_expected_paths"]

    # cert chain failed -> CONTRADICTED
    cert_failed = artifacts(gpu_attestation={"cert_chain_verified": False})
    assert gpu_attestation_binding(_pass_ir(cert_failed)).status == PASS_CONTRADICTED

    # cert chain indeterminate (non-boolean) -> UNKNOWN
    cert_odd = artifacts(gpu_attestation={"cert_chain_verified": "valid"})
    assert gpu_attestation_binding(_pass_ir(cert_odd)).status == PASS_UNKNOWN

    # replayed attestation: EAT nonce echoes a stale challenge -> CONTRADICTED
    replayed = artifacts(gpu_attestation={"attestation_nonce": "deadbeef" + "0" * 58, "nonce_match": False})
    assert gpu_attestation_binding(_pass_ir(replayed)).status == PASS_CONTRADICTED

    # loose prefix is not binding: remainder after the challenge must be all zeros
    loose = artifacts(gpu_attestation={"attestation_nonce": challenge + "1" + "0" * 49})
    assert gpu_attestation_binding(_pass_ir(loose)).status == PASS_CONTRADICTED

    # importer-recorded nonce_match=False is verdict-determining even if nonces look bound
    importer_flag = artifacts(gpu_attestation={"nonce_match": False})
    assert gpu_attestation_binding(_pass_ir(importer_flag)).status == PASS_CONTRADICTED

    # declared GPU ID with no bridge entry -> UNKNOWN (cannot resolve identity)
    unbridged = artifacts(identity_bridge={"mappings": [{"contract_gpu_id": "GPU-1", "ueid": ueid_a}]})
    unbridged_result = gpu_attestation_binding(_pass_ir(unbridged))
    assert unbridged_result.status == PASS_UNKNOWN
    assert "GPU-2" in unbridged_result.metadata["declared_gpu_ids_without_bridge_entry"]

    # bridged UEID absent from attested set -> CONTRADICTED with the mismatch named
    swapped = artifacts(gpu_attestation={"attested_ueids": [ueid_a, "UEID-PLANTED"]})
    swapped_result = gpu_attestation_binding(_pass_ir(swapped))
    assert swapped_result.status == PASS_CONTRADICTED
    assert any("GPU-2" in item for item in swapped_result.metadata["declared_gpu_id_to_bridged_ueid_mismatches"])
    assert "UEID-PLANTED" in swapped_result.metadata["attested_ueids_not_bridged"]

    # attestation collected outside the contract window -> UNKNOWN
    stale_window = artifacts(gpu_attestation={"collected_at": "2026-06-09T10:00:00Z"})
    stale_result = gpu_attestation_binding(_pass_ir(stale_window))
    assert stale_result.status == PASS_UNKNOWN
    assert "outside the contract window" in stale_result.detail

    # a definite parsed-vs-raw-token payload conflict is verdict-determining
    token_conflict = artifacts(gpu_attestation={"token_payload_consistent": False})
    assert gpu_attestation_binding(_pass_ir(token_conflict)).status == PASS_CONTRADICTED

    # the token's own verifier verdict is verdict-determining
    verifier_rejected = artifacts(gpu_attestation={"overall_result": False})
    assert gpu_attestation_binding(_pass_ir(verifier_rejected)).status == PASS_CONTRADICTED

    # a non-success firmware measurement result is verdict-determining
    meas_failed = artifacts(gpu_attestation={"measres": "failure"})
    assert gpu_attestation_binding(_pass_ir(meas_failed)).status == PASS_CONTRADICTED

    # attested hardware model must match the expected GPU class from the manifest
    wrong_class = artifacts(
        probe_manifest={"expected_gpu_class": "H100"},
        gpu_attestation={"hwmodel": "GA100 A01 GSP BROM"},
    )
    assert gpu_attestation_binding(_pass_ir(wrong_class)).status == PASS_CONTRADICTED
    right_class = artifacts(
        probe_manifest={"expected_gpu_class": "H100"},
        gpu_attestation={"hwmodel": "GH100 A01 GSP BROM", "measres": "success", "overall_result": True},
    )
    assert gpu_attestation_binding(_pass_ir(right_class)).status == PASS_SATISFIED


def run_gpu_collateral_tests() -> None:
    test_gpu_collateral_gallery_fixtures()
    test_gpu_boundary_uses_renderer_family_not_claim_id_prefix()
    test_grant_binding_cross_boundary_pass_units()
    test_inactive_grant_execution_flag_contradicts_authorization_claim()
    test_gpu_collateral_pass_units()
    test_gpu_attestation_binding_pass_units()
