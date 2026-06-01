#!/usr/bin/env python3
"""Execution-context receipt tests."""

from __future__ import annotations

import json

from constants import (
    PASS_OK,
    SUPPORTED,
)

from receipt_compile import (
    compile_bundle,
    compile_claim,
    load_artifacts_dir_bound,
)

from test_support import (
    ROOT,
    assert_receipt,
    run_json,
)


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


def run_execution_context_tests() -> None:
    test_v7_execution_context_absent_is_noop()
    test_v7_execution_context_round_trip_and_unknown_schema()
    test_v7_gpu_execution_context_disclosures()
    test_v7_complete_gpu_execution_context_adds_no_negative_context_disclosures()
    test_v7_execution_context_file_loaded_outside_artifacts()
