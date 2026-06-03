#!/usr/bin/env python3
"""GPU sustained-capacity impairment watch smoke tests."""

from __future__ import annotations

import copy
import json

from constants import (
    CONTRADICTED,
    PASS_CONTRADICTED,
    PASS_SATISFIED,
    PASS_UNKNOWN,
    SUPPORTED,
    UNKNOWN,
)
from passes import gpu_sustained_capacity_impairment_watch
from receipt_ir import ReceiptIR
from scan_artifacts import claim_artifact_keys, gpu_artifact_keys
from test_support import run_ashiba_process, run_receipt_json


def _pass_ir(artifacts: dict) -> ReceiptIR:
    return ReceiptIR(receipt_id="test", claim_type="test", claim={}, expected_evidence=[], artifacts=artifacts)


def _supported_artifacts() -> dict:
    return {
        "declaration": {
            "hardware_class": "8x H100 SXM",
            "window_start": "2026-06-01T00:00:00Z",
            "window_end": "2026-06-01T00:10:00Z",
            "min_sample_count": 2,
            "min_mean_gpu_utilization_pct": 70,
            "min_clock_ratio": 0.9,
            "max_throttle_sample_fraction": 0.02,
            "min_thermal_margin_c": 5,
            "min_power_margin_watts": 50,
            "max_uncorrectable_ecc_delta": 0,
            "max_xid_count_delta": 0,
            "max_fabric_error_delta": 0,
        },
        "gpu_impairment_binding": {
            "node_id": "node-redacted-001",
            "gpu_uuids": ["GPU-redacted-001", "GPU-redacted-002"],
            "binding_basis": "nvidia_smi_uuid",
        },
        "gpu_impairment_window": {
            "node_id": "node-redacted-001",
            "samples": [
                {
                    "observed_at": "2026-06-01T00:01:00Z",
                    "gpu_uuid": "GPU-redacted-001",
                    "gpu_utilization_pct": 88,
                    "sm_clock_mhz": 1880,
                    "expected_sm_clock_mhz": 1980,
                    "gpu_temp_c": 75,
                    "thermal_limit_c": 90,
                    "power_watts": 610,
                    "power_limit_watts": 700,
                    "throttle_reasons": [],
                    "uncorrectable_ecc_delta": 0,
                    "xid_count_delta": 0,
                    "fabric_error_delta": 0,
                },
                {
                    "observed_at": "2026-06-01T00:02:00Z",
                    "gpu_uuid": "GPU-redacted-002",
                    "gpu_utilization_pct": 84,
                    "sm_clock_mhz": 1875,
                    "expected_sm_clock_mhz": 1980,
                    "gpu_temp_c": 76,
                    "thermal_limit_c": 90,
                    "power_watts": 620,
                    "power_limit_watts": 700,
                    "throttle_reasons": [],
                    "uncorrectable_ecc_delta": 0,
                    "xid_count_delta": 0,
                    "fabric_error_delta": 0,
                },
            ],
        },
    }


def test_gpu_impairment_gallery_fixtures() -> None:
    cases = [
        ("gpu_impairment_supported", SUPPORTED, PASS_SATISFIED),
        ("gpu_impairment_contradicted_thermal", CONTRADICTED, PASS_CONTRADICTED),
        ("gpu_impairment_contradicted_fabric", CONTRADICTED, PASS_CONTRADICTED),
        ("gpu_impairment_unknown_idle", UNKNOWN, PASS_UNKNOWN),
        ("gpu_impairment_unknown_missing_clock", UNKNOWN, PASS_UNKNOWN),
    ]

    for directory, verdict, expected_status in cases:
        receipt = run_receipt_json(
            "--artifacts-dir",
            f"examples/{directory}",
            "--claim-type",
            "gpu_sustained_capacity_impairment_watch",
        )
        assert receipt["verdict"]["status"] == verdict, (directory, receipt)
        assert len(receipt.get("absence", [])) == 0, (directory, receipt)
        pass_results = {result["pass_id"]: result for result in receipt["pass_results"]}
        result = pass_results["gpu_sustained_capacity_impairment_watch"]
        assert result["status"] == expected_status, (directory, result)
        if directory == "gpu_impairment_supported":
            observed = result["metadata"]["observed"]
            assert observed["sample_count"] == 2
            assert observed["mean_gpu_utilization_pct"] == 86.0
            assert "dimension_margins" in result["metadata"]
        if directory == "gpu_impairment_unknown_idle":
            assert "meaningful-load threshold" in result["detail"]
        if directory == "gpu_impairment_unknown_missing_clock":
            assert "malformed sample row" in result["detail"]


def test_gpu_impairment_pass_units() -> None:
    supported = _supported_artifacts()
    supported_result = gpu_sustained_capacity_impairment_watch(_pass_ir(supported))
    assert supported_result.status == PASS_SATISFIED
    assert supported_result.verdict_effect == SUPPORTED

    low_load = copy.deepcopy(supported)
    for sample in low_load["gpu_impairment_window"]["samples"]:
        sample["gpu_utilization_pct"] = 10
    low_load_result = gpu_sustained_capacity_impairment_watch(_pass_ir(low_load))
    assert low_load_result.status == PASS_UNKNOWN
    assert low_load_result.verdict_effect == UNKNOWN
    assert "meaningful-load threshold" in low_load_result.detail

    thermal = copy.deepcopy(supported)
    thermal["gpu_impairment_window"]["samples"][0]["gpu_temp_c"] = 88
    thermal_result = gpu_sustained_capacity_impairment_watch(_pass_ir(thermal))
    assert thermal_result.status == PASS_CONTRADICTED
    assert "thermal margin" in thermal_result.detail

    unbound = copy.deepcopy(supported)
    unbound["gpu_impairment_window"]["samples"][0]["gpu_uuid"] = "GPU-redacted-999"
    unbound_result = gpu_sustained_capacity_impairment_watch(_pass_ir(unbound))
    assert unbound_result.status == PASS_CONTRADICTED
    assert "outside the bound node schedule" in unbound_result.detail

    missing_clock = copy.deepcopy(supported)
    del missing_clock["gpu_impairment_window"]["samples"][0]["expected_sm_clock_mhz"]
    missing_clock_result = gpu_sustained_capacity_impairment_watch(_pass_ir(missing_clock))
    assert missing_clock_result.status == PASS_UNKNOWN
    assert missing_clock_result.verdict_effect == UNKNOWN
    assert missing_clock_result.metadata["malformed_sample_indexes"] == [0]


def test_ashiba_scan_recognizes_gpu_impairment_artifacts() -> None:
    for artifact_key in ("declaration", "gpu_impairment_window", "gpu_impairment_binding"):
        assert artifact_key in claim_artifact_keys()
        assert artifact_key in gpu_artifact_keys()

    supported = run_ashiba_process("scan", "examples/gpu_impairment_supported", "--json")
    assert supported.returncode == 0, supported.stderr
    supported_result = json.loads(supported.stdout)
    assert "gpu_sustained_capacity_impairment_watch" in supported_result["can_decide"]
    assert supported_result["cannot_decide"] == []


def run_gpu_impairment_tests() -> None:
    test_gpu_impairment_gallery_fixtures()
    test_gpu_impairment_pass_units()
    test_ashiba_scan_recognizes_gpu_impairment_artifacts()
