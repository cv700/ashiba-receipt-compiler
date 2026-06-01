#!/usr/bin/env python3
"""GPU power/utilization consistency smoke tests."""

from __future__ import annotations

import json

from constants import (
    CONTRADICTED,
    PASS_CONTRADICTED,
    PASS_SATISFIED,
    PASS_UNKNOWN,
    SUPPORTED,
    UNKNOWN,
)
from passes import gpu_power_utilization_consistency
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
            "expected_power_band_kw": {"min": 6.5, "max": 9.0},
            "expected_gpu_utilization_pct": {"min": 80, "max": 100},
        },
        "gpu_utilization_window": {
            "node_id": "node-redacted-001",
            "samples": [
                {"observed_at": "2026-06-01T00:01:00Z", "gpu_utilization_pct": 94},
                {"observed_at": "2026-06-01T00:02:00Z", "gpu_utilization_pct": 92},
            ],
        },
        "power_window": {
            "rack_id": "rack-redacted-001",
            "samples": [
                {"observed_at": "2026-06-01T00:01:00Z", "rack_power_kw": 7.92},
                {"observed_at": "2026-06-01T00:02:00Z", "rack_power_kw": 7.8},
            ],
        },
        "node_rack_binding": {
            "node_id": "node-redacted-001",
            "rack_id": "rack-redacted-001",
        },
    }


def test_gpu_power_consistency_gallery_fixtures() -> None:
    cases = [
        ("gpu_power_consistency_supported", SUPPORTED, 0, PASS_SATISFIED),
        ("gpu_power_consistency_contradicted", CONTRADICTED, 0, PASS_CONTRADICTED),
        ("gpu_power_consistency_unknown_missing_power", UNKNOWN, 2, PASS_UNKNOWN),
        ("gpu_power_consistency_unknown_timestamp_mismatch", UNKNOWN, 0, PASS_UNKNOWN),
    ]

    for directory, verdict, absence_count, expected_status in cases:
        receipt = run_receipt_json(
            "--artifacts-dir",
            f"examples/{directory}",
            "--claim-type",
            "gpu_power_utilization_consistency",
        )
        assert receipt["verdict"]["status"] == verdict, (directory, receipt)
        assert len(receipt.get("absence", [])) == absence_count, (directory, receipt)
        pass_results = {result["pass_id"]: result for result in receipt["pass_results"]}
        result = pass_results["gpu_power_utilization_consistency"]
        assert result["status"] == expected_status, (directory, result)
        if directory == "gpu_power_consistency_supported":
            assert result["metadata"]["mean_gpu_utilization_pct"] == 93.0
            assert result["metadata"]["mean_rack_power_kw"] == 7.86
        if directory == "gpu_power_consistency_contradicted":
            assert result["verdict_effect"] == CONTRADICTED
            assert "mean rack power" in result["detail"]
        if directory == "gpu_power_consistency_unknown_missing_power":
            missing = {record["expected_path"] for record in receipt["absence"]}
            assert missing == {"power_window.rack_id", "power_window.samples"}
        if directory == "gpu_power_consistency_unknown_timestamp_mismatch":
            assert "no samples fell inside the declared window" in result["detail"]


def test_gpu_power_consistency_pass_units() -> None:
    supported = _pass_ir(_supported_artifacts())
    supported_result = gpu_power_utilization_consistency(supported)
    assert supported_result.status == PASS_SATISFIED
    assert supported_result.verdict_effect == SUPPORTED

    low_power = _supported_artifacts()
    low_power["power_window"]["samples"] = [
        {"observed_at": "2026-06-01T00:01:00Z", "rack_power_kw": 1.86}
    ]
    low_power_result = gpu_power_utilization_consistency(_pass_ir(low_power))
    assert low_power_result.status == PASS_CONTRADICTED
    assert "outside declared band" in low_power_result.detail

    rack_mismatch = _supported_artifacts()
    rack_mismatch["power_window"]["rack_id"] = "rack-redacted-999"
    rack_mismatch_result = gpu_power_utilization_consistency(_pass_ir(rack_mismatch))
    assert rack_mismatch_result.status == PASS_CONTRADICTED
    assert "does not match binding rack" in rack_mismatch_result.detail

    malformed_sample = _supported_artifacts()
    malformed_sample["gpu_utilization_window"]["samples"] = [
        {"observed_at": "2026-06-01T00:01:00Z", "gpu_utilization_pct": "high"}
    ]
    malformed_result = gpu_power_utilization_consistency(_pass_ir(malformed_sample))
    assert malformed_result.status == PASS_UNKNOWN
    assert malformed_result.verdict_effect == UNKNOWN


def test_ashiba_scan_recognizes_gpu_power_consistency_artifacts() -> None:
    for artifact_key in ("declaration", "gpu_utilization_window", "power_window", "node_rack_binding"):
        assert artifact_key in claim_artifact_keys()
        assert artifact_key in gpu_artifact_keys()

    supported = run_ashiba_process("scan", "examples/gpu_power_consistency_supported", "--json")
    assert supported.returncode == 0, supported.stderr
    supported_result = json.loads(supported.stdout)
    assert "gpu_power_utilization_consistency" in supported_result["can_decide"]
    assert supported_result["cannot_decide"] == []
    assert supported_result["summary"]["input_kinds"]["GPU artifact"] == 4
    assert supported_result["probeable_next"] == []

    missing_power = run_ashiba_process("scan", "examples/gpu_power_consistency_unknown_missing_power", "--json")
    assert missing_power.returncode == 0, missing_power.stderr
    missing_power_result = json.loads(missing_power.stdout)
    blocked = [
        item for item in missing_power_result["cannot_decide"]
        if item["claim"] == "gpu_power_utilization_consistency"
    ]
    assert len(blocked) == 1, missing_power_result
    assert blocked[0]["missing"] == ["power_window.rack_id", "power_window.samples"]
    assert "export independent power rack_id for the consistency window" in missing_power_result["probeable_next"]
    assert (
        "export BMC, PDU, SMBPBI, or rack power samples for the same measurement window"
        in missing_power_result["probeable_next"]
    )


def run_gpu_power_consistency_tests() -> None:
    test_gpu_power_consistency_gallery_fixtures()
    test_gpu_power_consistency_pass_units()
    test_ashiba_scan_recognizes_gpu_power_consistency_artifacts()


if __name__ == "__main__":
    run_gpu_power_consistency_tests()
    print("gpu power consistency smoke tests passed")
