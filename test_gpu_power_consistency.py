#!/usr/bin/env python3
"""GPU power/utilization consistency smoke tests."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

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
from test_support import run_ashiba_process, run_compile_process, run_import_pdu_csv_process, run_receipt_json


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
            "provenance": {
                "source_type": "pdu_csv",
                "custody_tier": "third_party_sensor",
                "measurement_type": "rack_aggregate",
                "binding_basis": "pdu_outlet_map",
            },
            "samples": [
                {"observed_at": "2026-06-01T00:01:00Z", "rack_power_kw": 7.92},
                {"observed_at": "2026-06-01T00:02:00Z", "rack_power_kw": 7.8},
            ],
        },
        "node_rack_binding": {
            "node_id": "node-redacted-001",
            "rack_id": "rack-redacted-001",
            "binding_basis": "pdu_outlet_map",
            "load_attribution": "full_rack_declared_inventory",
        },
    }


def _valid_power_csv() -> str:
    return (
        "timestamp,rack_id,rack_power_kw\n"
        "2026-06-01T00:01:00Z,rack-redacted-001,7.92\n"
        "2026-06-01T00:02:00Z,rack-redacted-001,7.80\n"
    )


def _write_power_import_inputs(tmp_dir: Path, artifacts: dict | None = None) -> tuple[Path, Path]:
    artifacts = artifacts or _supported_artifacts()
    declaration_path = tmp_dir / "declaration.json"
    binding_path = tmp_dir / "binding.json"
    declaration_path.write_text(json.dumps(artifacts["declaration"]), encoding="utf-8")
    binding_path.write_text(json.dumps(artifacts["node_rack_binding"]), encoding="utf-8")
    return declaration_path, binding_path


def test_gpu_power_consistency_gallery_fixtures() -> None:
    cases = [
        ("gpu_power_consistency_supported", SUPPORTED, 0, PASS_SATISFIED),
        ("gpu_power_consistency_contradicted", CONTRADICTED, 0, PASS_CONTRADICTED),
        ("gpu_power_consistency_unknown_missing_power", UNKNOWN, 4, PASS_UNKNOWN),
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
            assert missing == {
                "power_window.rack_id",
                "power_window.samples",
                "power_window.provenance.custody_tier",
                "power_window.provenance.measurement_type",
            }
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


def test_gpu_power_consistency_provenance_fail_closed() -> None:
    missing_provenance = _supported_artifacts()
    missing_provenance["power_window"].pop("provenance")
    missing_result = gpu_power_utilization_consistency(_pass_ir(missing_provenance))
    assert missing_result.status == PASS_UNKNOWN
    assert "power_window.provenance.custody_tier" in missing_result.metadata["missing_expected_paths"]

    operator_export = _supported_artifacts()
    operator_export["power_window"]["provenance"]["custody_tier"] = "operator_exported"
    operator_result = gpu_power_utilization_consistency(_pass_ir(operator_export))
    assert operator_result.status == PASS_UNKNOWN
    assert "not independent enough" in operator_result.detail

    operator_binding = _supported_artifacts()
    operator_binding["node_rack_binding"]["binding_basis"] = "operator_assertion"
    binding_result = gpu_power_utilization_consistency(_pass_ir(operator_binding))
    assert binding_result.status == PASS_UNKNOWN
    assert "operator assertion" in binding_result.detail

    aggregate_without_attribution = _supported_artifacts()
    aggregate_without_attribution["node_rack_binding"].pop("load_attribution")
    aggregate_result = gpu_power_utilization_consistency(_pass_ir(aggregate_without_attribution))
    assert aggregate_result.status == PASS_UNKNOWN
    assert "aggregate rack power lacks load attribution" in aggregate_result.detail

    per_outlet_without_attribution = _supported_artifacts()
    per_outlet_without_attribution["power_window"]["provenance"]["measurement_type"] = "per_outlet"
    per_outlet_without_attribution["node_rack_binding"].pop("load_attribution")
    per_outlet_result = gpu_power_utilization_consistency(_pass_ir(per_outlet_without_attribution))
    assert per_outlet_result.status == PASS_SATISFIED


def test_import_pdu_csv_emits_power_artifacts_with_custody_metadata() -> None:
    artifacts = _supported_artifacts()
    csv_text = _valid_power_csv()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        declaration_path, binding_path = _write_power_import_inputs(tmp_dir, artifacts)

        imported = run_import_pdu_csv_process(
            "-",
            "--declaration",
            str(declaration_path),
            "--binding",
            str(binding_path),
            "--custody-tier",
            "third_party_sensor",
            "--measurement-type",
            "rack_aggregate",
            "--source-label",
            "redacted independent PDU export",
            "--provided-by",
            "facility-ops-redacted",
            input_text=csv_text,
        )
        assert imported.returncode == 0, imported.stderr
        imported_artifacts = json.loads(imported.stdout)
        assert imported_artifacts["power_window"]["provenance"]["custody_tier"] == "third_party_sensor"
        assert imported_artifacts["power_window"]["provenance"]["measurement_type"] == "rack_aggregate"
        assert imported_artifacts["node_rack_binding"]["binding_basis"] == "pdu_outlet_map"
        assert imported_artifacts["node_rack_binding"]["load_attribution"] == "full_rack_declared_inventory"

        merged = {
            **imported_artifacts,
            "gpu_utilization_window": artifacts["gpu_utilization_window"],
        }
        verdict = run_compile_process(
            "-",
            "-v",
            "--claim-type",
            "gpu_power_utilization_consistency",
            input_text=json.dumps(merged),
        )
        assert verdict.returncode == 0, verdict.stderr
        assert verdict.stdout.strip() == SUPPORTED.upper()

        weak_import = run_import_pdu_csv_process(
            "-",
            "--declaration",
            str(declaration_path),
            "--binding",
            str(binding_path),
            input_text=csv_text,
        )
        assert weak_import.returncode == 0, weak_import.stderr
        weak_merged = {
            **json.loads(weak_import.stdout),
            "gpu_utilization_window": artifacts["gpu_utilization_window"],
        }
        weak_verdict = run_compile_process(
            "-",
            "-v",
            "--claim-type",
            "gpu_power_utilization_consistency",
            input_text=json.dumps(weak_merged),
        )
        assert weak_verdict.returncode == 0, weak_verdict.stderr
        assert weak_verdict.stdout.strip() == UNKNOWN.upper()


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
    assert blocked[0]["missing"] == [
        "power_window.rack_id",
        "power_window.samples",
        "power_window.provenance.custody_tier",
        "power_window.provenance.measurement_type",
    ]
    assert "export independent power rack_id for the consistency window" in missing_power_result["probeable_next"]
    assert (
        "export BMC, PDU, SMBPBI, or rack power samples for the same measurement window"
        in missing_power_result["probeable_next"]
    )


def test_power_unknown_when_provenance_missing() -> None:
    """Power evidence without provenance metadata must yield UNKNOWN, not SUPPORTED."""
    arts = _supported_artifacts()
    arts["power_window"].pop("provenance")
    result = gpu_power_utilization_consistency(_pass_ir(arts))
    assert result.status == PASS_UNKNOWN, result
    assert result.verdict_effect == UNKNOWN, result
    assert "power_window.provenance.custody_tier" in result.metadata["missing_expected_paths"]
    assert "power_window.provenance.measurement_type" in result.metadata["missing_expected_paths"]


def test_power_unknown_when_timestamp_window_mismatch() -> None:
    """Samples entirely outside the declared window must yield UNKNOWN."""
    arts = _supported_artifacts()
    arts["gpu_utilization_window"]["samples"] = [
        {"observed_at": "2026-05-31T12:00:00Z", "gpu_utilization_pct": 94},
    ]
    arts["power_window"]["samples"] = [
        {"observed_at": "2026-05-31T12:00:00Z", "rack_power_kw": 7.92},
    ]
    result = gpu_power_utilization_consistency(_pass_ir(arts))
    assert result.status == PASS_UNKNOWN, result
    assert "no samples fell inside the declared window" in result.detail


def test_power_unknown_when_node_rack_binding_missing() -> None:
    """Absent node-to-rack binding fields must yield UNKNOWN."""
    arts = _supported_artifacts()
    arts.pop("node_rack_binding")
    result = gpu_power_utilization_consistency(_pass_ir(arts))
    assert result.status == PASS_UNKNOWN, result
    missing = result.metadata["missing_expected_paths"]
    assert "node_rack_binding.node_id" in missing
    assert "node_rack_binding.rack_id" in missing
    assert "node_rack_binding.binding_basis" in missing


def test_power_unknown_when_aggregate_rack_load_unattributed() -> None:
    """Aggregate rack power without load attribution must yield UNKNOWN."""
    arts = _supported_artifacts()
    arts["power_window"]["provenance"]["measurement_type"] = "rack_aggregate"
    arts["node_rack_binding"].pop("load_attribution")
    result = gpu_power_utilization_consistency(_pass_ir(arts))
    assert result.status == PASS_UNKNOWN, result
    assert "aggregate rack power lacks load attribution" in result.detail


def test_power_contradicted_when_high_utilization_low_power() -> None:
    """High declared GPU utilization with idle-level power must contradict."""
    arts = _supported_artifacts()
    arts["power_window"]["samples"] = [
        {"observed_at": "2026-06-01T00:01:00Z", "rack_power_kw": 1.86},
        {"observed_at": "2026-06-01T00:02:00Z", "rack_power_kw": 1.90},
    ]
    result = gpu_power_utilization_consistency(_pass_ir(arts))
    assert result.status == PASS_CONTRADICTED, result
    assert result.verdict_effect == CONTRADICTED, result
    assert "outside declared band" in result.detail
    assert result.metadata["mean_rack_power_kw"] < 2.0


def test_power_not_supported_by_operator_csv_alone_for_independent_tier() -> None:
    """Operator-exported power data must not yield SUPPORTED — custody is too weak."""
    arts = _supported_artifacts()
    arts["power_window"]["provenance"]["custody_tier"] = "operator_exported"
    result = gpu_power_utilization_consistency(_pass_ir(arts))
    assert result.status == PASS_UNKNOWN, result
    assert result.verdict_effect == UNKNOWN, result
    assert "not independent enough" in result.detail

    arts2 = _supported_artifacts()
    arts2["node_rack_binding"]["binding_basis"] = "operator_assertion"
    result2 = gpu_power_utilization_consistency(_pass_ir(arts2))
    assert result2.status == PASS_UNKNOWN, result2
    assert "operator assertion" in result2.detail


def test_power_boundary_discloses_custody_tier() -> None:
    """SUPPORTED receipts must disclose power evidence custody and measurement tier."""
    receipt = run_receipt_json(
        "--artifacts-dir",
        "examples/gpu_power_consistency_supported",
        "--claim-type",
        "gpu_power_utilization_consistency",
    )
    assert receipt["verdict"]["status"] == SUPPORTED
    boundary_text = " ".join(receipt["boundary"]["does_not_support"])
    assert "third-party sensor" in boundary_text.lower() or "third_party_sensor" in boundary_text
    assert "rack-aggregate" in boundary_text.lower() or "rack readings" in boundary_text.lower()


def test_power_supported_when_independent_power_and_gpu_utilization_align() -> None:
    """Third-party-sensor power + GPU utilization inside declared bands = SUPPORTED."""
    arts = _supported_artifacts()
    assert arts["power_window"]["provenance"]["custody_tier"] == "third_party_sensor"
    assert arts["node_rack_binding"]["binding_basis"] == "pdu_outlet_map"
    assert arts["node_rack_binding"]["load_attribution"] == "full_rack_declared_inventory"
    result = gpu_power_utilization_consistency(_pass_ir(arts))
    assert result.status == PASS_SATISFIED, result
    assert result.verdict_effect == SUPPORTED, result
    assert result.metadata["mean_gpu_utilization_pct"] == 93.0
    assert result.metadata["mean_rack_power_kw"] == 7.86

    lender = _supported_artifacts()
    lender["power_window"]["provenance"]["custody_tier"] = "lender_controlled"
    lender_result = gpu_power_utilization_consistency(_pass_ir(lender))
    assert lender_result.status == PASS_SATISFIED, lender_result

    facility = _supported_artifacts()
    facility["power_window"]["provenance"]["custody_tier"] = "facility_exported"
    facility_result = gpu_power_utilization_consistency(_pass_ir(facility))
    assert facility_result.status == PASS_SATISFIED, facility_result


def test_power_unknown_when_facility_meter_too_coarse() -> None:
    """Facility-level meters are too coarse for a bound node/rack consistency claim."""
    arts = _supported_artifacts()
    arts["power_window"]["provenance"]["measurement_type"] = "facility_meter"
    result = gpu_power_utilization_consistency(_pass_ir(arts))
    assert result.status == PASS_UNKNOWN, result
    assert result.verdict_effect == UNKNOWN, result
    assert "facility-meter evidence is too coarse" in result.detail


def test_power_rack_label_supported_with_boundary_disclosure() -> None:
    """Rack-label binding can support the narrow claim but must be disclosed."""
    arts = _supported_artifacts()
    arts["node_rack_binding"]["binding_basis"] = "rack_label"
    arts["power_window"]["provenance"]["binding_basis"] = "rack_label"

    result = gpu_power_utilization_consistency(_pass_ir(arts))
    assert result.status == PASS_SATISFIED, result

    receipt = run_compile_process(
        "-",
        "--pretty",
        "--claim-type",
        "gpu_power_utilization_consistency",
        input_text=json.dumps(arts),
    )
    assert receipt.returncode == 0, receipt.stderr
    receipt_json = json.loads(receipt.stdout)
    assert receipt_json["verdict"]["status"] == SUPPORTED
    boundary_text = " ".join(receipt_json["boundary"]["does_not_support"])
    assert "rack label only" in boundary_text.lower()


def test_power_custody_boundary_disclosure_variants() -> None:
    """SUPPORTED receipts disclose weaker independent custody tiers without warning on lender custody."""
    facility = _supported_artifacts()
    facility["power_window"]["provenance"]["custody_tier"] = "facility_exported"
    facility_receipt = run_compile_process(
        "-",
        "--pretty",
        "--claim-type",
        "gpu_power_utilization_consistency",
        input_text=json.dumps(facility),
    )
    assert facility_receipt.returncode == 0, facility_receipt.stderr
    facility_json = json.loads(facility_receipt.stdout)
    assert facility_json["verdict"]["status"] == SUPPORTED
    facility_boundary = " ".join(facility_json["boundary"]["does_not_support"])
    assert "facility-exported" in facility_boundary

    lender = _supported_artifacts()
    lender["power_window"]["provenance"]["custody_tier"] = "lender_controlled"
    lender_receipt = run_compile_process(
        "-",
        "--pretty",
        "--claim-type",
        "gpu_power_utilization_consistency",
        input_text=json.dumps(lender),
    )
    assert lender_receipt.returncode == 0, lender_receipt.stderr
    lender_json = json.loads(lender_receipt.stdout)
    assert lender_json["verdict"]["status"] == SUPPORTED
    lender_boundary = " ".join(lender_json["boundary"]["does_not_support"])
    assert "facility-exported" not in lender_boundary
    assert "third-party sensor" not in lender_boundary.lower()


def test_import_pdu_csv_rejects_malformed_csv() -> None:
    """Importer rejects malformed power CSVs before they can enter the receipt path."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        declaration_path, binding_path = _write_power_import_inputs(tmp_dir)
        cases = [
            (
                "timestamp,rack_id\n2026-06-01T00:01:00Z,rack-redacted-001\n",
                "missing required column: rack_power_kw",
            ),
            (
                "timestamp,rack_id,rack_power_kw\n2026-06-01T00:01:00Z,rack-redacted-001,-1\n",
                "is negative",
            ),
            (
                (
                    "timestamp,rack_id,rack_power_kw\n"
                    "2026-06-01T00:01:00Z,rack-redacted-001,7.92\n"
                    "2026-06-01T00:02:00Z,rack-redacted-002,7.80\n"
                ),
                "multiple rack_id",
            ),
            (
                "timestamp,rack_id,rack_power_kw\nnot-a-time,rack-redacted-001,7.92\n",
                "could not be normalized to canonical UTC",
            ),
        ]
        for csv_text, expected_error in cases:
            proc = run_import_pdu_csv_process(
                "-",
                "--declaration",
                str(declaration_path),
                "--binding",
                str(binding_path),
                input_text=csv_text,
            )
            assert proc.returncode == 1, proc.stdout
            assert expected_error in proc.stderr, proc.stderr


def test_import_pdu_csv_out_mode_writes_artifacts() -> None:
    """--out mode writes compile-ready artifact files."""
    artifacts = _supported_artifacts()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        declaration_path, binding_path = _write_power_import_inputs(tmp_dir, artifacts)
        csv_path = tmp_dir / "power.csv"
        csv_path.write_text(_valid_power_csv(), encoding="utf-8")
        out_dir = tmp_dir / "artifacts"

        imported = run_import_pdu_csv_process(
            str(csv_path),
            "--declaration",
            str(declaration_path),
            "--binding",
            str(binding_path),
            "--custody-tier",
            "third_party_sensor",
            "--measurement-type",
            "rack_aggregate",
            "--load-attribution",
            "full_rack_declared_inventory",
            "--out",
            str(out_dir),
        )
        assert imported.returncode == 0, imported.stderr
        assert (out_dir / "declaration.json").is_file()
        assert (out_dir / "power_window.json").is_file()
        assert (out_dir / "node_rack_binding.json").is_file()

        (out_dir / "gpu_utilization_window.json").write_text(
            json.dumps({"gpu_utilization_window": artifacts["gpu_utilization_window"]}, indent=2) + "\n",
            encoding="utf-8",
        )
        receipt = run_receipt_json(
            "--artifacts-dir",
            str(out_dir),
            "--claim-type",
            "gpu_power_utilization_consistency",
        )
        assert receipt["verdict"]["status"] == SUPPORTED, receipt


def test_ashiba_scan_reports_missing_power_binding_basis() -> None:
    """Scanner should name missing binding_basis as a concrete GPU power gap."""
    artifacts = _supported_artifacts()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        for key in ("declaration", "gpu_utilization_window", "power_window"):
            (tmp_dir / f"{key}.json").write_text(
                json.dumps({key: artifacts[key]}, indent=2) + "\n",
                encoding="utf-8",
            )
        binding = dict(artifacts["node_rack_binding"])
        binding.pop("binding_basis")
        (tmp_dir / "node_rack_binding.json").write_text(
            json.dumps({"node_rack_binding": binding}, indent=2) + "\n",
            encoding="utf-8",
        )

        scan = run_ashiba_process("scan", str(tmp_dir), "--json")
        assert scan.returncode == 0, scan.stderr
        result = json.loads(scan.stdout)
        blocked = [
            item for item in result["cannot_decide"]
            if item["claim"] == "gpu_power_utilization_consistency"
        ]
        assert len(blocked) == 1, result
        assert "node_rack_binding.binding_basis" in blocked[0]["missing"]


def run_gpu_power_consistency_tests() -> None:
    test_gpu_power_consistency_gallery_fixtures()
    test_gpu_power_consistency_pass_units()
    test_gpu_power_consistency_provenance_fail_closed()
    test_import_pdu_csv_emits_power_artifacts_with_custody_metadata()
    test_ashiba_scan_recognizes_gpu_power_consistency_artifacts()
    test_power_unknown_when_provenance_missing()
    test_power_unknown_when_timestamp_window_mismatch()
    test_power_unknown_when_node_rack_binding_missing()
    test_power_unknown_when_aggregate_rack_load_unattributed()
    test_power_contradicted_when_high_utilization_low_power()
    test_power_not_supported_by_operator_csv_alone_for_independent_tier()
    test_power_boundary_discloses_custody_tier()
    test_power_supported_when_independent_power_and_gpu_utilization_align()
    test_power_unknown_when_facility_meter_too_coarse()
    test_power_rack_label_supported_with_boundary_disclosure()
    test_power_custody_boundary_disclosure_variants()
    test_import_pdu_csv_rejects_malformed_csv()
    test_import_pdu_csv_out_mode_writes_artifacts()
    test_ashiba_scan_reports_missing_power_binding_basis()


if __name__ == "__main__":
    run_gpu_power_consistency_tests()
    print("gpu power consistency smoke tests passed")
