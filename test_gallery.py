#!/usr/bin/env python3
"""Gallery manifest tests."""

from __future__ import annotations

import json
import subprocess

from constants import NOT_APPLICABLE

from demo_gallery import run_gallery

from receipt_compile import (
    compile_claims,
    detect_applicable_claim_types,
    load_artifacts_dir_bound,
)

from receipt_validate import validate_receipt

from test_support import (
    ENV,
    PYTHON,
    ROOT,
    load_manifest,
    verdict_word_in_directory,
)


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


def run_gallery_tests() -> None:
    test_gallery_manifest_outputs()
    test_gallery_summary_and_json_output()
