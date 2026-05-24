#!/usr/bin/env python3
"""Run ALL example bundles through the evidence compiler and print a summary table.

Usage:
    python3 demo_gallery.py
    python3 demo_gallery.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from constants import CONTRADICTED, NOT_APPLICABLE, SUPPORTED, UNKNOWN
from receipt_compile import (
    compile_claims,
    detect_applicable_claim_types,
    load_artifacts_dir_bound,
)
from receipt_ir import COMPILER_VERSION
from receipt_validate import validate_receipt


def load_gallery_manifest(root: Path) -> dict[str, Any] | None:
    manifest_path = root / "gallery_manifest.json"
    if not manifest_path.is_file():
        return None
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"gallery manifest root is not an object: {manifest_path}")
    return data


def run_directory(dir_path: Path, expected_claim_types: list[str] | None = None) -> list[dict[str, Any]]:
    """Compile one example directory. Returns a list of row dicts."""
    rows: list[dict[str, Any]] = []
    dir_name = dir_path.name

    try:
        loaded = load_artifacts_dir_bound(dir_path)
        artifacts = loaded.artifacts
        artifact_manifest = loaded.artifact_manifest
        input_hash = loaded.input_set_hash
        incident_manifest = loaded.incident_manifest
        claim_types = expected_claim_types or detect_applicable_claim_types(artifacts)

        if not claim_types:
            rows.append({
                "directory": dir_name,
                "claim_type": "(none detected)",
                "verdict": "skip",
                "passes": 0,
                "absent": 0,
                "errors": 0,
                "validation_errors": [],
                "error_msg": None,
            })
            return rows

        for claim_type in claim_types:
            try:
                receipts = compile_claims(
                    artifacts,
                    claim_type,
                    artifact_manifest=artifact_manifest,
                    input_set_hash=input_hash,
                    incident_manifest=incident_manifest,
                    execution_context=loaded.execution_context,
                )
                for receipt in receipts:
                    receipt_dict = receipt.to_dict()
                    rows.append({
                        "directory": dir_name,
                        "claim_type": claim_type,
                        "verdict": receipt_dict.get("verdict", {}).get("status", UNKNOWN),
                        "passes": len(receipt_dict.get("pass_results", [])),
                        "absent": len(receipt_dict.get("absence", [])),
                        "errors": len(receipt_dict.get("compiler_errors", [])),
                        "validation_errors": validate_receipt(receipt_dict),
                        "error_msg": None,
                    })
            except Exception as exc:
                rows.append({
                    "directory": dir_name,
                    "claim_type": claim_type,
                    "verdict": "ERROR",
                    "passes": 0,
                    "absent": 0,
                    "errors": 1,
                    "validation_errors": [],
                    "error_msg": str(exc),
                })

    except Exception as exc:
        rows.append({
            "directory": dir_name,
            "claim_type": "(load failed)",
            "verdict": "ERROR",
            "passes": 0,
            "absent": 0,
            "errors": 1,
            "validation_errors": [],
            "error_msg": str(exc),
        })

    return rows


def discover_example_dirs(examples_dir: Path) -> list[Path]:
    """Return example directories that contain JSON artifacts."""
    return sorted(
        directory
        for directory in examples_dir.iterdir()
        if directory.is_dir() and list(directory.glob("*.json"))
    )


def summarize(rows: list[dict[str, Any]], directory_count: int) -> dict[str, Any]:
    verdict_counts: dict[str, int] = {}
    compiler_errors = 0
    validation_errors = 0
    for row in rows:
        verdict = row["verdict"]
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        compiler_errors += row["errors"]
        validation_errors += len(row.get("validation_errors", []))
    return {
        "receipts": len(rows),
        "directories": directory_count,
        "verdict_counts": verdict_counts,
        "compiler_errors": compiler_errors,
        "validation_errors": validation_errors,
    }


def print_table(rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    """Print the human-readable gallery table."""
    w_dir = max(len(row["directory"]) for row in rows)
    w_dir = max(w_dir, len("Directory"))
    w_claim_type = max(len(row["claim_type"]) for row in rows)
    w_claim_type = max(w_claim_type, len("Claim Type"))
    w_verdict = max(len(row["verdict"]) for row in rows)
    w_verdict = max(w_verdict, len("Verdict"))

    header = (
        f"{'Directory':<{w_dir}}  "
        f"{'Claim Type':<{w_claim_type}}  "
        f"{'Verdict':<{w_verdict}}  "
        f"{'Passes':>6}  {'Absent':>6}  {'Errors':>6}"
    )
    sep = "-" * len(header)

    print(f"\nReceipt Compiler v7 - Demo Gallery  ({COMPILER_VERSION})")
    print("=" * len(header))
    print()
    print(header)
    print(sep)

    for row in rows:
        line = (
            f"{row['directory']:<{w_dir}}  "
            f"{row['claim_type']:<{w_claim_type}}  "
            f"{row['verdict']:<{w_verdict}}  "
            f"{row['passes']:>6}  {row['absent']:>6}  {row['errors']:>6}"
        )
        print(line)
        if row.get("error_msg"):
            print(f"  ^ {row['error_msg']}")
        for validation_error in row.get("validation_errors", []):
            print(f"  ^ receipt validation: {validation_error}")

    print()
    print(f"Summary: {summary['receipts']} receipts from {summary['directories']} incident directories")

    parts = []
    verdict_counts = summary["verdict_counts"]
    for verdict in (SUPPORTED, CONTRADICTED, UNKNOWN, NOT_APPLICABLE, "skip", "ERROR"):
        if verdict in verdict_counts:
            parts.append(f"{verdict}: {verdict_counts[verdict]}")
    parts.append(f"compiler errors: {summary['compiler_errors']}")
    if summary["validation_errors"]:
        parts.append(f"validation errors: {summary['validation_errors']}")
    print(f"  {' | '.join(parts)}")
    print()


def run_gallery() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = Path(__file__).resolve().parent
    examples_dir = root / "examples"
    if not examples_dir.is_dir():
        raise ValueError(f"examples directory not found: {examples_dir}")

    manifest = load_gallery_manifest(root)
    if manifest:
        entries = manifest.get("examples")
        if not isinstance(entries, list) or not entries:
            raise ValueError("gallery manifest has no examples")
        directories = [examples_dir / str(entry["directory"]) for entry in entries]
        expected_by_dir = {
            str(entry["directory"]): sorted({
                str(receipt["claim_type"])
                for receipt in entry.get("expected_receipts", [])
                if isinstance(receipt, dict)
            })
            for entry in entries
            if isinstance(entry, dict)
        }
    else:
        directories = discover_example_dirs(examples_dir)
        expected_by_dir = {}

    if not directories:
        raise ValueError("no example directories with JSON files found")

    rows: list[dict[str, Any]] = []
    for directory in directories:
        rows.extend(run_directory(directory, expected_by_dir.get(directory.name)))
    return rows, summarize(rows, len(directories))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable gallery summary.")
    args = parser.parse_args()

    try:
        rows, summary = run_gallery()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"summary": summary, "rows": rows}, indent=2, sort_keys=True))
    else:
        print_table(rows, summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
