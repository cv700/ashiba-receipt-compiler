#!/usr/bin/env python3
"""Demo real-world log importers feeding the receipt compiler."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from receipt_explain import missing_evidence_gaps
from receipt_validate import validate_receipt


ROOT = Path(__file__).resolve().parent


def _run(args: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        env={"PYTHONDONTWRITEBYTECODE": "1"},
    )


def _compile(imported_json: str) -> list[dict[str, Any]]:
    proc = _run(["compile", "-"], input_text=imported_json)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout)
    payload = json.loads(proc.stdout)
    receipts = payload.get("receipts") if isinstance(payload, dict) else None
    if isinstance(receipts, list):
        return [receipt for receipt in receipts if isinstance(receipt, dict)]
    if isinstance(payload, dict):
        return [payload]
    raise RuntimeError("compiler output was not a receipt object")


def _import(args: list[str]) -> str:
    proc = _run(args)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout)
    return proc.stdout


def _missing_summary(receipt: dict[str, Any]) -> str:
    gaps = missing_evidence_gaps(receipt)
    if not gaps:
        return "none"
    paths = [gap["missing_expected_path"] for gap in gaps[:3]]
    if len(gaps) > 3:
        paths.append(f"+{len(gaps) - 3} more")
    return ",".join(paths)


def _rows() -> list[tuple[str, str, str, str, str]]:
    policy = "examples/real_world_policy_sample.json"
    cases = [
        ("opentelemetry", ["import_otel", "examples/otel_span_sample.jsonl", "--policy", policy]),
        ("cloudtrail", ["import_cloudtrail", "examples/cloudtrail_sample.json", "--policy", policy]),
        ("github_actions", ["import_github_actions", "examples/github_actions_deployment_sample.json"]),
        ("kubernetes", ["import_kubernetes_audit", "examples/kubernetes_audit_sample.jsonl", "--policy", policy]),
        ("siem", ["import_siem_jsonl", "examples/siem_sample.jsonl", "--policy", policy]),
        ("opentelemetry_no_policy", ["import_otel", "examples/otel_span_sample.jsonl"]),
    ]
    rows = []
    for source, command in cases:
        for receipt in _compile(_import(command)):
            rows.append((
                source,
                str(receipt.get("claim_type", "(unknown)")),
                str(receipt.get("verdict", {}).get("status", "(missing)")),
                _missing_summary(receipt),
                "yes" if validate_receipt(receipt) == [] else "no",
            ))
    return rows


def main() -> int:
    print("source | claim | verdict | missing evidence | receipt valid")
    print("--- | --- | --- | --- | ---")
    for row in _rows():
        print(" | ".join(row))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
