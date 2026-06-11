#!/usr/bin/env python3
"""Shared helpers for standard-library smoke tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from constants import VERDICT_STATUSES
from receipt_validate import validate_receipt


ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable
ENV = {"PYTHONDONTWRITEBYTECODE": "1"}
VERDICT_WORDS = set(VERDICT_STATUSES)


def run_script(script: str, *args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, script, *args],
        cwd=ROOT,
        env=ENV,
        input=input_text,
        text=True,
        capture_output=True,
    )


def run_receipt_json(*args: str) -> dict:
    return json.loads(run_text(*args))


def run_json(*args: str) -> dict:
    return run_receipt_json(*args)


def run_text(*args: str) -> str:
    proc = run_script("receipt_compile.py", *args)
    proc.check_returncode()
    return proc.stdout


def run_process(*args: str) -> subprocess.CompletedProcess[str]:
    return run_script("receipt_compile.py", *args)


def run_compile_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("compile", *args, input_text=input_text)


def run_ashiba_process(*args: str) -> subprocess.CompletedProcess[str]:
    return run_script("ashiba", *args)


def run_import_nvidia_smi_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_nvidia_smi", *args, input_text=input_text)


def run_import_pdu_csv_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_pdu_csv", *args, input_text=input_text)


def run_import_anthropic_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_anthropic", *args, input_text=input_text)


def run_import_openai_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_openai", *args, input_text=input_text)


def run_import_eventlog_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_eventlog", *args, input_text=input_text)


def run_import_langsmith_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_langsmith", *args, input_text=input_text)


def run_import_otel_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_otel", *args, input_text=input_text)


def run_import_cloudtrail_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_cloudtrail", *args, input_text=input_text)


def run_import_github_actions_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_github_actions", *args, input_text=input_text)


def run_import_kubernetes_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_kubernetes_audit", *args, input_text=input_text)


def run_import_siem_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_siem_jsonl", *args, input_text=input_text)


def run_import_nvattest_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_nvattest", *args, input_text=input_text)


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
