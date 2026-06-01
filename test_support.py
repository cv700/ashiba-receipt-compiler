#!/usr/bin/env python3
"""Shared helpers for standard-library smoke tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable
ENV = {"PYTHONDONTWRITEBYTECODE": "1"}


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
    proc = subprocess.run(
        [PYTHON, "receipt_compile.py", *args],
        cwd=ROOT,
        env=ENV,
        check=True,
        text=True,
        capture_output=True,
    )
    return json.loads(proc.stdout)


def run_compile_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("compile", *args, input_text=input_text)


def run_ashiba_process(*args: str) -> subprocess.CompletedProcess[str]:
    return run_script("ashiba", *args)


def run_import_nvidia_smi_process(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_script("import_nvidia_smi", *args, input_text=input_text)
