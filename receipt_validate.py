#!/usr/bin/env python3
"""Validate compiled receipt JSON shape.

This is a structural validator for the reference compiler output. It checks
receipt invariants that should hold regardless of claim type.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from constants import VERDICT_STATUSES

UTC_FMT = "%Y-%m-%dT%H:%M:%SZ"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_utc_z(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.strptime(value, UTC_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return parsed.strftime(UTC_FMT) == value


def _manifest_hash(artifact_manifest: list[dict[str, Any]]) -> str:
    payload = json.dumps(artifact_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_path(source_root: Path, record: dict[str, Any]) -> Path | None:
    rel = record.get("relative_path") or record.get("filename")
    if not isinstance(rel, str) or not rel:
        return None
    rel_path = Path(rel)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        return None
    candidate = source_root / rel_path
    if not candidate.exists():
        return candidate
    try:
        source_root_resolved = source_root.resolve(strict=True)
        candidate_resolved = candidate.resolve(strict=True)
        candidate_resolved.relative_to(source_root_resolved)
    except (FileNotFoundError, ValueError):
        return None
    return candidate_resolved


def _validate_source_file(record: dict[str, Any], source_root: Path, idx: int) -> list[str]:
    errors: list[str] = []
    path = _source_path(source_root, record)
    if path is None:
        errors.append(f"artifact_manifest.{idx}.relative_path must be relative and stay under source_root")
        return errors
    if not path.is_file():
        errors.append(f"artifact_manifest.{idx} source file not found under source_root: {path}")
        return errors

    expected_size = record.get("byte_size")
    if isinstance(expected_size, int) and path.stat().st_size != expected_size:
        errors.append(f"artifact_manifest.{idx}.byte_size does not match source file")

    expected_digest = record.get("sha256")
    if isinstance(expected_digest, str) and SHA256_RE.fullmatch(expected_digest):
        if _sha256_file(path) != expected_digest:
            errors.append(f"artifact_manifest.{idx}.sha256 does not match source file")
    return errors


def validate_receipt(receipt: dict[str, Any], source_root: Path | None = None) -> list[str]:
    """Return a list of validation errors for a compiled receipt."""
    errors: list[str] = []

    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id.startswith("rcpt"):
        errors.append("receipt_id must be a string starting with 'rcpt'")

    if not _is_utc_z(receipt.get("created_at")):
        errors.append("created_at must be an ISO 8601 UTC timestamp with trailing Z")

    compiler_version = receipt.get("compiler_version")
    if not isinstance(compiler_version, str) or not compiler_version:
        errors.append("compiler_version must exist")

    artifact_manifest = receipt.get("artifact_manifest")
    if not isinstance(artifact_manifest, list):
        errors.append("artifact_manifest must be a list")
    else:
        for idx, record in enumerate(artifact_manifest):
            if not isinstance(record, dict):
                errors.append(f"artifact_manifest.{idx} must be an object")
                continue
            source = record.get("source")
            if source not in {"bundle", "artifact_file", "incident_manifest"}:
                errors.append(f"artifact_manifest.{idx}.source must be bundle, artifact_file, or incident_manifest")
            filename = record.get("filename")
            if not isinstance(filename, str) or not filename:
                errors.append(f"artifact_manifest.{idx}.filename must exist")
            relative_path = record.get("relative_path")
            safe_relative_path = False
            if not isinstance(relative_path, str) or not relative_path:
                errors.append(f"artifact_manifest.{idx}.relative_path must exist")
            else:
                rel_path = Path(relative_path)
                if rel_path.is_absolute() or ".." in rel_path.parts:
                    errors.append(f"artifact_manifest.{idx}.relative_path must be relative and stay under source_root")
                else:
                    safe_relative_path = True
            digest = record.get("sha256")
            if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
                errors.append(f"artifact_manifest.{idx}.sha256 must be a lowercase SHA-256 hex digest")
            byte_size = record.get("byte_size")
            if not isinstance(byte_size, int) or byte_size < 0:
                errors.append(f"artifact_manifest.{idx}.byte_size must be a nonnegative integer")
            if source == "artifact_file":
                artifact_key = record.get("artifact_key")
                if not isinstance(artifact_key, str) or not artifact_key:
                    errors.append(f"artifact_manifest.{idx}.artifact_key must exist for artifact_file records")
            if source_root is not None and safe_relative_path:
                errors.extend(_validate_source_file(record, source_root, idx))

    incident_manifest = receipt.get("incident_manifest")
    if incident_manifest is not None:
        if not isinstance(incident_manifest, dict):
            errors.append("incident_manifest must be an object when present")
        else:
            artifact_roles = incident_manifest.get("artifact_roles")
            if artifact_roles is not None and not isinstance(artifact_roles, list):
                errors.append("incident_manifest.artifact_roles must be a list when present")
            claim_types = incident_manifest.get("claim_types")
            if claim_types is not None and not isinstance(claim_types, list):
                errors.append("incident_manifest.claim_types must be a list when present")

    input_set_hash = receipt.get("input_set_hash")
    if not isinstance(input_set_hash, str) or SHA256_RE.fullmatch(input_set_hash) is None:
        errors.append("input_set_hash must be a lowercase SHA-256 hex digest")
    elif isinstance(artifact_manifest, list) and input_set_hash != _manifest_hash(artifact_manifest):
        errors.append("input_set_hash must match the ordered artifact_manifest records")

    verdict = receipt.get("verdict")
    if not isinstance(verdict, dict):
        errors.append("verdict must exist")
    else:
        status = verdict.get("status")
        if status not in VERDICT_STATUSES:
            errors.append(f"verdict.status must be one of {sorted(VERDICT_STATUSES)}")

    boundary = receipt.get("boundary")
    if not isinstance(boundary, dict):
        errors.append("boundary must exist")
    else:
        if not isinstance(boundary.get("supports"), list):
            errors.append("boundary.supports must exist")
        if not isinstance(boundary.get("does_not_support"), list):
            errors.append("boundary.does_not_support must exist")

    absence = receipt.get("absence", [])
    if not isinstance(absence, list):
        errors.append("absence must be a list")
    else:
        for idx, record in enumerate(absence):
            if not isinstance(record, dict):
                errors.append(f"absence.{idx} must be an object")
                continue
            for key in ("expected_path", "claim_id", "verdict_effect"):
                if key not in record:
                    errors.append(f"absence.{idx}.{key} must exist")

    pass_results = receipt.get("pass_results")
    if not isinstance(pass_results, list):
        errors.append("pass_results must be a list")
    else:
        for idx, result in enumerate(pass_results):
            if not isinstance(result, dict):
                errors.append(f"pass_results.{idx} must be an object")
                continue
            for key in ("pass_id", "status", "detail"):
                if key not in result:
                    errors.append(f"pass_results.{idx}.{key} must exist")

    return errors


def _load_receipts(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("receipts"), list):
        receipts = data["receipts"]
    else:
        receipts = [data]
    out: list[dict[str, Any]] = []
    for idx, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            raise ValueError(f"receipt at index {idx} is not an object")
        out.append(receipt)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-root",
        type=Path,
        help="Optional root for independently verifying artifact_manifest file digests.",
    )
    parser.add_argument("receipt_json", type=Path, nargs="+", help="Receipt JSON file(s) to validate.")
    args = parser.parse_args()

    failed = 0
    for path in args.receipt_json:
        try:
            receipts = _load_receipts(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            failed += 1
            print(f"{path}: ERROR: {exc}")
            continue

        for idx, receipt in enumerate(receipts):
            errors = validate_receipt(receipt, source_root=args.source_root)
            label = f"{path}" if len(receipts) == 1 else f"{path}#{idx}"
            if errors:
                failed += 1
                print(f"{label}: invalid")
                for error in errors:
                    print(f"  - {error}")
            else:
                print(f"{label}: valid")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
