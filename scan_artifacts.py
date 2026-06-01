"""Artifact dispatch helpers for the readiness scanner.

This module keeps claim-pack driven scan dispatch and raw GPU probe parsing out
of receipt_scan.py, which owns the high-level readiness flow.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from claim_contracts import claim_artifact_roots
from claim_types import build_claim_registry


TEXT_SUFFIXES = {".csv", ".json", ".jsonl", ".log", ".txt"}
SCANNER_BRIDGE_ARTIFACT_KEYS = ("parsed_actions", "tool_call")
NVIDIA_SMI_TIMESTAMP_TOLERANCE_SECONDS = 30


def _claim_packs_cache_key(claim_packs_dir: Path | None = None) -> str | None:
    if claim_packs_dir is None:
        return None
    return str(claim_packs_dir.resolve(strict=False))


@lru_cache(maxsize=8)
def _scan_registry(cache_key: str | None = None) -> dict[str, dict[str, Any]]:
    return build_claim_registry(Path(cache_key) if cache_key is not None else None)


def scan_claim_registry(claim_packs_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    """Return the claim registry used by scanner dispatch and readiness."""
    return _scan_registry(_claim_packs_cache_key(claim_packs_dir))


@lru_cache(maxsize=8)
def _claim_artifact_keys(cache_key: str | None = None) -> tuple[str, ...]:
    """Artifact roots accepted by the scanner because claim packs reference them."""
    return claim_artifact_roots(_scan_registry(cache_key))


def claim_artifact_keys(claim_packs_dir: Path | None = None) -> tuple[str, ...]:
    return _claim_artifact_keys(_claim_packs_cache_key(claim_packs_dir))


@lru_cache(maxsize=8)
def _gpu_artifact_keys(cache_key: str | None = None) -> tuple[str, ...]:
    """Artifact roots displayed as GPU evidence because GPU claim packs reference them."""
    registry = {
        name: config
        for name, config in _scan_registry(cache_key).items()
        if config.get("renderer_family") == "gpu_collateral"
    }
    return claim_artifact_roots(registry)


def gpu_artifact_keys(claim_packs_dir: Path | None = None) -> tuple[str, ...]:
    return _gpu_artifact_keys(_claim_packs_cache_key(claim_packs_dir))


def scan_artifact_keys(claim_packs_dir: Path | None = None) -> tuple[str, ...]:
    keys = list(claim_artifact_keys(claim_packs_dir))
    for key in SCANNER_BRIDGE_ARTIFACT_KEYS:
        if key not in keys:
            keys.append(key)
    return tuple(keys)


def nvidia_smi_csv_artifact(raw: str, source_label: str) -> dict[str, Any]:
    """Return gpu_probe_observation artifacts for a real nvidia-smi CSV."""
    reader = csv.DictReader(raw.splitlines())
    if not reader.fieldnames:
        return {}
    headers = {_normalize_csv_header(header) for header in reader.fieldnames if header}
    if not _looks_like_nvidia_smi_csv(headers, source_label):
        return {}

    rows = []
    for row in reader:
        normalized = {
            _normalize_csv_header(key): (value or "").strip()
            for key, value in row.items()
            if key is not None
        }
        if any(value for value in normalized.values()):
            rows.append(normalized)
    if not rows:
        return {}

    names = [row.get("name", "") for row in rows if row.get("name")]
    mig_modes = [row.get("mig.mode.current", "") for row in rows if row.get("mig.mode.current")]
    observation: dict[str, Any] = {"observed_count": len(rows)}
    if len(names) == len(rows):
        observation["observed_names"] = names
    if len(mig_modes) == len(rows):
        observation["observed_mig_modes"] = mig_modes

    timestamps = [_parse_nvidia_smi_timestamp(row.get("timestamp")) for row in rows if row.get("timestamp")]
    if timestamps and len(timestamps) == len(rows) and all(value is not None for value in timestamps):
        parsed_timestamps = [value for value in timestamps if value is not None]
        earliest = min(parsed_timestamps)
        latest = max(parsed_timestamps)
        if (latest - earliest).total_seconds() <= NVIDIA_SMI_TIMESTAMP_TOLERANCE_SECONDS:
            observation["observed_at"] = _format_nvidia_smi_timestamp(earliest)
    return {"gpu_probe_observation": observation}


def _normalize_csv_header(value: str) -> str:
    return value.strip().lower()


def _looks_like_nvidia_smi_csv(headers: set[str], source_label: str) -> bool:
    if "name" not in headers:
        return False
    source_name = Path(source_label).name.lower().replace("-", "_")
    if source_name.startswith("nvidia_smi"):
        return True
    gpu_specific_headers = {
        "mig.mode.current",
        "driver_version",
        "vbios_version",
        "persistence_mode",
        "ecc.mode.current",
        "pcie.link.gen.current",
        "pcie.link.width.current",
    }
    return bool(headers & gpu_specific_headers) or any(header.startswith("memory.total") for header in headers)


def _parse_nvidia_smi_timestamp(raw: Any) -> datetime | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    for fmt in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_nvidia_smi_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
