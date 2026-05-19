#!/usr/bin/env python3
"""Shared helpers for deterministic log importers."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import sys
from pathlib import Path
from typing import Any


def die(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def epoch_to_utc(epoch_seconds: int | float) -> str:
    return datetime.fromtimestamp(epoch_seconds, timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def unix_nanos_to_utc(raw: str | int) -> str | None:
    try:
        nanos = int(raw)
    except (TypeError, ValueError):
        return None
    return epoch_to_utc(nanos / 1_000_000_000)


def normalize_timestamp(raw: Any) -> str | None:
    """Normalize common UTC timestamp forms without inventing missing time."""
    if isinstance(raw, (int, float)):
        return epoch_to_utc(raw)
    if not isinstance(raw, str) or not raw.strip():
        return None
    s = raw.strip()
    if s.isdigit() and len(s) >= 16:
        nanos = unix_nanos_to_utc(s)
        if nanos:
            return nanos
    candidate = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        return s
    if dt.tzinfo is None:
        return s
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_text(path_arg: str, label: str) -> str:
    if path_arg == "-":
        return sys.stdin.read()
    path = Path(path_arg)
    if not path.is_file():
        die(f"{label} file {path_arg} not found")
    return path.read_text(encoding="utf-8")


def load_json(path_arg: str, label: str) -> Any:
    raw = read_text(path_arg, label)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        die(f"invalid JSON in {label}: {exc}")


def load_json_or_jsonl(path_arg: str, label: str, array_key: str | None = None) -> list[dict[str, Any]]:
    raw = read_text(path_arg, label)
    stripped = raw.strip()
    if not stripped:
        die(f"{label} is empty")

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        payload = None

    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict) and array_key and isinstance(payload.get(array_key), list):
        records = payload[array_key]
    elif isinstance(payload, dict):
        records = [payload]
    else:
        records = []
        for lineno, line in enumerate(raw.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                die(f"invalid JSONL at line {lineno}: {exc}")

    if not all(isinstance(record, dict) for record in records):
        die(f"every {label} record must be a JSON object")
    return records


def decode_json_maybe(raw: Any) -> Any:
    if isinstance(raw, str):
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw": raw}
    if raw is None:
        return {}
    return raw


def nested_get(obj: Any, *path: str) -> Any:
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def first_present(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing required {label}")
    return value


def require_timestamp(value: Any, label: str) -> str:
    normalized = normalize_timestamp(value)
    if not normalized:
        raise ValueError(f"missing required {label} timestamp")
    return normalized


def load_policy(path_arg: str | None) -> dict[str, Any] | None:
    if not path_arg:
        return None
    policy = load_json(path_arg, "policy")
    if not isinstance(policy, dict):
        die("policy JSON root must be an object")
    return policy


def authorization_from_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    """Build authorization artifact only from fields present in policy."""
    if not policy:
        return {}
    authorization: dict[str, Any] = {}
    for key in (
        "grant_id",
        "principal",
        "delegated_to",
        "scope",
        "grant_valid_from",
        "grant_valid_until",
        "revoked_at",
        "issuer",
        "grant_context",
        "decision_id",
    ):
        if key in policy:
            authorization[key] = policy[key]
    return {"authorization": authorization} if authorization else {}


def write_artifacts(out_dir: Path, merged: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for key, value in sorted(merged.items()):
        if value in ({}, [], None):
            continue
        (out_dir / f"{key}.json").write_text(
            json.dumps({key: value}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
