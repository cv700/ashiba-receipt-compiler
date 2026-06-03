#!/usr/bin/env python3
"""Shared helpers for GPU deterministic passes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


UTC_FMT = "%Y-%m-%dT%H:%M:%SZ"


def string_list(value: Any) -> list[str] | None:
    """Return a stringified list, or None when the value is not a non-empty list."""
    if not isinstance(value, list) or not value:
        return None
    return [str(item) for item in value]


def number(value: Any) -> float | None:
    """Return a numeric value without accepting booleans as numbers."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def integer(value: Any) -> int | None:
    """Return an integer value without accepting booleans as numbers."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def utc_timestamp(value: Any) -> datetime | None:
    """Parse a UTC timestamp with trailing Z, or return None."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, UTC_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def window_sample_values(
    samples: Any,
    value_key: str,
    start: datetime,
    end: datetime,
) -> tuple[list[float], list[int], int] | None:
    """Return numeric sample values inside a window, malformed indexes, and outside count."""
    if not isinstance(samples, list) or not samples:
        return None

    values: list[float] = []
    malformed_indexes: list[int] = []
    outside_window_count = 0
    for idx, sample in enumerate(samples):
        if not isinstance(sample, dict):
            malformed_indexes.append(idx)
            continue
        observed_at = utc_timestamp(sample.get("observed_at"))
        value = number(sample.get(value_key))
        if observed_at is None or value is None:
            malformed_indexes.append(idx)
            continue
        if observed_at < start or observed_at > end:
            outside_window_count += 1
            continue
        values.append(value)
    return values, malformed_indexes, outside_window_count
