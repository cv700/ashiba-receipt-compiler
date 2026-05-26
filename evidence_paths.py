#!/usr/bin/env python3
"""Shared dotted-path helpers for receipt evidence artifacts."""

from __future__ import annotations

from typing import Any


def get_path(obj: Any, dotted: str) -> Any:
    """Traverse dict/list objects using the scorer-compatible dotted path form."""
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            if 0 <= idx < len(cur):
                cur = cur[idx]
            else:
                return None
        else:
            return None
    return cur


def path_exists(obj: Any, dotted: str) -> bool:
    """Return whether a dotted path exists, even when its value is explicit null."""
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            if 0 <= idx < len(cur):
                cur = cur[idx]
            else:
                return False
        else:
            return False
    return True


def evidence_is_present(value: Any) -> bool:
    """Return whether an expected evidence path resolves to supplied evidence."""
    if value is None:
        return False
    if isinstance(value, (str, list, dict)):
        return len(value) > 0
    return True
