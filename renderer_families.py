#!/usr/bin/env python3
"""Registered renderer-family policy for claim packs and receipt boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RendererFamilyPolicy:
    adds_gpu_boundary: bool = False


RENDERER_FAMILIES: dict[str, RendererFamilyPolicy] = {
    "agent_trace_integrity": RendererFamilyPolicy(),
    "cyber_tool_use": RendererFamilyPolicy(),
    "deployment_provenance": RendererFamilyPolicy(),
    "external_side_effect_control": RendererFamilyPolicy(),
    "gpu_collateral": RendererFamilyPolicy(adds_gpu_boundary=True),
    "gpu_health": RendererFamilyPolicy(adds_gpu_boundary=True),
}


def renderer_family_names() -> tuple[str, ...]:
    return tuple(sorted(RENDERER_FAMILIES))


def validate_renderer_family(raw: Any, source_label: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{source_label} renderer_family must be a registered non-empty string")
    if raw not in RENDERER_FAMILIES:
        available = ", ".join(renderer_family_names())
        raise ValueError(f"{source_label} renderer_family {raw!r} is not registered; available: {available}")
    return raw


def renderer_family_adds_gpu_boundary(renderer_family: str) -> bool:
    family = RENDERER_FAMILIES.get(renderer_family)
    return bool(family and family.adds_gpu_boundary)
