#!/usr/bin/env python3
"""Boundary and unsupported-inference generation for receipts.

The boundary is where the receipt keeps faith with the reader. It names the
update, then protects the world from reading more into it than the probes saw.
"""

from __future__ import annotations

from typing import Any

from constants import CONTRADICTED, NOT_APPLICABLE, PASS_SATISFIED, SUPPORTED, UNKNOWN
from pass_specs import BOUNDARY_ROLE_DISCLOSURE, BOUNDARY_ROLE_SUPPORT_DETAIL, PassSpec, get_pass_spec
from renderer_families import renderer_family_adds_gpu_boundary


GENERAL_BOUNDARY = (
    "This receipt does not support claims about other executions, general system reliability, "
    "or behavior under different conditions."
)

GPU_BOUNDARY = [
    "This receipt does not verify that the node was under representative production load during testing.",
    "This receipt does not verify that the node was not recently rebooted to clear volatile ECC counters.",
    "This receipt does not assess residual economic value, remaining useful life, or depreciation trajectory.",
    "This receipt does not verify firmware authenticity or detect firmware-level tampering.",
]

GPU_UNSUPPORTED_INFERENCES = [
    "That the GPU will continue to pass diagnostics after this assessment.",
    "That the GPU's performance is representative of the full cluster.",
    "That the collateral is worth any specific dollar amount.",
]


def _result_spec(result: dict[str, Any]) -> PassSpec | None:
    pass_id = result.get("pass_id")
    if not isinstance(pass_id, str):
        return None
    try:
        return get_pass_spec(pass_id)
    except ValueError:
        return None


def generate_boundary(
    claim: dict[str, Any],
    verdict: dict[str, str],
    pass_results: list[dict[str, Any]],
    absence: list[dict[str, Any]],
    renderer_family: str = "",
) -> tuple[dict[str, list[str]], list[str]]:
    """Generate simple template boundary language from Receipt IR fields."""
    claim_text = str(claim.get("text", "")).strip()
    status = verdict.get("status")
    is_gpu_claim = renderer_family_adds_gpu_boundary(renderer_family)
    supports: list[str] = []

    if status == SUPPORTED and claim_text:
        supports.append(claim_text)
    if status == SUPPORTED:
        for result in pass_results:
            if result.get("status") != PASS_SATISFIED:
                continue
            spec = _result_spec(result)
            if spec is None or spec.boundary_role != BOUNDARY_ROLE_SUPPORT_DETAIL:
                continue
            detail = str(result.get("detail", ""))
            if detail:
                supports.append(detail)

    does_not_support = [GENERAL_BOUNDARY]
    if is_gpu_claim:
        does_not_support.extend(GPU_BOUNDARY)
    if status == UNKNOWN:
        does_not_support.append(
            "This receipt does not support the claim because required evidence was absent or ambiguous."
        )
    if status == CONTRADICTED:
        does_not_support.append("This receipt does not support the claim because supplied evidence conflicts with it.")
    if status == NOT_APPLICABLE:
        does_not_support.append(
            "This receipt does not support the claim because the artifact class does not instantiate the claim type."
        )
    if absence:
        does_not_support.append("This receipt does not fill missing expected evidence by inference.")
    for result in pass_results:
        spec = _result_spec(result)
        if spec is None or spec.boundary_role != BOUNDARY_ROLE_DISCLOSURE:
            continue
        metadata = result.get("metadata")
        if not isinstance(metadata, dict):
            continue
        disclosures = metadata.get("boundary_disclosures")
        if isinstance(disclosures, list):
            does_not_support.extend(str(disclosure) for disclosure in disclosures if disclosure)

    if is_gpu_claim:
        unsupported_inferences = [
            *GPU_UNSUPPORTED_INFERENCES,
            "That omitted artifacts would have supported the claim.",
            "That the system is secure, safe, certified, or generally reliable.",
        ]
    else:
        unsupported_inferences = [
            "That the action was semantically correct or desirable.",
            "That the model intended the action.",
            "That authorization behavior was the same in other runs.",
            "That the system is secure, safe, certified, or generally reliable.",
            "That omitted artifacts would have supported the claim.",
        ]

    return {"supports": supports, "does_not_support": does_not_support}, unsupported_inferences
