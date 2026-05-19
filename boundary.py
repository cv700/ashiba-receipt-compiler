#!/usr/bin/env python3
"""Boundary and unsupported-inference generation for receipts."""

from __future__ import annotations

from typing import Any

from constants import CONTRADICTED, NOT_APPLICABLE, PASS_SATISFIED, SUPPORTED, UNKNOWN


GENERAL_BOUNDARY = (
    "This receipt does not support claims about other executions, general system reliability, "
    "or behavior under different conditions."
)


def generate_boundary(
    claim: dict[str, Any],
    verdict: dict[str, str],
    pass_results: list[dict[str, Any]],
    absence: list[dict[str, Any]],
) -> tuple[dict[str, list[str]], list[str]]:
    """Generate simple template boundary language from Receipt IR fields."""
    claim_text = str(claim.get("text", "")).strip()
    status = verdict.get("status")
    supports: list[str] = []

    if status == SUPPORTED and claim_text:
        supports.append(claim_text)
    if status == SUPPORTED:
        for result in pass_results:
            if result.get("status") == PASS_SATISFIED and result.get("pass_id") in {
                "expected_evidence_absence",
                "grant_active_at_event_time",
                "revocation_before_action",
                "no_future_evidence",
                "parser_repair_logged",
                "repair_writeback_recorded",
                "prefix_continuity",
                "grant_binding_present",
                "no_action_from_untrusted_literal",
                "human_approval_before_action",
                "deployment_matches_reviewed_commit",
            }:
                supports.append(str(result.get("detail", "")))

    does_not_support = [GENERAL_BOUNDARY]
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

    unsupported_inferences = [
        "That the action was semantically correct or desirable.",
        "That the model intended the action.",
        "That authorization behavior was the same in other runs.",
        "That the system is secure, safe, certified, or generally reliable.",
        "That omitted artifacts would have supported the claim.",
    ]

    return {"supports": supports, "does_not_support": does_not_support}, unsupported_inferences
