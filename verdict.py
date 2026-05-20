#!/usr/bin/env python3
"""Verdict generation for the minimum evidence compiler."""

from __future__ import annotations

from typing import Any

from constants import (
    CLAIM_APPLICABILITY_PASS_ID,
    CONTRADICTED,
    NOT_APPLICABLE,
    PASS_NOT_APPLICABLE,
    PASS_OK,
    PASS_SATISFIED,
    PASS_SKIPPED,
    SUPPORTED,
    UNKNOWN,
)


def generate_verdict(pass_results: list[dict[str, Any]], absence: list[dict[str, Any]]) -> dict[str, str]:
    """Generate the final receipt verdict from pass effects and absence records."""
    effects = [result.get("verdict_effect") for result in pass_results]
    statuses = [result.get("status") for result in pass_results]
    verdict_results = [
        result for result in pass_results if result.get("pass_id") != "execution_context_disclosure"
    ]
    verdict_statuses = [result.get("status") for result in verdict_results]

    if CONTRADICTED in effects:
        reasons = [result.get("detail", "") for result in pass_results if result.get("verdict_effect") == CONTRADICTED]
        return {
            "status": CONTRADICTED,
            "basis": reasons[0] if reasons else "at least one deterministic pass contradicted the claim",
        }

    if absence:
        return {
            "status": UNKNOWN,
            "basis": f"{len(absence)} expected evidence path(s) absent",
        }

    if UNKNOWN in effects:
        reasons = [result.get("detail", "") for result in pass_results if result.get("verdict_effect") == UNKNOWN]
        return {
            "status": UNKNOWN,
            "basis": reasons[0] if reasons else "at least one deterministic pass could not resolve the claim",
        }

    if verdict_statuses and all(status == PASS_NOT_APPLICABLE for status in verdict_statuses):
        pass_ids = {result.get("pass_id") for result in verdict_results}
        if pass_ids == {CLAIM_APPLICABILITY_PASS_ID}:
            return {
                "status": NOT_APPLICABLE,
                "basis": "the artifact class does not instantiate the requested claim type",
            }
        return {
            "status": UNKNOWN,
            "basis": "not_applicable is only valid as an explicit claim-applicability result",
        }

    if statuses and all(status in {PASS_SATISFIED, PASS_SKIPPED, PASS_OK} for status in statuses):
        return {
            "status": SUPPORTED,
            "basis": "all required evidence was present and all required deterministic passes were satisfied",
        }

    return {
        "status": UNKNOWN,
        "basis": "the supplied evidence did not resolve the claim",
    }
