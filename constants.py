#!/usr/bin/env python3
"""Shared vocabulary for the receipt compiler."""

COMPILER_VERSION = "evidence-compiler-v0.6"

SUPPORTED = "supported"
CONTRADICTED = "contradicted"
UNKNOWN = "unknown"
NOT_APPLICABLE = "not_applicable"

VERDICT_STATUSES = frozenset({
    SUPPORTED,
    CONTRADICTED,
    UNKNOWN,
    NOT_APPLICABLE,
})

PASS_SATISFIED = "satisfied"
PASS_CONTRADICTED = "contradicted"
PASS_UNKNOWN = "unknown"
PASS_MISSING = "missing"
PASS_ERROR = "error"
PASS_SKIPPED = "skipped"
PASS_NOT_APPLICABLE = "not_applicable"

CLAIM_APPLICABILITY_PASS_ID = "claim_applicability"
