#!/usr/bin/env python3
"""Metadata contract for deterministic compiler passes.

This module intentionally contains no executable pass functions. Claim-pack
validation, scanner readiness, discovery, and boundary rendering should be able
to reason about pass contracts without importing the compiler implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from side_effect_envelope import (
    SIDE_EFFECT_ACTION_ID_PATH,
    SIDE_EFFECT_DECISION_ID_PATH,
    SIDE_EFFECT_EXECUTED_AT_PATH,
)

BOUNDARY_ROLE_SILENT = "silent"
BOUNDARY_ROLE_SUPPORT_DETAIL = "support_detail"
BOUNDARY_ROLE_DISCLOSURE = "disclosure"
BOUNDARY_ROLES = {
    BOUNDARY_ROLE_SILENT,
    BOUNDARY_ROLE_SUPPORT_DETAIL,
    BOUNDARY_ROLE_DISCLOSURE,
}
BoundaryRole = Literal["silent", "support_detail", "disclosure"]


@dataclass(frozen=True)
class PassSpec:
    """Metadata contract for one deterministic compiler pass."""

    pass_id: str
    family: str
    scope: str
    readiness: str
    required_paths: tuple[str, ...] = ()
    contradiction_paths: tuple[str, ...] = ()
    params_schema: dict[str, Any] = field(default_factory=dict)
    boundary_role: BoundaryRole = BOUNDARY_ROLE_SILENT

    def __post_init__(self) -> None:
        if self.boundary_role not in BOUNDARY_ROLES:
            raise ValueError(f"unknown boundary_role for {self.pass_id}: {self.boundary_role!r}")


PASS_SPECS: dict[str, PassSpec] = {
    # Universal
    "utc_timestamp_format": PassSpec(
        pass_id="utc_timestamp_format",
        family="universal",
        scope="global",
        readiness="validates supplied timestamp-like fields; missing optional fields do not block readiness",
    ),
    "expected_evidence_absence": PassSpec(
        pass_id="expected_evidence_absence",
        family="universal",
        scope="claim",
        readiness="uses claim_pack.expected_evidence as its dynamic required path list",
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    "no_future_evidence": PassSpec(
        pass_id="no_future_evidence",
        family="universal",
        scope="global",
        readiness="validates supplied timestamp-like fields against receipt creation time",
        contradiction_paths=("*_at", "*_from", "*_until", "*timestamp*",),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    "execution_context_disclosure": PassSpec(
        pass_id="execution_context_disclosure",
        family="execution_context",
        scope="context",
        readiness="boundary disclosure only; does not affect verdict readiness",
        boundary_role=BOUNDARY_ROLE_DISCLOSURE,
    ),
    # Authorization grant
    "grant_active_at_event_time": PassSpec(
        pass_id="grant_active_at_event_time",
        family="authorization",
        scope="action",
        readiness="missing or invalid grant/action timestamps make the claim unknown",
        required_paths=(
            "authorization.grant_valid_from",
            "authorization.grant_valid_until",
            SIDE_EFFECT_EXECUTED_AT_PATH,
        ),
        contradiction_paths=(
            "authorization.grant_valid_from",
            "authorization.grant_valid_until",
            SIDE_EFFECT_EXECUTED_AT_PATH,
        ),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    "revocation_before_action": PassSpec(
        pass_id="revocation_before_action",
        family="authorization",
        scope="action",
        readiness="authorization.revoked_at must exist; null means explicitly not revoked",
        required_paths=("authorization.revoked_at", SIDE_EFFECT_EXECUTED_AT_PATH),
        contradiction_paths=("authorization.revoked_at", SIDE_EFFECT_EXECUTED_AT_PATH),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    "grant_binding_present": PassSpec(
        pass_id="grant_binding_present",
        family="authorization",
        scope="action",
        readiness="missing binding evidence makes the claim unknown; mismatched or inactive binding contradicts it",
        required_paths=(
            "authorization.render_time_grant_hash",
            "authorization.execution_time_decision_id",
            "authorization.grant_active_at_execution",
            SIDE_EFFECT_DECISION_ID_PATH,
        ),
        contradiction_paths=(
            "authorization.grant_active_at_execution",
            "authorization.execution_time_decision_id",
            SIDE_EFFECT_DECISION_ID_PATH,
        ),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    "no_action_from_untrusted_literal": PassSpec(
        pass_id="no_action_from_untrusted_literal",
        family="authorization",
        scope="action",
        readiness="checks parsed action source_kind when present",
        contradiction_paths=("side_effects.*.source_kind",),
        params_schema={
            "forbidden_source_kinds": {
                "type": "list[str]",
                "default": ["literal_untrusted_text"],
            },
        },
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    # Parser repair
    "parser_repair_logged": PassSpec(
        pass_id="parser_repair_logged",
        family="parser_repair",
        scope="claim",
        readiness="requires at least one parser repair event with provenance fields",
        required_paths=(
            "parser.repair_events.0.repair_function",
            "parser.repair_events.0.before_hash",
            "parser.repair_events.0.after_hash",
            "parser.repair_events.0.writeback_to_model_history",
        ),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    "repair_writeback_recorded": PassSpec(
        pass_id="repair_writeback_recorded",
        family="parser_repair",
        scope="claim",
        readiness="missing or non-boolean repair writeback decision makes the claim unknown",
        required_paths=("parser.repair_events.0.writeback_to_model_history",),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    # Human approval and deployment
    "human_approval_before_action": PassSpec(
        pass_id="human_approval_before_action",
        family="approval",
        scope="action",
        readiness="missing approval binding or fields make the claim unknown; mismatched binding, non-approval, or late approval contradicts it",
        required_paths=(
            "approval.tool_call_id",
            SIDE_EFFECT_ACTION_ID_PATH,
            "approval.approved_at",
            "approval.decision",
            "approval.actor",
            SIDE_EFFECT_EXECUTED_AT_PATH,
        ),
        contradiction_paths=(
            "approval.tool_call_id",
            SIDE_EFFECT_ACTION_ID_PATH,
            "approval.approved_at",
            "approval.decision",
            SIDE_EFFECT_EXECUTED_AT_PATH,
        ),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    "deployment_matches_reviewed_commit": PassSpec(
        pass_id="deployment_matches_reviewed_commit",
        family="deployment",
        scope="claim",
        readiness="missing deployment/review fields make the claim unknown; mismatch, rejection, or late approval contradicts it",
        required_paths=(
            "deployment.commit_sha",
            "deployment.deployed_at",
            "review.commit_sha",
            "review.decision",
            "review.approved_at",
        ),
        contradiction_paths=(
            "deployment.commit_sha",
            "deployment.deployed_at",
            "review.commit_sha",
            "review.decision",
            "review.approved_at",
        ),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    # GPU collateral
    "gpu_serial_set_match": PassSpec(
        pass_id="gpu_serial_set_match",
        family="gpu_collateral",
        scope="claim",
        readiness="requires declared and observed serial lists; mismatched sets contradict collateral identity",
        required_paths=("gpu_inventory.declared_serials", "gpu_probe_observation.observed_serials"),
        contradiction_paths=("gpu_inventory.declared_serials", "gpu_probe_observation.observed_serials"),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    "gpu_node_id_match": PassSpec(
        pass_id="gpu_node_id_match",
        family="gpu_collateral",
        scope="claim",
        readiness="requires declared and observed node ids; mismatch contradicts collateral identity",
        required_paths=("gpu_inventory.declared_node_id", "gpu_probe_observation.observed_node_id"),
        contradiction_paths=("gpu_inventory.declared_node_id", "gpu_probe_observation.observed_node_id"),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    "dcgm_diag_result": PassSpec(
        pass_id="dcgm_diag_result",
        family="gpu_health",
        scope="claim",
        readiness="requires DCGM overall result when checking node health",
        required_paths=("dcgm_diag.overall_result",),
        contradiction_paths=("dcgm_diag.overall_result", "dcgm_diag.test_results"),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    "ecc_threshold_check": PassSpec(
        pass_id="ecc_threshold_check",
        family="gpu_health",
        scope="claim",
        readiness="requires ECC counters and page retirement threshold evidence",
        required_paths=(
            "xid_ecc_log.volatile_dbe_errors",
            "xid_ecc_log.total_retired_pages",
            "xid_ecc_log.page_retirement_limit",
        ),
        contradiction_paths=(
            "xid_ecc_log.volatile_dbe_errors",
            "xid_ecc_log.total_retired_pages",
            "xid_ecc_log.page_retirement_limit",
        ),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    "gpu_serial_cross_reference": PassSpec(
        pass_id="gpu_serial_cross_reference",
        family="gpu_health",
        scope="claim",
        readiness="requires serial evidence from health/collateral sources and checks they refer to the same GPU",
        required_paths=("dcgm_diag.gpu_serial", "xid_ecc_log.gpu_serial", "nvidia_smi.gpu_serial"),
        contradiction_paths=("dcgm_diag.gpu_serial", "xid_ecc_log.gpu_serial", "nvidia_smi.gpu_serial"),
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
    # Prefix continuity
    "prefix_continuity": PassSpec(
        pass_id="prefix_continuity",
        family="agent_trace_integrity",
        scope="claim",
        readiness="requires previous prompt, completion, and next prompt token sequences",
        required_paths=(
            "token_sequences.previous_prompt_tokens",
            "token_sequences.completion_tokens",
            "token_sequences.next_prompt_tokens",
        ),
        contradiction_paths=(
            "token_sequences.previous_prompt_tokens",
            "token_sequences.completion_tokens",
            "token_sequences.next_prompt_tokens",
        ),
        params_schema={
            "previous_key": {"type": "path", "default": "token_sequences.previous_prompt_tokens"},
            "completion_key": {"type": "path", "default": "token_sequences.completion_tokens"},
            "next_key": {"type": "path", "default": "token_sequences.next_prompt_tokens"},
        },
        boundary_role=BOUNDARY_ROLE_SUPPORT_DETAIL,
    ),
}


def get_pass_spec(pass_id: str) -> PassSpec:
    """Return the metadata contract for a pass_id, or raise ValueError."""
    if pass_id not in PASS_SPECS:
        available = ", ".join(sorted(PASS_SPECS))
        raise ValueError(f"unknown pass {pass_id!r}; available: {available}")
    return PASS_SPECS[pass_id]
