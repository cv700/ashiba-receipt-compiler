#!/usr/bin/env python3
"""Deterministic compiler passes for the minimum evidence compiler.

Each pass is a function (ReceiptIR, params?) -> PassResult.
Universal passes take only the IR. Claim-specific passes may accept
parameters from the claim type config.

Claims enter as priors, but passes are where the romance gets disciplined:
small, inspectable questions over artifacts, each refusing to infer past what
the evidence can bear.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from constants import (
    CONTRADICTED,
    PASS_CONTRADICTED,
    PASS_ERROR,
    PASS_MISSING,
    PASS_OK,
    PASS_SATISFIED,
    PASS_SKIPPED,
    PASS_UNKNOWN,
    SUPPORTED,
    UNKNOWN,
)
from receipt_ir import PassResult, ReceiptIR


UTC_FMT = "%Y-%m-%dT%H:%M:%SZ"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _parse_ts(raw: Any) -> datetime | None:
    """Parse an ISO 8601 UTC timestamp string, or return None."""
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw, UTC_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _timestamp_paths(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """Find receipt-bearing timestamp-looking fields in nested artifacts."""
    paths: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            key_lower = key.lower()
            if (
                key_lower.endswith("_at")
                or key_lower.endswith("_from")
                or key_lower.endswith("_until")
                or "timestamp" in key_lower
            ):
                paths.append((path, value))
            paths.extend(_timestamp_paths(value, path))
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            paths.extend(_timestamp_paths(value, f"{prefix}.{idx}" if prefix else str(idx)))
    return paths


def _authorization_paths() -> tuple[str, str, str, str]:
    return (
        "authorization.grant_valid_from",
        "authorization.grant_valid_until",
        "parsed_actions.0.executed_at",
        "authorization.revoked_at",
    )


def _missing_or_invalid_timestamp_paths(ir: ReceiptIR, paths: list[str]) -> list[str]:
    return [path for path in paths if _parse_ts(get_path(ir.artifacts, path)) is None]


# ---------------------------------------------------------------------------
# Universal passes (run for all claim types)
# ---------------------------------------------------------------------------

def utc_timestamp_format(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Validate verdict-bearing timestamps as ISO 8601 UTC with trailing Z."""
    invalid = []
    invalid_paths = []
    inspected = []
    for path, value in _timestamp_paths(ir.artifacts):
        if value is None:
            continue
        inspected.append(path)
        if _parse_ts(value) is None:
            invalid.append(f"{path}={value!r}")
            invalid_paths.append(path)
    if invalid:
        detail = "invalid receipt-controlled timestamp(s): " + "; ".join(invalid)
        return PassResult(
            pass_id="utc_timestamp_format",
            status=PASS_UNKNOWN,
            detail=detail,
            verdict_effect=UNKNOWN,
            metadata={"inspected_paths": inspected, "invalid_evidence_paths": invalid_paths},
        )
    if inspected:
        return PassResult(
            pass_id="utc_timestamp_format",
            status=PASS_SATISFIED,
            detail=f"all {len(inspected)} receipt-controlled timestamp(s) are UTC with trailing Z",
            verdict_effect=SUPPORTED,
            metadata={"inspected_paths": inspected},
        )
    return PassResult(
        pass_id="utc_timestamp_format",
        status=PASS_SKIPPED,
        detail="no receipt-controlled timestamps found in artifacts",
        verdict_effect=None,
    )


def expected_evidence_absence(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Compare expected evidence paths against the artifact bundle."""
    absence = []
    for path in ir.expected_evidence:
        value = get_path(ir.artifacts, path)
        if not evidence_is_present(value):
            # Missing evidence is not contradiction. It is the compiler drawing
            # a bright line from an unresolved claim to the next probe to build.
            absence.append(
                {
                    "expected_path": path,
                    "claim_id": str(ir.claim.get("id", "")),
                    "claim_text": str(ir.claim.get("text", "")),
                    "verdict_effect": UNKNOWN,
                    "reason": "expected evidence absent from artifacts",
                }
            )
    if absence:
        return PassResult(
            pass_id="expected_evidence_absence",
            status=PASS_MISSING,
            detail=f"{len(absence)} expected evidence path(s) absent",
            verdict_effect=UNKNOWN,
            absence=absence,
        )
    return PassResult(
        pass_id="expected_evidence_absence",
        status=PASS_SATISFIED,
        detail=f"all {len(ir.expected_evidence)} expected evidence path(s) present",
        verdict_effect=SUPPORTED,
    )


def no_future_evidence(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Flag evidence timestamps later than the receipt generation time."""
    cutoff = _parse_ts(ir.created_at)
    if cutoff is None:
        detail = f"receipt created_at is invalid: {ir.created_at!r}"
        return PassResult(
            pass_id="no_future_evidence",
            status=PASS_ERROR,
            detail=detail,
            verdict_effect=UNKNOWN,
            compiler_error=detail,
        )

    violations = []
    inspected = []
    for path, value in _timestamp_paths(ir.artifacts):
        ts = _parse_ts(value)
        if ts is None:
            continue
        inspected.append(path)
        if ts > cutoff:
            violations.append(f"{path}={value}")
    if violations:
        return PassResult(
            pass_id="no_future_evidence",
            status=PASS_CONTRADICTED,
            detail="evidence timestamp(s) later than receipt creation: " + "; ".join(violations),
            verdict_effect=CONTRADICTED,
            metadata={"created_at": ir.created_at, "inspected_paths": inspected},
        )
    return PassResult(
        pass_id="no_future_evidence",
        status=PASS_SATISFIED,
        detail=f"all {len(inspected)} parsed evidence timestamp(s) are <= receipt creation time",
        verdict_effect=SUPPORTED,
        metadata={"created_at": ir.created_at, "inspected_paths": inspected},
    )


# ---------------------------------------------------------------------------
# Execution context disclosure pass
# ---------------------------------------------------------------------------
# Boundary language is part of the update, not garnish. A receipt should say
# what moved the claim, and just as clearly where the movement stopped.

def _execution_context_disclosures(execution_context: dict[str, Any]) -> list[str]:
    """Return boundary disclosures for a typed execution context extension."""
    if not execution_context:
        return []

    schema_id = execution_context.get("schema_id")
    if schema_id != "gpu_goodput_context_v0":
        if isinstance(schema_id, str) and schema_id:
            return [
                (
                    f"Execution context schema {schema_id!r} not recognized; "
                    "domain-specific disclosures not available"
                )
            ]
        return ["Execution context schema not supplied; domain-specific disclosures not available"]

    disclosures: list[str] = []

    topology = execution_context.get("topology_manifest")
    if isinstance(topology, dict):
        coverage_ratio = topology.get("coverage_ratio")
        if isinstance(coverage_ratio, (int, float)) and coverage_ratio < 1.0:
            nodes_tested = topology.get("nodes_tested", "unknown")
            nodes_provisioned = topology.get("nodes_provisioned", "unknown")
            pct = max(0.0, coverage_ratio) * 100
            disclosures.append(
                f"Receipt covers {nodes_tested}/{nodes_provisioned} provisioned nodes ({pct:.1f}% coverage)"
            )

    system_state = execution_context.get("system_state")
    if isinstance(system_state, dict):
        freshly_rebooted = system_state.get("freshly_rebooted_nodes")
        if isinstance(freshly_rebooted, int) and freshly_rebooted > 0:
            disclosures.append(
                f"{freshly_rebooted} nodes were rebooted within 1 hour of test (uptime < 3600s)"
            )
        ecc_reboot_suspects = system_state.get("ecc_reboot_suspects")
        if isinstance(ecc_reboot_suspects, int) and ecc_reboot_suspects > 0:
            disclosures.append(
                f"{ecc_reboot_suspects} nodes show zero volatile ECC errors but nonzero aggregate "
                "(possible reboot to clear errors)"
            )

    ambient_load = execution_context.get("ambient_load")
    if isinstance(ambient_load, dict) and ambient_load.get("ambient_load_level") == "negligible":
        disclosures.append(
            "Test conducted under negligible fabric load; results may not reflect contended performance"
        )

    if not isinstance(execution_context.get("software_stack"), dict) or not execution_context.get("software_stack"):
        disclosures.append("Software stack not captured; environment reproducibility unknown")

    if not execution_context.get("challenge_nonce"):
        disclosures.append("No challenge nonce; receipt replay cannot be excluded")

    if (
        not isinstance(execution_context.get("probe_manifest_commitment"), dict)
        or not execution_context.get("probe_manifest_commitment")
    ):
        disclosures.append("No pre-committed probe manifest; probe selection by provider cannot be excluded")

    return disclosures


def execution_context_disclosure(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Disclose typed execution-context limits without changing the verdict."""
    disclosures = _execution_context_disclosures(ir.execution_context)
    schema_id = ir.execution_context.get("schema_id") if isinstance(ir.execution_context, dict) else None
    return PassResult(
        pass_id="execution_context_disclosure",
        status=PASS_OK,
        detail=f"execution context disclosed with {len(disclosures)} boundary disclosure(s)",
        verdict_effect=None,
        metadata={
            "schema_id": schema_id or "",
            "boundary_disclosures": disclosures,
        },
    )


# ---------------------------------------------------------------------------
# Authorization grant passes
# ---------------------------------------------------------------------------

def grant_active_at_event_time(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check grant_valid_from <= executed_at <= grant_valid_until."""
    grant_from_path, grant_until_path, executed_path, _ = _authorization_paths()
    grant_from = _parse_ts(get_path(ir.artifacts, grant_from_path))
    grant_until = _parse_ts(get_path(ir.artifacts, grant_until_path))
    executed_at = _parse_ts(get_path(ir.artifacts, executed_path))

    missing = [
        path
        for path, value in (
            (grant_from_path, grant_from),
            (grant_until_path, grant_until),
            (executed_path, executed_at),
        )
        if value is None
    ]
    if missing:
        return PassResult(
            pass_id="grant_active_at_event_time",
            status=PASS_UNKNOWN,
            detail="grant activity could not be determined; missing or invalid timestamp(s): " + ", ".join(missing),
            verdict_effect=UNKNOWN,
            metadata={
                "grant_valid_from_path": grant_from_path,
                "grant_valid_until_path": grant_until_path,
                "executed_at_path": executed_path,
                "missing_expected_paths": missing,
            },
        )

    assert grant_from is not None
    assert grant_until is not None
    assert executed_at is not None
    if grant_from <= executed_at <= grant_until:
        return PassResult(
            pass_id="grant_active_at_event_time",
            status=PASS_SATISFIED,
            detail=f"grant active at execution time {executed_at.strftime(UTC_FMT)}",
            verdict_effect=SUPPORTED,
        )
    return PassResult(
        pass_id="grant_active_at_event_time",
        status=PASS_CONTRADICTED,
        detail=(
            f"execution time {executed_at.strftime(UTC_FMT)} outside grant window "
            f"{grant_from.strftime(UTC_FMT)}..{grant_until.strftime(UTC_FMT)}"
        ),
        verdict_effect=CONTRADICTED,
    )


def revocation_before_action(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Flag contradiction when revoked_at <= executed_at."""
    _, _, executed_path, revoked_path = _authorization_paths()
    if not path_exists(ir.artifacts, revoked_path):
        return PassResult(
            pass_id="revocation_before_action",
            status=PASS_UNKNOWN,
            detail="revocation ordering could not be determined; authorization.revoked_at is missing",
            verdict_effect=UNKNOWN,
            metadata={"missing_expected_paths": [revoked_path]},
        )

    revoked_raw = get_path(ir.artifacts, revoked_path)
    executed_raw = get_path(ir.artifacts, executed_path)
    if revoked_raw is None:
        return PassResult(
            pass_id="revocation_before_action",
            status=PASS_SATISFIED,
            detail="no revocation timestamp supplied before the action",
            verdict_effect=SUPPORTED,
        )

    revoked_at = _parse_ts(revoked_raw)
    executed_at = _parse_ts(executed_raw)
    if revoked_at is None or executed_at is None:
        return PassResult(
            pass_id="revocation_before_action",
            status=PASS_UNKNOWN,
            detail="revocation ordering could not be determined; revoked_at or executed_at is missing or invalid",
            verdict_effect=UNKNOWN,
        )
    if revoked_at <= executed_at:
        return PassResult(
            pass_id="revocation_before_action",
            status=PASS_CONTRADICTED,
            detail=f"grant revoked at {revoked_at.strftime(UTC_FMT)} before action at {executed_at.strftime(UTC_FMT)}",
            verdict_effect=CONTRADICTED,
        )
    return PassResult(
        pass_id="revocation_before_action",
        status=PASS_SATISFIED,
        detail=(
            f"grant revocation at {revoked_at.strftime(UTC_FMT)} occurred after "
            f"action at {executed_at.strftime(UTC_FMT)}"
        ),
        verdict_effect=SUPPORTED,
    )


def grant_binding_present(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check that authorization evidence is bound to the executed tool call."""
    authorization = ir.artifacts.get("authorization", {})
    if not isinstance(authorization, dict):
        return PassResult(
            pass_id="grant_binding_present",
            status=PASS_UNKNOWN,
            detail="authorization artifact is missing or not a dict",
            verdict_effect=UNKNOWN,
        )

    required = ("render_time_grant_hash", "execution_time_decision_id", "grant_active_at_execution")
    missing = sorted(field for field in required if not evidence_is_present(authorization.get(field)))
    if missing:
        return PassResult(
            pass_id="grant_binding_present",
            status=PASS_UNKNOWN,
            detail=(
                "grant binding could not be determined; missing authorization field(s): "
                + ", ".join(missing)
            ),
            verdict_effect=UNKNOWN,
            metadata={
                "missing_fields": missing,
                "missing_expected_paths": [f"authorization.{field}" for field in missing],
                "present_fields": sorted(field for field in required if field not in missing),
            },
        )
    if authorization.get("grant_active_at_execution") is not True:
        return PassResult(
            pass_id="grant_binding_present",
            status=PASS_UNKNOWN,
            detail="grant binding could not support the claim; grant_active_at_execution is not true",
            verdict_effect=UNKNOWN,
            metadata={"field": "authorization.grant_active_at_execution"},
        )

    auth_decision_id = str(authorization.get("execution_time_decision_id", ""))
    tool_decision_path = "tool_call.invocation_context.decision_id"
    tool_decision_id = get_path(ir.artifacts, tool_decision_path)
    if not evidence_is_present(tool_decision_id):
        return PassResult(
            pass_id="grant_binding_present",
            status=PASS_UNKNOWN,
            detail=(
                "grant binding could not be determined; missing tool-call field: "
                f"{tool_decision_path}"
            ),
            verdict_effect=UNKNOWN,
            metadata={
                "missing_fields": ["tool_call.invocation_context.decision_id"],
                "missing_expected_paths": [tool_decision_path],
                "authorization_decision_id": auth_decision_id,
            },
        )
    tool_decision_text = str(tool_decision_id)
    if auth_decision_id != tool_decision_text:
        return PassResult(
            pass_id="grant_binding_present",
            status=PASS_CONTRADICTED,
            detail=(
                "grant binding decision mismatch: "
                f"authorization.execution_time_decision_id={auth_decision_id!r}; "
                f"{tool_decision_path}={tool_decision_text!r}"
            ),
            verdict_effect=CONTRADICTED,
            metadata={
                "authorization_decision_id": auth_decision_id,
                "tool_call_decision_id": tool_decision_text,
            },
        )
    return PassResult(
        pass_id="grant_binding_present",
        status=PASS_SATISFIED,
        detail="render-time grant hash and matching tool-call decision evidence present",
        verdict_effect=SUPPORTED,
        metadata={"decision_id": auth_decision_id},
    )


def no_action_from_untrusted_literal(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Flag contradiction if any parsed action derives from an untrusted literal source."""
    params = params or {}
    forbidden_kinds = set(params.get("forbidden_source_kinds", ["literal_untrusted_text"]))
    actions = ir.artifacts.get("parsed_actions", [])
    if not isinstance(actions, list):
        return PassResult(
            pass_id="no_action_from_untrusted_literal",
            status=PASS_SKIPPED,
            detail="no parsed_actions array in artifacts",
            verdict_effect=None,
        )

    offenders = []
    for i, action in enumerate(actions):
        if not isinstance(action, dict):
            continue
        source_kind = action.get("source_kind", "")
        if source_kind in forbidden_kinds:
            offenders.append(f"parsed_actions.{i} (source_kind={source_kind})")

    if offenders:
        return PassResult(
            pass_id="no_action_from_untrusted_literal",
            status=PASS_CONTRADICTED,
            detail="parsed action(s) derived from untrusted source: " + "; ".join(offenders),
            verdict_effect=CONTRADICTED,
            metadata={"offending_actions": offenders},
        )
    return PassResult(
        pass_id="no_action_from_untrusted_literal",
        status=PASS_SATISFIED,
        detail=f"all {len(actions)} parsed action(s) have trusted source_kind",
        verdict_effect=SUPPORTED,
    )


# ---------------------------------------------------------------------------
# Parser repair passes
# ---------------------------------------------------------------------------

def parser_repair_logged(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check that at least one parser repair event has full provenance fields."""
    repair_events = get_path(ir.artifacts, "parser.repair_events")
    if not isinstance(repair_events, list) or not repair_events:
        return PassResult(
            pass_id="parser_repair_logged",
            status=PASS_UNKNOWN,
            detail="no parser.repair_events found in artifacts",
            verdict_effect=UNKNOWN,
        )

    required_fields = {"repair_function", "before_hash", "after_hash", "writeback_to_model_history"}
    for i, event in enumerate(repair_events):
        if not isinstance(event, dict):
            continue
        missing = sorted(required_fields - set(event))
        if missing:
            return PassResult(
                pass_id="parser_repair_logged",
                status=PASS_MISSING,
                detail=f"repair event {i} missing fields: {', '.join(missing)}",
                verdict_effect=UNKNOWN,
                metadata={"event_index": i, "missing_fields": missing},
            )

    return PassResult(
        pass_id="parser_repair_logged",
        status=PASS_SATISFIED,
        detail=f"all {len(repair_events)} repair event(s) have full provenance",
        verdict_effect=SUPPORTED,
    )


def repair_writeback_recorded(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check that every repair event has an explicit writeback_to_model_history decision (true or false)."""
    repair_events = get_path(ir.artifacts, "parser.repair_events")
    if not isinstance(repair_events, list) or not repair_events:
        return PassResult(
            pass_id="repair_writeback_recorded",
            status=PASS_SKIPPED,
            detail="no parser.repair_events found in artifacts",
            verdict_effect=None,
        )

    for i, event in enumerate(repair_events):
        if not isinstance(event, dict):
            continue
        wb = event.get("writeback_to_model_history")
        if wb is None:
            return PassResult(
                pass_id="repair_writeback_recorded",
                status=PASS_MISSING,
                detail=f"repair event {i} has null/missing writeback_to_model_history",
                verdict_effect=UNKNOWN,
                metadata={"event_index": i},
            )
        if not isinstance(wb, bool):
            return PassResult(
                pass_id="repair_writeback_recorded",
                status=PASS_UNKNOWN,
                detail=f"repair event {i} writeback_to_model_history is {type(wb).__name__}, expected bool",
                verdict_effect=UNKNOWN,
                metadata={"event_index": i, "observed_type": type(wb).__name__},
            )

    return PassResult(
        pass_id="repair_writeback_recorded",
        status=PASS_SATISFIED,
        detail=f"all {len(repair_events)} repair event(s) have explicit writeback decision",
        verdict_effect=SUPPORTED,
    )


# ---------------------------------------------------------------------------
# Human approval and deployment passes
# ---------------------------------------------------------------------------

def human_approval_before_action(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check that an explicit approval preceded an external side-effect action."""
    approved_path = "approval.approved_at"
    executed_path = "parsed_actions.0.executed_at"
    decision_path = "approval.decision"
    actor_path = "approval.actor"
    missing = [
        path
        for path in (approved_path, executed_path, decision_path, actor_path)
        if not evidence_is_present(get_path(ir.artifacts, path))
    ]
    missing.extend(path for path in _missing_or_invalid_timestamp_paths(ir, [approved_path, executed_path]) if path not in missing)
    if missing:
        return PassResult(
            pass_id="human_approval_before_action",
            status=PASS_UNKNOWN,
            detail="human approval ordering could not be determined; missing or invalid field(s): " + ", ".join(missing),
            verdict_effect=UNKNOWN,
            metadata={"missing_expected_paths": missing},
        )

    decision = str(get_path(ir.artifacts, decision_path)).lower()
    if decision not in {"approved", "approve", "allowed", "allow"}:
        return PassResult(
            pass_id="human_approval_before_action",
            status=PASS_CONTRADICTED,
            detail=f"human approval decision was {decision!r}, not approved",
            verdict_effect=CONTRADICTED,
        )

    approved_at = _parse_ts(get_path(ir.artifacts, approved_path))
    executed_at = _parse_ts(get_path(ir.artifacts, executed_path))
    assert approved_at is not None
    assert executed_at is not None
    if approved_at > executed_at:
        return PassResult(
            pass_id="human_approval_before_action",
            status=PASS_CONTRADICTED,
            detail=(
                f"human approval at {approved_at.strftime(UTC_FMT)} occurred after "
                f"action at {executed_at.strftime(UTC_FMT)}"
            ),
            verdict_effect=CONTRADICTED,
        )
    return PassResult(
        pass_id="human_approval_before_action",
        status=PASS_SATISFIED,
        detail=f"human approval preceded action at {executed_at.strftime(UTC_FMT)}",
        verdict_effect=SUPPORTED,
    )


def deployment_matches_reviewed_commit(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check that the deployed commit matches an approved reviewed commit."""
    deployment_sha_path = "deployment.commit_sha"
    review_sha_path = "review.commit_sha"
    review_decision_path = "review.decision"
    review_at_path = "review.approved_at"
    deployed_at_path = "deployment.deployed_at"
    missing = [
        path
        for path in (
            deployment_sha_path,
            review_sha_path,
            review_decision_path,
            review_at_path,
            deployed_at_path,
        )
        if not evidence_is_present(get_path(ir.artifacts, path))
    ]
    missing.extend(path for path in _missing_or_invalid_timestamp_paths(ir, [review_at_path, deployed_at_path]) if path not in missing)
    if missing:
        return PassResult(
            pass_id="deployment_matches_reviewed_commit",
            status=PASS_UNKNOWN,
            detail="deployment review match could not be determined; missing or invalid field(s): " + ", ".join(missing),
            verdict_effect=UNKNOWN,
            metadata={"missing_expected_paths": missing},
        )

    deployment_sha = str(get_path(ir.artifacts, deployment_sha_path))
    review_sha = str(get_path(ir.artifacts, review_sha_path))
    if deployment_sha != review_sha:
        return PassResult(
            pass_id="deployment_matches_reviewed_commit",
            status=PASS_CONTRADICTED,
            detail=f"deployed commit {deployment_sha} does not match reviewed commit {review_sha}",
            verdict_effect=CONTRADICTED,
        )

    decision = str(get_path(ir.artifacts, review_decision_path)).lower()
    if decision not in {"approved", "approve", "allowed", "allow"}:
        return PassResult(
            pass_id="deployment_matches_reviewed_commit",
            status=PASS_CONTRADICTED,
            detail=f"review decision was {decision!r}, not approved",
            verdict_effect=CONTRADICTED,
        )

    approved_at = _parse_ts(get_path(ir.artifacts, review_at_path))
    deployed_at = _parse_ts(get_path(ir.artifacts, deployed_at_path))
    assert approved_at is not None
    assert deployed_at is not None
    if approved_at > deployed_at:
        return PassResult(
            pass_id="deployment_matches_reviewed_commit",
            status=PASS_CONTRADICTED,
            detail=(
                f"review approval at {approved_at.strftime(UTC_FMT)} occurred after "
                f"deployment at {deployed_at.strftime(UTC_FMT)}"
            ),
            verdict_effect=CONTRADICTED,
        )

    return PassResult(
        pass_id="deployment_matches_reviewed_commit",
        status=PASS_SATISFIED,
        detail=f"deployment used reviewed commit {deployment_sha}",
        verdict_effect=SUPPORTED,
    )


# ---------------------------------------------------------------------------
# GPU collateral passes
# ---------------------------------------------------------------------------
# v0 keeps identity, health, and economic value disentangled. Serial matching is
# a collateral-identity update; diagnostics are a health update; valuation stays
# outside the compiler because the evidence here cannot honestly price a GPU.

def _string_list(value: Any) -> list[str] | None:
    """Return a stringified list, or None when the value is not a non-empty list."""
    if not isinstance(value, list) or not value:
        return None
    return [str(item) for item in value]


def _number(value: Any) -> float | None:
    """Return a numeric value without accepting booleans as numbers."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def gpu_serial_set_match(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check observed GPU serials against the declared collateral schedule."""
    declared = _string_list(get_path(ir.artifacts, "gpu_inventory.declared_serials"))
    observed = _string_list(get_path(ir.artifacts, "gpu_probe_observation.observed_serials"))
    if declared is None or observed is None:
        return PassResult(
            pass_id="gpu_serial_set_match",
            status=PASS_SKIPPED,
            detail="serial set match skipped because declared or observed serial list is missing",
        )

    declared_set = set(declared)
    observed_set = set(observed)
    missing_from_hardware = sorted(declared_set - observed_set)
    undeclared_on_hardware = sorted(observed_set - declared_set)
    if missing_from_hardware or undeclared_on_hardware:
        return PassResult(
            pass_id="gpu_serial_set_match",
            status=PASS_CONTRADICTED,
            detail=(
                "Serial set mismatch: declared but not observed: "
                f"{missing_from_hardware}; observed but not declared: {undeclared_on_hardware}."
            ),
            verdict_effect=CONTRADICTED,
            metadata={
                "declared_count": len(declared_set),
                "observed_count": len(observed_set),
                "declared_but_not_observed": missing_from_hardware,
                "observed_but_not_declared": undeclared_on_hardware,
            },
        )

    return PassResult(
        pass_id="gpu_serial_set_match",
        status=PASS_SATISFIED,
        detail=f"All {len(declared_set)} declared serial(s) matched observed serial(s).",
        metadata={"serial_count": len(declared_set)},
    )


def gpu_node_id_match(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check observed GPU node identity against the declared collateral node."""
    declared = get_path(ir.artifacts, "gpu_inventory.declared_node_id")
    observed = get_path(ir.artifacts, "gpu_probe_observation.observed_node_id")
    if not evidence_is_present(declared) or not evidence_is_present(observed):
        return PassResult(
            pass_id="gpu_node_id_match",
            status=PASS_SKIPPED,
            detail="node ID match skipped because declared or observed node ID is missing",
        )

    declared_text = str(declared)
    observed_text = str(observed)
    if declared_text != observed_text:
        return PassResult(
            pass_id="gpu_node_id_match",
            status=PASS_CONTRADICTED,
            detail=f"Node ID mismatch: declared '{declared_text}', observed '{observed_text}'.",
            verdict_effect=CONTRADICTED,
            metadata={"declared_node_id": declared_text, "observed_node_id": observed_text},
        )

    return PassResult(
        pass_id="gpu_node_id_match",
        status=PASS_SATISFIED,
        detail=f"Node ID matched: {declared_text}.",
        metadata={"node_id": declared_text},
    )


def dcgm_diag_result(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check DCGM diagnostic status without interpreting missing evidence."""
    raw_result = get_path(ir.artifacts, "dcgm_diag.overall_result")
    if not evidence_is_present(raw_result):
        return PassResult(
            pass_id="dcgm_diag_result",
            status=PASS_SKIPPED,
            detail="DCGM diagnostic result skipped because dcgm_diag.overall_result is missing",
        )

    result = str(raw_result)
    if result == "Pass":
        return PassResult(
            pass_id="dcgm_diag_result",
            status=PASS_SATISFIED,
            detail="DCGM diagnostic result passed.",
        )
    if result == "Warn":
        return PassResult(
            pass_id="dcgm_diag_result",
            status=PASS_UNKNOWN,
            detail="DCGM reported warning status; health is indeterminate.",
            verdict_effect=UNKNOWN,
        )
    if result == "Fail":
        failed = []
        test_results = get_path(ir.artifacts, "dcgm_diag.test_results")
        if isinstance(test_results, list):
            for item in test_results:
                if not isinstance(item, dict) or item.get("result") != "Fail":
                    continue
                name = item.get("test_name", "unknown_test")
                detail = item.get("detail")
                failed.append(f"{name}: {detail}" if detail else str(name))
        failed_text = "; ".join(failed) if failed else "no failed test detail supplied"
        return PassResult(
            pass_id="dcgm_diag_result",
            status=PASS_CONTRADICTED,
            detail=f"DCGM diagnostic failed: {failed_text}.",
            verdict_effect=CONTRADICTED,
            metadata={"failed_tests": failed},
        )

    return PassResult(
        pass_id="dcgm_diag_result",
        status=PASS_UNKNOWN,
        detail=f"DCGM diagnostic result {result!r} is not recognized.",
        verdict_effect=UNKNOWN,
    )


def ecc_threshold_check(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check uncorrectable ECC and retired-page thresholds."""
    dbe = _number(get_path(ir.artifacts, "xid_ecc_log.volatile_dbe_errors"))
    retired = _number(get_path(ir.artifacts, "xid_ecc_log.total_retired_pages"))
    limit = _number(get_path(ir.artifacts, "xid_ecc_log.page_retirement_limit"))
    if dbe is None or retired is None or limit is None:
        return PassResult(
            pass_id="ecc_threshold_check",
            status=PASS_SKIPPED,
            detail="ECC threshold check skipped because DBE or retired-page threshold evidence is missing",
        )

    contradictions = []
    if dbe > 0:
        contradictions.append(f"Uncorrectable double-bit ECC errors detected: {dbe:g} volatile DBE")
    if retired >= limit:
        contradictions.append(f"Retired page count ({retired:g}) meets or exceeds limit ({limit:g})")

    if contradictions:
        return PassResult(
            pass_id="ecc_threshold_check",
            status=PASS_CONTRADICTED,
            detail="; ".join(contradictions) + ".",
            verdict_effect=CONTRADICTED,
            metadata={
                "volatile_dbe_errors": dbe,
                "total_retired_pages": retired,
                "page_retirement_limit": limit,
            },
        )

    return PassResult(
        pass_id="ecc_threshold_check",
        status=PASS_SATISFIED,
        detail=f"ECC within thresholds: 0 volatile DBE, {retired:g}/{limit:g} retired pages.",
        metadata={
            "volatile_dbe_errors": dbe,
            "total_retired_pages": retired,
            "page_retirement_limit": limit,
        },
    )


def gpu_serial_cross_reference(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check that GPU health evidence sources refer to the same serial."""
    sources = {
        "dcgm_diag": get_path(ir.artifacts, "dcgm_diag.gpu_serial"),
        "xid_ecc_log": get_path(ir.artifacts, "xid_ecc_log.gpu_serial"),
        "nvidia_smi": get_path(ir.artifacts, "nvidia_smi.gpu_serial"),
    }
    present = {name: str(value) for name, value in sources.items() if evidence_is_present(value)}
    if not present:
        return PassResult(
            pass_id="gpu_serial_cross_reference",
            status=PASS_SKIPPED,
            detail="GPU serial cross-reference skipped because no serial evidence is present",
        )

    serials = set(present.values())
    if len(serials) > 1:
        detail_parts = [f"{name}='{value}'" for name, value in sorted(present.items())]
        return PassResult(
            pass_id="gpu_serial_cross_reference",
            status=PASS_CONTRADICTED,
            detail="Evidence serial mismatch: " + ", ".join(detail_parts) + ".",
            verdict_effect=CONTRADICTED,
            metadata=present,
        )

    serial = next(iter(serials))
    return PassResult(
        pass_id="gpu_serial_cross_reference",
        status=PASS_SATISFIED,
        detail=f"All evidence sources reference same GPU: {serial}.",
        metadata=present,
    )


# ---------------------------------------------------------------------------
# Prefix continuity passes
# ---------------------------------------------------------------------------

def prefix_continuity(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check that next_prompt_tokens preserves the prefix previous_prompt_tokens + completion_tokens."""
    params = params or {}
    prev_path = params.get("previous_key", "token_sequences.previous_prompt_tokens")
    comp_path = params.get("completion_key", "token_sequences.completion_tokens")
    next_path = params.get("next_key", "token_sequences.next_prompt_tokens")

    previous = get_path(ir.artifacts, prev_path)
    completion = get_path(ir.artifacts, comp_path)
    next_prompt = get_path(ir.artifacts, next_path)

    if not isinstance(previous, list):
        return PassResult(
            pass_id="prefix_continuity",
            status=PASS_UNKNOWN,
            detail=f"previous_prompt_tokens at {prev_path} is missing or not a list",
            verdict_effect=UNKNOWN,
        )
    if not isinstance(completion, list):
        return PassResult(
            pass_id="prefix_continuity",
            status=PASS_UNKNOWN,
            detail=f"completion_tokens at {comp_path} is missing or not a list",
            verdict_effect=UNKNOWN,
        )
    if not isinstance(next_prompt, list):
        return PassResult(
            pass_id="prefix_continuity",
            status=PASS_UNKNOWN,
            detail=f"next_prompt_tokens at {next_path} is missing or not a list",
            verdict_effect=UNKNOWN,
        )

    expected_prefix = previous + completion
    actual_prefix = next_prompt[: len(expected_prefix)]

    if actual_prefix == expected_prefix:
        return PassResult(
            pass_id="prefix_continuity",
            status=PASS_SATISFIED,
            detail=f"next prompt preserves exact prefix of {len(expected_prefix)} tokens",
            verdict_effect=SUPPORTED,
            metadata={
                "prefix_length": len(expected_prefix),
                "next_prompt_length": len(next_prompt),
            },
        )

    # Find first divergence point for diagnostics
    diverge_at = 0
    for i, (a, b) in enumerate(zip(expected_prefix, actual_prefix)):
        if a != b:
            diverge_at = i
            break
    else:
        diverge_at = min(len(expected_prefix), len(actual_prefix))

    return PassResult(
        pass_id="prefix_continuity",
        status=PASS_CONTRADICTED,
        detail=f"next prompt diverges from expected prefix at token {diverge_at}",
        verdict_effect=CONTRADICTED,
        metadata={
            "divergence_index": diverge_at,
            "expected_prefix_length": len(expected_prefix),
            "actual_prefix_length": len(actual_prefix),
        },
    )


# ---------------------------------------------------------------------------
# Pass registry
# ---------------------------------------------------------------------------

PASS_REGISTRY: dict[str, Any] = {
    # Universal
    "utc_timestamp_format": utc_timestamp_format,
    "expected_evidence_absence": expected_evidence_absence,
    "no_future_evidence": no_future_evidence,
    "execution_context_disclosure": execution_context_disclosure,
    # Authorization grant
    "grant_active_at_event_time": grant_active_at_event_time,
    "revocation_before_action": revocation_before_action,
    "grant_binding_present": grant_binding_present,
    "no_action_from_untrusted_literal": no_action_from_untrusted_literal,
    # Parser repair
    "parser_repair_logged": parser_repair_logged,
    "repair_writeback_recorded": repair_writeback_recorded,
    # Human approval and deployment
    "human_approval_before_action": human_approval_before_action,
    "deployment_matches_reviewed_commit": deployment_matches_reviewed_commit,
    # GPU collateral
    "gpu_serial_set_match": gpu_serial_set_match,
    "gpu_node_id_match": gpu_node_id_match,
    "dcgm_diag_result": dcgm_diag_result,
    "ecc_threshold_check": ecc_threshold_check,
    "gpu_serial_cross_reference": gpu_serial_cross_reference,
    # Prefix continuity
    "prefix_continuity": prefix_continuity,
}


def get_pass(pass_id: str) -> Any:
    """Return the pass function for a pass_id, or raise ValueError."""
    if pass_id not in PASS_REGISTRY:
        available = ", ".join(sorted(PASS_REGISTRY))
        raise ValueError(f"unknown pass {pass_id!r}; available: {available}")
    return PASS_REGISTRY[pass_id]


# Legacy ordered passes list for v1 compatibility (bundle-mode)
ORDERED_PASSES = [
    utc_timestamp_format,
    expected_evidence_absence,
    grant_active_at_event_time,
    revocation_before_action,
    no_future_evidence,
]
