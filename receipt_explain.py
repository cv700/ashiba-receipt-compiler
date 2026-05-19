#!/usr/bin/env python3
"""Human-readable explanations for compiled receipts."""

from __future__ import annotations

from typing import Any

from constants import CONTRADICTED, PASS_CONTRADICTED, PASS_MISSING, PASS_UNKNOWN, UNKNOWN


GAP_GUIDANCE_BY_PATH = {
    "authorization.grant_id": (
        "identifies which grant is being relied on for the action",
        "Log the authorization grant id beside the tool invocation.",
    ),
    "authorization.grant_valid_from": (
        "establishes the beginning of the authorization window",
        "Log grant_valid_from as an ISO 8601 UTC field in the authorization record.",
    ),
    "authorization.grant_valid_until": (
        "establishes the end of the authorization window",
        "Log grant_valid_until as an ISO 8601 UTC field in the authorization record.",
    ),
    "authorization.revoked_at": (
        "separates an explicitly non-revoked grant from an unobserved revocation state",
        "Log revoked_at as ISO 8601 UTC when revoked, or explicit null when checked and not revoked.",
    ),
    "parsed_actions.0.executed_at": (
        "anchors the action time used for grant-window and revocation checks",
        "Log the tool execution timestamp as parsed_actions[].executed_at in ISO 8601 UTC.",
    ),
    "tool_call.action_id": (
        "binds the parsed action to the underlying tool-call record",
        "Log the same stable action_id in both parsed_actions[] and tool_call.",
    ),
    "parser.repair_events.0.repair_id": (
        "identifies which parser repair event is being reviewed",
        "Log parser.repair_events[].repair_id for every repair attempt.",
    ),
    "parser.repair_events.0.repair_function": (
        "names the deterministic repair logic applied to the input",
        "Log parser.repair_events[].repair_function before accepting repaired input.",
    ),
    "parser.repair_events.0.before_hash": (
        "binds the repair to the original malformed payload",
        "Log parser.repair_events[].before_hash over the pre-repair bytes.",
    ),
    "parser.repair_events.0.after_hash": (
        "binds the repair to the repaired payload",
        "Log parser.repair_events[].after_hash over the post-repair bytes.",
    ),
    "parser.repair_events.0.writeback_to_model_history": (
        "records whether repaired content was written back into model-visible history",
        "Log parser.repair_events[].writeback_to_model_history as an explicit boolean.",
    ),
    "token_sequences.previous_prompt_tokens": (
        "anchors the previous prompt token prefix",
        "Log token_sequences.previous_prompt_tokens from the tokenizer actually used.",
    ),
    "token_sequences.completion_tokens": (
        "anchors the completion tokens appended to the next prompt",
        "Log token_sequences.completion_tokens from the tokenizer actually used.",
    ),
    "token_sequences.next_prompt_tokens": (
        "lets the compiler compare the expected and actual next prompt prefix",
        "Log token_sequences.next_prompt_tokens from the tokenizer actually used.",
    ),
    "approval.approved_at": (
        "proves a human approval timestamp existed before the external action",
        "Log approval.approved_at as ISO 8601 UTC from the approval system.",
    ),
    "approval.decision": (
        "records whether the human decision authorized or rejected the action",
        "Log approval.decision with an explicit approved/rejected value.",
    ),
    "approval.actor": (
        "identifies the human or group responsible for the approval",
        "Log approval.actor from the approval workflow identity provider.",
    ),
    "deployment.commit_sha": (
        "identifies the commit that was deployed",
        "Log deployment.commit_sha from the deployment job environment.",
    ),
    "review.commit_sha": (
        "identifies the reviewed commit used as the comparison point",
        "Log review.commit_sha from the code-review or change-management system.",
    ),
    "review.decision": (
        "records whether the reviewed commit was approved",
        "Log review.decision with an explicit approved/rejected value.",
    ),
    "deployment.deployed_at": (
        "anchors when the deployment happened",
        "Log deployment.deployed_at as ISO 8601 UTC from the deployment controller.",
    ),
}


def _bullet_lines(items: list[str], indent: str = "  - ") -> list[str]:
    if not items:
        return [f"{indent}(none)"]
    return [f"{indent}{item}" for item in items]


def _get_path(obj: Any, dotted: str) -> Any:
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


def _evidence_is_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, list, dict)):
        return len(value) > 0
    return True


def _claim_label(receipt: dict[str, Any]) -> str:
    claim = receipt.get("claim", {})
    if not isinstance(claim, dict):
        return "(claim unavailable)"
    claim_id = str(claim.get("id", "")).strip()
    claim_text = str(claim.get("text", "")).strip()
    if claim_id and claim_text:
        return f"{claim_id}: {claim_text}"
    return claim_id or claim_text or "(claim unavailable)"


def _guidance_for_path(path: str) -> tuple[str, str]:
    if path in GAP_GUIDANCE_BY_PATH:
        return GAP_GUIDANCE_BY_PATH[path]
    if path.endswith(".executed_at") or path.endswith("_at"):
        return (
            "anchors event ordering for the claim",
            f"Log {path} as an ISO 8601 UTC timestamp from the system of record.",
        )
    if "commit_sha" in path:
        return (
            "binds the claim to a concrete commit identity",
            f"Log {path} from the workflow or review system that produced it.",
        )
    return (
        "is expected evidence for the selected claim",
        f"Add a structured log field for {path} in the artifact bundle.",
    )


def missing_evidence_gaps(receipt: dict[str, Any]) -> list[dict[str, str]]:
    """Return actionable missing-evidence gaps for one receipt dict."""
    gaps: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    claim = _claim_label(receipt)

    def add_gap(path: Any) -> None:
        if not isinstance(path, str) or not path:
            return
        key = (claim, path)
        if key in seen:
            return
        seen.add(key)
        why, instrumentation = _guidance_for_path(path)
        gaps.append({
            "missing_expected_path": path,
            "claim_affected": claim,
            "why_it_matters": why,
            "instrumentation_or_log_field": instrumentation,
            "verdict_effect": "unknown, not contradicted",
        })

    for record in receipt.get("absence", []):
        if isinstance(record, dict):
            add_gap(record.get("expected_path"))

    for result in receipt.get("pass_results", []):
        if not isinstance(result, dict):
            continue
        if result.get("status") not in {PASS_MISSING, PASS_UNKNOWN}:
            continue
        metadata = result.get("metadata", {})
        if not isinstance(metadata, dict):
            continue
        for path in metadata.get("missing_expected_paths", []):
            add_gap(path)
        for path in metadata.get("invalid_evidence_paths", []):
            add_gap(path)

    return gaps


def format_gap_report(receipt: dict[str, Any]) -> str:
    """Return an actionable missing-evidence report for one receipt."""
    gaps = missing_evidence_gaps(receipt)
    lines = [
        "Missing Evidence Gaps",
        "=====================",
        f"Claim type: {receipt.get('claim_type', '(bundle mode)')}",
        f"Verdict: {receipt.get('verdict', {}).get('status', '(missing)')}",
    ]
    if not gaps:
        lines.append("No missing-evidence gaps reported.")
        return "\n".join(lines)

    for gap in gaps:
        lines.extend([
            f"- missing expected path: {gap['missing_expected_path']}",
            f"  claim affected: {gap['claim_affected']}",
            f"  why it matters: {gap['why_it_matters']}",
            f"  instrumentation/log field: {gap['instrumentation_or_log_field']}",
            f"  verdict effect: {gap['verdict_effect']}",
        ])
    return "\n".join(lines)


def format_receipts_gap_report(receipts: list[dict[str, Any]]) -> str:
    """Return missing-evidence reports for one or more receipts."""
    return "\n\n".join(format_gap_report(receipt) for receipt in receipts)


def _expected_evidence_lines(receipt: dict[str, Any], want_present: bool) -> list[str]:
    artifacts = receipt.get("artifacts", {})
    expected = receipt.get("expected_evidence", [])
    if not isinstance(artifacts, dict) or not isinstance(expected, list):
        return []
    lines = []
    for path in expected:
        if not isinstance(path, str):
            continue
        present = _evidence_is_present(_get_path(artifacts, path))
        if present == want_present:
            lines.append(path)
    return lines


def _incident_line(receipt: dict[str, Any]) -> str:
    manifest = receipt.get("incident_manifest")
    if not isinstance(manifest, dict) or not manifest:
        return "Incident: no incident manifest supplied"
    incident_id = manifest.get("incident_id", "(unspecified)")
    renderer = manifest.get("renderer", {})
    if not isinstance(renderer, dict):
        renderer = {}
    renderer_name = renderer.get("name", "(renderer unspecified)")
    renderer_version = renderer.get("version", "(version unspecified)")
    return f"Incident: {incident_id} | renderer: {renderer_name} {renderer_version}"


def _decisive_pass(receipt: dict[str, Any]) -> str:
    for result in receipt.get("pass_results", []):
        if result.get("verdict_effect") == CONTRADICTED or result.get("status") == PASS_CONTRADICTED:
            return f"{result.get('pass_id')}: {result.get('detail')}"
    absence = receipt.get("absence", [])
    if absence:
        return f"expected_evidence_absence: {len(absence)} expected evidence path(s) absent"
    for result in receipt.get("pass_results", []):
        if result.get("verdict_effect") == UNKNOWN or result.get("status") in {PASS_MISSING, PASS_UNKNOWN}:
            return f"{result.get('pass_id')}: {result.get('detail')}"
    pass_results = receipt.get("pass_results", [])
    if pass_results:
        return f"{len(pass_results)} deterministic pass(es) ran without contradiction"
    return "no pass results were emitted"


def _artifact_lines(receipt: dict[str, Any]) -> list[str]:
    manifest = receipt.get("artifact_manifest", [])
    if not isinstance(manifest, list):
        return ["artifact manifest is absent or malformed"]
    lines = []
    for record in manifest:
        if not isinstance(record, dict):
            continue
        rel = record.get("relative_path") or record.get("filename") or "(unknown path)"
        source = record.get("source", "artifact")
        role = record.get("role")
        artifact_key = record.get("artifact_key")
        parts = [str(source), str(rel)]
        if artifact_key:
            parts.append(f"key={artifact_key}")
        if role:
            parts.append(f"role={role}")
        lines.append(" | ".join(parts))
    return lines


def format_receipt_explanation(receipt: dict[str, Any]) -> str:
    """Return one compact human report for a receipt dict."""
    verdict = receipt.get("verdict", {})
    boundary = receipt.get("boundary", {})
    absence = receipt.get("absence", [])
    lines = [
        "Receipt Explanation",
        "===================",
        f"Receipt: {receipt.get('receipt_id', '(missing)')}",
        _incident_line(receipt),
        f"Claim type: {receipt.get('claim_type', '(bundle mode)')}",
        f"Claim: {receipt.get('claim', {}).get('text', '')}",
        f"Verdict: {verdict.get('status', '(missing)')}",
        f"Basis: {verdict.get('basis', '(missing)')}",
        f"Decisive check: {_decisive_pass(receipt)}",
        f"Input set hash: {receipt.get('input_set_hash', '(missing)')}",
        "",
        "Input files:",
    ]
    lines.extend(_bullet_lines(_artifact_lines(receipt)))

    lines.extend(["", "Missing expected evidence:"])
    lines.extend(_bullet_lines([str(item.get("expected_path")) for item in absence if isinstance(item, dict)]))

    gaps = missing_evidence_gaps(receipt)
    if gaps:
        lines.extend(["", "Missing-evidence guidance:"])
        for gap in gaps:
            lines.append(f"  - {gap['missing_expected_path']}: {gap['instrumentation_or_log_field']}")
            lines.append(f"    verdict effect: {gap['verdict_effect']}")

    lines.extend(["", "Boundary:"])
    does_not_support = boundary.get("does_not_support", [])
    if not isinstance(does_not_support, list):
        does_not_support = []
    lines.extend(_bullet_lines([str(item) for item in does_not_support]))
    return "\n".join(lines)


def format_receipts_explanation(receipts: list[dict[str, Any]]) -> str:
    """Return a human report for one or more receipt dicts."""
    return "\n\n".join(format_receipt_explanation(receipt) for receipt in receipts)


def format_receipt_card(receipt: dict[str, Any]) -> str:
    """Return a short pasteable receipt card for Slack or email."""
    verdict = receipt.get("verdict", {})
    boundary = receipt.get("boundary", {})
    does_not_support = boundary.get("does_not_support", [])
    if not isinstance(does_not_support, list):
        does_not_support = []
    unsupported = receipt.get("unsupported_inferences", [])
    if not isinstance(unsupported, list):
        unsupported = []

    missing = missing_evidence_gaps(receipt)
    missing_lines = [
        f"{gap['missing_expected_path']} -> {gap['instrumentation_or_log_field']}" for gap in missing
    ]
    lines = [
        "Receipt Card",
        f"Claim: {_claim_label(receipt)}",
        f"Verdict: {verdict.get('status', '(missing)')}",
        f"Basis: {verdict.get('basis', '(missing)')}",
        "Evidence present:",
    ]
    lines.extend(_bullet_lines(_expected_evidence_lines(receipt, True)[:8]))
    lines.extend(["Evidence missing:"])
    lines.extend(_bullet_lines(missing_lines[:8]))
    lines.extend(["Boundary / does-not-support:"])
    lines.extend(_bullet_lines([str(item) for item in does_not_support[:4]]))
    lines.extend(["Unsupported inferences:"])
    lines.extend(_bullet_lines([str(item) for item in unsupported[:4]]))
    return "\n".join(lines)


def format_receipts_card(receipts: list[dict[str, Any]]) -> str:
    """Return pasteable receipt cards for one or more receipts."""
    return "\n\n".join(format_receipt_card(receipt) for receipt in receipts)
