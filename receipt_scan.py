#!/usr/bin/env python3
"""Readiness scanner for side-effect authorization evidence.

The scanner is the scout before the receipt: it reads the logs people already
have, asks which claims are ready for a bounded update, and turns UNKNOWN into
a concrete instrumentation punch list.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass, field
import json
from pathlib import Path
import sys
from typing import Any

from claim_contracts import (
    claim_conflicts,
    claim_has_action_scope,
    claim_missing,
    conflict_excluded,
)
from claim_types import build_claim_registry
from importer_common import (
    authorization_decision_id_from_fields as _decision_id_from_fields,
    authorization_from_policy as _authorization_from_policy,
    first_present,
    nested_get,
    normalize_timestamp,
)
from passes import get_path
from side_effect_envelope import (
    SIDE_EFFECT_ACTION_ID_PATH,
    SIDE_EFFECT_DECISION_ID_PATH,
    SIDE_EFFECT_EXECUTED_AT_PATH,
    SIDE_EFFECTS_KEY,
    legacy_artifacts_from_side_effect,
    normalize_side_effect,
    normalize_side_effect_artifacts,
)


ALL_SCAN_CLAIMS = ("deployment_matches_reviewed_commit", "authorization_bound_action",
                    "human_approval_before_external_side_effect")
TEXT_SUFFIXES = {".json", ".jsonl", ".log", ".txt"}

CLAIM_EVIDENCE_TRIGGERS: dict[str, list[str]] = {
    "authorization_bound_action": ["authorization", SIDE_EFFECTS_KEY, "parsed_actions", "tool_call"],
    "deployment_matches_reviewed_commit": ["deployment", "review"],
    "human_approval_before_external_side_effect": ["approval"],
}
REVOCATION_PATH = "authorization.revoked_at"
AUTHORIZATION_BINDING = "authorization-to-action binding"
PROBE_BY_MISSING = {
    REVOCATION_PATH: "add revocation_state export",
    AUTHORIZATION_BINDING: "carry authorization execution_time_decision_id into the tool call",
    "review.commit_sha": "log reviewed commit_sha from the review system",
    "review.decision": "log review decision with approved/rejected",
    "review.approved_at": "log review approved_at as UTC",
    "deployment.commit_sha": "log deployed commit_sha from the deployment job",
    "deployment.deployed_at": "log deployment time as UTC",
    SIDE_EFFECT_ACTION_ID_PATH: "log stable tool_call_id/action_id on side effects",
    SIDE_EFFECT_EXECUTED_AT_PATH: "log tool execution time as UTC",
    "approval.approved_at": "log human approval timestamp as UTC",
    "approval.decision": "log approval decision (approved/rejected)",
    "approval.actor": "log the identity of the human approver",
}

WHY_BY_MISSING = {
    REVOCATION_PATH: "Without explicit revocation state, absence of a revocation event can be confused with missing evidence.",
    AUTHORIZATION_BINDING: "Without a matching decision ID on both sides of the boundary, the evidence cannot show that this authorization decision governed this exact action.",
    "review.commit_sha": "Without the reviewed commit, deployment evidence cannot be compared to the approved artifact.",
    "review.decision": "Without the review decision, a review record does not show approval.",
    "review.approved_at": "Without the approval timestamp, the compiler cannot check review-before-deploy ordering.",
    "deployment.commit_sha": "Without the deployed commit, the compiler cannot compare deployment to review.",
    "deployment.deployed_at": "Without deployment time, the compiler cannot check chronology.",
    SIDE_EFFECT_ACTION_ID_PATH: "Without a stable action ID, logs from different systems cannot be joined to one side effect.",
    SIDE_EFFECT_EXECUTED_AT_PATH: "Without execution time, the compiler cannot check authorization or approval windows.",
    "approval.approved_at": "Without approval time, the compiler cannot prove approval happened before the side effect.",
    "approval.decision": "Without the approval decision, the compiler cannot distinguish approval from rejection or review-only records.",
    "approval.actor": "Without approver identity, the compiler cannot show who approved the side effect.",
}

SUGGESTED_FIELDS_BY_MISSING = {
    REVOCATION_PATH: {"authorization": {"revoked_at": None}},
    AUTHORIZATION_BINDING: {
        "authorization": {
            "render_time_grant_hash": "sha256:grant-hash-123",
            "execution_time_decision_id": "authz-decision-123",
            "grant_active_at_execution": True,
        },
        SIDE_EFFECTS_KEY: [{"invocation": {"decision_id": "authz-decision-123"}}],
    },
    "review.commit_sha": {"review": {"commit_sha": "abc123"}},
    "review.decision": {"review": {"decision": "approved"}},
    "review.approved_at": {"review": {"approved_at": "2026-05-14T16:59:00Z"}},
    "deployment.commit_sha": {"deployment": {"commit_sha": "abc123"}},
    "deployment.deployed_at": {"deployment": {"deployed_at": "2026-05-14T17:01:30Z"}},
    SIDE_EFFECT_ACTION_ID_PATH: {SIDE_EFFECTS_KEY: [{"action_id": "act-123"}]},
    SIDE_EFFECT_EXECUTED_AT_PATH: {SIDE_EFFECTS_KEY: [{"executed_at": "2026-05-14T17:01:30Z"}]},
    "approval.approved_at": {"approval": {"approved_at": "2026-05-14T16:59:00Z"}},
    "approval.decision": {"approval": {"decision": "approved"}},
    "approval.actor": {"approval": {"actor": "user@example.com"}},
}


@dataclass
class ClaimReadiness:
    claim: str
    can_decide: bool
    missing: list[str]
    conflicts: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        out = {"claim": self.claim, "missing": self.missing}
        if self.conflicts:
            out["conflicts"] = self.conflicts
        return out


@dataclass
class EvidenceConflict:
    path: str
    existing: Any
    incoming: Any
    source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "existing": _conflict_value(self.existing),
            "incoming": _conflict_value(self.incoming),
            "source": self.source,
        }


@dataclass
class ActionCandidate:
    action_id: str | None
    source: str
    source_kind: str
    artifacts: dict[str, Any]


@dataclass
class FileObservation:
    path: str
    kinds: list[str]
    records: int
    actions: int
    evidence: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kinds": self.kinds,
            "records": self.records,
            "actions": self.actions,
            "evidence": self.evidence,
        }


@dataclass
class ActionReadiness:
    action_id: str | None
    source: str
    source_kind: str
    tool: str | None
    executed_at: str | None
    decidable: bool
    can_decide: list[str]
    cannot_decide: list[ClaimReadiness]
    probeable_next: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "source": self.source,
            "source_kind": self.source_kind,
            "tool": self.tool,
            "executed_at": self.executed_at,
            "decidable": self.decidable,
            "can_decide": self.can_decide,
            "cannot_decide": [item.as_dict() for item in self.cannot_decide],
            "probeable_next": self.probeable_next,
        }


@dataclass
class ScanResult:
    input_status: str
    files_scanned: list[str]
    can_decide: list[str]
    cannot_decide: list[ClaimReadiness]
    probeable_next: list[str]
    warnings: list[str]
    conflicts: list[EvidenceConflict]
    actions: list[ActionReadiness]
    observations: list[FileObservation]
    punch_list: list[str]

    def as_dict(self) -> dict[str, Any]:
        actions_decidable = sum(1 for action in self.actions if action.decidable)
        kind_counts: dict[str, int] = {}
        for observation in self.observations:
            for kind in observation.kinds:
                kind_counts[kind] = kind_counts.get(kind, 0) + 1
        return {
            "input_status": self.input_status,
            "files_scanned": self.files_scanned,
            "summary": {
                "input_status": self.input_status,
                "files_scanned": len(self.files_scanned),
                "actions_found": len(self.actions),
                "actions_decidable": actions_decidable,
                "actions_blocked": len(self.actions) - actions_decidable,
                "input_kinds": kind_counts,
                "claims_decidable": len(self.can_decide),
                "claims_blocked": len(self.cannot_decide),
            },
            "detected_inputs": [observation.as_dict() for observation in self.observations],
            "can_decide": self.can_decide,
            "cannot_decide": [item.as_dict() for item in self.cannot_decide],
            "probeable_next": self.probeable_next,
            "punch_list": self.punch_list,
            "warnings": self.warnings,
            "evidence_conflicts": [conflict.as_dict() for conflict in self.conflicts],
            "actions": [action.as_dict() for action in self.actions],
        }


@dataclass
class ScanContext:
    artifacts: dict[str, Any]
    files_scanned: list[str]
    warnings: list[str]
    conflicts: list[EvidenceConflict]
    actions: list[ActionCandidate]
    approvals: list[dict[str, Any]]
    observations: list[FileObservation]


def _load_json_file(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read {label}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {label}: {path}: {exc}") from exc


def _candidate_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.is_dir():
        raise ValueError(f"scan input is not a file or directory: {root}")
    return [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and (path.suffix.lower() in TEXT_SUFFIXES or not path.suffix)
    ]


def _parse_key_value_log(raw: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower().replace("-", "_")
        value = value.strip()
        if key and value:
            out[key] = value
    return out


def _payloads_from_file(path: Path) -> list[Any]:
    raw = path.read_text(encoding="utf-8")
    stripped = raw.strip()
    if not stripped:
        return []
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        payload = None

    if payload is not None:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("events", "items", "spans"):
                records = payload.get(key)
                if isinstance(records, list):
                    return records
        return [payload]

    jsonl_records = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            jsonl_records.append(json.loads(line))
        except json.JSONDecodeError:
            jsonl_records = []
            break
    if jsonl_records:
        return jsonl_records

    kv = _parse_key_value_log(raw)
    return [kv] if kv else []


def _conflict_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    try:
        encoded = json.dumps(value, sort_keys=True)
    except TypeError:
        encoded = repr(value)
    if len(encoded) > 240:
        return encoded[:237] + "..."
    return encoded


def _record_conflict(
    conflicts: list[EvidenceConflict] | None,
    path: str,
    existing: Any,
    incoming: Any,
    source: str,
) -> None:
    if conflicts is None or existing == incoming:
        return
    conflict = EvidenceConflict(path=path, existing=existing, incoming=incoming, source=source)
    marker = conflict.as_dict()
    if any(item.as_dict() == marker for item in conflicts):
        return
    conflicts.append(conflict)


def _join_path(parent: str, child: str) -> str:
    return f"{parent}.{child}" if parent else child


def _merge_value(
    existing: Any,
    incoming: Any,
    conflicts: list[EvidenceConflict] | None = None,
    path: str = "",
    source: str = "",
) -> Any:
    if incoming in ({}, [], None):
        return existing
    if existing in ({}, [], None):
        return incoming
    if isinstance(existing, dict) and isinstance(incoming, dict):
        out = dict(existing)
        for key, value in incoming.items():
            out[key] = _merge_value(out.get(key), value, conflicts, _join_path(path, str(key)), source)
        return out
    if isinstance(existing, list) and isinstance(incoming, list):
        return existing + incoming
    _record_conflict(conflicts, path, existing, incoming, source)
    return existing


def _merge_artifacts(
    target: dict[str, Any],
    source: dict[str, Any],
    conflicts: list[EvidenceConflict] | None = None,
    source_label: str = "",
) -> None:
    for key in ("authorization", SIDE_EFFECTS_KEY, "parsed_actions", "tool_call", "deployment", "review", "approval"):
        if key in source:
            target[key] = _merge_value(target.get(key), source[key], conflicts, key, source_label)


def _append_unique(items: list[str], value: str | None) -> None:
    if value and value not in items:
        items.append(value)


def _review_from_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    if not policy:
        return {}
    raw = policy.get("review") if isinstance(policy.get("review"), dict) else policy
    review = {}
    for dest, keys in {
        "commit_sha": ("commit_sha", "reviewed_commit_sha", "head_sha"),
        "decision": ("decision", "review_decision"),
        "approved_at": ("approved_at", "review_approved_at"),
        "reviewer": ("reviewer", "actor"),
    }.items():
        value = first_present(*(raw.get(key) for key in keys))
        if value is not None:
            review[dest] = value
    return {"review": review} if review else {}


def _approval_from_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    if not policy:
        return {}
    raw = policy.get("approval") if isinstance(policy.get("approval"), dict) else policy
    approval = {}
    for dest, keys in {
        "approval_id": ("approval_id", "decision_id"),
        "tool_call_id": ("tool_call_id", "action_id"),
        "approved_at": ("approved_at", "approval_approved_at"),
        "decision": ("decision", "approval_decision"),
        "actor": ("actor", "approver"),
    }.items():
        value = first_present(*(raw.get(key) for key in keys))
        if value is not None:
            approval[dest] = value
    return {"approval": approval} if approval else {}


def _payload_authorization(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict) and isinstance(payload.get("authorization"), dict):
        return {"authorization": payload["authorization"]}
    return {}


def _payload_review(payload: dict[str, Any]) -> dict[str, Any]:
    raw = payload.get("review") if isinstance(payload.get("review"), dict) else {}
    review = {}
    for dest, value in {
        "commit_sha": first_present(raw.get("commit_sha"), payload.get("review_commit_sha"), payload.get("reviewed_commit_sha")),
        "decision": first_present(raw.get("decision"), payload.get("review_decision")),
        "approved_at": first_present(raw.get("approved_at"), payload.get("review_approved_at")),
        "reviewer": first_present(raw.get("reviewer"), payload.get("reviewer")),
    }.items():
        if value is not None:
            review[dest] = value
    return review


def _payload_to_deployment(payload: dict[str, Any]) -> dict[str, Any]:
    workflow_run = payload.get("workflow_run") if isinstance(payload.get("workflow_run"), dict) else {}
    job = payload.get("job") if isinstance(payload.get("job"), dict) else {}
    deployment = payload.get("deployment") if isinstance(payload.get("deployment"), dict) else {}
    deployment_id = first_present(deployment.get("id"), payload.get("deployment_id"), job.get("id"), workflow_run.get("id"))
    commit_sha = first_present(
        deployment.get("commit_sha"),
        deployment.get("sha"),
        payload.get("commit_sha"),
        payload.get("github_sha"),
        workflow_run.get("head_sha"),
        job.get("head_sha"),
    )
    deployed_at = normalize_timestamp(first_present(
        deployment.get("deployed_at"),
        deployment.get("created_at"),
        payload.get("deployed_at"),
        payload.get("completed_at"),
        workflow_run.get("updated_at"),
        job.get("completed_at"),
    ))
    out = {}
    if deployment_id is not None:
        out["deployment_id"] = str(deployment_id)
    if commit_sha is not None:
        out["commit_sha"] = str(commit_sha)
    if deployed_at is not None:
        out["deployed_at"] = deployed_at
    environment = first_present(deployment.get("environment"), payload.get("environment"))
    if environment is not None:
        out["environment"] = environment
    actor = first_present(payload.get("actor"), nested_get(workflow_run, "actor", "login"))
    if actor is not None and out:
        out["actor"] = actor
    return {"deployment": out} if out else {}


def _cloudtrail_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("Records"), list):
        return [record for record in payload["Records"] if isinstance(record, dict)]
    if isinstance(payload, dict) and "eventSource" in payload and "eventName" in payload:
        return [payload]
    return []


def _cloudtrail_artifacts(payload: Any) -> dict[str, Any]:
    records = _cloudtrail_records(payload)
    if not records:
        return {}
    event = records[0]
    event_source = event.get("eventSource")
    event_name = event.get("eventName")
    action_id = first_present(event.get("eventID"), event.get("requestID"), event.get("eventId"))
    executed_at = normalize_timestamp(event.get("eventTime"))
    tool_name = f"{event_source}:{event_name}" if event_source and event_name else None
    request_parameters = event.get("requestParameters") if isinstance(event.get("requestParameters"), dict) else {}
    response_elements = event.get("responseElements") if isinstance(event.get("responseElements"), dict) else {}
    additional_event_data = event.get("additionalEventData") if isinstance(event.get("additionalEventData"), dict) else {}
    decision_id = _decision_id_from_fields(event, request_parameters, response_elements, additional_event_data)
    out: dict[str, Any] = {}
    if action_id or executed_at or tool_name:
        action = {}
        if action_id:
            action["action_id"] = action_id
        if tool_name:
            action["tool"] = tool_name
        if executed_at:
            action["executed_at"] = executed_at
        action["source_kind"] = "cloudtrail_event"
        out["parsed_actions"] = [action]
    if action_id or tool_name:
        tool_call: dict[str, Any] = {
            "invocation_context": {
                "source": "cloudtrail",
                "event_source": event_source,
                "event_name": event_name,
                "actor": nested_get(event, "userIdentity", "arn"),
            }
        }
        if decision_id is not None:
            tool_call["invocation_context"]["decision_id"] = str(decision_id)
        if action_id:
            tool_call["action_id"] = action_id
        if tool_name:
            tool_call["tool_name"] = tool_name
        out["tool_call"] = tool_call
    return normalize_side_effect_artifacts(out)


def _cloudtrail_action_candidates(payload: Any, source: str) -> list[ActionCandidate]:
    candidates = []
    for record in _cloudtrail_records(payload):
        artifacts = _cloudtrail_artifacts(record)
        if not artifacts:
            continue
        action_id = first_present(
            get_path(artifacts, "tool_call.action_id"),
            get_path(artifacts, "parsed_actions.0.action_id"),
        )
        candidates.append(ActionCandidate(
            action_id=str(action_id) if action_id is not None else None,
            source=source,
            source_kind="cloudtrail",
            artifacts=artifacts,
        ))
    return candidates


def _otel_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if key in value:
            return value[key]
    if "value" in value:
        return _otel_value(value["value"])
    return value


def _otel_attributes(span: dict[str, Any]) -> dict[str, Any]:
    raw = span.get("attributes", {})
    if isinstance(raw, dict):
        return raw
    attrs: dict[str, Any] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            key = item.get("key")
            if isinstance(key, str) and key:
                attrs[key] = _otel_value(item.get("value"))
    return attrs


def _is_otel_action_span(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if not isinstance(payload.get("spanId") or payload.get("span_id"), str):
        return False
    attrs = _otel_attributes(payload)
    if any(key in attrs for key in ("tool.name", "gen_ai.tool.name", "function.name", "db.system", "http.method")):
        return True
    kind = str(payload.get("kind", "")).lower()
    if "client" in kind or "producer" in kind:
        return True
    name = str(payload.get("name", "")).lower()
    return any(token in name for token in ("tool", "function", "invoke", "deploy", "exec"))


def _otel_action_candidates(payload: Any, source: str) -> list[ActionCandidate]:
    if not _is_otel_action_span(payload):
        return []
    attrs = _otel_attributes(payload)
    action_id = first_present(
        attrs.get("tool.call_id"),
        attrs.get("gen_ai.tool.call.id"),
        attrs.get("action_id"),
        payload.get("spanId"),
        payload.get("span_id"),
    )
    tool_name = first_present(
        attrs.get("tool.name"),
        attrs.get("gen_ai.tool.name"),
        attrs.get("function.name"),
        payload.get("name"),
    )
    executed_at = normalize_timestamp(first_present(
        payload.get("startTimeUnixNano"),
        payload.get("start_time_unix_nano"),
        payload.get("startTime"),
        payload.get("start_time"),
        attrs.get("event.time"),
        attrs.get("timestamp"),
    ))
    decision_id = _decision_id_from_fields(attrs, payload)
    artifacts = {
        "parsed_actions": [
            {
                "action_id": str(action_id) if action_id is not None else "",
                "tool": str(tool_name) if tool_name is not None else "opentelemetry.action",
                "executed_at": executed_at,
                "source_kind": "opentelemetry_span",
            }
        ],
        "tool_call": {
            "action_id": str(action_id) if action_id is not None else "",
            "tool_name": str(tool_name) if tool_name is not None else "opentelemetry.action",
            "invocation_context": {
                "source": "opentelemetry",
                "trace_id": first_present(payload.get("traceId"), payload.get("trace_id")),
                "span_id": first_present(payload.get("spanId"), payload.get("span_id")),
                "approval_id": attrs.get("approval_id"),
                "decision_id": str(decision_id) if decision_id is not None else None,
            },
        },
    }
    return [ActionCandidate(
        action_id=str(action_id) if action_id is not None else None,
        source=source,
        source_kind="opentelemetry",
        artifacts=artifacts,
    )]


def _generic_event_action_candidates(payload: Any, source: str) -> list[ActionCandidate]:
    if not isinstance(payload, dict):
        return []
    kind = str(first_present(payload.get("type"), payload.get("event"), payload.get("event_type"), payload.get("kind"), "")).lower()
    if any(token in kind for token in ("result", "response", "output")):
        return []
    tool_name = first_present(payload.get("tool_name"), payload.get("tool"), payload.get("function_name"), payload.get("name"))
    action_id = first_present(payload.get("tool_call_id"), payload.get("call_id"), payload.get("action_id"), payload.get("id"))
    if "tool" not in kind and "function" not in kind and not (tool_name and action_id):
        return []
    executed_at = normalize_timestamp(first_present(
        payload.get("executed_at"),
        payload.get("timestamp"),
        payload.get("start_time"),
        payload.get("created_at"),
    ))
    decision_id = _decision_id_from_fields(payload)
    artifacts = {
        "parsed_actions": [
            {
                "action_id": str(action_id) if action_id is not None else "",
                "tool": str(tool_name) if tool_name is not None else "event_log.action",
                "executed_at": executed_at,
                "source_kind": "event_log",
            }
        ],
        "tool_call": {
            "action_id": str(action_id) if action_id is not None else "",
            "tool_name": str(tool_name) if tool_name is not None else "event_log.action",
            "approval_id": payload.get("approval_id"),
            "invocation_context": {
                "source": "event_log",
                "approval_id": payload.get("approval_id"),
                "decision_id": str(decision_id) if decision_id is not None else None,
            },
        },
    }
    return [ActionCandidate(
        action_id=str(action_id) if action_id is not None else None,
        source=source,
        source_kind="agent_event_log",
        artifacts=artifacts,
    )]


def _kubernetes_action_candidates(payload: Any, source: str) -> list[ActionCandidate]:
    if not isinstance(payload, dict):
        return []
    if not (payload.get("auditID") or payload.get("requestUID")):
        return []
    verb = str(payload.get("verb", "")).lower()
    if not verb:
        return []
    ref = payload.get("objectRef") if isinstance(payload.get("objectRef"), dict) else {}
    resource = first_present(ref.get("resource"), "resource")
    namespace = ref.get("namespace")
    name = ref.get("name")
    subresource = ref.get("subresource")
    resource_parts = [str(resource)]
    for part in (namespace, name, subresource):
        if part:
            resource_parts.append(str(part))
    tool_name = f"kubernetes.{verb}.{'/'.join(resource_parts)}"
    action_id = first_present(payload.get("auditID"), payload.get("requestUID"))
    decision_id = _decision_id_from_fields(
        payload,
        payload.get("annotations") if isinstance(payload.get("annotations"), dict) else {},
    )
    executed_at = normalize_timestamp(first_present(
        payload.get("requestReceivedTimestamp"),
        payload.get("stageTimestamp"),
        payload.get("timestamp"),
    ))
    artifacts = {
        "parsed_actions": [
            {
                "action_id": str(action_id),
                "tool": tool_name,
                "executed_at": executed_at,
                "source_kind": "kubernetes_audit",
            }
        ],
        "tool_call": {
            "action_id": str(action_id),
            "tool_name": tool_name,
            "invocation_context": {
                "source": "kubernetes_audit",
                "user": nested_get(payload, "user", "username"),
                "decision_id": str(decision_id) if decision_id is not None else None,
            },
        },
    }
    return [ActionCandidate(
        action_id=str(action_id),
        source=source,
        source_kind="kubernetes_audit",
        artifacts=artifacts,
    )]


def _siem_action_candidates(payload: Any, source: str) -> list[ActionCandidate]:
    if not isinstance(payload, dict):
        return []
    action_id = first_present(payload.get("event_id"), payload.get("id"), payload.get("uuid"), payload.get("request_id"))
    action = first_present(payload.get("action"), payload.get("operation"), payload.get("event.action"))
    resource = first_present(payload.get("resource"), payload.get("target"), payload.get("object"))
    if not (action_id and action and resource):
        return []
    tool_name = f"siem.{action}.{resource}"
    executed_at = normalize_timestamp(first_present(payload.get("timestamp"), payload.get("@timestamp"), payload.get("time")))
    decision_id = _decision_id_from_fields(payload)
    artifacts = {
        "parsed_actions": [
            {
                "action_id": str(action_id),
                "tool": tool_name,
                "executed_at": executed_at,
                "source_kind": "siem_event",
            }
        ],
        "tool_call": {
            "action_id": str(action_id),
            "tool_name": tool_name,
            "invocation_context": {
                "source": "siem_jsonl",
                "actor": first_present(payload.get("actor"), payload.get("user"), payload.get("principal")),
                "decision_id": str(decision_id) if decision_id is not None else None,
            },
        },
    }
    return [ActionCandidate(
        action_id=str(action_id),
        source=source,
        source_kind="siem_jsonl",
        artifacts=artifacts,
    )]


def _imported_action_candidates(payload: Any, source: str) -> list[ActionCandidate]:
    if not isinstance(payload, dict):
        return []
    side_effects = payload.get(SIDE_EFFECTS_KEY)
    if isinstance(side_effects, dict):
        side_effects = [side_effects]
    if isinstance(side_effects, list):
        candidates = []
        for idx, raw_side_effect in enumerate(side_effects):
            if not isinstance(raw_side_effect, dict):
                continue
            side_effect = normalize_side_effect(raw_side_effect)
            artifacts = {SIDE_EFFECTS_KEY: [side_effect], **legacy_artifacts_from_side_effect(side_effect)}
            action_id = get_path(artifacts, SIDE_EFFECT_ACTION_ID_PATH)
            candidates.append(ActionCandidate(
                action_id=str(action_id) if action_id is not None else f"side_effect_{idx}",
                source=source,
                source_kind=str(side_effect.get("source_kind") or "side_effect_envelope"),
                artifacts=artifacts,
            ))
        if candidates:
            return candidates

    parsed_actions = payload.get("parsed_actions")
    if isinstance(parsed_actions, dict):
        parsed_actions = [parsed_actions]
    if not isinstance(parsed_actions, list):
        return []

    candidates = []
    tool_call = payload.get("tool_call") if isinstance(payload.get("tool_call"), dict) else {}
    for idx, action in enumerate(parsed_actions):
        if not isinstance(action, dict):
            continue
        action_id = first_present(action.get("action_id"), tool_call.get("action_id"))
        tool_name = first_present(action.get("tool"), tool_call.get("tool_name"))
        per_action_tool_call = dict(tool_call)
        if action_id is not None:
            per_action_tool_call["action_id"] = str(action_id)
        if tool_name is not None:
            per_action_tool_call["tool_name"] = str(tool_name)
        artifacts = {
            "parsed_actions": [action],
            "tool_call": per_action_tool_call,
        }
        candidates.append(ActionCandidate(
            action_id=str(action_id) if action_id is not None else f"parsed_action_{idx}",
            source=source,
            source_kind=str(action.get("source_kind") or "imported_artifact"),
            artifacts=artifacts,
        ))
    return candidates


def _payload_action_candidates(payload: Any, source: str) -> list[ActionCandidate]:
    candidates: list[ActionCandidate] = []
    for extractor in (
        _cloudtrail_action_candidates,
        _otel_action_candidates,
        _generic_event_action_candidates,
        _kubernetes_action_candidates,
        _siem_action_candidates,
        _imported_action_candidates,
    ):
        candidates.extend(extractor(payload, source))

    deduped = []
    seen = set()
    for candidate in candidates:
        candidate.artifacts = normalize_side_effect_artifacts(candidate.artifacts)
        if candidate.action_id is None:
            action_id = get_path(candidate.artifacts, SIDE_EFFECT_ACTION_ID_PATH)
            if action_id is not None:
                candidate.action_id = str(action_id)
        marker = (candidate.source, candidate.action_id, candidate.source_kind)
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(candidate)
    return deduped


def _payload_to_approval(payload: dict[str, Any]) -> dict[str, Any]:
    has_explicit_approval_shape = (
        isinstance(payload.get("approval"), dict)
        or any(key in payload for key in ("approval_id", "approved_at", "approval_decision", "approval_approved_at", "approver", "tool_call_id"))
    )
    if not has_explicit_approval_shape:
        return {}
    raw = payload.get("approval") if isinstance(payload.get("approval"), dict) else payload
    approval = {}
    for dest, keys in {
        "approval_id": ("approval_id", "decision_id"),
        "tool_call_id": ("tool_call_id", "action_id"),
        "approved_at": ("approved_at", "approval_approved_at"),
        "decision": ("decision", "approval_decision"),
        "actor": ("actor", "approver"),
    }.items():
        value = first_present(*(raw.get(key) for key in keys))
        if value is not None:
            approval[dest] = value
    return {"approval": approval} if approval and any(key in approval for key in ("approval_id", "approved_at", "decision")) else {}


def _approval_records_from_payload(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    records = []
    for key in ("approval", "approvals"):
        raw = payload.get(key)
        if isinstance(raw, dict):
            records.append(raw)
        elif isinstance(raw, list):
            records.extend(item for item in raw if isinstance(item, dict))
    flat = _payload_to_approval(payload)
    if isinstance(flat.get("approval"), dict):
        records.append(flat["approval"])

    unique = []
    seen = set()
    for record in records:
        marker = json.dumps(record, sort_keys=True)
        if marker not in seen:
            unique.append(record)
            seen.add(marker)
    return unique


def _payload_artifacts(
    payload: Any,
    conflicts: list[EvidenceConflict] | None = None,
    source_label: str = "",
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    out: dict[str, Any] = {}
    _merge_artifacts(out, _payload_authorization(payload), conflicts, source_label)
    for key in (SIDE_EFFECTS_KEY, "parsed_actions", "tool_call", "deployment", "review", "approval"):
        if key in payload:
            _merge_artifacts(out, {key: payload[key]}, conflicts, source_label)
    _merge_artifacts(out, _cloudtrail_artifacts(payload), conflicts, source_label)
    _merge_artifacts(out, _payload_to_deployment(payload), conflicts, source_label)
    review = _payload_review(payload)
    if review:
        _merge_artifacts(out, {"review": review}, conflicts, source_label)
    _merge_artifacts(out, _payload_to_approval(payload), conflicts, source_label)
    return normalize_side_effect_artifacts(out)


def _payload_kinds(payload: Any) -> list[str]:
    kinds: list[str] = []
    if _cloudtrail_records(payload):
        _append_unique(kinds, "CloudTrail")
    if _is_otel_action_span(payload):
        _append_unique(kinds, "OpenTelemetry")
    if isinstance(payload, dict):
        if payload.get("apiVersion") == "audit.k8s.io/v1" or payload.get("kind") == "Event" and payload.get("auditID"):
            _append_unique(kinds, "Kubernetes audit")
        if payload.get("workflow_run") or payload.get("deployment"):
            _append_unique(kinds, "GitHub/deployment")
        if first_present(payload.get("event_id"), payload.get("uuid"), payload.get("request_id")) and payload.get("action"):
            _append_unique(kinds, "SIEM JSONL")
        if first_present(payload.get("type"), payload.get("event"), payload.get("event_type")):
            _append_unique(kinds, "agent event log")
        if any(key in payload for key in ("approval", "approvals")):
            _append_unique(kinds, "approval evidence")
        if any(key in payload for key in ("authorization", SIDE_EFFECTS_KEY, "parsed_actions", "tool_call", "review")):
            _append_unique(kinds, "Ashiba/evidence artifact")
    if not kinds:
        _append_unique(kinds, "unrecognized JSON")
    return kinds


def _payload_record_count(payload: Any) -> int:
    if isinstance(payload, dict):
        for key in ("Records", "events", "items", "spans"):
            raw = payload.get(key)
            if isinstance(raw, list):
                return len(raw)
    if isinstance(payload, list):
        return len(payload)
    return 1


def _payload_evidence_labels(payload: Any) -> list[str]:
    labels: list[str] = []
    artifacts = _payload_artifacts(payload)
    for key in ("authorization", SIDE_EFFECTS_KEY, "parsed_actions", "tool_call", "deployment", "review", "approval"):
        if key in artifacts:
            _append_unique(labels, key)
    if _approval_records_from_payload(payload):
        _append_unique(labels, "approval")
    return labels


def _file_observation(path: Path, payloads: list[Any], actions: list[ActionCandidate]) -> FileObservation:
    kinds: list[str] = []
    evidence: list[str] = []
    records = 0
    for payload in payloads:
        records += _payload_record_count(payload)
        for kind in _payload_kinds(payload):
            _append_unique(kinds, kind)
        for label in _payload_evidence_labels(payload):
            _append_unique(evidence, label)
    return FileObservation(
        path=str(path),
        kinds=kinds,
        records=records,
        actions=len(actions),
        evidence=evidence,
    )


def collect_scan_context(logs: Path, policy_path: Path | None = None) -> ScanContext:
    artifacts: dict[str, Any] = {}
    warnings: list[str] = []
    conflicts: list[EvidenceConflict] = []
    files_scanned: list[str] = []
    actions: list[ActionCandidate] = []
    approvals: list[dict[str, Any]] = []
    observations: list[FileObservation] = []

    policy = None
    if policy_path is not None:
        policy = _load_json_file(policy_path, "policy")
        if not isinstance(policy, dict):
            raise ValueError("policy JSON root must be an object")
        _merge_artifacts(artifacts, _authorization_from_policy(policy), conflicts, str(policy_path))
        _merge_artifacts(artifacts, _review_from_policy(policy), conflicts, str(policy_path))
        _merge_artifacts(artifacts, _approval_from_policy(policy), conflicts, str(policy_path))
        approvals.extend(_approval_records_from_payload(policy))
        observations.append(FileObservation(
            path=str(policy_path),
            kinds=["policy"],
            records=1,
            actions=0,
            evidence=sorted(_authorization_from_policy(policy).keys() | _review_from_policy(policy).keys() | _approval_from_policy(policy).keys()),
        ))

    candidates = _candidate_files(logs)
    if not candidates:
        warnings.append(f"no candidate log files found in {logs}")

    for path in candidates:
        try:
            payloads = _payloads_from_file(path)
        except (OSError, UnicodeDecodeError) as exc:
            warnings.append(f"skipped unreadable file {path}: {exc}")
            continue
        if not payloads:
            if path.suffix.lower() in {".json", ".jsonl"}:
                warnings.append(f"skipped invalid or unrecognized JSON file {path}")
            else:
                warnings.append(f"skipped unrecognized file {path}")
            continue
        files_scanned.append(str(path))
        file_actions: list[ActionCandidate] = []
        for payload in payloads:
            _merge_artifacts(
                artifacts,
                _payload_artifacts(payload, conflicts, str(path)),
                conflicts,
                str(path),
            )
            payload_actions = _payload_action_candidates(payload, str(path))
            file_actions.extend(payload_actions)
            actions.extend(payload_actions)
            approvals.extend(_approval_records_from_payload(payload))
        observations.append(_file_observation(path, payloads, file_actions))
    return ScanContext(
        artifacts=artifacts,
        files_scanned=files_scanned,
        warnings=warnings,
        conflicts=conflicts,
        actions=actions,
        approvals=approvals,
        observations=observations,
    )


def collect_scan_artifacts(logs: Path, policy_path: Path | None = None) -> tuple[dict[str, Any], list[str], list[str]]:
    context = collect_scan_context(logs, policy_path)
    return context.artifacts, context.files_scanned, context.warnings


def _probeable_next(cannot_decide: list[ClaimReadiness]) -> list[str]:
    probeable_next = []
    for item in cannot_decide:
        for missing in item.missing:
            probe = PROBE_BY_MISSING.get(missing)
            if probe and probe not in probeable_next:
                probeable_next.append(probe)
    return probeable_next


def _punch_list(cannot_decide: list[ClaimReadiness], actions: list[ActionReadiness]) -> list[str]:
    # Every punch-list item is an UNKNOWN made useful: one missing field, one
    # proposed probe, one fewer place for operational truth to hide next time.
    counts: dict[str, int] = {}
    for item in cannot_decide:
        for missing in item.missing:
            probe = PROBE_BY_MISSING.get(missing)
            if probe:
                counts.setdefault(probe, 0)
    for action in actions:
        for item in action.cannot_decide:
            for missing in item.missing:
                probe = PROBE_BY_MISSING.get(missing)
                if probe:
                    counts[probe] = counts.get(probe, 0) + 1

    out = []
    for probe in PROBE_BY_MISSING.values():
        if probe not in counts:
            continue
        blocked = counts[probe]
        if blocked > 0:
            out.append(f"{probe} ({blocked} action{'s' if blocked != 1 else ''} blocked)")
        else:
            out.append(probe)
    return out


def _action_base_artifacts(artifacts: dict[str, Any]) -> dict[str, Any]:
    base = deepcopy(artifacts)
    for action_specific_key in (SIDE_EFFECTS_KEY, "parsed_actions", "tool_call", "approval"):
        base.pop(action_specific_key, None)
    return base


def _match_approval_for_action(action: ActionCandidate, approvals: list[dict[str, Any]]) -> dict[str, Any] | None:
    action_id = first_present(
        get_path(action.artifacts, SIDE_EFFECT_ACTION_ID_PATH),
        get_path(action.artifacts, "tool_call.action_id"),
    )
    action_approval_id = first_present(
        get_path(action.artifacts, "side_effects.0.invocation.approval_id"),
        get_path(action.artifacts, SIDE_EFFECT_DECISION_ID_PATH),
        get_path(action.artifacts, "tool_call.approval_id"),
        get_path(action.artifacts, "tool_call.invocation_context.approval_id"),
        get_path(action.artifacts, "tool_call.invocation_context.decision_id"),
    )
    for approval in approvals:
        approval_tool_call_id = approval.get("tool_call_id")
        if action_id and approval_tool_call_id and str(action_id) == str(approval_tool_call_id):
            return approval
        approval_id = first_present(approval.get("approval_id"), approval.get("decision_id"))
        if action_approval_id and approval_id and str(action_approval_id) == str(approval_id):
            return approval
    return None


ACTION_SPECIFIC_CONFLICT_PREFIXES = (SIDE_EFFECTS_KEY, "parsed_actions", "tool_call", "approval")


def _action_readiness(
    context: ScanContext,
    registry: dict[str, Any],
    inferred_claims: list[str] | None = None,
) -> list[ActionReadiness]:
    action_claims = [
        claim
        for claim in (inferred_claims or ALL_SCAN_CLAIMS)
        if claim in registry and claim_has_action_scope(registry[claim])
    ]
    base = _action_base_artifacts(context.artifacts)
    rows = []
    for action in context.actions:
        artifacts = deepcopy(base)
        action_conflicts = [
            conflict
            for conflict in context.conflicts
            if not conflict_excluded(conflict, ACTION_SPECIFIC_CONFLICT_PREFIXES)
        ]
        _merge_artifacts(artifacts, normalize_side_effect_artifacts(action.artifacts), action_conflicts, action.source)
        approval = _match_approval_for_action(action, context.approvals)
        if approval is not None:
            _merge_artifacts(artifacts, {"approval": approval}, action_conflicts, action.source)

        readiness: list[ClaimReadiness] = []
        for claim in action_claims:
            missing = claim_missing(artifacts, registry[claim])
            conflicts = claim_conflicts(registry[claim], action_conflicts)
            readiness.append(ClaimReadiness(
                claim=claim,
                can_decide=not missing and not conflicts,
                missing=missing,
                conflicts=conflicts,
            ))
        can_decide = [item.claim for item in readiness if item.can_decide]
        cannot_decide = [item for item in readiness if not item.can_decide]
        rows.append(ActionReadiness(
            action_id=action.action_id,
            source=action.source,
            source_kind=action.source_kind,
            tool=first_present(
                get_path(action.artifacts, "side_effects.0.tool"),
                get_path(action.artifacts, "parsed_actions.0.tool"),
                get_path(action.artifacts, "tool_call.tool_name"),
            ),
            executed_at=first_present(
                get_path(action.artifacts, SIDE_EFFECT_EXECUTED_AT_PATH),
                get_path(action.artifacts, "parsed_actions.0.executed_at"),
            ),
            decidable=not cannot_decide,
            can_decide=can_decide,
            cannot_decide=cannot_decide,
            probeable_next=_probeable_next(cannot_decide),
        ))
    return rows


def _claim_readiness_from_action_rows(claim: str, action_rows: list[ActionReadiness]) -> ClaimReadiness | None:
    rows = [
        row
        for row in action_rows
        if claim in row.can_decide or any(item.claim == claim for item in row.cannot_decide)
    ]
    if not rows:
        return None

    missing: list[str] = []
    conflicts: list[str] = []
    for row in rows:
        for item in row.cannot_decide:
            if item.claim != claim:
                continue
            for path in item.missing:
                if path not in missing:
                    missing.append(path)
            for path in item.conflicts:
                if path not in conflicts:
                    conflicts.append(path)

    return ClaimReadiness(
        claim=claim,
        can_decide=all(claim in row.can_decide for row in rows),
        missing=missing,
        conflicts=sorted(conflicts),
    )


def _infer_claims(context: ScanContext) -> list[str]:
    present_keys = set(context.artifacts.keys())
    if context.approvals:
        present_keys.add("approval")
    for action in context.actions:
        present_keys.update(action.artifacts.keys())
    claims = []
    for claim in ALL_SCAN_CLAIMS:
        triggers = CLAIM_EVIDENCE_TRIGGERS.get(claim, [])
        if any(t in present_keys for t in triggers):
            claims.append(claim)
    return claims


def scan_readiness(logs: Path, policy_path: Path | None = None) -> ScanResult:
    context = collect_scan_context(logs, policy_path)
    artifacts = context.artifacts
    registry = build_claim_registry()
    inferred = _infer_claims(context)
    action_rows = _action_readiness(context, registry, inferred)
    readiness: list[ClaimReadiness] = []
    for claim in inferred:
        if claim_has_action_scope(registry[claim]):
            action_readiness = _claim_readiness_from_action_rows(claim, action_rows)
            if action_readiness is not None:
                readiness.append(action_readiness)
                continue
        missing = claim_missing(artifacts, registry[claim])
        conflicts = claim_conflicts(registry[claim], context.conflicts)
        readiness.append(ClaimReadiness(
            claim=claim,
            can_decide=not missing and not conflicts,
            missing=missing,
            conflicts=conflicts,
        ))

    can_decide = [item.claim for item in readiness if item.can_decide]
    cannot_decide = [item for item in readiness if not item.can_decide]
    return ScanResult(
        input_status="ok" if context.files_scanned else "no_parseable_inputs",
        files_scanned=context.files_scanned,
        can_decide=can_decide,
        cannot_decide=cannot_decide,
        probeable_next=_probeable_next(cannot_decide),
        warnings=context.warnings,
        conflicts=context.conflicts,
        actions=action_rows,
        observations=context.observations,
        punch_list=_punch_list(cannot_decide, action_rows),
    )


def _missing_counts(result: ScanResult) -> list[tuple[str, int, str | None]]:
    counts: dict[str, int] = {}
    for item in result.cannot_decide:
        for missing in item.missing:
            counts.setdefault(missing, 0)
    for action in result.actions:
        seen_for_action = set()
        for item in action.cannot_decide:
            for missing in item.missing:
                if missing in seen_for_action:
                    continue
                seen_for_action.add(missing)
                counts[missing] = counts.get(missing, 0) + 1
    ranked = [
        (missing, count, PROBE_BY_MISSING.get(missing))
        for missing, count in counts.items()
    ]
    ranked.sort(key=lambda item: (-item[1], item[0]))
    return ranked


def format_scan_text(result: ScanResult) -> str:
    actions_decidable = sum(1 for action in result.actions if action.decidable)
    actions_blocked = len(result.actions) - actions_decidable
    missing_counts = _missing_counts(result)
    lines = [
        "Ashiba scan",
        "",
        "Summary:",
        f"- Files scanned: {len(result.files_scanned)}",
        f"- Side-effect actions found: {len(result.actions)}",
        f"- Receipt-ready actions: {actions_decidable}",
        f"- Blocked actions: {actions_blocked}",
    ]
    if result.input_status != "ok":
        lines.append(f"- input status: {result.input_status}")
        lines.append("- problem: no usable log files were parsed")
    lines.append(f"- Claim families ready: {', '.join(result.can_decide) if result.can_decide else 'none'}")
    lines.append(
        "- Claim families blocked: "
        + (
            ", ".join(item.claim for item in result.cannot_decide)
            if result.cannot_decide
            else "none"
        )
    )

    lines.extend(["", "Detected evidence:"])
    if not result.observations:
        lines.append("- none")
    for observation in result.observations:
        if observation.kinds == ["policy"]:
            lines.append(f"- policy evidence: {', '.join(observation.evidence) if observation.evidence else 'present'}")
            continue
        kind_text = ", ".join(observation.kinds)
        evidence_text = f"; evidence: {', '.join(observation.evidence)}" if observation.evidence else ""
        lines.append(f"- {kind_text}: {observation.records} record{'s' if observation.records != 1 else ''}, {observation.actions} action{'s' if observation.actions != 1 else ''}{evidence_text}")

    lines.extend([
        "",
        "Action groups:",
    ])
    if result.actions:
        lines.append(f"- {actions_decidable} receipt-ready, {actions_blocked} blocked")
        for action in result.actions:
            label = action.action_id or "(missing action_id)"
            tool = f" {action.tool}" if action.tool else ""
            if action.decidable:
                lines.append(f"  - READY {label}{tool}")
            else:
                missing = []
                conflicts = []
                for item in action.cannot_decide:
                    missing.extend(item.missing)
                    conflicts.extend(item.conflicts)
                problems = []
                if missing:
                    problems.append(f"missing {', '.join(missing)}")
                if conflicts:
                    problems.append(f"conflicting {', '.join(sorted(set(conflicts)))}")
                lines.append(f"  - BLOCKED {label}{tool}: {'; '.join(problems)}")
    else:
        lines.append("- no side-effect actions recognized")

    if result.conflicts:
        lines.extend(["", "Evidence conflicts:"])
        for conflict in result.conflicts:
            source = f" from {conflict.source}" if conflict.source else ""
            lines.append(
                f"- {conflict.path}: {conflict.existing!r} vs {conflict.incoming!r}{source}"
            )

    lines.extend(["", "Top missing evidence:"])
    if missing_counts:
        for missing, count, probe in missing_counts:
            scope = (
                f"{count} action{'s' if count != 1 else ''} blocked"
                if count
                else "global claim gap"
            )
            probe_text = f" -> {probe}" if probe else ""
            lines.append(f"- {missing}: {scope}{probe_text}")
    else:
        lines.append("- (none)")

    lines.extend(["", "Punch list:"])
    if result.punch_list:
        lines.extend(f"- {item}" for item in result.punch_list)
    else:
        lines.append("- no missing probes detected for current claim set")

    lines.extend([
        "",
        "Boundary:",
        "- This is a readiness scan, not a receipt verdict.",
        "- Missing evidence means unknown, not contradicted.",
    ])
    if result.conflicts:
        lines.append("- Conflicting evidence blocks readiness until the source logs are reconciled.")

    if result.warnings:
        lines.extend(["", "Warnings:"])
        lines.extend(f"- {warning}" for warning in result.warnings)
    return "\n".join(lines)


def _missing_groups(result: ScanResult) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}

    def ensure(path: str) -> dict[str, Any]:
        group = groups.setdefault(path, {
            "missing": path,
            "probe": PROBE_BY_MISSING.get(path),
            "why": WHY_BY_MISSING.get(path, "This missing evidence prevents at least one claim from being decidable."),
            "suggested_log_shape": SUGGESTED_FIELDS_BY_MISSING.get(path),
            "claims": [],
            "affected_actions": [],
            "action_count": 0,
        })
        return group

    for item in result.cannot_decide:
        for missing in item.missing:
            group = ensure(missing)
            if item.claim not in group["claims"]:
                group["claims"].append(item.claim)

    for action in result.actions:
        action_label = action.action_id or "(missing action_id)"
        for item in action.cannot_decide:
            for missing in item.missing:
                group = ensure(missing)
                if item.claim not in group["claims"]:
                    group["claims"].append(item.claim)
                if action_label not in group["affected_actions"]:
                    group["affected_actions"].append(action_label)

    out = []
    for missing in sorted(groups):
        group = groups[missing]
        group["claims"] = sorted(group["claims"])
        group["affected_actions"] = sorted(group["affected_actions"])
        group["action_count"] = len(group["affected_actions"])
        out.append(group)
    out.sort(key=lambda item: (-item["action_count"], item["missing"]))
    return out


def build_scan_report(result: ScanResult) -> dict[str, Any]:
    report = {
        "schema_version": "ashiba-scan-report-v0.1",
        "summary": result.as_dict()["summary"],
        "can_decide": result.can_decide,
        "cannot_decide": [item.as_dict() for item in result.cannot_decide],
        "detected_inputs": [observation.as_dict() for observation in result.observations],
        "missing_evidence": _missing_groups(result),
        "evidence_conflicts": [conflict.as_dict() for conflict in result.conflicts],
        "punch_list": result.punch_list,
        "warnings": result.warnings,
        "actions": [action.as_dict() for action in result.actions],
    }
    return report


def _json_block(value: Any) -> list[str]:
    return ["```json", json.dumps(value, indent=2, sort_keys=True), "```"]


def format_scan_report_markdown(result: ScanResult) -> str:
    report = build_scan_report(result)
    summary = report["summary"]
    lines = [
        "# Ashiba Evidence Readiness Report",
        "",
        "## Summary",
        "",
        f"- Input status: `{summary['input_status']}`",
        f"- Files scanned: {summary['files_scanned']}",
        f"- Side-effect actions found: {summary['actions_found']}",
        f"- Actions receipt-ready: {summary['actions_decidable']}",
        f"- Actions blocked: {summary['actions_blocked']}",
        f"- Claim families ready: {summary['claims_decidable']}",
        f"- Claim families blocked: {summary['claims_blocked']}",
        "",
        "## Detected Inputs",
        "",
    ]

    if report["detected_inputs"]:
        lines.extend([
            "| Source | Kinds | Records | Actions | Evidence |",
            "| --- | --- | ---: | ---: | --- |",
        ])
        for item in report["detected_inputs"]:
            lines.append(
                f"| `{item['path']}` | {', '.join(item['kinds']) or '-'} | "
                f"{item['records']} | {item['actions']} | {', '.join(item['evidence']) or '-'} |"
            )
    else:
        lines.append("- No parseable inputs detected.")

    lines.extend(["", "## Claim Readiness", ""])
    if result.can_decide:
        lines.append("Receipt-ready claim families:")
        lines.extend(f"- `{claim}`" for claim in result.can_decide)
    else:
        lines.append("Receipt-ready claim families: none")

    if result.cannot_decide:
        lines.extend(["", "Blocked claim families:"])
        for item in result.cannot_decide:
            missing = ", ".join(f"`{path}`" for path in item.missing)
            lines.append(f"- `{item.claim}` missing {missing}")
    else:
        lines.extend(["", "Blocked claim families: none"])

    lines.extend(["", "## Missing Evidence Punch List", ""])
    if report["missing_evidence"]:
        for group in report["missing_evidence"]:
            action_text = (
                f"{group['action_count']} affected action"
                f"{'s' if group['action_count'] != 1 else ''}"
                if group["action_count"]
                else "global claim gap"
            )
            lines.extend([
                f"### `{group['missing']}`",
                "",
                f"- Next probe: {group['probe'] or 'no automatic probe suggestion yet'}",
                f"- Why it matters: {group['why']}",
                f"- Scope: {action_text}",
                f"- Affected claims: {', '.join(f'`{claim}`' for claim in group['claims']) or '-'}",
            ])
            if group["affected_actions"]:
                preview = ", ".join(f"`{action}`" for action in group["affected_actions"][:10])
                extra = len(group["affected_actions"]) - 10
                if extra > 0:
                    preview += f", ... (+{extra} more)"
                lines.append(f"- Example affected actions: {preview}")
            if group["suggested_log_shape"] is not None:
                lines.extend(["", "Suggested log shape:"])
                lines.extend(_json_block(group["suggested_log_shape"]))
            lines.append("")
    else:
        lines.append("- No missing evidence detected for the inferred claim set.")

    if report["evidence_conflicts"]:
        lines.extend(["", "## Evidence Conflicts", ""])
        lines.extend([
            "| Path | Existing | Incoming | Source |",
            "| --- | --- | --- | --- |",
        ])
        for conflict in report["evidence_conflicts"]:
            lines.append(
                f"| `{conflict['path']}` | `{conflict['existing']}` | "
                f"`{conflict['incoming']}` | `{conflict['source'] or '-'}` |"
            )

    lines.extend(["## Action Readiness", ""])
    if result.actions:
        lines.extend([
            "| Action | Tool | Source kind | Status | Missing evidence | Conflicts |",
            "| --- | --- | --- | --- | --- | --- |",
        ])
        for action in result.actions:
            missing_paths = []
            conflict_paths = []
            for item in action.cannot_decide:
                missing_paths.extend(item.missing)
                conflict_paths.extend(item.conflicts)
            status = "receipt-ready" if action.decidable else "blocked"
            lines.append(
                f"| `{action.action_id or '(missing action_id)'}` | "
                f"{action.tool or '-'} | {action.source_kind} | {status} | "
                f"{', '.join(f'`{path}`' for path in missing_paths) or '-'} | "
                f"{', '.join(f'`{path}`' for path in sorted(set(conflict_paths))) or '-'} |"
            )
    else:
        lines.append("- No side-effect actions recognized.")

    if result.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in result.warnings)

    lines.extend([
        "",
        "## Boundary",
        "",
        "- This report is a readiness scan, not a receipt verdict.",
        "- Missing evidence means `unknown`, not `contradicted`.",
        "- Conflicting evidence blocks readiness until the source logs are reconciled.",
        "- The report does not prove model intent, safety, custody, authenticity, or general system reliability.",
        "",
    ])
    return "\n".join(lines)


def write_scan_report(result: ScanResult, out_dir: Path) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = out_dir / "ashiba_report.md"
    json_path = out_dir / "ashiba_report.json"
    markdown_path.write_text(format_scan_report_markdown(result), encoding="utf-8")
    json_path.write_text(json.dumps(build_scan_report(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"markdown": str(markdown_path), "json": str(json_path)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", type=Path, help="Log file or directory to scan")
    parser.add_argument("--policy", "-p", type=Path, help="Optional policy/review/approval JSON")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable readiness output")
    parser.add_argument("--report", action="store_true", help="Write ashiba_report.md and ashiba_report.json")
    parser.add_argument("--out", type=Path, default=Path("."), help="Output directory for --report")
    args = parser.parse_args(argv)

    try:
        result = scan_readiness(args.logs, args.policy)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    report_paths = None
    if args.report:
        try:
            report_paths = write_scan_report(result, args.out)
        except OSError as exc:
            print(f"ERROR: could not write scan report: {exc}", file=sys.stderr)
            return 1

    if args.json:
        payload = result.as_dict()
        if report_paths is not None:
            payload["report_paths"] = report_paths
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(format_scan_text(result))
        if report_paths is not None:
            print()
            print("Report written:")
            print(f"- {report_paths['markdown']}")
            print(f"- {report_paths['json']}")
    return 1 if result.input_status == "no_parseable_inputs" else 0


if __name__ == "__main__":
    raise SystemExit(main())
