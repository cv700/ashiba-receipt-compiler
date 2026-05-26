#!/usr/bin/env python3
"""Reference boundary probe for authorization-bound side effects.

This is intentionally small and boring: it demonstrates the runtime evidence a
tool boundary should emit before an external side effect executes.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


GRANT_HASH_FIELDS = (
    "grant_id",
    "principal",
    "delegated_to",
    "scope",
    "grant_valid_from",
    "grant_valid_until",
    "issuer",
)


def die(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path, label: str) -> Any:
    if not path.is_file():
        die(f"{label} file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        die(f"invalid JSON in {label}: {exc}")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        die(f"missing {label}")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        die(f"{label} must be ISO 8601: {value}")
    if parsed.tzinfo is None:
        die(f"{label} must include timezone: {value}")
    return parsed.astimezone(timezone.utc)


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def cloudtrail_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("Records"), list):
        records = [record for record in payload["Records"] if isinstance(record, dict)]
    elif isinstance(payload, dict) and "eventSource" in payload and "eventName" in payload:
        records = [payload]
    else:
        records = []
    if not records:
        die("cloudtrail input must contain a CloudTrail record or Records array")
    return records


def select_record(records: list[dict[str, Any]], action_id: str | None) -> dict[str, Any]:
    if action_id is None:
        return records[0]
    for record in records:
        if action_id in {record.get("eventID"), record.get("eventId"), record.get("requestID")}:
            return record
    die(f"no CloudTrail record matched action id {action_id}")


def grant_hash(policy: dict[str, Any]) -> str:
    grant_material = {key: policy.get(key) for key in GRANT_HASH_FIELDS if key in policy}
    raw = json.dumps(grant_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def decision_id_for(record: dict[str, Any], override: str | None) -> str:
    if override:
        return override
    action_id = record.get("eventID") or record.get("eventId") or record.get("requestID")
    if action_id:
        return f"authz-decision-{action_id}"
    return "authz-decision-reference-probe"


def grant_active(policy: dict[str, Any], executed_at: datetime, revoked_at: str | None) -> bool:
    valid_from = parse_utc(policy.get("grant_valid_from"), "policy.grant_valid_from")
    valid_until = parse_utc(policy.get("grant_valid_until"), "policy.grant_valid_until")
    if not (valid_from <= executed_at <= valid_until):
        return False
    if revoked_at:
        return parse_utc(revoked_at, "revoked_at") > executed_at
    return True


def normalize_revoked_at(raw: str | None) -> str | None:
    if raw is None or raw.lower() in {"", "null", "none"}:
        return None
    return format_utc(parse_utc(raw, "revoked_at"))


def build_probe_packet(
    policy: dict[str, Any],
    cloudtrail: dict[str, Any],
    action_id: str | None,
    decision_id: str | None,
    revoked_at: str | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    records = cloudtrail_records(cloudtrail)
    selected = select_record(records, action_id)
    executed_at = parse_utc(selected.get("eventTime"), "CloudTrail eventTime")
    normalized_revoked_at = normalize_revoked_at(revoked_at)
    runtime_decision_id = decision_id_for(selected, decision_id)

    emitted_policy = deepcopy(policy)
    emitted_policy["revoked_at"] = normalized_revoked_at
    emitted_policy["render_time_grant_hash"] = grant_hash(policy)
    emitted_policy["execution_time_decision_id"] = runtime_decision_id
    emitted_policy["grant_active_at_execution"] = grant_active(
        policy,
        executed_at,
        normalized_revoked_at,
    )

    emitted_cloudtrail = deepcopy(cloudtrail)
    emitted_records = cloudtrail_records(emitted_cloudtrail)
    emitted_selected = select_record(emitted_records, action_id)
    request_parameters = emitted_selected.setdefault("requestParameters", {})
    if not isinstance(request_parameters, dict):
        die("CloudTrail requestParameters must be an object when present")
    request_parameters["decision_id"] = runtime_decision_id

    actual_action_id = (
        emitted_selected.get("eventID")
        or emitted_selected.get("eventId")
        or emitted_selected.get("requestID")
        or action_id
        or "action-reference-probe"
    )
    event_source = emitted_selected.get("eventSource")
    event_name = emitted_selected.get("eventName")
    tool_name = f"{event_source}:{event_name}" if event_source and event_name else "cloudtrail.action"
    parameters = {key: value for key, value in request_parameters.items() if key != "decision_id"}

    artifacts = {
        "authorization": {
            "authorization": {
                "grant_id": emitted_policy.get("grant_id"),
                "principal": emitted_policy.get("principal"),
                "delegated_to": emitted_policy.get("delegated_to"),
                "scope": emitted_policy.get("scope"),
                "grant_valid_from": emitted_policy.get("grant_valid_from"),
                "grant_valid_until": emitted_policy.get("grant_valid_until"),
                "revoked_at": emitted_policy.get("revoked_at"),
                "render_time_grant_hash": emitted_policy.get("render_time_grant_hash"),
                "execution_time_decision_id": emitted_policy.get("execution_time_decision_id"),
                "grant_active_at_execution": emitted_policy.get("grant_active_at_execution"),
            }
        },
        "tool_call": {
            "tool_call": {
                "action_id": actual_action_id,
                "tool_name": tool_name,
                "tool_version": "aws-cloudtrail",
                "invocation_context": {
                    "source": "authorization_boundary_probe",
                    "decision_id": runtime_decision_id,
                    "event_source": event_source,
                    "event_name": event_name,
                },
            }
        },
        "parsed_actions": {
            "parsed_actions": [
                {
                    "action_id": actual_action_id,
                    "tool": tool_name,
                    "executed_at": format_utc(executed_at),
                    "source_kind": "cloudtrail_event",
                    "parameters": parameters,
                }
            ]
        },
    }
    return emitted_policy, emitted_cloudtrail, artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit reference authorization-boundary probe evidence.")
    parser.add_argument("--policy", required=True, type=Path, help="Input grant/policy JSON.")
    parser.add_argument("--cloudtrail", required=True, type=Path, help="Input CloudTrail JSON.")
    parser.add_argument("--out", required=True, type=Path, help="Output packet directory.")
    parser.add_argument("--action-id", help="Optional CloudTrail eventID/requestID to bind.")
    parser.add_argument("--decision-id", help="Optional authorization decision id to emit.")
    parser.add_argument(
        "--revoked-at",
        default="null",
        help="Revocation timestamp, or null/none for explicitly checked non-revocation.",
    )
    args = parser.parse_args()

    policy = load_json(args.policy, "policy")
    cloudtrail = load_json(args.cloudtrail, "cloudtrail")
    if not isinstance(policy, dict):
        die("policy root must be a JSON object")
    if not isinstance(cloudtrail, dict):
        die("cloudtrail root must be a JSON object")

    emitted_policy, emitted_cloudtrail, artifacts = build_probe_packet(
        policy=policy,
        cloudtrail=cloudtrail,
        action_id=args.action_id,
        decision_id=args.decision_id,
        revoked_at=args.revoked_at,
    )

    write_json(args.out / "policy.json", emitted_policy)
    write_json(args.out / "logs" / "cloudtrail_lambda_invoke.json", emitted_cloudtrail)
    for name, artifact in artifacts.items():
        write_json(args.out / "artifacts" / f"{name}.json", artifact)

    action = artifacts["parsed_actions"]["parsed_actions"][0]
    authorization = artifacts["authorization"]["authorization"]
    print("Authorization boundary probe emitted boundary evidence")
    print(f"- output: {args.out}")
    print(f"- action_id: {action['action_id']}")
    print(f"- decision_id: {authorization['execution_time_decision_id']}")
    revoked_at_text = "null" if authorization["revoked_at"] is None else authorization["revoked_at"]
    print(f"- revoked_at: {revoked_at_text}")
    print(f"- grant_active_at_execution: {json.dumps(authorization['grant_active_at_execution'])}")
    print("")
    print("Next:")
    print(f"  ./ashiba scan {args.out / 'logs'} --policy {args.out / 'policy.json'}")
    print(f"  ./compile {args.out / 'artifacts'} --claim-type authorization_bound_action --card")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
