#!/usr/bin/env python3
"""SideEffectEnvelope v1 compatibility helpers."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


SIDE_EFFECTS_KEY = "side_effects"
SIDE_EFFECT_SCHEMA_VERSION = "side_effect_envelope_v1"
SIDE_EFFECT_ACTION_ID_PATH = "side_effects.0.action_id"
SIDE_EFFECT_EXECUTED_AT_PATH = "side_effects.0.executed_at"
SIDE_EFFECT_DECISION_ID_PATH = "side_effects.0.invocation.decision_id"


def _present(value: Any) -> bool:
    return value not in (None, "", [], {})


def _first_present(*values: Any) -> Any:
    for value in values:
        if _present(value):
            return value
    return None


def _as_action_list(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _as_side_effect_list(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [normalize_side_effect(item) for item in raw if isinstance(item, dict)]


def normalize_side_effect(raw: dict[str, Any]) -> dict[str, Any]:
    envelope = deepcopy(raw)
    envelope.setdefault("schema_version", SIDE_EFFECT_SCHEMA_VERSION)
    invocation = envelope.get("invocation")
    if not isinstance(invocation, dict):
        invocation = {}
    envelope["invocation"] = invocation
    return envelope


def side_effect_from_legacy(action: dict[str, Any], tool_call: dict[str, Any] | None = None) -> dict[str, Any]:
    tool_call = tool_call if isinstance(tool_call, dict) else {}
    invocation = tool_call.get("invocation_context") if isinstance(tool_call.get("invocation_context"), dict) else {}
    envelope: dict[str, Any] = {
        "schema_version": SIDE_EFFECT_SCHEMA_VERSION,
        "executed_at": action.get("executed_at"),
        "invocation": deepcopy(invocation),
    }
    action_id = _first_present(action.get("action_id"), tool_call.get("action_id"))
    tool = _first_present(action.get("tool"), tool_call.get("tool_name"))
    source_kind = _first_present(action.get("source_kind"), invocation.get("source"))
    if action_id is not None:
        envelope["action_id"] = str(action_id)
    if tool is not None:
        envelope["tool"] = str(tool)
    if source_kind is not None:
        envelope["source_kind"] = str(source_kind)
    return {key: value for key, value in envelope.items() if _present(value)}


def side_effects_from_legacy_artifacts(artifacts: dict[str, Any]) -> list[dict[str, Any]]:
    actions = _as_action_list(artifacts.get("parsed_actions"))
    tool_call = artifacts.get("tool_call") if isinstance(artifacts.get("tool_call"), dict) else {}
    return [side_effect_from_legacy(action, tool_call) for action in actions]


def legacy_artifacts_from_side_effect(side_effect: dict[str, Any]) -> dict[str, Any]:
    action: dict[str, Any] = {}
    action_id = side_effect.get("action_id")
    tool = side_effect.get("tool")
    executed_at = side_effect.get("executed_at")
    source_kind = side_effect.get("source_kind")
    if action_id is not None:
        action["action_id"] = str(action_id)
    if tool is not None:
        action["tool"] = str(tool)
    if executed_at is not None:
        action["executed_at"] = executed_at
    if source_kind is not None:
        action["source_kind"] = str(source_kind)

    tool_call: dict[str, Any] = {}
    if action_id is not None:
        tool_call["action_id"] = str(action_id)
    if tool is not None:
        tool_call["tool_name"] = str(tool)
    invocation = side_effect.get("invocation")
    if isinstance(invocation, dict):
        tool_call["invocation_context"] = deepcopy(invocation)

    out: dict[str, Any] = {}
    if action:
        out["parsed_actions"] = [action]
    if tool_call:
        out["tool_call"] = tool_call
    return out


def normalize_side_effect_artifacts(artifacts: dict[str, Any]) -> dict[str, Any]:
    out = dict(artifacts)
    side_effects = _as_side_effect_list(out.get(SIDE_EFFECTS_KEY))
    if not side_effects:
        side_effects = side_effects_from_legacy_artifacts(out)
    if side_effects:
        out[SIDE_EFFECTS_KEY] = side_effects
        if "parsed_actions" not in out or "tool_call" not in out:
            legacy = legacy_artifacts_from_side_effect(side_effects[0])
            out.setdefault("parsed_actions", legacy.get("parsed_actions", []))
            if "tool_call" in legacy:
                out.setdefault("tool_call", legacy["tool_call"])
    return out
