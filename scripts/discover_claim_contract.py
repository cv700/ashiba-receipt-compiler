#!/usr/bin/env python3
"""Discover runtime evidence obligations from the active claim packs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from claim_contracts import claim_has_action_scope, support_requirement_paths  # noqa: E402
from claim_types import build_claim_registry  # noqa: E402
from pass_specs import get_pass_spec  # noqa: E402


SCHEMA_VERSION = "ashiba-claim-contract-discovery-v0.1"
SIDE_EFFECT_PREFIX = "side_effects.0."
SIDE_EFFECT_WILDCARD_PREFIX = "side_effects.*."

PROPOSED_SIDE_EFFECT_FIELDS = (
    "schema_version",
    "action_id",
    "episode_id",
    "trace_id",
    "span_id",
    "parent_action_id",
    "tool",
    "tool_name",
    "side_effect_class",
    "executed_at",
    "principal",
    "agent_id",
    "source_kind",
    "invocation.decision_id",
    "invocation.approval_id",
    "input_set_hash",
    "evidence_refs",
)


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted({value for value in values if value})


def _pass_paths(pass_ids: list[str], attr: str) -> list[str]:
    paths: list[str] = []
    for pass_id in pass_ids:
        raw = getattr(get_pass_spec(pass_id), attr)
        paths.extend(str(path) for path in raw)
    return _unique_sorted(paths)


def _normalize_side_effect_path(path: str) -> str | None:
    if path.startswith(SIDE_EFFECT_PREFIX):
        return path.removeprefix(SIDE_EFFECT_PREFIX)
    if path.startswith(SIDE_EFFECT_WILDCARD_PREFIX):
        return path.removeprefix(SIDE_EFFECT_WILDCARD_PREFIX)
    return None


def _side_effect_fields(paths: list[str]) -> list[str]:
    fields = []
    for path in paths:
        normalized = _normalize_side_effect_path(path)
        if normalized:
            fields.append(normalized)
    return _unique_sorted(fields)


def _top_level_groups(paths: list[str]) -> list[str]:
    return _unique_sorted([path.split(".", 1)[0] for path in paths if "." in path])


def _binding_requirements(requirements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for requirement in requirements:
        same_value = requirement.get("same_value")
        if isinstance(same_value, list) and len(same_value) == 2:
            bindings.append({
                "id": str(requirement.get("id", "")),
                "same_value": [str(same_value[0]), str(same_value[1])],
            })
    return bindings


def _has_cross_prefix_binding(requirements: list[dict[str, Any]], left_prefix: str, right_prefix: str) -> bool:
    for binding in _binding_requirements(requirements):
        left, right = binding["same_value"]
        if (
            left.startswith(left_prefix) and right.startswith(right_prefix)
            or left.startswith(right_prefix) and right.startswith(left_prefix)
        ):
            return True
    return False


def _discover_gaps(claim: dict[str, Any], requirements: list[dict[str, Any]], all_paths: list[str]) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    has_approval = any(path.startswith("approval.") for path in all_paths)
    has_side_effect = any(path.startswith("side_effects.") for path in all_paths)
    if (
        claim["scope"] == "action"
        and has_approval
        and has_side_effect
        and not _has_cross_prefix_binding(requirements, "approval.", "side_effects.")
    ):
        gaps.append({
            "id": "approval-action binding not encoded",
            "reason": (
                "action-scoped approval evidence can support chronology, but the claim contract "
                "does not require a same_value binding between approval and the selected side effect"
            ),
        })
    return gaps


def discover(claim_packs_dir: Path | None = None) -> dict[str, Any]:
    registry = build_claim_registry(claim_packs_dir)
    claims = []
    side_effect_required: list[str] = []
    side_effect_contradiction_relevant: list[str] = []
    discovered_gaps: list[dict[str, str]] = []

    for name, config in sorted(registry.items()):
        pass_ids = [str(pass_id) for pass_id in config.get("passes", [])]
        expected = [str(path) for path in config.get("expected_evidence", [])]
        applicability = [str(path) for path in config.get("applicability_evidence", [])]
        requirements = list(config.get("support_requirements", []))
        support_paths = support_requirement_paths(requirements)
        pass_required = _pass_paths(pass_ids, "required_paths")
        contradiction_paths = _pass_paths(pass_ids, "contradiction_paths")
        all_support_paths = _unique_sorted(expected + support_paths + pass_required)
        scope = "action" if claim_has_action_scope(config) else "claim"

        side_effect_required.extend(_side_effect_fields(all_support_paths))
        side_effect_contradiction_relevant.extend(_side_effect_fields(contradiction_paths))

        claim = {
            "name": name,
            "claim_id": str(config.get("claim", {}).get("id", "")),
            "renderer_family": str(config.get("renderer_family", "")),
            "scope": scope,
            "evidence_groups": _top_level_groups(all_support_paths),
            "expected_evidence": expected,
            "applicability_evidence": applicability,
            "support_required_paths": _unique_sorted(support_paths),
            "pass_required_paths": pass_required,
            "contradiction_paths": contradiction_paths,
            "binding_requirements": _binding_requirements(requirements),
            "side_effect_required_fields": _side_effect_fields(all_support_paths),
            "side_effect_contradiction_fields": _side_effect_fields(contradiction_paths),
        }
        claim_gaps = _discover_gaps(claim, requirements, all_support_paths)
        if claim_gaps:
            for gap in claim_gaps:
                discovered_gaps.append({"claim": name, **gap})
            claim["discovered_gaps"] = claim_gaps
        claims.append(claim)

    required_fields = _unique_sorted(side_effect_required)
    contradiction_fields = _unique_sorted(side_effect_contradiction_relevant)
    proposed = list(PROPOSED_SIDE_EFFECT_FIELDS)
    return {
        "schema_version": SCHEMA_VERSION,
        "claim_count": len(claims),
        "claims": claims,
        "side_effect_envelope_v1_minimum": {
            "required_by_current_claims": required_fields,
            "contradiction_relevant": contradiction_fields,
            "proposed_but_unclaimed": sorted(
                field for field in proposed
                if field not in required_fields and field not in contradiction_fields
            ),
        },
        "discovered_gaps": discovered_gaps,
    }


def _format_text(discovery: dict[str, Any]) -> str:
    lines = [
        "Ashiba claim contract discovery",
        "",
        f"Claims: {discovery['claim_count']}",
        "",
        "SideEffectEnvelope v1 minimum required by current claims:",
    ]
    for field in discovery["side_effect_envelope_v1_minimum"]["required_by_current_claims"]:
        lines.append(f"- {field}")
    lines.extend(["", "SideEffectEnvelope contradiction-relevant fields:"])
    for field in discovery["side_effect_envelope_v1_minimum"]["contradiction_relevant"]:
        lines.append(f"- {field}")
    lines.extend(["", "Proposed envelope fields not required by current claims:"])
    for field in discovery["side_effect_envelope_v1_minimum"]["proposed_but_unclaimed"]:
        lines.append(f"- {field}")
    if discovery["discovered_gaps"]:
        lines.extend(["", "Discovered contract gaps:"])
        for gap in discovery["discovered_gaps"]:
            lines.append(f"- {gap['claim']}: {gap['id']} - {gap['reason']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim-packs-dir", type=Path, help="Optional external claim packs directory.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args()

    discovery = discover(args.claim_packs_dir)
    if args.json:
        print(json.dumps(discovery, indent=2, sort_keys=True))
    else:
        print(_format_text(discovery), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
