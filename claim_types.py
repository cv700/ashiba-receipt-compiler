#!/usr/bin/env python3
"""Claim type registry for the evidence compiler.

Each claim type defines:
  - claim: the claim text and ID
  - expected_evidence: dotted paths that must resolve in the artifact bundle
  - passes: list of pass IDs to run (in order) for this claim type
  - pass_params: per-pass parameters keyed by pass_id

The default registry is loaded from JSON claim packs in claim_packs/. The
hardcoded configs remain as a fallback so the reference compiler can still run
if the pack directory is absent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_CLAIM_PACKS_DIR = Path(__file__).resolve().parent / "claim_packs"


def _auth_grant_config() -> dict[str, Any]:
    return {
        "claim": {
            "id": "claim.authorization_bound_action",
            "text": "The tool action was executed under an active authorization grant.",
        },
        "expected_evidence": [
            "authorization.grant_id",
            "authorization.grant_valid_from",
            "authorization.grant_valid_until",
            "parsed_actions.0.executed_at",
            "tool_call.action_id",
        ],
        "applicability_evidence": [
            "authorization",
            "parsed_actions",
            "tool_call",
        ],
        "passes": [
            "utc_timestamp_format",
            "expected_evidence_absence",
            "grant_binding_present",
            "grant_active_at_event_time",
            "revocation_before_action",
            "no_action_from_untrusted_literal",
            "no_future_evidence",
        ],
        "pass_params": {
            "no_action_from_untrusted_literal": {
                "forbidden_source_kinds": ["literal_untrusted_text"],
            },
        },
    }


def _parser_repair_config() -> dict[str, Any]:
    return {
        "claim": {
            "id": "claim.parser_repair_visibility",
            "text": "A parser repair event was logged with full provenance and the writeback decision is recorded.",
        },
        "expected_evidence": [
            "parser.repair_events.0.repair_id",
            "parser.repair_events.0.repair_function",
            "parser.repair_events.0.before_hash",
            "parser.repair_events.0.after_hash",
            "parser.repair_events.0.writeback_to_model_history",
        ],
        "applicability_evidence": [
            "parser",
            "parser.repair_events",
        ],
        "passes": [
            "utc_timestamp_format",
            "expected_evidence_absence",
            "parser_repair_logged",
            "repair_writeback_recorded",
            "no_future_evidence",
        ],
        "pass_params": {},
    }


def _prefix_continuity_config() -> dict[str, Any]:
    return {
        "claim": {
            "id": "claim.prefix_continuity",
            "text": "The next prompt preserves the exact token prefix from the previous prompt plus completion.",
        },
        "expected_evidence": [
            "token_sequences.previous_prompt_tokens",
            "token_sequences.completion_tokens",
            "token_sequences.next_prompt_tokens",
        ],
        "applicability_evidence": [
            "token_sequences",
        ],
        "passes": [
            "utc_timestamp_format",
            "expected_evidence_absence",
            "prefix_continuity",
            "no_future_evidence",
        ],
        "pass_params": {
            "prefix_continuity": {
                "previous_key": "token_sequences.previous_prompt_tokens",
                "completion_key": "token_sequences.completion_tokens",
                "next_key": "token_sequences.next_prompt_tokens",
            },
        },
    }


BUILTIN_CLAIM_TYPES: dict[str, dict[str, Any]] = {
    "authorization_bound_action": _auth_grant_config(),
    "parser_repair_visibility": _parser_repair_config(),
    "prefix_continuity": _prefix_continuity_config(),
}


def _require_str_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} must be a list of non-empty strings")
    return [str(item) for item in value]


def _validate_claim_pack(name: str, config: dict[str, Any], source: Path) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ValueError(f"claim pack {source} must be a JSON object")

    claim = config.get("claim")
    if not isinstance(claim, dict):
        raise ValueError(f"claim pack {source} missing claim object")
    if not isinstance(claim.get("id"), str) or not claim["id"]:
        raise ValueError(f"claim pack {source} claim.id must be a non-empty string")
    if not isinstance(claim.get("text"), str) or not claim["text"]:
        raise ValueError(f"claim pack {source} claim.text must be a non-empty string")

    expected_evidence = _require_str_list(config.get("expected_evidence"), f"{source} expected_evidence")
    passes = _require_str_list(config.get("passes"), f"{source} passes")
    applicability = config.get("applicability_evidence", [])
    if applicability:
        applicability = _require_str_list(applicability, f"{source} applicability_evidence")
    else:
        applicability = []

    pass_params = config.get("pass_params", {})
    if not isinstance(pass_params, dict):
        raise ValueError(f"claim pack {source} pass_params must be an object")
    for pass_id, params in pass_params.items():
        if not isinstance(pass_id, str) or not pass_id:
            raise ValueError(f"claim pack {source} pass_params keys must be non-empty strings")
        if not isinstance(params, dict):
            raise ValueError(f"claim pack {source} pass_params.{pass_id} must be an object")

    from passes import PASS_REGISTRY

    unknown_passes = sorted(set(passes) - set(PASS_REGISTRY))
    if unknown_passes:
        raise ValueError(f"claim pack {source} references unknown pass(es): {', '.join(unknown_passes)}")

    out = {
        "claim": {"id": claim["id"], "text": claim["text"]},
        "expected_evidence": expected_evidence,
        "applicability_evidence": applicability,
        "passes": passes,
        "pass_params": pass_params,
    }
    for optional_key in ("schema_version", "description", "owner", "renderer_family"):
        if optional_key in config:
            out[optional_key] = config[optional_key]
    out["name"] = str(config.get("name") or name)
    out["source_path"] = str(source)
    return out


def load_claim_packs(claim_packs_dir: Path) -> dict[str, dict[str, Any]]:
    """Load all JSON claim packs from a directory."""
    if not claim_packs_dir.exists():
        return {}
    if not claim_packs_dir.is_dir():
        raise ValueError(f"claim packs path is not a directory: {claim_packs_dir}")

    registry: dict[str, dict[str, Any]] = {}
    for path in sorted(claim_packs_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"claim pack {path} must be a JSON object")
        name = str(data.get("name") or path.stem)
        if not name:
            raise ValueError(f"claim pack {path} name must be non-empty")
        if name in registry:
            raise ValueError(f"duplicate claim pack name {name!r} in {claim_packs_dir}")
        registry[name] = _validate_claim_pack(name, data, path)
    return registry


def build_claim_registry(claim_packs_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    """Build the active claim type registry from default and optional external packs."""
    registry = load_claim_packs(DEFAULT_CLAIM_PACKS_DIR)
    for name, config in BUILTIN_CLAIM_TYPES.items():
        registry.setdefault(name, config)

    if claim_packs_dir is not None:
        if claim_packs_dir.resolve(strict=False) == DEFAULT_CLAIM_PACKS_DIR.resolve(strict=False):
            return registry
        external = load_claim_packs(claim_packs_dir)
        duplicates = sorted(set(registry) & set(external))
        if duplicates:
            raise ValueError(f"external claim pack(s) duplicate existing claim type(s): {', '.join(duplicates)}")
        registry.update(external)
    return registry


CLAIM_TYPES: dict[str, dict[str, Any]] = build_claim_registry()


def get_claim_type(name: str, claim_types: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return the claim type config, or raise ValueError."""
    registry = claim_types or CLAIM_TYPES
    if name not in registry:
        available = ", ".join(sorted(registry))
        raise ValueError(f"unknown claim type {name!r}; available: {available}")
    return registry[name]


def list_claim_types(claim_types: dict[str, dict[str, Any]] | None = None) -> list[str]:
    registry = claim_types or CLAIM_TYPES
    return sorted(registry)
