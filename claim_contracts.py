#!/usr/bin/env python3
"""Shared claim-pack contract helpers for validation and readiness."""

from __future__ import annotations

from typing import Any

from evidence_paths import evidence_is_present, get_path, path_exists
from pass_specs import get_pass_spec


def _require_str_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} must be a list of non-empty strings")
    return [str(item) for item in value]


def validate_support_requirements(source_label: str, raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{source_label} support_requirements must be a list")

    requirements: list[dict[str, Any]] = []
    for idx, item in enumerate(raw):
        label = f"{source_label} support_requirements.{idx}"
        if not isinstance(item, dict):
            raise ValueError(f"{label} must be an object")
        requirement_id = item.get("id")
        if not isinstance(requirement_id, str) or not requirement_id:
            raise ValueError(f"{label}.id must be a non-empty string")

        requirement: dict[str, Any] = {"id": requirement_id}
        if "path" in item:
            path = item["path"]
            if not isinstance(path, str) or not path:
                raise ValueError(f"{label}.path must be a non-empty string")
            requirement["path"] = path
            presence = item.get("presence", "evidence_present")
            if presence not in {"evidence_present", "path_exists"}:
                raise ValueError(f"{label}.presence must be evidence_present or path_exists")
            requirement["presence"] = presence
        if "all_of" in item:
            requirement["all_of"] = _require_str_list(item["all_of"], f"{label}.all_of")
        if "same_value" in item:
            same_value = _require_str_list(item["same_value"], f"{label}.same_value")
            if len(same_value) != 2:
                raise ValueError(f"{label}.same_value must contain exactly two paths")
            requirement["same_value"] = same_value
        if not any(key in requirement for key in ("path", "all_of", "same_value")):
            raise ValueError(f"{label} must define path, all_of, or same_value")
        requirements.append(requirement)
    return requirements


def support_requirement_paths(requirements: list[dict[str, Any]]) -> list[str]:
    paths: list[str] = []
    for requirement in requirements:
        path = requirement.get("path")
        if isinstance(path, str):
            paths.append(path)
        for key in ("all_of", "same_value"):
            raw = requirement.get(key)
            if isinstance(raw, list):
                paths.extend(item for item in raw if isinstance(item, str))
    return paths


def support_requirement_ids(requirements: list[dict[str, Any]]) -> list[str]:
    return [
        str(requirement["id"])
        for requirement in requirements
        if isinstance(requirement.get("id"), str) and requirement["id"]
    ]


def validate_evidence_guidance(
    source_label: str,
    raw: Any,
    known_missing_keys: list[str],
) -> dict[str, dict[str, Any]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"{source_label} evidence_guidance must be an object")

    known = set(known_missing_keys)
    out: dict[str, dict[str, Any]] = {}
    allowed_keys = {"probe", "why", "suggested_log_shape"}
    for missing_key, entry in raw.items():
        label = f"{source_label} evidence_guidance.{missing_key}"
        if not isinstance(missing_key, str) or not missing_key:
            raise ValueError(f"{source_label} evidence_guidance keys must be non-empty strings")
        if missing_key not in known:
            raise ValueError(f"{label} does not match expected evidence or support requirement id")
        if not isinstance(entry, dict):
            raise ValueError(f"{label} must be an object")
        unknown_keys = sorted(set(entry) - allowed_keys)
        if unknown_keys:
            raise ValueError(f"{label} has unknown key(s): {', '.join(unknown_keys)}")

        normalized: dict[str, Any] = {}
        for text_key in ("probe", "why"):
            value = entry.get(text_key)
            if value is None:
                continue
            if not isinstance(value, str) or not value:
                raise ValueError(f"{label}.{text_key} must be a non-empty string")
            normalized[text_key] = value
        if "suggested_log_shape" in entry:
            normalized["suggested_log_shape"] = entry["suggested_log_shape"]
        out[missing_key] = normalized
    return out


def registry_evidence_guidance(registry: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    guidance: dict[str, dict[str, Any]] = {}
    for config in registry.values():
        raw = config.get("evidence_guidance", {})
        if not isinstance(raw, dict):
            continue
        for missing, entry in raw.items():
            if not isinstance(missing, str) or not isinstance(entry, dict):
                continue
            current = guidance.setdefault(missing, {})
            for key in ("probe", "why", "suggested_log_shape"):
                if key in entry and key not in current:
                    current[key] = entry[key]
    return guidance


def validate_pass_required_paths(
    source_label: str,
    passes: list[str],
    expected_evidence: list[str],
    support_requirements: list[dict[str, Any]],
) -> None:
    covered = set(expected_evidence) | set(support_requirement_paths(support_requirements))
    missing_by_pass: dict[str, list[str]] = {}
    for pass_id in passes:
        spec = get_pass_spec(pass_id)
        missing = sorted(path for path in spec.required_paths if path not in covered)
        if missing:
            missing_by_pass[pass_id] = missing
    if not missing_by_pass:
        return

    parts = [
        f"{pass_id}: {', '.join(paths)}"
        for pass_id, paths in sorted(missing_by_pass.items())
    ]
    raise ValueError(
        f"{source_label} does not cover required path(s) for pass metadata: "
        + "; ".join(parts)
    )


def missing_expected_paths(artifacts: dict[str, Any], expected_paths: list[str]) -> list[str]:
    return [
        path
        for path in expected_paths
        if not evidence_is_present(get_path(artifacts, path))
    ]


def support_requirement_missing(artifacts: dict[str, Any], requirement: dict[str, Any]) -> bool:
    path = requirement.get("path")
    if isinstance(path, str):
        presence = requirement.get("presence", "evidence_present")
        if presence == "path_exists":
            if not path_exists(artifacts, path):
                return True
        elif not evidence_is_present(get_path(artifacts, path)):
            return True

    all_of = requirement.get("all_of", [])
    if isinstance(all_of, list):
        for required_path in all_of:
            if isinstance(required_path, str) and not evidence_is_present(get_path(artifacts, required_path)):
                return True

    same_value = requirement.get("same_value", [])
    if isinstance(same_value, list) and len(same_value) == 2:
        left = get_path(artifacts, str(same_value[0]))
        right = get_path(artifacts, str(same_value[1]))
        if not evidence_is_present(left) or not evidence_is_present(right):
            return True
        if str(left) != str(right):
            return True
    return False


def missing_support_requirements(artifacts: dict[str, Any], requirements: list[dict[str, Any]]) -> list[str]:
    missing = []
    for requirement in requirements:
        requirement_id = requirement.get("id")
        if not isinstance(requirement_id, str) or not requirement_id:
            continue
        if support_requirement_missing(artifacts, requirement) and requirement_id not in missing:
            missing.append(requirement_id)
    return missing


def claim_missing(artifacts: dict[str, Any], config: dict[str, Any]) -> list[str]:
    missing = missing_expected_paths(artifacts, list(config["expected_evidence"]))
    for requirement in missing_support_requirements(artifacts, list(config.get("support_requirements", []))):
        if requirement not in missing:
            missing.append(requirement)
    return missing


def applicability_paths(config: dict[str, Any]) -> list[str]:
    """Return the configured paths that instantiate a claim for an artifact set."""
    raw_paths = config.get("applicability_evidence") or config.get("expected_evidence", [])
    out = []
    for path in raw_paths:
        if isinstance(path, str) and path and path not in out:
            out.append(path)
    return out


def claim_instantiated(artifacts: dict[str, Any], config: dict[str, Any]) -> bool:
    """Return whether artifacts contain evidence that makes a claim applicable."""
    return any(evidence_is_present(get_path(artifacts, path)) for path in applicability_paths(config))


def claim_evidence_paths(config: dict[str, Any]) -> list[str]:
    paths = [str(path) for path in config.get("expected_evidence", [])]
    paths.extend(str(path) for path in config.get("applicability_evidence", []) if isinstance(path, str))
    paths.extend(support_requirement_paths(list(config.get("support_requirements", []))))
    for pass_id in config.get("passes", []):
        if not isinstance(pass_id, str):
            continue
        paths.extend(get_pass_spec(pass_id).required_paths)
    out = []
    for path in paths:
        if path and path not in out:
            out.append(path)
    return out


def artifact_root(path: str) -> str:
    """Return the top-level artifact key for a dotted evidence path."""
    root = path.split(".", 1)[0].strip()
    return root if root and "*" not in root else ""


def claim_artifact_roots(registry: dict[str, dict[str, Any]]) -> tuple[str, ...]:
    """Return artifact roots referenced by claim-pack contracts and pass specs."""
    roots = []
    for config in registry.values():
        for path in claim_evidence_paths(config):
            root = artifact_root(path)
            if root and root not in roots:
                roots.append(root)
    return tuple(sorted(roots))


def path_overlaps(left: str, right: str) -> bool:
    return left == right or left.startswith(right + ".") or right.startswith(left + ".")


def _conflict_path(conflict: Any) -> str:
    if isinstance(conflict, dict):
        path = conflict.get("path")
    else:
        path = getattr(conflict, "path", "")
    return str(path) if path else ""


def conflict_excluded(conflict: Any, excluded_prefixes: tuple[str, ...]) -> bool:
    path = _conflict_path(conflict)
    return any(path == prefix or path.startswith(prefix + ".") for prefix in excluded_prefixes)


def claim_conflicts(
    config: dict[str, Any],
    conflicts: list[Any],
    excluded_prefixes: tuple[str, ...] = (),
) -> list[str]:
    relevant_paths = claim_evidence_paths(config)
    out = []
    for conflict in conflicts:
        path = _conflict_path(conflict)
        if not path or conflict_excluded(conflict, excluded_prefixes):
            continue
        if any(path_overlaps(path, relevant) for relevant in relevant_paths):
            if path not in out:
                out.append(path)
    return sorted(out)


def claim_has_action_scope(config: dict[str, Any]) -> bool:
    for pass_id in config.get("passes", []):
        if isinstance(pass_id, str) and get_pass_spec(pass_id).scope == "action":
            return True
    return False
