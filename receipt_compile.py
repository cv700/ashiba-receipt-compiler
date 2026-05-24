#!/usr/bin/env python3
"""Minimum evidence compiler entry point.

Usage modes:
  v1 (bundle):     receipt_compile.py --bundle incident_bundle.json
  v2 (artifacts):  receipt_compile.py --artifacts-dir ./incident_001/ --claim-type authorization_bound_action
  v5 (manifest):   receipt_compile.py --artifacts-dir ./incident_001/  (uses incident_manifest claim_types if present)
  explain:         receipt_compile.py --artifacts-dir ./incident_001/ --explain
  list types:      receipt_compile.py --list-claim-types
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any

from boundary import generate_boundary
from claim_contracts import claim_has_action_scope
from claim_types import CLAIM_TYPES, build_claim_registry, get_claim_type, list_claim_types
from constants import CLAIM_APPLICABILITY_PASS_ID, COMPILER_VERSION, PASS_NOT_APPLICABLE, UNKNOWN
from passes import get_pass
from receipt_explain import format_receipts_explanation
from receipt_ir import ReceiptIR, utc_now
from renderer_families import validate_renderer_family
from side_effect_envelope import iter_action_scoped_artifacts, normalize_side_effect_artifacts
from verdict import generate_verdict


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

INCIDENT_MANIFEST_FILENAME = "incident_manifest.json"


@dataclass(frozen=True)
class ArtifactLoad:
    """Loaded artifacts plus the input binding metadata used by receipts."""

    artifacts: dict[str, Any]
    artifact_manifest: list[dict[str, Any]]
    input_set_hash: str
    incident_manifest: dict[str, Any]
    execution_context: dict[str, Any] = field(default_factory=dict)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _input_set_hash(artifact_manifest: list[dict[str, Any]]) -> str:
    payload = json.dumps(artifact_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def bundle_manifest(path: Path) -> tuple[list[dict[str, Any]], str]:
    """Return deterministic artifact manifest records for a v1 bundle file."""
    record = {
        "source": "bundle",
        "filename": path.name,
        "relative_path": path.name,
        "sha256": _sha256_file(path),
        "byte_size": path.stat().st_size,
    }
    records = [record]
    return records, _input_set_hash(records)


def artifact_file_manifest(path: Path, artifact_key: str) -> dict[str, Any]:
    """Return one artifact manifest record for a v2 JSON artifact file."""
    return {
        "source": "artifact_file",
        "filename": path.name,
        "relative_path": path.name,
        "artifact_key": artifact_key,
        "sha256": _sha256_file(path),
        "byte_size": path.stat().st_size,
    }


def incident_manifest_record(path: Path) -> dict[str, Any]:
    """Return one manifest record for an incident manifest file."""
    return {
        "source": "incident_manifest",
        "filename": path.name,
        "relative_path": path.name,
        "sha256": _sha256_file(path),
        "byte_size": path.stat().st_size,
    }


def manifest_artifact_file_record(
    path: Path,
    relative_path: str,
    artifact_key: str,
    role: str = "",
) -> dict[str, Any]:
    """Return one artifact manifest record for an incident-manifest entry."""
    record = artifact_file_manifest(path, artifact_key)
    record["relative_path"] = relative_path
    if role:
        record["role"] = role
    return record


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return data


def _safe_relative_path(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{label} must be a non-empty relative path")
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must be relative and stay under the incident directory")
    return raw


def _resolve_under_root(root: Path, relative_path: str, label: str) -> Path:
    """Resolve a manifest path and reject symlink/path escapes from root."""
    root_resolved = root.resolve(strict=True)
    candidate = (root / relative_path).resolve(strict=True)
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"{label} must resolve under the incident directory") from exc
    return candidate


def _merge_artifact(data: dict[str, Any], artifact_key: str) -> Any:
    if len(data) == 1 and artifact_key in data:
        return data[artifact_key]
    return data


def load_artifacts_from_incident_manifest(artifacts_dir: Path, manifest_path: Path) -> ArtifactLoad:
    """Load an incident directory using explicit artifact roles from incident_manifest.json."""
    incident_manifest = load_json(manifest_path)
    roles = incident_manifest.get("artifact_roles")
    if not isinstance(roles, list) or not roles:
        raise ValueError(f"{INCIDENT_MANIFEST_FILENAME} must contain a non-empty artifact_roles list")

    merged: dict[str, Any] = {}
    artifact_manifest: list[dict[str, Any]] = [incident_manifest_record(manifest_path)]
    execution_context: dict[str, Any] = {}
    manifest_execution_context = incident_manifest.get("execution_context")
    if isinstance(manifest_execution_context, dict):
        execution_context = manifest_execution_context

    for idx, entry in enumerate(roles):
        if not isinstance(entry, dict):
            raise ValueError(f"artifact_roles.{idx} must be an object")
        rel = _safe_relative_path(entry.get("path"), f"artifact_roles.{idx}.path")
        artifact_key = entry.get("artifact_key") or Path(rel).stem
        if not isinstance(artifact_key, str) or not artifact_key:
            raise ValueError(f"artifact_roles.{idx}.artifact_key must be a non-empty string")
        role = entry.get("role", "")
        if role is not None and not isinstance(role, str):
            raise ValueError(f"artifact_roles.{idx}.role must be a string when supplied")

        try:
            path = _resolve_under_root(artifacts_dir, rel, f"artifact_roles.{idx}.path")
        except FileNotFoundError as exc:
            raise ValueError(f"artifact file listed in incident manifest does not exist: {rel}")
        if not path.is_file():
            raise ValueError(f"artifact file listed in incident manifest is not a file: {rel}")
        if artifact_key in merged:
            raise ValueError(f"duplicate artifact_key in incident manifest: {artifact_key}")

        data = load_json(path)
        if artifact_key == "execution_context" or role == "execution_context":
            execution_context = data
        else:
            merged[artifact_key] = _merge_artifact(data, artifact_key)
        artifact_manifest.append(manifest_artifact_file_record(path, rel, artifact_key, role or ""))

    return ArtifactLoad(
        artifacts=merged,
        artifact_manifest=artifact_manifest,
        input_set_hash=_input_set_hash(artifact_manifest),
        incident_manifest=incident_manifest,
        execution_context=execution_context,
    )


def load_artifacts_dir_bound(artifacts_dir: Path) -> ArtifactLoad:
    """Load all JSON files from a directory and merge into a single artifacts dict.

    Each file's stem becomes a top-level key in the merged dict.
    If a file's root object has a single key matching the stem, it is unwrapped.
    """
    if not artifacts_dir.is_dir():
        raise ValueError(f"not a directory: {artifacts_dir}")

    manifest_path = artifacts_dir / INCIDENT_MANIFEST_FILENAME
    if manifest_path.is_file():
        return load_artifacts_from_incident_manifest(artifacts_dir, manifest_path)

    merged: dict[str, Any] = {}
    artifact_manifest: list[dict[str, Any]] = []
    execution_context: dict[str, Any] = {}
    json_files = sorted(artifacts_dir.glob("*.json"))
    if not json_files:
        raise ValueError(f"no JSON files found in {artifacts_dir}")

    for path in json_files:
        data = load_json(path)
        stem = path.stem

        if stem == "execution_context":
            execution_context = data
        else:
            merged[stem] = _merge_artifact(data, stem)
        artifact_manifest.append(artifact_file_manifest(path, stem))

    return ArtifactLoad(
        artifacts=merged,
        artifact_manifest=artifact_manifest,
        input_set_hash=_input_set_hash(artifact_manifest),
        incident_manifest={},
        execution_context=execution_context,
    )


def load_artifacts_dir_with_manifest(artifacts_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    """Load v2 artifacts and binding metadata; preserved for existing callers."""
    loaded = load_artifacts_dir_bound(artifacts_dir)
    return loaded.artifacts, loaded.artifact_manifest, loaded.input_set_hash


def load_artifacts_dir(artifacts_dir: Path) -> dict[str, Any]:
    """Load v2 artifacts only; preserved for callers that do not need binding metadata."""
    artifacts, _, _ = load_artifacts_dir_with_manifest(artifacts_dir)
    return artifacts


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

def _claim_surface_instantiated(artifacts: dict[str, Any], config: dict[str, Any]) -> bool:
    """Return whether the artifact class instantiates the configured claim type."""
    from evidence_paths import evidence_is_present, get_path

    paths = config.get("applicability_evidence") or config.get("expected_evidence", [])
    for path in paths:
        if evidence_is_present(get_path(artifacts, path)):
            return True
    return False


def _finalize_receipt(ir: ReceiptIR) -> ReceiptIR:
    if ir.execution_context and not any(
        result.get("pass_id") == "execution_context_disclosure" for result in ir.pass_results
    ):
        _apply_pass_result(ir, get_pass("execution_context_disclosure")(ir, None))
    ir.verdict = generate_verdict(ir.pass_results, ir.absence)
    ir.boundary, ir.unsupported_inferences = generate_boundary(
        claim=ir.claim,
        verdict=ir.verdict,
        pass_results=ir.pass_results,
        absence=ir.absence,
        renderer_family=ir.renderer_family,
    )
    return ir


def _apply_pass_result(ir: ReceiptIR, result: Any) -> None:
    result_dict = result.to_dict()
    ir.pass_results.append(result_dict)
    if result.absence:
        ir.absence.extend(result.absence)
    if result.compiler_error:
        ir.compiler_errors.append({"pass_id": result.pass_id, "detail": result.compiler_error})


def _run_pass_sequence(
    ir: ReceiptIR,
    pass_ids: list[str],
    pass_params: dict[str, Any] | None = None,
) -> ReceiptIR:
    params_by_pass = pass_params or {}
    for pass_id in pass_ids:
        compiler_pass = get_pass(pass_id)
        _apply_pass_result(ir, compiler_pass(ir, params_by_pass.get(pass_id)))
    return _finalize_receipt(ir)


def _bundle_claim_type_name(
    bundle: dict[str, Any],
    claim_types: dict[str, dict[str, Any]] | None = None,
) -> str:
    """Resolve a legacy bundle claim to the canonical claim-pack registry."""
    registry = claim_types or CLAIM_TYPES
    explicit = bundle.get("claim_type")
    if isinstance(explicit, str) and explicit:
        get_claim_type(explicit, registry)
        return explicit

    claim = bundle.get("claim")
    claim_id = claim.get("id") if isinstance(claim, dict) else None
    if isinstance(claim_id, str) and claim_id:
        matches = sorted(
            name
            for name, config in registry.items()
            if isinstance(config.get("claim"), dict) and config["claim"].get("id") == claim_id
        )
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError(f"bundle claim id {claim_id!r} matches multiple claim types: {', '.join(matches)}")

    raise ValueError(
        "legacy bundle claim does not match a known claim pack; "
        "add claim_type or convert the bundle to artifact-directory form"
    )


def compile_bundle(
    bundle: dict[str, Any],
    artifact_manifest: list[dict[str, Any]] | None = None,
    input_set_hash: str = "",
    claim_types: dict[str, dict[str, Any]] | None = None,
) -> ReceiptIR:
    """v1 compilation: single bundle routed through the canonical claim-pack path."""
    artifacts = bundle.get("artifacts")
    if not isinstance(artifacts, dict):
        artifacts = {}
    execution_context = bundle.get("execution_context")
    return compile_claim(
        artifacts=artifacts,
        claim_type_name=_bundle_claim_type_name(bundle, claim_types),
        artifact_manifest=artifact_manifest,
        input_set_hash=input_set_hash,
        execution_context=execution_context if isinstance(execution_context, dict) else {},
        claim_types=claim_types,
    )


def _compile_claim_normalized(
    artifacts: dict[str, Any],
    claim_type_name: str,
    config: dict[str, Any],
    renderer_family: str,
    artifact_manifest: list[dict[str, Any]] | None = None,
    input_set_hash: str = "",
    incident_manifest: dict[str, Any] | None = None,
    execution_context: dict[str, Any] | None = None,
) -> ReceiptIR:
    ir = ReceiptIR.from_artifacts(
        artifacts=artifacts,
        claim=config["claim"],
        expected_evidence=config["expected_evidence"],
        claim_type=claim_type_name,
        artifact_manifest=artifact_manifest,
        input_set_hash=input_set_hash,
        incident_manifest=incident_manifest,
        execution_context=execution_context,
        renderer_family=renderer_family,
    )

    if not _claim_surface_instantiated(artifacts, config):
        ir.pass_results.append({
            "pass_id": CLAIM_APPLICABILITY_PASS_ID,
            "status": PASS_NOT_APPLICABLE,
            "detail": (
                f"artifact class does not instantiate claim type {claim_type_name}; "
                "missing expected paths for an otherwise applicable claim are handled separately as unknown"
            ),
            "metadata": {
                "applicability_evidence": [str(path) for path in config.get("applicability_evidence", [])],
            },
        })
        return _finalize_receipt(ir)

    return _run_pass_sequence(ir, config["passes"], config.get("pass_params", {}))


def compile_claim(
    artifacts: dict[str, Any],
    claim_type_name: str,
    artifact_manifest: list[dict[str, Any]] | None = None,
    input_set_hash: str = "",
    incident_manifest: dict[str, Any] | None = None,
    execution_context: dict[str, Any] | None = None,
    claim_types: dict[str, dict[str, Any]] | None = None,
) -> ReceiptIR:
    """Compile one receipt for a claim type.

    For action-scoped claim types, multi-action artifacts must go through
    compile_claims so the caller cannot accidentally first-win the log.
    """
    config = get_claim_type(claim_type_name, claim_types)
    renderer_family = validate_renderer_family(config.get("renderer_family"), f"claim type {claim_type_name}")
    artifacts = normalize_side_effect_artifacts(artifacts)
    if claim_has_action_scope(config):
        artifact_sets = iter_action_scoped_artifacts(artifacts)
        if len(artifact_sets) > 1:
            raise ValueError(
                f"claim type {claim_type_name} is action-scoped; "
                "use compile_claims for multi-action artifacts"
            )
        artifacts = artifact_sets[0]
    return _compile_claim_normalized(
        artifacts,
        claim_type_name,
        config,
        renderer_family,
        artifact_manifest=artifact_manifest,
        input_set_hash=input_set_hash,
        incident_manifest=incident_manifest,
        execution_context=execution_context,
    )


def compile_claims(
    artifacts: dict[str, Any],
    claim_type_name: str,
    artifact_manifest: list[dict[str, Any]] | None = None,
    input_set_hash: str = "",
    incident_manifest: dict[str, Any] | None = None,
    execution_context: dict[str, Any] | None = None,
    claim_types: dict[str, dict[str, Any]] | None = None,
) -> list[ReceiptIR]:
    """Compile every receipt implied by a claim type.

    Claim-scoped packs produce one receipt. Action-scoped packs produce one
    receipt per SideEffectEnvelope v1 action, with legacy parsed_actions/tool_call
    projected into the same envelope shape at the boundary.
    """
    config = get_claim_type(claim_type_name, claim_types)
    renderer_family = validate_renderer_family(config.get("renderer_family"), f"claim type {claim_type_name}")
    artifacts = normalize_side_effect_artifacts(artifacts)
    artifact_sets = iter_action_scoped_artifacts(artifacts) if claim_has_action_scope(config) else [artifacts]
    return [
        _compile_claim_normalized(
            scoped_artifacts,
            claim_type_name,
            config,
            renderer_family,
            artifact_manifest=artifact_manifest,
            input_set_hash=input_set_hash,
            incident_manifest=incident_manifest,
            execution_context=execution_context,
        )
        for scoped_artifacts in artifact_sets
    ]


def detect_applicable_claim_types(
    artifacts: dict[str, Any],
    claim_types: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """Heuristic: which claim types have enough artifacts to be worth running?

    A claim type is applicable if at least one of its expected evidence paths
    resolves to a non-empty value.
    """
    from evidence_paths import evidence_is_present, get_path

    artifacts = normalize_side_effect_artifacts(artifacts)
    registry = claim_types or CLAIM_TYPES
    applicable = []
    for name, config in registry.items():
        for path in config.get("applicability_evidence") or config["expected_evidence"]:
            value = get_path(artifacts, path)
            if evidence_is_present(value):
                applicable.append(name)
                break
    return sorted(applicable)


def claim_types_from_incident_manifest(
    incident_manifest: dict[str, Any],
    registry: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """Return explicit claim types declared by an incident manifest, if any."""
    raw = incident_manifest.get("claim_types")
    if not isinstance(raw, list):
        return []
    declared = []
    for idx, item in enumerate(raw):
        if not isinstance(item, str) or not item:
            raise ValueError(f"incident_manifest.claim_types.{idx} must be a non-empty string")
        get_claim_type(item, registry)
        declared.append(item)
    return sorted(set(declared))


# ---------------------------------------------------------------------------
# Error receipt
# ---------------------------------------------------------------------------

def error_receipt(exc: Exception) -> dict[str, Any]:
    artifact_manifest: list[dict[str, Any]] = []
    return {
        "receipt_id": "rcpt.error",
        "created_at": utc_now(),
        "compiler_version": COMPILER_VERSION,
        "claim": {},
        "expected_evidence": [],
        "absence": [],
        "artifacts": {},
        "pass_results": [],
        "compiler_errors": [{"pass_id": "receipt_compile", "detail": str(exc)}],
        "verdict": {"status": UNKNOWN, "basis": "compiler could not load or compile the input"},
        "boundary": {
            "supports": [],
            "does_not_support": [
                "This receipt does not support claims because the input could not be loaded or compiled."
            ],
        },
        "unsupported_inferences": ["That the supplied bundle was valid JSON."],
        "artifact_manifest": artifact_manifest,
        "input_set_hash": _input_set_hash(artifact_manifest),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle", type=Path, help="Path to incident_bundle.json (v1 mode).")
    parser.add_argument("--artifacts-dir", type=Path, help="Directory of artifact JSON files (v2 mode).")
    parser.add_argument(
        "--claim-type",
        type=str,
        help="Claim type to compile. Omit to use incident_manifest claim_types or auto-detect candidates.",
    )
    parser.add_argument("--list-claim-types", action="store_true", help="List available claim types and exit.")
    parser.add_argument("--out", type=Path, help="Write receipt(s) to this directory instead of stdout.")
    parser.add_argument("--claim-packs-dir", type=Path, help="Optional directory of external JSON claim packs.")
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Emit a human-readable explanation instead of receipt JSON.",
    )
    args = parser.parse_args()
    try:
        active_claim_types: dict[str, dict[str, Any]] | None = None
        if args.list_claim_types or args.artifacts_dir or args.bundle or args.claim_packs_dir:
            active_claim_types = build_claim_registry(args.claim_packs_dir)

        if args.list_claim_types:
            assert active_claim_types is not None
            for ct in list_claim_types(active_claim_types):
                config = get_claim_type(ct, active_claim_types)
                print(f"  {ct}: {config['claim']['text']}")
            return 0

        if not args.bundle and not args.artifacts_dir:
            parser.error("one of --bundle or --artifacts-dir is required")

        if args.bundle:
            # v1 mode: single bundle file
            bundle = load_json(args.bundle)
            artifact_manifest, input_hash = bundle_manifest(args.bundle)
            receipt = compile_bundle(
                bundle,
                artifact_manifest=artifact_manifest,
                input_set_hash=input_hash,
                claim_types=active_claim_types,
            )
            receipts = [receipt.to_dict()]

        else:
            assert active_claim_types is not None
            # v2 mode: artifacts directory + claim type(s)
            loaded = load_artifacts_dir_bound(args.artifacts_dir)
            artifacts = loaded.artifacts
            artifact_manifest = loaded.artifact_manifest
            input_hash = loaded.input_set_hash
            incident_manifest = loaded.incident_manifest

            if args.claim_type:
                claim_types = [args.claim_type]
            else:
                claim_types = claim_types_from_incident_manifest(incident_manifest, active_claim_types)
                if not claim_types:
                    claim_types = detect_applicable_claim_types(artifacts, active_claim_types)
                if not claim_types:
                    raise ValueError(
                        f"no applicable claim types detected for artifacts in {args.artifacts_dir}. "
                        f"Available claim types: {', '.join(list_claim_types(active_claim_types))}"
                    )

            receipts = []
            for ct in claim_types:
                receipts.extend(receipt.to_dict() for receipt in compile_claims(
                    artifacts,
                    ct,
                    artifact_manifest=artifact_manifest,
                    input_set_hash=input_hash,
                    incident_manifest=incident_manifest,
                    execution_context=loaded.execution_context,
                    claim_types=active_claim_types,
                ))

    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps(error_receipt(exc), indent=2, sort_keys=True))
        return 1

    if args.explain:
        print(format_receipts_explanation(receipts))
    elif args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        for r in receipts:
            out_path = args.out / f"{r['receipt_id']}.json"
            out_path.write_text(json.dumps(r, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"wrote {out_path}")
    elif len(receipts) == 1:
        print(json.dumps(receipts[0], indent=2, sort_keys=True))
    else:
        print(json.dumps({"receipts": receipts}, indent=2, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
