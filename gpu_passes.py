#!/usr/bin/env python3
"""GPU-specific deterministic compiler passes."""

from __future__ import annotations

import re
from typing import Any

from constants import (
    CONTRADICTED,
    PASS_CONTRADICTED,
    PASS_SATISFIED,
    PASS_SKIPPED,
    PASS_UNKNOWN,
    SUPPORTED,
    UNKNOWN,
)
from evidence_paths import evidence_is_present, get_path
from receipt_ir import PassResult, ReceiptIR


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


def _integer(value: Any) -> int | None:
    """Return an integer value without accepting booleans as numbers."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _gpu_sku_tokens(value: Any) -> set[str]:
    if not isinstance(value, str):
        return set()
    normalized = value.upper().replace("PCI-E", "PCIE")
    return {token for token in re.split(r"[^A-Z0-9]+", normalized) if token}


def _gpu_sku_family(value: Any) -> str | None:
    """Return the supported GPU SKU family token from a declared SKU string."""
    tokens = _gpu_sku_tokens(value)
    for family in ("H100", "A100", "A10", "B200"):
        if family in tokens:
            return family
    return None


def _gpu_sku_variant(value: Any) -> str | None:
    """Return a coarse GPU packaging/topology variant when the SKU string says it."""
    tokens = _gpu_sku_tokens(value)
    if not tokens:
        return None
    if "NVL" in tokens or "NVL72" in tokens:
        return "NVL"
    if "PCIE" in tokens:
        return "PCIE"
    if any(token == "SXM" or token.startswith("SXM") for token in tokens):
        return "SXM"
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


def gpu_sku_count_match(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check declared GPU SKU/count against buyer-observed nvidia-smi names/count."""
    declared_sku = get_path(ir.artifacts, "gpu_inventory.declared_sku")
    declared_count = _integer(get_path(ir.artifacts, "gpu_inventory.declared_count"))
    observed_names = _string_list(get_path(ir.artifacts, "gpu_probe_observation.observed_names"))
    observed_count = _integer(get_path(ir.artifacts, "gpu_probe_observation.observed_count"))

    missing = []
    if not evidence_is_present(declared_sku):
        missing.append("gpu_inventory.declared_sku")
    if declared_count is None:
        missing.append("gpu_inventory.declared_count")
    if observed_names is None:
        missing.append("gpu_probe_observation.observed_names")
    if observed_count is None:
        missing.append("gpu_probe_observation.observed_count")
    if missing:
        return PassResult(
            pass_id="gpu_sku_count_match",
            status=PASS_UNKNOWN,
            detail="GPU SKU/count match could not be determined; missing or invalid field(s): " + ", ".join(missing),
            verdict_effect=UNKNOWN,
            metadata={"missing_expected_paths": missing},
        )

    assert observed_names is not None
    blank_name_indexes = [idx for idx, name in enumerate(observed_names) if not name.strip()]
    if blank_name_indexes:
        return PassResult(
            pass_id="gpu_sku_count_match",
            status=PASS_UNKNOWN,
            detail="GPU SKU/count match could not be determined; observed_names contains blank value(s)",
            verdict_effect=UNKNOWN,
            metadata={
                "missing_expected_paths": ["gpu_probe_observation.observed_names"],
                "blank_indexes": blank_name_indexes,
            },
        )

    assert observed_count is not None
    if len(observed_names) != observed_count:
        return PassResult(
            pass_id="gpu_sku_count_match",
            status=PASS_UNKNOWN,
            detail=(
                "GPU SKU/count match could not be determined; observed_names contains "
                f"{len(observed_names)} row(s) but observed_count is {observed_count}"
            ),
            verdict_effect=UNKNOWN,
            metadata={
                "missing_expected_paths": ["gpu_probe_observation.observed_names"],
                "observed_names_count": len(observed_names),
                "observed_count": observed_count,
            },
        )

    family = _gpu_sku_family(declared_sku)
    if family is None:
        return PassResult(
            pass_id="gpu_sku_count_match",
            status=PASS_UNKNOWN,
            detail=f"declared GPU SKU {declared_sku!r} does not contain a supported family token (H100, A100, A10, B200)",
            verdict_effect=UNKNOWN,
            metadata={"field": "gpu_inventory.declared_sku"},
        )

    declared_variant = _gpu_sku_variant(declared_sku)
    for idx, name in enumerate(observed_names):
        observed_family = _gpu_sku_family(name)
        if observed_family != family:
            return PassResult(
                pass_id="gpu_sku_count_match",
                status=PASS_CONTRADICTED,
                detail=f"GPU {idx} observed name {name!r} does not match declared family {family}",
                verdict_effect=CONTRADICTED,
                metadata={
                    "declared_family": family,
                    "observed_name": name,
                    "observed_index": idx,
                },
            )
        observed_variant = _gpu_sku_variant(name)
        if declared_variant and observed_variant is None:
            return PassResult(
                pass_id="gpu_sku_count_match",
                status=PASS_UNKNOWN,
                detail=(
                    f"GPU {idx} observed name {name!r} matches declared family {family} "
                    f"but does not expose declared variant {declared_variant}"
                ),
                verdict_effect=UNKNOWN,
                metadata={
                    "declared_family": family,
                    "declared_variant": declared_variant,
                    "observed_name": name,
                    "observed_index": idx,
                },
            )
        if declared_variant and observed_variant != declared_variant:
            return PassResult(
                pass_id="gpu_sku_count_match",
                status=PASS_CONTRADICTED,
                detail=(
                    f"GPU {idx} observed name {name!r} exposes variant {observed_variant}, "
                    f"not declared variant {declared_variant}"
                ),
                verdict_effect=CONTRADICTED,
                metadata={
                    "declared_family": family,
                    "declared_variant": declared_variant,
                    "observed_variant": observed_variant,
                    "observed_name": name,
                    "observed_index": idx,
                },
            )

    assert declared_count is not None
    if observed_count != declared_count:
        return PassResult(
            pass_id="gpu_sku_count_match",
            status=PASS_CONTRADICTED,
            detail=f"observed GPU count {observed_count} does not equal declared count {declared_count}",
            verdict_effect=CONTRADICTED,
            metadata={"declared_count": declared_count, "observed_count": observed_count},
        )

    return PassResult(
        pass_id="gpu_sku_count_match",
        status=PASS_SATISFIED,
        detail=f"observed {observed_count} {family} GPU(s), matching declared count {declared_count}",
        verdict_effect=SUPPORTED,
        metadata={
            "declared_family": family,
            "declared_variant": declared_variant,
            "declared_count": declared_count,
            "observed_count": observed_count,
        },
    )


def gpu_not_mig_sliced(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check that buyer-observed GPUs were not MIG-sliced for dedicated-capacity acceptance."""
    modes = _string_list(get_path(ir.artifacts, "gpu_probe_observation.observed_mig_modes"))
    observed_count = _integer(get_path(ir.artifacts, "gpu_probe_observation.observed_count"))
    missing = []
    if modes is None:
        missing.append("gpu_probe_observation.observed_mig_modes")
    if observed_count is None:
        missing.append("gpu_probe_observation.observed_count")
    if missing:
        return PassResult(
            pass_id="gpu_not_mig_sliced",
            status=PASS_UNKNOWN,
            detail="GPU MIG dedication could not be determined; missing or invalid field(s): " + ", ".join(missing),
            verdict_effect=UNKNOWN,
            metadata={"missing_expected_paths": missing},
        )

    assert modes is not None
    assert observed_count is not None
    if len(modes) != observed_count:
        return PassResult(
            pass_id="gpu_not_mig_sliced",
            status=PASS_UNKNOWN,
            detail=(
                "GPU MIG dedication could not be determined; observed_mig_modes contains "
                f"{len(modes)} row(s) but observed_count is {observed_count}"
            ),
            verdict_effect=UNKNOWN,
            metadata={
                "missing_expected_paths": ["gpu_probe_observation.observed_mig_modes"],
                "observed_mig_modes_count": len(modes),
                "observed_count": observed_count,
            },
        )

    def canonical_mode(value: str) -> str:
        normalized = value.strip().upper()
        if normalized.startswith("[") and normalized.endswith("]"):
            normalized = normalized[1:-1].strip()
        return normalized

    acceptable = {"DISABLED", "N/A", "NOT APPLICABLE"}
    for idx, mode in enumerate(modes):
        normalized = canonical_mode(mode)
        if normalized in acceptable:
            continue
        if normalized == "ENABLED":
            return PassResult(
                pass_id="gpu_not_mig_sliced",
                status=PASS_UNKNOWN,
                detail=(
                    f"GPU {idx} reports MIG enabled: {mode}; instance-level GI/CI evidence "
                    "is required to decide whether capacity was actually sliced"
                ),
                verdict_effect=UNKNOWN,
                metadata={"observed_index": idx, "observed_mig_mode": mode},
            )
        return PassResult(
            pass_id="gpu_not_mig_sliced",
            status=PASS_UNKNOWN,
            detail=f"GPU {idx} reports unrecognized MIG mode: {mode!r}",
            verdict_effect=UNKNOWN,
            metadata={"observed_index": idx, "observed_mig_mode": mode},
        )

    na_count = sum(1 for mode in modes if canonical_mode(mode) in {"N/A", "NOT APPLICABLE"})
    detail = f"no observed GPU reported MIG enabled across {len(modes)} MIG mode field(s)"
    if na_count:
        detail += f"; {na_count} mode field(s) reported N/A"
    return PassResult(
        pass_id="gpu_not_mig_sliced",
        status=PASS_SATISFIED,
        detail=detail,
        verdict_effect=SUPPORTED,
        metadata={"observed_mig_modes": modes},
    )
