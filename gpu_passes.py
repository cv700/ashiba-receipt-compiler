#!/usr/bin/env python3
"""GPU-specific deterministic compiler passes."""

from __future__ import annotations

import re
from datetime import datetime, timezone
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


UTC_FMT = "%Y-%m-%dT%H:%M:%SZ"
GPU_POWER_UTILIZATION_PASS_ID = "gpu_power_utilization_consistency"
GPU_IMPAIRMENT_WATCH_PASS_ID = "gpu_sustained_capacity_impairment_watch"
GPU_POWER_UTILIZATION_REQUIRED_PATHS = (
    "declaration.hardware_class",
    "declaration.window_start",
    "declaration.window_end",
    "declaration.expected_power_band_kw.min",
    "declaration.expected_power_band_kw.max",
    "declaration.expected_gpu_utilization_pct.min",
    "declaration.expected_gpu_utilization_pct.max",
    "gpu_utilization_window.node_id",
    "gpu_utilization_window.samples",
    "power_window.rack_id",
    "power_window.samples",
    "power_window.provenance.custody_tier",
    "power_window.provenance.measurement_type",
    "node_rack_binding.node_id",
    "node_rack_binding.rack_id",
    "node_rack_binding.binding_basis",
)
GPU_POWER_UTILIZATION_OPTIONAL_PATHS = (
    "power_window.provenance.source_label",
    "power_window.provenance.clock_source",
    "power_window.provenance.collection_method",
    "node_rack_binding.load_attribution",
)
INDEPENDENT_POWER_CUSTODY_TIERS = {"facility_exported", "third_party_sensor", "lender_controlled"}
POWER_CUSTODY_TIERS = {"operator_exported", *INDEPENDENT_POWER_CUSTODY_TIERS}
POWER_MEASUREMENT_TYPES = {"per_outlet", "rack_aggregate", "facility_meter"}
POWER_BINDING_BASES = {"rack_label", "pdu_outlet_map", "facility_circuit_map", "operator_assertion"}
RACK_AGGREGATE_LOAD_ATTRIBUTIONS = {"single_bound_node", "full_rack_declared_inventory", "pdu_outlet_map"}
GPU_IMPAIRMENT_REQUIRED_PATHS = (
    "declaration.hardware_class",
    "declaration.window_start",
    "declaration.window_end",
    "declaration.min_sample_count",
    "declaration.min_mean_gpu_utilization_pct",
    "declaration.min_clock_ratio",
    "declaration.max_throttle_sample_fraction",
    "declaration.min_thermal_margin_c",
    "declaration.min_power_margin_watts",
    "declaration.max_uncorrectable_ecc_delta",
    "declaration.max_xid_count_delta",
    "declaration.max_fabric_error_delta",
    "gpu_impairment_window.node_id",
    "gpu_impairment_window.samples",
    "gpu_impairment_binding.node_id",
    "gpu_impairment_binding.gpu_uuids",
    "gpu_impairment_binding.binding_basis",
)
GPU_IMPAIRMENT_BINDING_BASES = {"nvidia_smi_uuid", "dcgm_uuid", "probe_manifest", "operator_assertion"}
GPU_IMPAIRMENT_SAMPLE_NUMERIC_FIELDS = (
    "gpu_utilization_pct",
    "sm_clock_mhz",
    "expected_sm_clock_mhz",
    "gpu_temp_c",
    "thermal_limit_c",
    "power_watts",
    "power_limit_watts",
    "uncorrectable_ecc_delta",
    "xid_count_delta",
    "fabric_error_delta",
)


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


def _utc_timestamp(value: Any) -> datetime | None:
    """Parse a UTC timestamp with trailing Z, or return None."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, UTC_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _window_sample_values(
    samples: Any,
    value_key: str,
    start: datetime,
    end: datetime,
) -> tuple[list[float], list[int], int] | None:
    """Return numeric sample values inside a window, malformed indexes, and outside count."""
    if not isinstance(samples, list) or not samples:
        return None

    values: list[float] = []
    malformed_indexes: list[int] = []
    outside_window_count = 0
    for idx, sample in enumerate(samples):
        if not isinstance(sample, dict):
            malformed_indexes.append(idx)
            continue
        observed_at = _utc_timestamp(sample.get("observed_at"))
        value = _number(sample.get(value_key))
        if observed_at is None or value is None:
            malformed_indexes.append(idx)
            continue
        if observed_at < start or observed_at > end:
            outside_window_count += 1
            continue
        values.append(value)
    return values, malformed_indexes, outside_window_count


def _unknown_power_utilization_result(detail: str, metadata: dict[str, Any]) -> PassResult:
    return PassResult(
        pass_id=GPU_POWER_UTILIZATION_PASS_ID,
        status=PASS_UNKNOWN,
        detail=detail,
        verdict_effect=UNKNOWN,
        metadata=metadata,
    )


def _unknown_impairment_result(detail: str, metadata: dict[str, Any]) -> PassResult:
    return PassResult(
        pass_id=GPU_IMPAIRMENT_WATCH_PASS_ID,
        status=PASS_UNKNOWN,
        detail=detail,
        verdict_effect=UNKNOWN,
        metadata=metadata,
    )


def _required_impairment_values(ir: ReceiptIR) -> tuple[dict[str, Any], list[str]]:
    values = {
        path: get_path(ir.artifacts, path)
        for path in GPU_IMPAIRMENT_REQUIRED_PATHS
    }
    missing = [
        path for path, value in values.items()
        if not evidence_is_present(value)
    ]
    return values, missing


def _required_power_utilization_values(ir: ReceiptIR) -> tuple[dict[str, Any], list[str]]:
    values = {
        path: get_path(ir.artifacts, path)
        for path in GPU_POWER_UTILIZATION_REQUIRED_PATHS
    }
    values.update({
        path: get_path(ir.artifacts, path)
        for path in GPU_POWER_UTILIZATION_OPTIONAL_PATHS
    })
    missing = [path for path, value in values.items() if not evidence_is_present(value)]
    missing = [path for path in missing if path in GPU_POWER_UTILIZATION_REQUIRED_PATHS]
    return values, missing


def _declared_power_utilization_window(
    values: dict[str, Any],
) -> tuple[datetime, datetime, float, float, float, float] | PassResult:
    start = _utc_timestamp(values["declaration.window_start"])
    end = _utc_timestamp(values["declaration.window_end"])
    power_min = _number(values["declaration.expected_power_band_kw.min"])
    power_max = _number(values["declaration.expected_power_band_kw.max"])
    util_min = _number(values["declaration.expected_gpu_utilization_pct.min"])
    util_max = _number(values["declaration.expected_gpu_utilization_pct.max"])
    invalid = []
    if start is None:
        invalid.append("declaration.window_start")
    if end is None:
        invalid.append("declaration.window_end")
    if power_min is None:
        invalid.append("declaration.expected_power_band_kw.min")
    if power_max is None:
        invalid.append("declaration.expected_power_band_kw.max")
    if util_min is None:
        invalid.append("declaration.expected_gpu_utilization_pct.min")
    if util_max is None:
        invalid.append("declaration.expected_gpu_utilization_pct.max")
    if invalid:
        return _unknown_power_utilization_result(
            "power/utilization consistency could not be determined; invalid field(s): " + ", ".join(invalid),
            {"missing_expected_paths": invalid},
        )

    assert start is not None
    assert end is not None
    assert power_min is not None
    assert power_max is not None
    assert util_min is not None
    assert util_max is not None
    if end <= start:
        return _unknown_power_utilization_result(
            "measurement window is invalid; declaration.window_end must be after window_start",
            {
                "window_start": values["declaration.window_start"],
                "window_end": values["declaration.window_end"],
            },
        )
    if power_min > power_max or util_min > util_max:
        return _unknown_power_utilization_result(
            "declared expected power or utilization band has min greater than max",
            {
                "expected_power_band_kw": {"min": power_min, "max": power_max},
                "expected_gpu_utilization_pct": {"min": util_min, "max": util_max},
            },
        )
    return start, end, power_min, power_max, util_min, util_max


def _power_utilization_binding_result(values: dict[str, Any]) -> PassResult | tuple[str, str]:
    gpu_node_id = str(values["gpu_utilization_window.node_id"])
    bound_node_id = str(values["node_rack_binding.node_id"])
    power_rack_id = str(values["power_window.rack_id"])
    bound_rack_id = str(values["node_rack_binding.rack_id"])
    binding_mismatches = []
    if gpu_node_id != bound_node_id:
        binding_mismatches.append(f"GPU node {gpu_node_id!r} does not match binding node {bound_node_id!r}")
    if power_rack_id != bound_rack_id:
        binding_mismatches.append(f"power rack {power_rack_id!r} does not match binding rack {bound_rack_id!r}")
    if binding_mismatches:
        return PassResult(
            pass_id=GPU_POWER_UTILIZATION_PASS_ID,
            status=PASS_CONTRADICTED,
            detail="; ".join(binding_mismatches) + ".",
            verdict_effect=CONTRADICTED,
            metadata={
                "gpu_node_id": gpu_node_id,
                "binding_node_id": bound_node_id,
                "power_rack_id": power_rack_id,
                "binding_rack_id": bound_rack_id,
            },
        )
    return gpu_node_id, power_rack_id


def _power_utilization_provenance_result(values: dict[str, Any]) -> PassResult | dict[str, Any]:
    custody_tier = str(values["power_window.provenance.custody_tier"])
    measurement_type = str(values["power_window.provenance.measurement_type"])
    binding_basis = str(values["node_rack_binding.binding_basis"])
    load_attribution = values.get("node_rack_binding.load_attribution")

    invalid = []
    if custody_tier not in POWER_CUSTODY_TIERS:
        invalid.append("power_window.provenance.custody_tier")
    if measurement_type not in POWER_MEASUREMENT_TYPES:
        invalid.append("power_window.provenance.measurement_type")
    if binding_basis not in POWER_BINDING_BASES:
        invalid.append("node_rack_binding.binding_basis")
    metadata = {
        "power_custody_tier": custody_tier,
        "power_measurement_type": measurement_type,
        "node_rack_binding_basis": binding_basis,
        "node_rack_load_attribution": load_attribution,
    }
    for optional_path in (
        "power_window.provenance.source_label",
        "power_window.provenance.clock_source",
        "power_window.provenance.collection_method",
    ):
        if evidence_is_present(values.get(optional_path)):
            metadata[optional_path.rsplit(".", 1)[1]] = values[optional_path]
    if invalid:
        return _unknown_power_utilization_result(
            "power/utilization consistency could not be determined; invalid provenance field(s): "
            + ", ".join(invalid),
            {"missing_expected_paths": invalid, **metadata},
        )
    if custody_tier not in INDEPENDENT_POWER_CUSTODY_TIERS:
        return _unknown_power_utilization_result(
            f"power/utilization consistency could not be determined; power evidence custody tier "
            f"{custody_tier!r} is not independent enough for this claim",
            metadata,
        )
    if binding_basis == "operator_assertion":
        return _unknown_power_utilization_result(
            "power/utilization consistency could not be determined; node-to-rack binding is only an operator assertion",
            metadata,
        )
    if measurement_type == "facility_meter":
        return _unknown_power_utilization_result(
            "power/utilization consistency could not be determined; facility-meter evidence is too coarse for a bound node/rack claim in v0",
            metadata,
        )
    if (
        measurement_type == "rack_aggregate"
        and load_attribution not in RACK_AGGREGATE_LOAD_ATTRIBUTIONS
    ):
        return _unknown_power_utilization_result(
            "power/utilization consistency could not be determined; aggregate rack power lacks load attribution for the bound node/rack pair",
            metadata,
        )
    return metadata


def _power_utilization_samples_in_window(
    values: dict[str, Any],
    start: datetime,
    end: datetime,
) -> tuple[list[float], list[float], int, int] | PassResult:
    gpu_samples = _window_sample_values(
        values["gpu_utilization_window.samples"],
        "gpu_utilization_pct",
        start,
        end,
    )
    power_samples = _window_sample_values(
        values["power_window.samples"],
        "rack_power_kw",
        start,
        end,
    )
    if gpu_samples is None or power_samples is None:
        missing_sample_paths = []
        if gpu_samples is None:
            missing_sample_paths.append("gpu_utilization_window.samples")
        if power_samples is None:
            missing_sample_paths.append("power_window.samples")
        return _unknown_power_utilization_result(
            "power/utilization consistency could not be determined; sample list missing or empty",
            {"missing_expected_paths": missing_sample_paths},
        )

    gpu_values, malformed_gpu_indexes, outside_gpu_count = gpu_samples
    power_values, malformed_power_indexes, outside_power_count = power_samples
    if malformed_gpu_indexes or malformed_power_indexes:
        return _unknown_power_utilization_result(
            "power/utilization consistency could not be determined; malformed sample row(s) present",
            {
                "malformed_gpu_sample_indexes": malformed_gpu_indexes,
                "malformed_power_sample_indexes": malformed_power_indexes,
            },
        )
    if not gpu_values or not power_values:
        missing_inside = []
        if not gpu_values:
            missing_inside.append("gpu_utilization_window.samples")
        if not power_values:
            missing_inside.append("power_window.samples")
        return _unknown_power_utilization_result(
            "power/utilization consistency could not be determined; no samples fell inside the declared window",
            {
                "missing_expected_paths": missing_inside,
                "outside_window_gpu_sample_count": outside_gpu_count,
                "outside_window_power_sample_count": outside_power_count,
            },
        )
    return gpu_values, power_values, outside_gpu_count, outside_power_count


def _gpu_sku_tokens(value: Any) -> set[str]:
    if not isinstance(value, str):
        return set()
    normalized = value.upper().replace("PCI-E", "PCIE")
    return {token for token in re.split(r"[^A-Z0-9]+", normalized) if token}


def _gpu_sku_family(value: Any) -> str | None:
    """Return the supported GPU SKU family token from a declared SKU string."""
    tokens = _gpu_sku_tokens(value)
    for family in ("H100", "H200", "A100", "A10", "B200"):
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
        supported_families = "H100, H200, A100, A10, B200"
        return PassResult(
            pass_id="gpu_sku_count_match",
            status=PASS_UNKNOWN,
            detail=(
                f"declared GPU SKU {declared_sku!r} does not contain a supported "
                f"family token ({supported_families})"
            ),
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


def _declared_impairment_thresholds(
    values: dict[str, Any],
) -> tuple[datetime, datetime, dict[str, float | int]] | PassResult:
    start = _utc_timestamp(values["declaration.window_start"])
    end = _utc_timestamp(values["declaration.window_end"])
    if start is None or end is None:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; declaration window is not valid UTC",
            {
                "window_start": values["declaration.window_start"],
                "window_end": values["declaration.window_end"],
            },
        )
    if start >= end:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; declaration window start is not before end",
            {
                "window_start": values["declaration.window_start"],
                "window_end": values["declaration.window_end"],
            },
        )

    min_sample_count = _integer(values["declaration.min_sample_count"])
    min_mean_utilization = _number(values["declaration.min_mean_gpu_utilization_pct"])
    min_clock_ratio = _number(values["declaration.min_clock_ratio"])
    max_throttle_fraction = _number(values["declaration.max_throttle_sample_fraction"])
    min_thermal_margin = _number(values["declaration.min_thermal_margin_c"])
    min_power_margin = _number(values["declaration.min_power_margin_watts"])
    max_ecc_delta = _integer(values["declaration.max_uncorrectable_ecc_delta"])
    max_xid_delta = _integer(values["declaration.max_xid_count_delta"])
    max_fabric_delta = _integer(values["declaration.max_fabric_error_delta"])
    thresholds: dict[str, float | int] = {}
    invalid: list[str] = []

    if min_sample_count is None or min_sample_count <= 0:
        invalid.append("declaration.min_sample_count")
    else:
        thresholds["min_sample_count"] = min_sample_count
    if min_mean_utilization is None or min_mean_utilization < 0 or min_mean_utilization > 100:
        invalid.append("declaration.min_mean_gpu_utilization_pct")
    else:
        thresholds["min_mean_gpu_utilization_pct"] = min_mean_utilization
    if min_clock_ratio is None or min_clock_ratio <= 0:
        invalid.append("declaration.min_clock_ratio")
    else:
        thresholds["min_clock_ratio"] = min_clock_ratio
    if max_throttle_fraction is None or max_throttle_fraction < 0 or max_throttle_fraction > 1:
        invalid.append("declaration.max_throttle_sample_fraction")
    else:
        thresholds["max_throttle_sample_fraction"] = max_throttle_fraction
    if min_thermal_margin is None or min_thermal_margin < 0:
        invalid.append("declaration.min_thermal_margin_c")
    else:
        thresholds["min_thermal_margin_c"] = min_thermal_margin
    if min_power_margin is None or min_power_margin < 0:
        invalid.append("declaration.min_power_margin_watts")
    else:
        thresholds["min_power_margin_watts"] = min_power_margin
    if max_ecc_delta is None or max_ecc_delta < 0:
        invalid.append("declaration.max_uncorrectable_ecc_delta")
    else:
        thresholds["max_uncorrectable_ecc_delta"] = max_ecc_delta
    if max_xid_delta is None or max_xid_delta < 0:
        invalid.append("declaration.max_xid_count_delta")
    else:
        thresholds["max_xid_count_delta"] = max_xid_delta
    if max_fabric_delta is None or max_fabric_delta < 0:
        invalid.append("declaration.max_fabric_error_delta")
    else:
        thresholds["max_fabric_error_delta"] = max_fabric_delta

    if invalid:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; invalid threshold field(s): "
            + ", ".join(invalid),
            {"invalid_threshold_paths": invalid},
        )
    return start, end, thresholds


def _impairment_binding_result(values: dict[str, Any]) -> PassResult | tuple[str, set[str], str]:
    window_node_id = str(values["gpu_impairment_window.node_id"])
    binding_node_id = str(values["gpu_impairment_binding.node_id"])
    binding_basis = str(values["gpu_impairment_binding.binding_basis"])
    bound_gpu_uuids = _string_list(values["gpu_impairment_binding.gpu_uuids"])
    if not bound_gpu_uuids:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; bound GPU UUID list is missing or empty",
            {"missing_expected_paths": ["gpu_impairment_binding.gpu_uuids"]},
        )
    if binding_basis not in GPU_IMPAIRMENT_BINDING_BASES:
        return _unknown_impairment_result(
            f"capacity impairment watch could not be determined; binding basis {binding_basis!r} is not recognized",
            {
                "binding_basis": binding_basis,
                "accepted_binding_bases": sorted(GPU_IMPAIRMENT_BINDING_BASES),
            },
        )
    if window_node_id != binding_node_id:
        return PassResult(
            pass_id=GPU_IMPAIRMENT_WATCH_PASS_ID,
            status=PASS_CONTRADICTED,
            detail=(
                f"capacity impairment evidence node {window_node_id!r} does not match "
                f"binding node {binding_node_id!r}"
            ),
            verdict_effect=CONTRADICTED,
            metadata={
                "gpu_impairment_window_node_id": window_node_id,
                "gpu_impairment_binding_node_id": binding_node_id,
            },
        )
    return window_node_id, set(bound_gpu_uuids), binding_basis


def _impairment_samples_in_window(
    values: dict[str, Any],
    start: datetime,
    end: datetime,
    bound_gpu_uuids: set[str],
) -> PassResult | tuple[list[dict[str, Any]], int]:
    samples = values["gpu_impairment_window.samples"]
    if not isinstance(samples, list) or not samples:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; sample list missing or empty",
            {"missing_expected_paths": ["gpu_impairment_window.samples"]},
        )

    rows: list[dict[str, Any]] = []
    malformed_indexes: list[int] = []
    unbound_gpu_uuids: list[str] = []
    outside_window_count = 0

    for idx, sample in enumerate(samples):
        if not isinstance(sample, dict):
            malformed_indexes.append(idx)
            continue
        observed_at = _utc_timestamp(sample.get("observed_at"))
        if observed_at is None:
            malformed_indexes.append(idx)
            continue
        if observed_at < start or observed_at > end:
            outside_window_count += 1
            continue

        gpu_uuid = sample.get("gpu_uuid")
        if not isinstance(gpu_uuid, str) or not gpu_uuid:
            malformed_indexes.append(idx)
            continue
        if gpu_uuid not in bound_gpu_uuids:
            unbound_gpu_uuids.append(gpu_uuid)

        numeric_values: dict[str, float] = {}
        row_malformed = False
        for field in GPU_IMPAIRMENT_SAMPLE_NUMERIC_FIELDS:
            numeric_value = _number(sample.get(field))
            if numeric_value is None:
                row_malformed = True
                break
            numeric_values[field] = numeric_value
        throttle_reasons = sample.get("throttle_reasons")
        if not isinstance(throttle_reasons, list) or any(not isinstance(reason, str) for reason in throttle_reasons):
            row_malformed = True
        if row_malformed:
            malformed_indexes.append(idx)
            continue
        if numeric_values["expected_sm_clock_mhz"] <= 0:
            malformed_indexes.append(idx)
            continue
        if (
            numeric_values["uncorrectable_ecc_delta"] < 0
            or numeric_values["xid_count_delta"] < 0
            or numeric_values["fabric_error_delta"] < 0
        ):
            malformed_indexes.append(idx)
            continue

        rows.append({
            "gpu_uuid": gpu_uuid,
            **numeric_values,
            "throttle_reasons": throttle_reasons,
        })

    if malformed_indexes:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; malformed sample row(s) present",
            {"malformed_sample_indexes": malformed_indexes},
        )
    if unbound_gpu_uuids:
        return PassResult(
            pass_id=GPU_IMPAIRMENT_WATCH_PASS_ID,
            status=PASS_CONTRADICTED,
            detail="capacity impairment samples reference GPU UUID(s) outside the bound node schedule.",
            verdict_effect=CONTRADICTED,
            metadata={"unbound_gpu_uuids": sorted(set(unbound_gpu_uuids))},
        )
    if not rows:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; no samples fell inside the declared window",
            {"outside_window_sample_count": outside_window_count},
        )
    return rows, outside_window_count


def _impairment_window_summary(rows: list[dict[str, Any]]) -> dict[str, float | int]:
    sample_count = len(rows)
    mean_utilization = sum(row["gpu_utilization_pct"] for row in rows) / sample_count
    clock_ratios = [row["sm_clock_mhz"] / row["expected_sm_clock_mhz"] for row in rows]
    thermal_margins = [row["thermal_limit_c"] - row["gpu_temp_c"] for row in rows]
    power_margins = [row["power_limit_watts"] - row["power_watts"] for row in rows]
    throttle_count = sum(1 for row in rows if row["throttle_reasons"])
    return {
        "sample_count": sample_count,
        "mean_gpu_utilization_pct": mean_utilization,
        "min_clock_ratio": min(clock_ratios),
        "min_thermal_margin_c": min(thermal_margins),
        "min_power_margin_watts": min(power_margins),
        "throttle_sample_fraction": throttle_count / sample_count,
        "total_uncorrectable_ecc_delta": int(sum(row["uncorrectable_ecc_delta"] for row in rows)),
        "total_xid_count_delta": int(sum(row["xid_count_delta"] for row in rows)),
        "total_fabric_error_delta": int(sum(row["fabric_error_delta"] for row in rows)),
    }


def _impairment_dimension_margins(
    summary: dict[str, float | int],
    thresholds: dict[str, float | int],
) -> dict[str, float | int]:
    return {
        "sample_count_above_min": int(summary["sample_count"]) - int(thresholds["min_sample_count"]),
        "mean_gpu_utilization_pct_above_min": round(
            float(summary["mean_gpu_utilization_pct"]) - float(thresholds["min_mean_gpu_utilization_pct"]), 3
        ),
        "clock_ratio_above_min": round(float(summary["min_clock_ratio"]) - float(thresholds["min_clock_ratio"]), 6),
        "thermal_margin_c_above_min": round(
            float(summary["min_thermal_margin_c"]) - float(thresholds["min_thermal_margin_c"]), 3
        ),
        "power_margin_watts_above_min": round(
            float(summary["min_power_margin_watts"]) - float(thresholds["min_power_margin_watts"]), 3
        ),
        "throttle_fraction_below_max": round(
            float(thresholds["max_throttle_sample_fraction"]) - float(summary["throttle_sample_fraction"]), 6
        ),
        "uncorrectable_ecc_delta_remaining": int(thresholds["max_uncorrectable_ecc_delta"])
        - int(summary["total_uncorrectable_ecc_delta"]),
        "xid_count_delta_remaining": int(thresholds["max_xid_count_delta"]) - int(summary["total_xid_count_delta"]),
        "fabric_error_delta_remaining": int(thresholds["max_fabric_error_delta"])
        - int(summary["total_fabric_error_delta"]),
    }


def gpu_sustained_capacity_impairment_watch(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check objective impairment dimensions under meaningful observed load."""
    values, missing = _required_impairment_values(ir)
    if missing:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; missing field(s): " + ", ".join(missing),
            {"missing_expected_paths": missing},
        )

    declared = _declared_impairment_thresholds(values)
    if isinstance(declared, PassResult):
        return declared
    start, end, thresholds = declared

    binding = _impairment_binding_result(values)
    if isinstance(binding, PassResult):
        return binding
    node_id, bound_gpu_uuids, binding_basis = binding

    sample_result = _impairment_samples_in_window(values, start, end, bound_gpu_uuids)
    if isinstance(sample_result, PassResult):
        return sample_result
    rows, outside_window_count = sample_result

    summary = _impairment_window_summary(rows)
    metadata = {
        "hardware_class": str(values["declaration.hardware_class"]),
        "node_id": node_id,
        "window_start": values["declaration.window_start"],
        "window_end": values["declaration.window_end"],
        "binding_basis": binding_basis,
        "gpu_uuid_count": len(bound_gpu_uuids),
        "outside_window_sample_count": outside_window_count,
        "observed": {
            "sample_count": summary["sample_count"],
            "mean_gpu_utilization_pct": round(float(summary["mean_gpu_utilization_pct"]), 3),
            "min_clock_ratio": round(float(summary["min_clock_ratio"]), 6),
            "min_thermal_margin_c": round(float(summary["min_thermal_margin_c"]), 3),
            "min_power_margin_watts": round(float(summary["min_power_margin_watts"]), 3),
            "throttle_sample_fraction": round(float(summary["throttle_sample_fraction"]), 6),
            "total_uncorrectable_ecc_delta": summary["total_uncorrectable_ecc_delta"],
            "total_xid_count_delta": summary["total_xid_count_delta"],
            "total_fabric_error_delta": summary["total_fabric_error_delta"],
        },
        "thresholds": thresholds,
        "dimension_margins": _impairment_dimension_margins(summary, thresholds),
    }

    if int(summary["sample_count"]) < int(thresholds["min_sample_count"]):
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; too few samples fell inside the declared window",
            metadata,
        )
    if float(summary["mean_gpu_utilization_pct"]) < float(thresholds["min_mean_gpu_utilization_pct"]):
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; observed load was below the meaningful-load threshold",
            metadata,
        )

    contradictions = []
    if float(summary["min_clock_ratio"]) < float(thresholds["min_clock_ratio"]):
        contradictions.append(
            f"minimum clock ratio {float(summary['min_clock_ratio']):.3g} is below declared floor "
            f"{float(thresholds['min_clock_ratio']):g}"
        )
    if float(summary["throttle_sample_fraction"]) > float(thresholds["max_throttle_sample_fraction"]):
        contradictions.append(
            f"throttle sample fraction {float(summary['throttle_sample_fraction']):.3g} exceeds declared maximum "
            f"{float(thresholds['max_throttle_sample_fraction']):g}"
        )
    if float(summary["min_thermal_margin_c"]) < float(thresholds["min_thermal_margin_c"]):
        contradictions.append(
            f"minimum thermal margin {float(summary['min_thermal_margin_c']):.3g} C is below declared floor "
            f"{float(thresholds['min_thermal_margin_c']):g} C"
        )
    if float(summary["min_power_margin_watts"]) < float(thresholds["min_power_margin_watts"]):
        contradictions.append(
            f"minimum power margin {float(summary['min_power_margin_watts']):.3g} W is below declared floor "
            f"{float(thresholds['min_power_margin_watts']):g} W"
        )
    if int(summary["total_uncorrectable_ecc_delta"]) > int(thresholds["max_uncorrectable_ecc_delta"]):
        contradictions.append(
            f"uncorrectable ECC delta {int(summary['total_uncorrectable_ecc_delta'])} exceeds declared maximum "
            f"{int(thresholds['max_uncorrectable_ecc_delta'])}"
        )
    if int(summary["total_xid_count_delta"]) > int(thresholds["max_xid_count_delta"]):
        contradictions.append(
            f"Xid count delta {int(summary['total_xid_count_delta'])} exceeds declared maximum "
            f"{int(thresholds['max_xid_count_delta'])}"
        )
    if int(summary["total_fabric_error_delta"]) > int(thresholds["max_fabric_error_delta"]):
        contradictions.append(
            f"fabric error delta {int(summary['total_fabric_error_delta'])} exceeds declared maximum "
            f"{int(thresholds['max_fabric_error_delta'])}"
        )

    if contradictions:
        return PassResult(
            pass_id=GPU_IMPAIRMENT_WATCH_PASS_ID,
            status=PASS_CONTRADICTED,
            detail="; ".join(contradictions) + ".",
            verdict_effect=CONTRADICTED,
            metadata=metadata,
        )

    return PassResult(
        pass_id=GPU_IMPAIRMENT_WATCH_PASS_ID,
        status=PASS_SATISFIED,
        detail=(
            "observed GPU samples met declared capacity-impairment thresholds under meaningful load; "
            "this is not a predictive headroom guarantee"
        ),
        verdict_effect=SUPPORTED,
        metadata=metadata,
    )


def gpu_power_utilization_consistency(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check bound GPU utilization and independent power samples against declared bands."""
    values, missing = _required_power_utilization_values(ir)
    if missing:
        return _unknown_power_utilization_result(
            "power/utilization consistency could not be determined; missing field(s): " + ", ".join(missing),
            {"missing_expected_paths": missing},
        )

    declared = _declared_power_utilization_window(values)
    if isinstance(declared, PassResult):
        return declared
    start, end, power_min, power_max, util_min, util_max = declared

    binding = _power_utilization_binding_result(values)
    if isinstance(binding, PassResult):
        return binding
    gpu_node_id, power_rack_id = binding

    provenance = _power_utilization_provenance_result(values)
    if isinstance(provenance, PassResult):
        return provenance

    sample_result = _power_utilization_samples_in_window(values, start, end)
    if isinstance(sample_result, PassResult):
        return sample_result
    gpu_values, power_values, outside_gpu_count, outside_power_count = sample_result

    mean_gpu_utilization_pct = sum(gpu_values) / len(gpu_values)
    mean_rack_power_kw = sum(power_values) / len(power_values)
    metadata = {
        "hardware_class": str(values["declaration.hardware_class"]),
        "node_id": gpu_node_id,
        "rack_id": power_rack_id,
        "window_start": values["declaration.window_start"],
        "window_end": values["declaration.window_end"],
        "gpu_sample_count": len(gpu_values),
        "power_sample_count": len(power_values),
        "outside_window_gpu_sample_count": outside_gpu_count,
        "outside_window_power_sample_count": outside_power_count,
        "mean_gpu_utilization_pct": round(mean_gpu_utilization_pct, 3),
        "mean_rack_power_kw": round(mean_rack_power_kw, 3),
        "expected_gpu_utilization_pct": {"min": util_min, "max": util_max},
        "expected_power_band_kw": {"min": power_min, "max": power_max},
        **provenance,
    }
    contradictions = []
    if mean_gpu_utilization_pct < util_min or mean_gpu_utilization_pct > util_max:
        contradictions.append(
            f"mean GPU utilization {mean_gpu_utilization_pct:.3g}% is outside declared band "
            f"{util_min:g}-{util_max:g}%"
        )
    if mean_rack_power_kw < power_min or mean_rack_power_kw > power_max:
        contradictions.append(
            f"mean rack power {mean_rack_power_kw:.3g} kW is outside declared band "
            f"{power_min:g}-{power_max:g} kW"
        )
    if contradictions:
        return PassResult(
            pass_id=GPU_POWER_UTILIZATION_PASS_ID,
            status=PASS_CONTRADICTED,
            detail="; ".join(contradictions) + ".",
            verdict_effect=CONTRADICTED,
            metadata=metadata,
        )

    return PassResult(
        pass_id=GPU_POWER_UTILIZATION_PASS_ID,
        status=PASS_SATISFIED,
        detail=(
            f"mean GPU utilization {mean_gpu_utilization_pct:.3g}% and mean rack power "
            f"{mean_rack_power_kw:.3g} kW fell inside declared bands for bound node/rack evidence"
        ),
        verdict_effect=SUPPORTED,
        metadata=metadata,
    )
