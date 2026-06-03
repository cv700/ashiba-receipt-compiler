#!/usr/bin/env python3
"""GPU sustained-capacity impairment watch pass."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from constants import (
    CONTRADICTED,
    PASS_CONTRADICTED,
    PASS_SATISFIED,
    PASS_UNKNOWN,
    SUPPORTED,
    UNKNOWN,
)
from evidence_paths import evidence_is_present, get_path
from gpu_pass_utils import integer, number, string_list, utc_timestamp
from receipt_ir import PassResult, ReceiptIR


GPU_IMPAIRMENT_WATCH_PASS_ID = "gpu_sustained_capacity_impairment_watch"
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


@dataclass(frozen=True)
class ImpairmentThresholds:
    min_sample_count: int
    min_mean_gpu_utilization_pct: float
    min_clock_ratio: float
    max_throttle_sample_fraction: float
    min_thermal_margin_c: float
    min_power_margin_watts: float
    max_uncorrectable_ecc_delta: int
    max_xid_count_delta: int
    max_fabric_error_delta: int

    def as_metadata(self) -> dict[str, float | int]:
        return {
            "min_sample_count": self.min_sample_count,
            "min_mean_gpu_utilization_pct": self.min_mean_gpu_utilization_pct,
            "min_clock_ratio": self.min_clock_ratio,
            "max_throttle_sample_fraction": self.max_throttle_sample_fraction,
            "min_thermal_margin_c": self.min_thermal_margin_c,
            "min_power_margin_watts": self.min_power_margin_watts,
            "max_uncorrectable_ecc_delta": self.max_uncorrectable_ecc_delta,
            "max_xid_count_delta": self.max_xid_count_delta,
            "max_fabric_error_delta": self.max_fabric_error_delta,
        }


@dataclass(frozen=True)
class DeclaredImpairmentWindow:
    start: datetime
    end: datetime
    thresholds: ImpairmentThresholds


@dataclass(frozen=True)
class ImpairmentBinding:
    node_id: str
    gpu_uuids: set[str]
    basis: str


@dataclass(frozen=True)
class ImpairmentSample:
    gpu_uuid: str
    gpu_utilization_pct: float
    sm_clock_mhz: float
    expected_sm_clock_mhz: float
    gpu_temp_c: float
    thermal_limit_c: float
    power_watts: float
    power_limit_watts: float
    throttle_reasons: list[str]
    uncorrectable_ecc_delta: int
    xid_count_delta: int
    fabric_error_delta: int

    @property
    def clock_ratio(self) -> float:
        return self.sm_clock_mhz / self.expected_sm_clock_mhz

    @property
    def thermal_margin_c(self) -> float:
        return self.thermal_limit_c - self.gpu_temp_c

    @property
    def power_margin_watts(self) -> float:
        return self.power_limit_watts - self.power_watts


@dataclass(frozen=True)
class WindowedImpairmentSamples:
    rows: list[ImpairmentSample]
    outside_window_count: int


@dataclass(frozen=True)
class ImpairmentSummary:
    sample_count: int
    mean_gpu_utilization_pct: float
    min_clock_ratio: float
    min_thermal_margin_c: float
    min_power_margin_watts: float
    throttle_sample_fraction: float
    total_uncorrectable_ecc_delta: int
    total_xid_count_delta: int
    total_fabric_error_delta: int

    @classmethod
    def from_samples(cls, rows: list[ImpairmentSample]) -> "ImpairmentSummary":
        sample_count = len(rows)
        return cls(
            sample_count=sample_count,
            mean_gpu_utilization_pct=sum(row.gpu_utilization_pct for row in rows) / sample_count,
            min_clock_ratio=min(row.clock_ratio for row in rows),
            min_thermal_margin_c=min(row.thermal_margin_c for row in rows),
            min_power_margin_watts=min(row.power_margin_watts for row in rows),
            throttle_sample_fraction=sum(1 for row in rows if row.throttle_reasons) / sample_count,
            total_uncorrectable_ecc_delta=sum(row.uncorrectable_ecc_delta for row in rows),
            total_xid_count_delta=sum(row.xid_count_delta for row in rows),
            total_fabric_error_delta=sum(row.fabric_error_delta for row in rows),
        )

    def observed_metadata(self) -> dict[str, float | int]:
        return {
            "sample_count": self.sample_count,
            "mean_gpu_utilization_pct": round(self.mean_gpu_utilization_pct, 3),
            "min_clock_ratio": round(self.min_clock_ratio, 6),
            "min_thermal_margin_c": round(self.min_thermal_margin_c, 3),
            "min_power_margin_watts": round(self.min_power_margin_watts, 3),
            "throttle_sample_fraction": round(self.throttle_sample_fraction, 6),
            "total_uncorrectable_ecc_delta": self.total_uncorrectable_ecc_delta,
            "total_xid_count_delta": self.total_xid_count_delta,
            "total_fabric_error_delta": self.total_fabric_error_delta,
        }

    def dimension_margins(self, thresholds: ImpairmentThresholds) -> dict[str, float | int]:
        return {
            "sample_count_above_min": self.sample_count - thresholds.min_sample_count,
            "mean_gpu_utilization_pct_above_min": round(
                self.mean_gpu_utilization_pct - thresholds.min_mean_gpu_utilization_pct, 3
            ),
            "clock_ratio_above_min": round(self.min_clock_ratio - thresholds.min_clock_ratio, 6),
            "thermal_margin_c_above_min": round(
                self.min_thermal_margin_c - thresholds.min_thermal_margin_c, 3
            ),
            "power_margin_watts_above_min": round(
                self.min_power_margin_watts - thresholds.min_power_margin_watts, 3
            ),
            "throttle_fraction_below_max": round(
                thresholds.max_throttle_sample_fraction - self.throttle_sample_fraction, 6
            ),
            "uncorrectable_ecc_delta_remaining": (
                thresholds.max_uncorrectable_ecc_delta - self.total_uncorrectable_ecc_delta
            ),
            "xid_count_delta_remaining": thresholds.max_xid_count_delta - self.total_xid_count_delta,
            "fabric_error_delta_remaining": thresholds.max_fabric_error_delta - self.total_fabric_error_delta,
        }


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


def _declared_impairment_window(values: dict[str, Any]) -> DeclaredImpairmentWindow | PassResult:
    start = utc_timestamp(values["declaration.window_start"])
    end = utc_timestamp(values["declaration.window_end"])
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

    threshold_values = {
        "min_sample_count": integer(values["declaration.min_sample_count"]),
        "min_mean_gpu_utilization_pct": number(values["declaration.min_mean_gpu_utilization_pct"]),
        "min_clock_ratio": number(values["declaration.min_clock_ratio"]),
        "max_throttle_sample_fraction": number(values["declaration.max_throttle_sample_fraction"]),
        "min_thermal_margin_c": number(values["declaration.min_thermal_margin_c"]),
        "min_power_margin_watts": number(values["declaration.min_power_margin_watts"]),
        "max_uncorrectable_ecc_delta": integer(values["declaration.max_uncorrectable_ecc_delta"]),
        "max_xid_count_delta": integer(values["declaration.max_xid_count_delta"]),
        "max_fabric_error_delta": integer(values["declaration.max_fabric_error_delta"]),
    }
    invalid = _invalid_threshold_paths(threshold_values)
    if invalid:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; invalid threshold field(s): "
            + ", ".join(invalid),
            {"invalid_threshold_paths": invalid},
        )

    return DeclaredImpairmentWindow(
        start=start,
        end=end,
        thresholds=ImpairmentThresholds(
            min_sample_count=int(threshold_values["min_sample_count"]),
            min_mean_gpu_utilization_pct=float(threshold_values["min_mean_gpu_utilization_pct"]),
            min_clock_ratio=float(threshold_values["min_clock_ratio"]),
            max_throttle_sample_fraction=float(threshold_values["max_throttle_sample_fraction"]),
            min_thermal_margin_c=float(threshold_values["min_thermal_margin_c"]),
            min_power_margin_watts=float(threshold_values["min_power_margin_watts"]),
            max_uncorrectable_ecc_delta=int(threshold_values["max_uncorrectable_ecc_delta"]),
            max_xid_count_delta=int(threshold_values["max_xid_count_delta"]),
            max_fabric_error_delta=int(threshold_values["max_fabric_error_delta"]),
        ),
    )


def _invalid_threshold_paths(threshold_values: dict[str, float | int | None]) -> list[str]:
    threshold_rules = {
        "min_sample_count": lambda value: isinstance(value, int) and value > 0,
        "min_mean_gpu_utilization_pct": lambda value: isinstance(value, float) and 0 <= value <= 100,
        "min_clock_ratio": lambda value: isinstance(value, float) and value > 0,
        "max_throttle_sample_fraction": lambda value: isinstance(value, float) and 0 <= value <= 1,
        "min_thermal_margin_c": lambda value: isinstance(value, float) and value >= 0,
        "min_power_margin_watts": lambda value: isinstance(value, float) and value >= 0,
        "max_uncorrectable_ecc_delta": lambda value: isinstance(value, int) and value >= 0,
        "max_xid_count_delta": lambda value: isinstance(value, int) and value >= 0,
        "max_fabric_error_delta": lambda value: isinstance(value, int) and value >= 0,
    }
    return [
        "declaration." + key
        for key, valid in threshold_rules.items()
        if not valid(threshold_values[key])
    ]


def _impairment_binding_result(values: dict[str, Any]) -> ImpairmentBinding | PassResult:
    window_node_id = str(values["gpu_impairment_window.node_id"])
    binding_node_id = str(values["gpu_impairment_binding.node_id"])
    binding_basis = str(values["gpu_impairment_binding.binding_basis"])
    bound_gpu_uuids = string_list(values["gpu_impairment_binding.gpu_uuids"])
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
    return ImpairmentBinding(
        node_id=window_node_id,
        gpu_uuids=set(bound_gpu_uuids),
        basis=binding_basis,
    )


def _impairment_samples_in_window(
    values: dict[str, Any],
    declared: DeclaredImpairmentWindow,
    binding: ImpairmentBinding,
) -> WindowedImpairmentSamples | PassResult:
    samples = values["gpu_impairment_window.samples"]
    if not isinstance(samples, list) or not samples:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; sample list missing or empty",
            {"missing_expected_paths": ["gpu_impairment_window.samples"]},
        )

    rows: list[ImpairmentSample] = []
    malformed_indexes: list[int] = []
    unbound_gpu_uuids: list[str] = []
    outside_window_count = 0

    for idx, sample in enumerate(samples):
        if not isinstance(sample, dict):
            malformed_indexes.append(idx)
            continue
        observed_at = utc_timestamp(sample.get("observed_at"))
        if observed_at is None:
            malformed_indexes.append(idx)
            continue
        if observed_at < declared.start or observed_at > declared.end:
            outside_window_count += 1
            continue

        gpu_uuid = sample.get("gpu_uuid")
        if not isinstance(gpu_uuid, str) or not gpu_uuid:
            malformed_indexes.append(idx)
            continue
        if gpu_uuid not in binding.gpu_uuids:
            unbound_gpu_uuids.append(gpu_uuid)

        impairment_sample = _impairment_sample_from_row(gpu_uuid, sample)
        if impairment_sample is None:
            malformed_indexes.append(idx)
            continue
        rows.append(impairment_sample)

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
    return WindowedImpairmentSamples(rows=rows, outside_window_count=outside_window_count)


def _impairment_sample_from_row(gpu_uuid: str, sample: dict[str, Any]) -> ImpairmentSample | None:
    numeric_values: dict[str, float] = {}
    for field in GPU_IMPAIRMENT_SAMPLE_NUMERIC_FIELDS:
        numeric_value = number(sample.get(field))
        if numeric_value is None:
            return None
        numeric_values[field] = numeric_value

    throttle_reasons = sample.get("throttle_reasons")
    if not isinstance(throttle_reasons, list) or any(not isinstance(reason, str) for reason in throttle_reasons):
        return None
    if numeric_values["expected_sm_clock_mhz"] <= 0:
        return None
    if (
        numeric_values["uncorrectable_ecc_delta"] < 0
        or numeric_values["xid_count_delta"] < 0
        or numeric_values["fabric_error_delta"] < 0
    ):
        return None

    return ImpairmentSample(
        gpu_uuid=gpu_uuid,
        gpu_utilization_pct=numeric_values["gpu_utilization_pct"],
        sm_clock_mhz=numeric_values["sm_clock_mhz"],
        expected_sm_clock_mhz=numeric_values["expected_sm_clock_mhz"],
        gpu_temp_c=numeric_values["gpu_temp_c"],
        thermal_limit_c=numeric_values["thermal_limit_c"],
        power_watts=numeric_values["power_watts"],
        power_limit_watts=numeric_values["power_limit_watts"],
        throttle_reasons=throttle_reasons,
        uncorrectable_ecc_delta=int(numeric_values["uncorrectable_ecc_delta"]),
        xid_count_delta=int(numeric_values["xid_count_delta"]),
        fabric_error_delta=int(numeric_values["fabric_error_delta"]),
    )


def _impairment_metadata(
    values: dict[str, Any],
    binding: ImpairmentBinding,
    samples: WindowedImpairmentSamples,
    summary: ImpairmentSummary,
    thresholds: ImpairmentThresholds,
) -> dict[str, Any]:
    return {
        "hardware_class": str(values["declaration.hardware_class"]),
        "node_id": binding.node_id,
        "window_start": values["declaration.window_start"],
        "window_end": values["declaration.window_end"],
        "binding_basis": binding.basis,
        "gpu_uuid_count": len(binding.gpu_uuids),
        "outside_window_sample_count": samples.outside_window_count,
        "observed": summary.observed_metadata(),
        "thresholds": thresholds.as_metadata(),
        "dimension_margins": summary.dimension_margins(thresholds),
    }


def _impairment_contradictions(
    summary: ImpairmentSummary,
    thresholds: ImpairmentThresholds,
) -> list[str]:
    contradictions = []
    if summary.min_clock_ratio < thresholds.min_clock_ratio:
        contradictions.append(
            f"minimum clock ratio {summary.min_clock_ratio:.3g} is below declared floor "
            f"{thresholds.min_clock_ratio:g}"
        )
    if summary.throttle_sample_fraction > thresholds.max_throttle_sample_fraction:
        contradictions.append(
            f"throttle sample fraction {summary.throttle_sample_fraction:.3g} exceeds declared maximum "
            f"{thresholds.max_throttle_sample_fraction:g}"
        )
    if summary.min_thermal_margin_c < thresholds.min_thermal_margin_c:
        contradictions.append(
            f"minimum thermal margin {summary.min_thermal_margin_c:.3g} C is below declared floor "
            f"{thresholds.min_thermal_margin_c:g} C"
        )
    if summary.min_power_margin_watts < thresholds.min_power_margin_watts:
        contradictions.append(
            f"minimum power margin {summary.min_power_margin_watts:.3g} W is below declared floor "
            f"{thresholds.min_power_margin_watts:g} W"
        )
    if summary.total_uncorrectable_ecc_delta > thresholds.max_uncorrectable_ecc_delta:
        contradictions.append(
            f"uncorrectable ECC delta {summary.total_uncorrectable_ecc_delta} exceeds declared maximum "
            f"{thresholds.max_uncorrectable_ecc_delta}"
        )
    if summary.total_xid_count_delta > thresholds.max_xid_count_delta:
        contradictions.append(
            f"Xid count delta {summary.total_xid_count_delta} exceeds declared maximum "
            f"{thresholds.max_xid_count_delta}"
        )
    if summary.total_fabric_error_delta > thresholds.max_fabric_error_delta:
        contradictions.append(
            f"fabric error delta {summary.total_fabric_error_delta} exceeds declared maximum "
            f"{thresholds.max_fabric_error_delta}"
        )
    return contradictions


def gpu_sustained_capacity_impairment_watch(ir: ReceiptIR, params: dict[str, Any] | None = None) -> PassResult:
    """Check objective impairment dimensions under meaningful observed load."""
    values, missing = _required_impairment_values(ir)
    if missing:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; missing field(s): " + ", ".join(missing),
            {"missing_expected_paths": missing},
        )

    declared = _declared_impairment_window(values)
    if isinstance(declared, PassResult):
        return declared

    binding = _impairment_binding_result(values)
    if isinstance(binding, PassResult):
        return binding

    sample_result = _impairment_samples_in_window(values, declared, binding)
    if isinstance(sample_result, PassResult):
        return sample_result

    summary = ImpairmentSummary.from_samples(sample_result.rows)
    thresholds = declared.thresholds
    metadata = _impairment_metadata(values, binding, sample_result, summary, thresholds)

    if summary.sample_count < thresholds.min_sample_count:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; too few samples fell inside the declared window",
            metadata,
        )
    if summary.mean_gpu_utilization_pct < thresholds.min_mean_gpu_utilization_pct:
        return _unknown_impairment_result(
            "capacity impairment watch could not be determined; observed load was below the meaningful-load threshold",
            metadata,
        )

    contradictions = _impairment_contradictions(summary, thresholds)
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
