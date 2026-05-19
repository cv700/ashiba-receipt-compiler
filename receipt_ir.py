#!/usr/bin/env python3
"""Receipt IR data structures for the minimum evidence compiler."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid

from constants import COMPILER_VERSION, UNKNOWN


def utc_now() -> str:
    """Return a receipt-controlled UTC timestamp with trailing Z."""
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_receipt_id() -> str:
    """Return a short receipt id of the form rcpt.<8-char-hex>."""
    return f"rcpt.{uuid.uuid4().hex[:8]}"


@dataclass
class PassResult:
    """Result emitted by one deterministic compiler pass."""

    pass_id: str
    status: str
    detail: str
    verdict_effect: str | None = None
    absence: list[dict[str, Any]] = field(default_factory=list)
    compiler_error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        return {key: value for key, value in out.items() if value not in (None, [], {})}


@dataclass
class ReceiptIR:
    """Claim-bound Receipt IR for deterministic evidence compilation."""

    claim: dict[str, Any]
    expected_evidence: list[str]
    artifacts: dict[str, Any]
    claim_type: str = ""
    receipt_id: str = field(default_factory=new_receipt_id)
    created_at: str = field(default_factory=utc_now)
    compiler_version: str = COMPILER_VERSION
    absence: list[dict[str, Any]] = field(default_factory=list)
    pass_results: list[dict[str, Any]] = field(default_factory=list)
    compiler_errors: list[dict[str, str]] = field(default_factory=list)
    verdict: dict[str, str] = field(default_factory=lambda: {"status": UNKNOWN, "basis": "verdict not generated"})
    boundary: dict[str, list[str]] = field(default_factory=lambda: {"supports": [], "does_not_support": []})
    unsupported_inferences: list[str] = field(default_factory=list)
    artifact_manifest: list[dict[str, Any]] = field(default_factory=list)
    input_set_hash: str = ""
    incident_manifest: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_bundle(
        cls,
        bundle: dict[str, Any],
        artifact_manifest: list[dict[str, Any]] | None = None,
        input_set_hash: str = "",
    ) -> "ReceiptIR":
        """Create IR from a single JSON bundle (v1 compat)."""
        claim = bundle.get("claim")
        expected_evidence = bundle.get("expected_evidence")
        artifacts = bundle.get("artifacts")
        if not isinstance(claim, dict):
            claim = {"id": "claim.unknown", "text": ""}
        if not isinstance(expected_evidence, list):
            expected_evidence = []
        if not isinstance(artifacts, dict):
            artifacts = {}
        return cls(
            claim=claim,
            expected_evidence=[str(item) for item in expected_evidence],
            artifacts=artifacts,
            artifact_manifest=artifact_manifest or [],
            input_set_hash=input_set_hash,
        )

    @classmethod
    def from_artifacts(
        cls,
        artifacts: dict[str, Any],
        claim: dict[str, Any],
        expected_evidence: list[str],
        claim_type: str = "",
        artifact_manifest: list[dict[str, Any]] | None = None,
        input_set_hash: str = "",
        incident_manifest: dict[str, Any] | None = None,
    ) -> "ReceiptIR":
        """Create IR from a pre-merged artifacts dict and claim type config."""
        return cls(
            claim=claim,
            expected_evidence=[str(item) for item in expected_evidence],
            artifacts=artifacts,
            claim_type=claim_type,
            artifact_manifest=artifact_manifest or [],
            input_set_hash=input_set_hash,
            incident_manifest=incident_manifest or {},
        )

    def to_dict(self) -> dict[str, Any]:
        out = {
            "receipt_id": self.receipt_id,
            "created_at": self.created_at,
            "compiler_version": self.compiler_version,
            "claim": self.claim,
            "expected_evidence": self.expected_evidence,
            "absence": self.absence,
            "artifacts": self.artifacts,
            "pass_results": self.pass_results,
            "compiler_errors": self.compiler_errors,
            "verdict": self.verdict,
            "boundary": self.boundary,
            "unsupported_inferences": self.unsupported_inferences,
            "artifact_manifest": self.artifact_manifest,
            "input_set_hash": self.input_set_hash,
        }
        if self.claim_type:
            out["claim_type"] = self.claim_type
        if self.incident_manifest:
            out["incident_manifest"] = self.incident_manifest
        return out
