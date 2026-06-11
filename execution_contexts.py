#!/usr/bin/env python3
"""Typed execution-context disclosure handlers."""

from __future__ import annotations

from typing import Any, Callable


ContextDisclosureHandler = Callable[[dict[str, Any]], list[str]]


def _gpu_goodput_context_v0_disclosures(execution_context: dict[str, Any]) -> list[str]:
    disclosures: list[str] = []

    topology = execution_context.get("topology_manifest")
    if isinstance(topology, dict):
        coverage_ratio = topology.get("coverage_ratio")
        if isinstance(coverage_ratio, (int, float)) and coverage_ratio < 1.0:
            nodes_tested = topology.get("nodes_tested", "unknown")
            nodes_provisioned = topology.get("nodes_provisioned", "unknown")
            pct = max(0.0, coverage_ratio) * 100
            disclosures.append(
                f"Receipt covers {nodes_tested}/{nodes_provisioned} provisioned nodes ({pct:.1f}% coverage)"
            )

    system_state = execution_context.get("system_state")
    if isinstance(system_state, dict):
        freshly_rebooted = system_state.get("freshly_rebooted_nodes")
        if isinstance(freshly_rebooted, int) and freshly_rebooted > 0:
            disclosures.append(
                f"{freshly_rebooted} nodes were rebooted within 1 hour of test (uptime < 3600s)"
            )
        ecc_reboot_suspects = system_state.get("ecc_reboot_suspects")
        if isinstance(ecc_reboot_suspects, int) and ecc_reboot_suspects > 0:
            disclosures.append(
                f"{ecc_reboot_suspects} nodes show zero volatile ECC errors but nonzero aggregate "
                "(possible reboot to clear errors)"
            )

    ambient_load = execution_context.get("ambient_load")
    if isinstance(ambient_load, dict) and ambient_load.get("ambient_load_level") == "negligible":
        disclosures.append(
            "Test conducted under negligible fabric load; results may not reflect contended performance"
        )

    if not isinstance(execution_context.get("software_stack"), dict) or not execution_context.get("software_stack"):
        disclosures.append("Software stack not captured; environment reproducibility unknown")

    if not execution_context.get("challenge_nonce"):
        disclosures.append("No challenge nonce; receipt replay cannot be excluded")

    if (
        not isinstance(execution_context.get("probe_manifest_commitment"), dict)
        or not execution_context.get("probe_manifest_commitment")
    ):
        disclosures.append("No pre-committed probe manifest; probe selection by provider cannot be excluded")

    return disclosures


def _gpu_lending_decision_context_v0_disclosures(execution_context: dict[str, Any]) -> list[str]:
    """Disclose the lender decision rule bound to an attestation receipt.

    The rule maps receipt verdicts to lender actions (release payment, hold
    payment, haircut, cure request, dispute). The receipt does not execute the
    action; it discloses which rule the verdict feeds.
    """
    disclosures: list[str] = []

    decision_rule = execution_context.get("decision_rule")
    if isinstance(decision_rule, dict) and decision_rule:
        rule_parts = [
            f"{verdict} -> {action}"
            for verdict, action in sorted(decision_rule.items())
            if isinstance(action, str) and action
        ]
        if rule_parts:
            owner = execution_context.get("decision_owner")
            owner_label = f" (owner: {owner})" if isinstance(owner, str) and owner else ""
            disclosures.append(
                "Lender decision rule bound to this receipt" + owner_label + ": " + "; ".join(rule_parts)
            )
    if not disclosures:
        disclosures.append("No lender decision rule supplied; verdict-to-action mapping is not on record")

    disclosures.append(
        "Attestation evidence decides identity and freshness only; this receipt does not show "
        "that contracted capacity was delivered. Capacity claims require delivery/probe evidence."
    )
    return disclosures


EXECUTION_CONTEXT_DISCLOSURES: dict[str, ContextDisclosureHandler] = {
    "gpu_goodput_context_v0": _gpu_goodput_context_v0_disclosures,
    "gpu_lending_decision_context_v0": _gpu_lending_decision_context_v0_disclosures,
}


def execution_context_disclosures(execution_context: dict[str, Any]) -> list[str]:
    """Return boundary disclosures for a typed execution context extension."""
    if not execution_context:
        return []

    schema_id = execution_context.get("schema_id")
    if isinstance(schema_id, str):
        handler = EXECUTION_CONTEXT_DISCLOSURES.get(schema_id)
        if handler is not None:
            return handler(execution_context)
        if schema_id:
            return [
                (
                    f"Execution context schema {schema_id!r} not recognized; "
                    "domain-specific disclosures not available"
                )
            ]
    return ["Execution context schema not supplied; domain-specific disclosures not available"]
