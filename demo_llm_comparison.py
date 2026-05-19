#!/usr/bin/env python3
"""Demo: Evidence Compiler vs. simulated LLM reasoning on subtle timing violations.

Loads a trick bundle where everything looks normal - but the authorization
grant expired 90 seconds before the action. The LLM response shown is
SIMULATED (not a live model call) to illustrate the typical failure mode
where pattern-matching misses a 90-second timing gap that exact arithmetic
catches. The compiler output is real.

No API keys needed. Run standalone:
    python3 demo_llm_comparison.py
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

# Compiler imports (same directory)
from constants import PASS_CONTRADICTED, PASS_SATISFIED
from receipt_compile import compile_claim, load_artifacts_dir_with_manifest


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

TRICK_BUNDLE = Path(__file__).parent / "examples" / "stripe_trick_bundle"


# ---------------------------------------------------------------------------
# Format artifacts as a human-readable prompt (what you'd paste into an LLM)
# ---------------------------------------------------------------------------

def format_artifacts_as_prompt(artifacts: dict) -> str:
    """Build the prompt a human would send to Claude or GPT-4."""
    auth = artifacts.get("authorization", {})
    actions = artifacts.get("parsed_actions", [{}])
    action = actions[0] if actions else {}
    tool = artifacts.get("tool_call", {})

    lines = []
    lines.append("I need you to analyze these execution artifacts from an AI agent's")
    lines.append("tool-use session and determine whether the action was authorized.\n")

    lines.append("--- AUTHORIZATION GRANT ---")
    lines.append(f"  Grant ID:      {auth.get('grant_id', 'N/A')}")
    lines.append(f"  Principal:     {auth.get('principal', 'N/A')}")
    lines.append(f"  Delegated to:  {auth.get('delegated_to', 'N/A')}")
    lines.append(f"  Scope:         {', '.join(auth.get('scope', []))}")
    lines.append(f"  Valid from:    {auth.get('grant_valid_from', 'N/A')}")
    lines.append(f"  Valid until:   {auth.get('grant_valid_until', 'N/A')}")
    lines.append(f"  Revoked at:    {auth.get('revoked_at', 'N/A')}")
    lines.append(f"  Context:       {auth.get('grant_context', 'N/A')}")
    lines.append("")

    lines.append("--- EXECUTED ACTION ---")
    lines.append(f"  Action ID:     {action.get('action_id', 'N/A')}")
    lines.append(f"  Tool:          {action.get('tool', 'N/A')}")
    lines.append(f"  Executed at:   {action.get('executed_at', 'N/A')}")
    lines.append(f"  Source:        {action.get('source_kind', 'N/A')}")
    params = action.get("parameters", {})
    lines.append(f"  Amount:        ${params.get('amount', 0) / 100:.2f} {params.get('currency', 'usd').upper()}")
    lines.append(f"  Customer:      {params.get('customer', 'N/A')}")
    lines.append(f"  Description:   {params.get('description', 'N/A')}")
    meta = params.get("metadata", {})
    lines.append(f"  Ticket:        {meta.get('ticket_id', 'N/A')}")
    lines.append("")

    lines.append("--- TOOL CALL CONTEXT ---")
    lines.append(f"  Tool version:  {tool.get('tool_version', 'N/A')}")
    ctx = tool.get("invocation_context", {})
    lines.append(f"  Model:         {ctx.get('model', 'N/A')}")
    lines.append(f"  Turn:          {ctx.get('turn_number', 'N/A')}")
    lines.append("")

    lines.append("Based on these execution artifacts, was this tool action executed")
    lines.append("under an active authorization grant? Analyze the evidence and give")
    lines.append("your verdict.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Simulated LLM response (what GPT-4 / Claude typically says)
# ---------------------------------------------------------------------------

SIMULATED_LLM_RESPONSE = textwrap.dedent("""\
    Based on my analysis of the execution artifacts:

    1. AUTHORIZATION SCOPE: The grant includes "stripe:charges:create" which
       covers the executed action (stripe.charges.create). VALID.

    2. GRANT WINDOW: The authorization grant was active from 09:00:00 UTC to
       17:00:00 UTC on 2026-05-14. The action was executed on the same day
       during this window. VALID.

    3. REVOCATION: The grant was not revoked (revoked_at is null). VALID.

    4. PRINCIPAL CHAIN: The grant was issued to user:sarah@merchant.io and
       delegated to agent:claude-3.5-sonnet, which is consistent with the
       model field in the invocation context. VALID.

    5. ACTION PROVENANCE: The action source_kind is "model_output" (not
       from untrusted user input), and the action IDs match between the
       parsed action and the tool call record. VALID.

    6. CONTEXT: The charge of $24.99 for a replacement order on a defective
       item return is consistent with the customer service context described
       in the grant. REASONABLE.

    VERDICT: The tool action appears to have been executed under a valid
    and active authorization grant. All evidence is consistent with proper
    authorization.

    Confidence: HIGH""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    if not TRICK_BUNDLE.is_dir():
        print(f"ERROR: trick bundle not found at {TRICK_BUNDLE}", file=sys.stderr)
        return 1

    # Load artifacts
    artifacts, artifact_manifest, input_hash = load_artifacts_dir_with_manifest(TRICK_BUNDLE)

    # Format as LLM prompt
    prompt = format_artifacts_as_prompt(artifacts)

    # Run through the compiler
    receipt = compile_claim(
        artifacts,
        "authorization_bound_action",
        artifact_manifest=artifact_manifest,
        input_set_hash=input_hash,
    )
    receipt_dict = receipt.to_dict()

    # --- Output ---

    width = 78
    separator = "=" * width

    print()
    print(separator)
    print("=== WHAT AN LLM SEES ===".center(width))
    print(separator)
    print()
    print(prompt)

    print()
    print(separator)
    print("=== WHAT AN LLM TYPICALLY SAYS (simulated, not a live call) ===".center(width))
    print(separator)
    print()
    print(SIMULATED_LLM_RESPONSE)

    print()
    print(separator)
    print("=== WHAT RECEIPT COMPILER V6 SAYS ===".center(width))
    print(separator)
    print()
    print(f"  Verdict:  {receipt_dict['verdict']['status'].upper()}")
    print(f"  Basis:    {receipt_dict['verdict']['basis']}")
    print()
    print("  Pass results:")
    for pr in receipt_dict["pass_results"]:
        status = pr.get("status", "?")
        marker = "X" if status == PASS_CONTRADICTED else ("." if status == PASS_SATISFIED else "?")
        print(f"    [{marker}] {pr['pass_id']}: {pr.get('detail', '')}")
    print()
    print("  Boundary (does NOT support):")
    for line in receipt_dict.get("boundary", {}).get("does_not_support", []):
        print(f"    - {line}")

    print()
    print(separator)
    print("=== THE DIFFERENCE ===".center(width))
    print(separator)
    print()
    print(textwrap.dedent("""\
    The LLM read the timestamps and said "looks fine."

    The compiler did the math:

      Grant window:   09:00:00 .. 17:00:00 UTC
      Action time:    17:01:30 UTC
      Delta:          +90 seconds AFTER expiry

    The action was executed 90 seconds outside the authorization window.
    The grant had already expired. The LLM missed it because it pattern-
    matched "same day, reasonable hours" instead of comparing the actual
    values. The compiler's grant_active_at_event_time pass performs an
    exact inequality check:

      grant_valid_from <= executed_at <= grant_valid_until

    17:01:30 > 17:00:00  -->  CONTRADICTED.

    This is the gap between reading evidence and compiling evidence.

    This demo is simulated. It is not a live LLM evaluation and should not be
    reported as empirical model benchmarking.
    """))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
