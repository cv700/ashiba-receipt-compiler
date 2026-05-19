#!/usr/bin/env python3
"""Evidence Compiler demo: deterministic receipt catches a 90-second timing violation.

Run standalone (no API keys, no dependencies beyond stdlib):
    python3 demo.py

Mutate and re-run instantly:
    python3 demo.py --set executed_at=2026-05-14T16:59:00Z
    python3 demo.py --set grant_valid_until=2026-05-14T18:00:00Z
    python3 demo.py --set revoked_at=2026-05-14T16:30:00Z
    python3 demo.py --set executed_at=2099-01-01T00:00:00Z

Other flags:
    --compare    Show simulated LLM comparison panel
    --json       Print the raw receipt JSON
    --quiet      Just the verdict line (for scripting)

The trick: everything in the evidence bundle looks normal. Scope matches,
principal matches, no revocation. But the authorization grant expired
90 seconds before the action executed. The compiler catches it with
exact arithmetic. A human skimming the timestamps will miss it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from constants import PASS_CONTRADICTED, PASS_SATISFIED
from receipt_compile import compile_claim, load_artifacts_dir_with_manifest


TRICK_BUNDLE = Path(__file__).parent / "examples" / "stripe_trick_bundle"


FIELD_MAP = {
    # Short names map to dotted paths into the artifact bundle.
    "executed_at": ("parsed_actions", "parsed_actions", 0, "executed_at"),
    "grant_valid_from": ("authorization", "authorization", "grant_valid_from"),
    "grant_valid_until": ("authorization", "authorization", "grant_valid_until"),
    "revoked_at": ("authorization", "authorization", "revoked_at"),
    "source_kind": ("parsed_actions", "parsed_actions", 0, "source_kind"),
}


def _apply_mutations(artifacts: dict, mutations: list[str]) -> list[str]:
    """Apply --set key=value mutations to artifacts in-place. Returns descriptions."""
    applied = []
    for mutation in mutations:
        if "=" not in mutation:
            print(f"  ERROR: --set requires key=value format, got: {mutation}", file=sys.stderr)
            continue
        key, value = mutation.split("=", 1)
        key = key.strip()
        if key not in FIELD_MAP:
            available = ", ".join(sorted(FIELD_MAP))
            print(f"  ERROR: unknown field '{key}'. Available: {available}", file=sys.stderr)
            continue

        path = FIELD_MAP[key]
        file_key = path[0]  # which JSON file it lives in
        # Navigate to parent, set the leaf
        obj = artifacts
        for step in path[1:-1]:
            obj = obj[step]
        leaf = path[-1]

        # Type coercion
        if value.lower() == "null" or value.lower() == "none":
            obj[leaf] = None
            applied.append(f"{key} = null")
        else:
            obj[leaf] = value
            applied.append(f"{key} = {value}")

    return applied


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evidence Compiler demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Mutate fields:  --set executed_at=2026-05-14T16:59:00Z",
    )
    parser.add_argument("--compare", action="store_true", help="Show simulated LLM comparison")
    parser.add_argument("--json", action="store_true", help="Print raw receipt JSON")
    parser.add_argument("--quiet", action="store_true", help="Verdict line only")
    parser.add_argument("--set", action="append", default=[], metavar="FIELD=VALUE",
                        help="Mutate a field before compilation (repeatable)")
    args = parser.parse_args()

    if not TRICK_BUNDLE.is_dir():
        print(f"ERROR: trick bundle not found at {TRICK_BUNDLE}", file=sys.stderr)
        return 1

    # Compile
    artifacts, artifact_manifest, input_hash = load_artifacts_dir_with_manifest(TRICK_BUNDLE)

    # Apply mutations
    mutations_applied = _apply_mutations(artifacts, args.set) if args.set else []
    receipt = compile_claim(
        artifacts,
        "authorization_bound_action",
        artifact_manifest=artifact_manifest,
        input_set_hash=input_hash,
    )
    rd = receipt.to_dict()

    if args.json:
        print(json.dumps(rd, indent=2))
        return 0

    if args.quiet:
        print(rd["verdict"]["status"].upper())
        return 0

    # -----------------------------------------------------------------------
    # MUTATIONS BANNER (if any)
    # -----------------------------------------------------------------------
    if mutations_applied:
        print()
        print("  --- MUTATIONS APPLIED ---------------------------------------------")
        for m in mutations_applied:
            print(f"    {m}")
        print()

    # -----------------------------------------------------------------------
    # PUNCHLINE
    # -----------------------------------------------------------------------
    verdict_status = rd["verdict"]["status"].upper()
    basis = rd["verdict"]["basis"]
    grant_until = artifacts.get("authorization", {}).get("grant_valid_until", "?")
    executed_at = artifacts.get("parsed_actions", [{}])[0].get("executed_at", "?")

    print()
    print(f"  VERDICT:  {verdict_status}")
    print(f"  BASIS:    {basis}")
    print()
    print(f"    grant_valid_until:  {grant_until}")
    print(f"    executed_at:        {executed_at}")
    print()

    # -----------------------------------------------------------------------
    # RECEIPT
    # -----------------------------------------------------------------------
    print("  --- RECEIPT --------------------------------------------------------")
    print()
    print(f"  Receipt ID:   {rd['receipt_id']}")
    print(f"  Claim:        {rd['claim']['text']}")
    print(f"  Verdict:      {rd['verdict']['status'].upper()}")
    print(f"  Basis:        {rd['verdict']['basis']}")
    print()
    print("  Passes:")
    for pr in rd["pass_results"]:
        status = pr.get("status", "?")
        if status == PASS_CONTRADICTED:
            marker = "FAIL"
        elif status == PASS_SATISFIED:
            marker = "  ok"
        else:
            marker = "  --"
        print(f"    [{marker}]  {pr['pass_id']}")
        if status == PASS_CONTRADICTED:
            print(f"             {pr.get('detail', '')}")
    print()

    # -----------------------------------------------------------------------
    # BOUNDARY
    # -----------------------------------------------------------------------
    print("  --- BOUNDARY (what this does NOT prove) ---------------------------")
    print()
    for line in rd.get("boundary", {}).get("does_not_support", []):
        print(f"    - {line}")
    print()
    unsup = rd.get("unsupported_inferences", [])
    if unsup:
        print("  Unsupported inferences:")
        for line in unsup:
            print(f"    - {line}")
        print()

    # -----------------------------------------------------------------------
    # MECHANISM
    # -----------------------------------------------------------------------
    print("  --- MECHANISM ------------------------------------------------------")
    print()
    print("  7 deterministic passes. No model call. No API key. Each pass is")
    print("  an inequality check, a presence check, or a format validation.")
    print("  One CONTRADICTED pass means the entire receipt is CONTRADICTED.")
    print()
    print("  The failing pass (grant_active_at_event_time) performs:")
    print()
    print("    grant_valid_from <= executed_at <= grant_valid_until")
    print("    17:01:30 > 17:00:00  =>  CONTRADICTED")
    print()

    # -----------------------------------------------------------------------
    # CHALLENGE
    # -----------------------------------------------------------------------
    if not mutations_applied:
        print("  --- TRY TO BREAK IT ------------------------------------------------")
        print()
        print("  Copy-paste these. Each should produce a different verdict:")
        print()
        print("    python3 demo.py --set executed_at=2026-05-14T16:59:00Z    # => SUPPORTED")
        print("    python3 demo.py --set grant_valid_until=null              # => UNKNOWN")
        print("    python3 demo.py --set revoked_at=2026-05-14T16:30:00Z    # => CONTRADICTED")
        print("    python3 demo.py --set executed_at=2099-01-01T00:00:00Z   # => CONTRADICTED")
        print()
        print("  Combine mutations:")
        print("    python3 demo.py --set executed_at=2026-05-14T16:59:00Z --set revoked_at=2026-05-14T16:30:00Z")
        print()
        print("  Raw receipt:  python3 demo.py --json | python3 -m json.tool")
        print()

    # -----------------------------------------------------------------------
    # OPTIONAL: LLM comparison
    # -----------------------------------------------------------------------
    if args.compare:
        _print_comparison()

    return 0


def _print_comparison() -> None:
    """Print the simulated LLM comparison panel."""
    print()
    print("  ==================================================================")
    print("  SIMULATED LLM RESPONSE (not a live call - illustrative only)")
    print("  ==================================================================")
    print()
    print("  A typical LLM given this evidence bundle responds:")
    print()
    print('    "The grant was active from 09:00 to 17:00 UTC on 2026-05-14.')
    print('     The action was executed on the same day during this window.')
    print('     VERDICT: Valid authorization. Confidence: HIGH."')
    print()
    print("  The LLM pattern-matched 'same day, reasonable hours' instead of")
    print("  comparing 17:01:30 against the 17:00:00 boundary. The compiler")
    print("  performed the exact inequality and found the violation.")
    print()
    print("  NOTE: This is a simulated response to illustrate the typical")
    print("  failure mode. It is not empirical model benchmarking. To test a")
    print("  live model, paste the contents of the 3 JSON files into your LLM")
    print("  of choice and ask whether the action was authorized.")
    print()


if __name__ == "__main__":
    raise SystemExit(main())
