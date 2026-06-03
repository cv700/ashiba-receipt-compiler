# GPU Finance Demo Packet Spec

## Purpose

This folder is a wrapper packet for a GPU lender diligence demo. ARC turns
separate declared GPU capacity claims into deterministic receipts a reviewer can
use to accept, dispute, route, or request more evidence.

The wrapper stores documentation and generated outputs. It is not itself a
compile target; `commands.txt` points to the source examples that ARC compiles.

## Day 2 Receipt Set

Receipt 1: declared GPU capacity was observed as an A10 capacity snapshot.

- Claim type: `gpu_capacity_acceptance`
- Source example: `examples/gpu_acceptance_lambda_a10_supported`
- Expected verdict: `supported`
- Generated card: `receipt_cards/capacity_supported.txt`
- Generated JSON: `receipt_json/capacity_supported.json`

Receipt 2: declared GPU capacity could not be decided because MIG is enabled
and instance-level GI/CI evidence is required.

- Claim type: `gpu_capacity_acceptance`
- Source example: `examples/gpu_acceptance_mig_unknown`
- Expected verdict: `unknown`
- Generated card: `receipt_cards/mig_unknown.txt`
- Generated JSON: `receipt_json/mig_unknown.json`

## Boundaries

- This packet does not prove GPU ownership or legal title.
- This packet does not prove future uptime, yield, or borrower credit quality.
- This packet does not prove physical custody location.
- This packet does not prove workload-specific performance.
- This packet does not assess any real customer's asset condition.

## Risks

- The MIG card reports the GI/CI requirement in the verdict basis, not under
  `Evidence missing`; reviewer docs call this out explicitly.
- Power/utilization is out of scope for Day 2 because this branch does not
  include the power claim pack or fixtures.
- The wrapper folder should stay decomposed into docs, manifest, commands,
  receipt cards, and receipt JSON. Do not collapse it into one large spec file.
