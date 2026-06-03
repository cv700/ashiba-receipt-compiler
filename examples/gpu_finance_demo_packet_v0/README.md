# GPU Finance Demo Packet - ARC Receipt Compiler

## What This Is

A demo showing how ARC produces bounded GPU verification receipts for a
declared GPU-backed compute asset. It uses existing ARC examples only. No
customer proprietary data is used.

This folder is a wrapper packet: it stores docs plus generated receipt cards and
JSON. The compiler inputs remain the source examples named in `commands.txt`.

## Files That Matter

- `README.md` - 5-minute walkthrough.
- `claim_summary.md` - receipt claims and scope limits.
- `evidence_manifest.json` - all 7 evidence artifacts labeled by source.
- `commands.txt` - exact regeneration commands.
- `receipt_cards/` - 3 ARC-generated receipt cards.
- `receipt_json/` - 3 ARC-generated JSON receipts.
- `ie_report_excerpt.md` - short IE-style report excerpt.
- `reviewer_note.md` - PR review note and final verification record.

## 5-Minute Walkthrough

1. Read `claim_summary.md` to see what claim is being tested and what it does
   not prove.
2. Read `evidence_manifest.json` to see every evidence file, its source, and
   its label.
3. Run Receipt 1:

```bash
./compile examples/gpu_acceptance_lambda_a10_supported \
  --claim-type gpu_capacity_acceptance --card
```

4. Read `receipt_cards/capacity_supported.txt`.
5. Run Receipt 2:

```bash
./compile examples/gpu_acceptance_mig_unknown \
  --claim-type gpu_capacity_acceptance --card
```

6. Read `receipt_cards/mig_unknown.txt` and note the MIG GI/CI evidence gap in
   the basis. ARC does not list this under `Evidence missing`; the generated
   card treats MIG enabled as ambiguous evidence.
7. Run Receipt 3:

```bash
./compile examples/gpu_serial_match_contradicted \
  --claim-type gpu_serial_collateral_match --card
```

NOTE: Receipt 3 is a synthetic adversarial fixture. It is not a real asset.

8. Read `receipt_cards/serial_contradicted_synthetic.txt`.
9. Read `ie_report_excerpt.md` for the IE-style one-page finding.

## What This Proves

- ARC can compile a supported GPU capacity snapshot receipt from complete,
  consistent evidence.
- ARC can return `unknown` instead of false support when MIG evidence is
  ambiguous.
- ARC can return `contradicted` when synthetic collateral identity evidence
  conflicts.

## What This Does Not Prove

This does not prove legal ownership, GPU title, future yield, uptime,
workload-specific performance, physical custody location, or anything about
any real customer's actual operations.
