# Reviewer Note - GPU Finance Demo Packet v0

Branch: `feat/compute-labs-demo-spec`
Date: 2026-06-04

## What Changed

Added `examples/gpu_finance_demo_packet_v0/`:

- `README.md`
- `claim_summary.md`
- `evidence_manifest.json`
- `commands.txt`
- `receipt_cards/` with 3 ARC-generated cards
- `receipt_json/` with 3 ARC-generated JSON receipts
- `ie_report_excerpt.md`
- `reviewer_note.md`

Updated `gallery_manifest.json` so the wrapper packet is registered as
`not_applicable` in gallery tests. No runtime code was added. No pass logic or
claim pack was changed.

## Product Layer Reached

Demo packet: evidence labels, ARC-generated receipt cards, JSON receipts, and a
short IE-style report. This is compile-only against existing examples.

## What The Receipts Prove

Receipt 1: `gpu_acceptance_lambda_a10_supported` returns `SUPPORTED` when the
declared A10 capacity snapshot and observed `nvidia-smi` evidence are complete
and consistent.

Receipt 2: `gpu_acceptance_mig_unknown` returns `UNKNOWN` when MIG is enabled
and GI/CI instance records are absent.

Receipt 3: `gpu_serial_match_contradicted` returns `CONTRADICTED` when declared
serials conflict with observed serials. This is a synthetic adversarial fixture.

## What They Do Not Prove

Legal ownership, GPU title, future yield, uptime, workload-specific performance,
physical custody location, borrower credit quality, or any real customer asset
condition.

## False-Supported Case Tested

`gpu_serial_match_contradicted`: declared serial `GPU-H100-SXM-0008`; observed
serial `GPU-H100-SXM-XXXX`. ARC returns `CONTRADICTED` instead of silently
accepting an operational but wrong unit.

## Missing Evidence Returns UNKNOWN

`gpu_acceptance_mig_unknown`: MIG enabled, no GI/CI records. ARC returns
`UNKNOWN` and names the required next evidence: `nvidia-smi mig -lgi` and
`nvidia-smi mig -lci`.

## Direct Conflict Returns CONTRADICTED

`gpu_serial_match_contradicted`: serial mismatch between collateral declaration
and probe observation.

## Files Changed And Why

New demo packet files live under `examples/gpu_finance_demo_packet_v0/`.
`gallery_manifest.json` was updated only so the wrapper packet does not break
gallery tests. The redundant spec file was removed because the README and this
reviewer note now define the cold-review path. No `passes.py` edits. No
`claim_packs/` edits.

## Commands Run - Final Verified

```text
PYTHONDONTWRITEBYTECODE=1 python3 test_receipt_compiler.py  -> PASS
PYTHONDONTWRITEBYTECODE=1 python3 test_gpu_acceptance.py    -> PASS
PYTHONDONTWRITEBYTECODE=1 python3 test_gpu_collateral.py    -> PASS
PYTHONDONTWRITEBYTECODE=1 python3 test_scan.py              -> PASS

./compile examples/gpu_acceptance_lambda_a10_supported \
  --claim-type gpu_capacity_acceptance --card                -> SUPPORTED

./compile examples/gpu_acceptance_mig_unknown \
  --claim-type gpu_capacity_acceptance --card                -> UNKNOWN

./compile examples/gpu_serial_match_contradicted \
  --claim-type gpu_serial_collateral_match --card            -> CONTRADICTED
```

## What To Check First

1. Open `receipt_cards/capacity_supported.txt` and confirm `SUPPORTED`.
2. Open `receipt_cards/mig_unknown.txt` and confirm `UNKNOWN`.
3. Open `receipt_cards/serial_contradicted_synthetic.txt` and confirm
   `CONTRADICTED` plus the visible `SYNTHETIC` note at the top.
4. Open `ie_report_excerpt.md` and confirm it reads in under 60 seconds.
5. Run `zsh examples/gpu_finance_demo_packet_v0/commands.txt`.
