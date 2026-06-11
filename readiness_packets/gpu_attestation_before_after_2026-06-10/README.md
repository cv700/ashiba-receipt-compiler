# GPU Attestation Before/After: Self-Report vs Nonce-Bound Identity

Date: 2026-06-10
Status: synthetic evidence. All attestation content in `after/` is
nvattest-shaped fixture data, not live H100 output. Until one live run binds
nonce + manifest + identity bridge, GPU attestation is **not** validated ARC
evidence (see `docs/gpu_attestation_evidence_status_2026-06-10.md`).

## The bounded claim

`claim.gpu_attested_identity_window`:

> Each GPU identity bridged from the contract schedule produced a fresh,
> nonce-bound NVIDIA attestation during the contract window.

Identity and freshness only. The claim does not cover delivered capacity,
utilization, or performance — every receipt in this packet discloses that
boundary, and the capacity question belongs to separate claim packs
(`gpu_capacity_acceptance`, `gpu_power_utilization_consistency`,
`gpu_sustained_capacity_impairment_watch`).

## Before: provider self-report

`before/` holds what a lender typically has today: a collateral schedule and a
provider-submitted `nvidia-smi` serial listing, plus a probe manifest that
commits to the bounded claim for window 2026-05-18..2026-05-25.

- `receipts/before_gpu_serial_collateral_match.json` — **SUPPORTED**. The
  provider-reported serials match the schedule. This receipt supports only the
  report-vs-report claim; it cannot support attested identity or freshness.
- `receipts/before_gpu_attested_identity_window.json` — **UNKNOWN** with 15
  named absences: no attestation, no EAT nonce, no identity bridge, no
  challenge nonce, no evidence hashes. The absence list is the cure request.

**Action under the recorded decision rule: hold payment and issue cure
request.** The self-report SUPPORTED verdict does not release payment, because
the payment-gating claim is the attested one, and it is UNKNOWN.

## After: attestation plus identity bridge

`after/` adds nvattest-shaped attestation evidence and an identity bridge
(`contract_gpu_id -> provider_asset_id -> UEID`, with mapping_source,
mapping_time, mapper). The bridge maps `GPU-H100-SXM-0003` to a UEID that the
nonce-bound attested UEID set does not contain — a planted-card scenario the
self-report could not see.

- `receipts/after_gpu_attested_identity_window.json` — **CONTRADICTED**: the
  bridged UEID for GPU-H100-SXM-0003 is absent from the attested set.

**Action under the recorded decision rule: hold payment and open dispute.**

Had the attested set matched, the verdict would be SUPPORTED and the recorded
action `release payment` — for this identity/freshness claim only, never as a
proxy for capacity delivery.

## Action change summary

| Evidence state | Verdict on bounded claim | Lender action |
|---|---|---|
| Self-report only (before) | UNKNOWN | hold payment, issue cure request |
| Attestation + bridge, identity mismatch (after) | CONTRADICTED | hold payment, open dispute |
| Attestation + bridge, all bound (not in this packet) | SUPPORTED | release payment |

The verdict-to-action rule is carried inside each receipt via
`execution_context.json` (`gpu_lending_decision_context_v0`), so the receipt
states which decision it feeds without putting lending fields on the base
receipt schema.

## Reproduce

```bash
./compile readiness_packets/gpu_attestation_before_after_2026-06-10/before \
  --claim-type gpu_serial_collateral_match
./compile readiness_packets/gpu_attestation_before_after_2026-06-10/before \
  --claim-type gpu_attested_identity_window
./compile readiness_packets/gpu_attestation_before_after_2026-06-10/after \
  --claim-type gpu_attested_identity_window
```
