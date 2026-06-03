# Claim Summary

## Demo Claim

For declared GPU-backed compute asset claims, ARC can compile separate bounded
receipts for capacity snapshot, MIG ambiguity, and collateral serial binding
from the supplied evidence.

## Receipt 1 - Supported Capacity Snapshot

Claim: The observed GPU names, count, timestamp, and MIG-mode field were
consistent with the declared GPU capacity snapshot.

Expected verdict: `supported`

Source example: `examples/gpu_acceptance_lambda_a10_supported`

Why: The declared A10 count and buyer-observed `nvidia-smi` name/count/MIG
fields are complete and consistent for the snapshot.

## Receipt 2 - Unknown MIG Ambiguity

Claim: The observed GPU names, count, timestamp, and MIG-mode field were
consistent with the declared GPU capacity snapshot.

Expected verdict: `unknown`

Source example: `examples/gpu_acceptance_mig_unknown`

Why: MIG is enabled and ARC requires instance-level GI/CI evidence before
deciding whether declared capacity was actually sliced.

Generated-output note: ARC names the GI/CI evidence gap in the verdict basis.
The generated receipt card's `Evidence missing` section is `(none)` because all
configured expected fields are present; the issue is ambiguity, not absence.

## Receipt 3 - Contradicted Serial Binding

Claim: The GPU serial numbers observed during probe execution matched the
serial numbers declared in the collateral schedule.

Expected verdict: `contradicted`

Source example: `examples/gpu_serial_match_contradicted`

Label: `SYNTHETIC` adversarial ARC fixture, for demonstration only.

Why: The declared serial set includes `GPU-H100-SXM-0008`, while the observed
serial set includes `GPU-H100-SXM-XXXX` instead.

## Scope Limits

ARC does not prove GPU ownership, legal title, future yield, future uptime,
physical custody location, workload-specific performance, or real-world defects
in any real customer asset.
