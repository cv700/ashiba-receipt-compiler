# Claim Summary

## Demo Claim

For a declared GPU-backed compute asset, ARC can determine whether supplied
evidence supports a narrow GPU capacity snapshot claim, or leaves it unknown
when capacity evidence is ambiguous.

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

## Scope Limits

ARC does not prove GPU ownership, legal title, future yield, future uptime,
physical custody location, workload-specific performance, or real-world defects
in any real customer asset.
