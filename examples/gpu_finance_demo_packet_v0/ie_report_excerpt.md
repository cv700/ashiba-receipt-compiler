# Independent Engineer-Style Excerpt

## Scope

ARC reviewed two evidence packets for a declared GPU-backed compute asset. The
scope is limited to GPU capacity snapshot evidence and MIG ambiguity for the
captured snapshot.

## Evidence Reviewed

- `examples/gpu_acceptance_lambda_a10_supported/gpu_inventory.json`
- `examples/gpu_acceptance_lambda_a10_supported/gpu_probe_observation.json`
- `examples/gpu_acceptance_mig_unknown/gpu_inventory.json`
- `examples/gpu_acceptance_mig_unknown/gpu_probe_observation.json`

## Findings

1. GPU capacity snapshot: `SUPPORTED`
   Basis: declared A10 capacity and observed `nvidia-smi` name/count/MIG-mode
   evidence are complete and consistent.

2. MIG ambiguity: `UNKNOWN`
   Basis: one observed GPU reports MIG enabled. ARC requires instance-level
   GI/CI evidence to decide whether declared capacity was actually sliced. This
   is an ambiguity finding, not a missing-field absence finding.

## Limits

These receipts do not prove legal ownership, title, future uptime, yield,
workload-specific performance, physical custody location, or any real customer
operational practice.

## Requested Next Evidence

- `nvidia-smi mig -lgi` output for the same snapshot.
- `nvidia-smi mig -lci` output for the same snapshot.
- A probe manifest binding any GI/CI capture to the observed capacity snapshot.
