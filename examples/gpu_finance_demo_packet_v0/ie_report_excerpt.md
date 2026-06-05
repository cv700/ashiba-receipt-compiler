# Independent Engineer Report Excerpt

ARC Receipt Compiler - GPU Finance Demo
Date: 2026-06-04
Status: DEMO - ARC fixture evidence only

## Scope

Review of declared GPU-backed compute asset claims for lender diligence. Scope:
capacity snapshot, positive serial collateral binding, MIG ambiguity, and
adversarial serial collateral conflict. Evidence window is as declared in each
ARC example packet. No real customer asset, operation, or proprietary data is
reviewed.

## Evidence Reviewed

| File | Source | Label |
|---|---|---|
| `gpu_inventory.json` | `gpu_acceptance_lambda_a10_supported` | real redacted ARC fixture |
| `gpu_probe_observation.json` | `gpu_acceptance_lambda_a10_supported` | tenant-observed redacted fixture |
| `gpu_inventory.json` | `gpu_serial_match_supported` | synthetic ARC fixture |
| `gpu_probe_observation.json` | `gpu_serial_match_supported` | synthetic ARC fixture |
| `probe_manifest.json` | `gpu_serial_match_supported` | synthetic ARC fixture |
| `gpu_inventory.json` | `gpu_acceptance_mig_unknown` | synthetic ARC fixture |
| `gpu_probe_observation.json` | `gpu_acceptance_mig_unknown` | synthetic ARC fixture |
| `gpu_inventory.json` | `gpu_serial_match_contradicted` | SYNTHETIC adversarial fixture |
| `gpu_probe_observation.json` | `gpu_serial_match_contradicted` | SYNTHETIC adversarial fixture |
| `probe_manifest.json` | `gpu_serial_match_contradicted` | SYNTHETIC adversarial fixture |

## Findings

1. Capacity snapshot: `SUPPORTED`
   Declared A10 capacity and observed `nvidia-smi` name, count, MIG-mode, and
   timestamp evidence are complete and consistent.

2. Serial collateral binding: `SUPPORTED` [SYNTHETIC]
   Declared serial set and observed serial set match for the declared node.
   Synthetic fixture only.

3. MIG status: `UNKNOWN`
   One GPU reports MIG enabled. ARC requires GI/CI evidence to decide whether
   declared capacity was sliced.

4. Serial collateral binding: `CONTRADICTED` [SYNTHETIC]
   Declared serial set includes `GPU-H100-SXM-0008`; observed serial set
   includes `GPU-H100-SXM-XXXX` instead. Synthetic fixture only.

## Limits

Does not prove legal ownership, title, future uptime, yield, workload-specific
performance, physical custody location, borrower credit quality, or any real
customer asset condition.

## Requested Next Evidence

For MIG: collect `nvidia-smi mig -lgi` and `nvidia-smi mig -lci` for the same
snapshot, with probe metadata binding records to the capacity packet.
