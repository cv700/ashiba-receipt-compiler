# GPU Capacity Acceptance Demo

This is a buyer-side acceptance receipt for one rental snapshot.

ARC checks whether buyer-observed `nvidia-smi` names, count, timestamp, and
MIG-mode fields are consistent with a declared GPU capacity snapshot. It does
not monitor ongoing performance, prove cryptographic invoice binding, guarantee
reliability, certify the operator, or prove MIG instance allocation.

## Commands

Scan readiness:

```bash
./ashiba scan examples/gpu_acceptance_supported --json
```

Supported:

```bash
./compile examples/gpu_acceptance_supported --claim-type gpu_capacity_acceptance --card
```

Real Lambda A10 packet, redacted:

```bash
./ashiba scan examples/gpu_acceptance_lambda_a10_supported --json
./compile examples/gpu_acceptance_lambda_a10_supported --claim-type gpu_capacity_acceptance --card
```

MIG ambiguous:

```bash
./compile examples/gpu_acceptance_mig_unknown --claim-type gpu_capacity_acceptance --card
```

Unknown:

```bash
./ashiba scan examples/gpu_acceptance_unknown
./compile examples/gpu_acceptance_unknown --claim-type gpu_capacity_acceptance --card
```

## Verdict Shape

- `supported`: declared SKU/count are present, observed GPU names/count match,
  and observed MIG mode fields do not raise ambiguity.
- `contradicted`: observed GPU names/count conflict with the declared
  snapshot claim.
- `unknown`: required declared or observed evidence is missing, or MIG mode is
  enabled without instance-level slicing evidence.

The Lambda A10 fixture intentionally declares family-level `A10`. The original
dashboard text included `1x A10 (24 GB PCIe)`, but the captured `nvidia-smi`
name exposed only `NVIDIA A10`; a literal `A10-PCIe` declaration therefore
compiles to `unknown` because the variant is not observable in the packet.
