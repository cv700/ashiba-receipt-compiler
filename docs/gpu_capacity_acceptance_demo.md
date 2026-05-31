# GPU Capacity Acceptance Demo

This is a buyer-side acceptance receipt for one rental snapshot.

ARC checks whether buyer-observed `nvidia-smi` names, count, timestamp, and
MIG-mode fields are consistent with a declared GPU capacity snapshot. It does
not monitor ongoing performance, prove cryptographic invoice binding, guarantee
reliability, certify the operator, or prove MIG instance allocation.

## Commands

Supported:

```bash
./compile examples/gpu_acceptance_supported --claim-type gpu_capacity_acceptance --card
```

MIG ambiguous:

```bash
./compile examples/gpu_acceptance_mig_unknown --claim-type gpu_capacity_acceptance --card
```

Unknown:

```bash
./compile examples/gpu_acceptance_unknown --claim-type gpu_capacity_acceptance --card
```

## Verdict Shape

- `supported`: declared SKU/count are present, observed GPU names/count match,
  and observed MIG mode fields do not raise ambiguity.
- `contradicted`: observed GPU names/count conflict with the declared
  snapshot claim.
- `unknown`: required declared or observed evidence is missing, or MIG mode is
  enabled without instance-level slicing evidence.
