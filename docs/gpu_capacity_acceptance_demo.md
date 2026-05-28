# GPU Capacity Acceptance Demo

This is a buyer-side acceptance receipt for one rental snapshot.

ARC checks whether declared GPU capacity matches buyer-observed `nvidia-smi`
evidence at session start. It does not monitor ongoing performance, prove
cryptographic invoice binding, guarantee reliability, or certify the operator.

## Commands

Supported:

```bash
./compile examples/gpu_acceptance_supported --claim-type gpu_capacity_acceptance --card
```

MIG contradicted:

```bash
./compile examples/gpu_acceptance_mig_contradicted --claim-type gpu_capacity_acceptance --card
```

Unknown:

```bash
./compile examples/gpu_acceptance_unknown --claim-type gpu_capacity_acceptance --card
```

## Verdict Shape

- `supported`: declared SKU/count are present, observed GPU names/count match,
  and observed MIG modes show dedicated capacity.
- `contradicted`: observed GPU names/count/MIG modes conflict with the declared
  acceptance claim.
- `unknown`: required declared or observed evidence is missing.
