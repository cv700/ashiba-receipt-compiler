# GPU Finance Demo Packet Spec

## Section 1 - Claim Ladder

This packet demonstrates separate ARC receipts for GPU lender diligence: a capacity snapshot receipt, a collateral identity receipt, and appendix cases for unknown or contradicted evidence.

Receipt 1: The observed GPU names, count, timestamp, and MIG-mode field were consistent with the declared GPU capacity snapshot. -> expected verdict: SUPPORTED
  Evidence source: `examples/gpu_acceptance_lambda_a10_supported`
  Claim type: `gpu_capacity_acceptance`
  Scope word: snapshot, not window

Receipt 2: The GPU serial numbers observed during probe execution matched the serial numbers declared in the collateral schedule. -> expected verdict: SUPPORTED
  Evidence source: `examples/gpu_serial_match_supported`
  Claim type: `gpu_serial_collateral_match`

Appendix receipt A: The observed GPU names, count, timestamp, and MIG-mode field were consistent with the declared GPU capacity snapshot. -> expected verdict: UNKNOWN
  Evidence source: `examples/gpu_acceptance_mig_unknown`
  Claim type: `gpu_capacity_acceptance`
  Reason: MIG is enabled and instance-level GI/CI evidence is required to decide whether capacity was sliced.

Appendix receipt B: The GPU serial numbers observed during probe execution matched the serial numbers declared in the collateral schedule. -> expected verdict: CONTRADICTED
  Evidence source: `examples/gpu_serial_match_contradicted`
  Claim type: `gpu_serial_collateral_match`
  Conflict: declared serial set includes `GPU-H100-SXM-0008`; observed serial set includes `GPU-H100-SXM-XXXX` instead.
  Label: SYNTHETIC - clearly labeled

Extra credit only: `gpu_power_utilization_consistency` should be included only after the claim pack and `examples/gpu_power_consistency_*` fixtures exist in this branch.

Evidence completeness is a scanner/readiness and manifest question in this packet. It is not a receipt verdict unless a specific claim pack implements it.

## Section 2 - Folder + File List

```text
examples/gpu_finance_demo_packet_v0/
|-- README.md                         -> 5-minute walkthrough: open the claim summary, run current commands, read receipt cards and IE excerpt.
|-- claim_summary.md                  -> Claim ladder, demo narrative, and scope limits for GPU lender diligence.
|-- gpu_finance_demo_packet_spec.md   -> Working packet specification for claim ladder, file list, evidence manifest, commands, blockers, and open questions.
|-- evidence_manifest.json            -> Exact copied packet paths and source example paths with source type, custody tier, claim type, and generation command.
|-- commands.txt                      -> Runnable commands only; a reviewer can run these from a clean checkout.
|-- blocked_target_commands.md        -> Future power-utilization commands and blockers; not part of reviewer regeneration.
|-- raw_scan_input/                   -> Optional raw scanner input if the packet includes raw logs or capture files.
|-- artifacts/                        -> Optional compile-ready copied artifacts if the packet targets direct `./compile examples/gpu_finance_demo_packet_v0/artifacts`.
|-- receipt_cards/
|   |-- capacity_supported.txt        -> Receipt card generated from `examples/gpu_acceptance_lambda_a10_supported`.
|   |-- serial_supported.txt          -> Receipt card generated from `examples/gpu_serial_match_supported`.
|   |-- capacity_mig_unknown.txt      -> Appendix receipt card generated from `examples/gpu_acceptance_mig_unknown`.
|   `-- serial_contradicted_synthetic.txt -> Appendix receipt card generated from `examples/gpu_serial_match_contradicted`.
|-- receipt_json/
|   |-- capacity_supported.json       -> Full JSON receipt for `examples/gpu_acceptance_lambda_a10_supported`.
|   |-- serial_supported.json         -> Full JSON receipt for `examples/gpu_serial_match_supported`.
|   |-- capacity_mig_unknown.json     -> Full JSON receipt for `examples/gpu_acceptance_mig_unknown`.
|   `-- serial_contradicted_synthetic.json -> Full JSON receipt for `examples/gpu_serial_match_contradicted`.
|-- ie_report_excerpt.md              -> Independent Engineer-style one-page finding with evidence reviewed, findings, limits, and requested next evidence.
`-- reviewer_note.md                  -> Short reviewer context explaining that this is a neutral GPU finance/lender diligence demo, not a customer-specific audit.
```

### Receipt Card Generation

`receipt_cards/capacity_supported.txt`

- Existing ARC example: `examples/gpu_acceptance_lambda_a10_supported`
- Claim type: `gpu_capacity_acceptance`
- Command:

```bash
./compile examples/gpu_acceptance_lambda_a10_supported \
  --claim-type gpu_capacity_acceptance \
  --card
```

`receipt_cards/serial_supported.txt`

- Existing ARC example: `examples/gpu_serial_match_supported`
- Claim type: `gpu_serial_collateral_match`
- Command:

```bash
./compile examples/gpu_serial_match_supported \
  --claim-type gpu_serial_collateral_match \
  --card
```

`receipt_cards/capacity_mig_unknown.txt`

- Existing ARC example: `examples/gpu_acceptance_mig_unknown`
- Claim type: `gpu_capacity_acceptance`
- Command:

```bash
./compile examples/gpu_acceptance_mig_unknown \
  --claim-type gpu_capacity_acceptance \
  --card
```

`receipt_cards/serial_contradicted_synthetic.txt`

- Existing ARC example: `examples/gpu_serial_match_contradicted`
- Claim type: `gpu_serial_collateral_match`
- Command:

```bash
./compile examples/gpu_serial_match_contradicted \
  --claim-type gpu_serial_collateral_match \
  --card
```

## Section 3 - Evidence Manifest

The implementation manifest must use exact packet paths, not presentation aliases.

| packet_path | source_example_path | claim_type | source_type | custody_tier | generated_by_command | supports_receipt | notes |
|---|---|---|---|---|---|---|---|
| `artifacts/capacity_supported/gpu_inventory.json` | `examples/gpu_acceptance_lambda_a10_supported/gpu_inventory.json` | `gpu_capacity_acceptance` | manual declaration | declaration | copied from source example | `capacity_supported` | Hand-entered declared SKU/count; evidence of declaration, not provider-side truth. |
| `artifacts/capacity_supported/gpu_probe_observation.json` | `examples/gpu_acceptance_lambda_a10_supported/gpu_probe_observation.json` | `gpu_capacity_acceptance` | real redacted Lambda output | operator_exported | copied from source example | `capacity_supported` | Redacted Lambda A10 `nvidia-smi` observation; stable identifiers omitted. |
| `artifacts/serial_supported/gpu_inventory.json` | `examples/gpu_serial_match_supported/gpu_inventory.json` | `gpu_serial_collateral_match` | synthetic declared collateral schedule | synthetic | copied from source example | `serial_supported` | Labeled synthetic identity fixture. |
| `artifacts/serial_supported/gpu_probe_observation.json` | `examples/gpu_serial_match_supported/gpu_probe_observation.json` | `gpu_serial_collateral_match` | synthetic serial probe | synthetic | copied from source example | `serial_supported` | Labeled synthetic observed serial fixture. |
| `artifacts/serial_supported/probe_manifest.json` | `examples/gpu_serial_match_supported/probe_manifest.json` | `gpu_serial_collateral_match` | synthetic probe commitment | synthetic | copied from source example | `serial_supported` | Labeled synthetic probe manifest. |
| `artifacts/capacity_mig_unknown/gpu_inventory.json` | `examples/gpu_acceptance_mig_unknown/gpu_inventory.json` | `gpu_capacity_acceptance` | synthetic declaration | synthetic | copied from source example | `capacity_mig_unknown` | Appendix unknown case. |
| `artifacts/capacity_mig_unknown/gpu_probe_observation.json` | `examples/gpu_acceptance_mig_unknown/gpu_probe_observation.json` | `gpu_capacity_acceptance` | synthetic MIG-enabled observation | synthetic | copied from source example | `capacity_mig_unknown` | Unknown because MIG enabled requires GI/CI evidence. |
| `artifacts/serial_contradicted_synthetic/gpu_inventory.json` | `examples/gpu_serial_match_contradicted/gpu_inventory.json` | `gpu_serial_collateral_match` | synthetic declared collateral schedule | synthetic | copied from source example | `serial_contradicted_synthetic` | Appendix contradiction case. |
| `artifacts/serial_contradicted_synthetic/gpu_probe_observation.json` | `examples/gpu_serial_match_contradicted/gpu_probe_observation.json` | `gpu_serial_collateral_match` | synthetic serial probe | synthetic | copied from source example | `serial_contradicted_synthetic` | Conflicts with declared serial set. |
| `artifacts/serial_contradicted_synthetic/probe_manifest.json` | `examples/gpu_serial_match_contradicted/probe_manifest.json` | `gpu_serial_collateral_match` | synthetic probe commitment | synthetic | copied from source example | `serial_contradicted_synthetic` | Labeled synthetic probe manifest. |

No fake customer data. No unlabeled synthetic evidence.

## Section 4 - Commands

### Current Runnable Commands

These commands work today from the repo root and are the only commands that should appear in `commands.txt`.

Scanner for current capacity fixture:

```bash
./ashiba scan examples/gpu_acceptance_lambda_a10_supported --json
```

Supported capacity receipt card:

```bash
./compile examples/gpu_acceptance_lambda_a10_supported \
  --claim-type gpu_capacity_acceptance \
  --card
```

Supported collateral identity receipt card:

```bash
./compile examples/gpu_serial_match_supported \
  --claim-type gpu_serial_collateral_match \
  --card
```

Appendix MIG ambiguity receipt card:

```bash
./compile examples/gpu_acceptance_mig_unknown \
  --claim-type gpu_capacity_acceptance \
  --card
```

Appendix synthetic serial contradiction receipt card:

```bash
./compile examples/gpu_serial_match_contradicted \
  --claim-type gpu_serial_collateral_match \
  --card
```

### Blocked Target Commands

These belong in `blocked_target_commands.md`, not `commands.txt`, until implementation exists.

```bash
./compile examples/gpu_power_consistency_unknown_missing_power \
  --claim-type gpu_power_utilization_consistency \
  --card
```

```bash
./compile examples/gpu_power_consistency_contradicted \
  --claim-type gpu_power_utilization_consistency \
  --card
```

Blocker: this repo does not currently include `claim_packs/gpu_power_utilization_consistency.json`, and no `examples/gpu_power_consistency_*` directories exist.

## Section 5 - What Is Out of Scope

- ARC does not prove any real customer's assets have any defect.
- ARC does not prove GPU ownership or legal title.
- ARC does not prove future yield or uptime.
- ARC does not prove physical custody location.
- ARC does not prove workload-specific performance.
- This is a neutral GPU finance / GPU lender diligence demo, not a customer audit or relationship claim.

## Section 6 - Biggest Risk / Open Question

The thing most likely to break on Day 2 is scanner/compiler targeting for the new packet folder unless the folder is explicitly split into raw scan inputs, compile-ready artifacts, generated receipt cards, and generated receipt JSON with runnable commands that match each output.
