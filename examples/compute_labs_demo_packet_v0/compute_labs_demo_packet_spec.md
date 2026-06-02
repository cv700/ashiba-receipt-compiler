# Compute Labs Demo Packet Spec

## Section 1 - The Demo Claim

For a declared GPU-backed compute asset, ARC can determine whether the provided evidence supports the claimed GPU identity, capacity snapshot, and basic evidence completeness for a stated time window.

Receipt 1: The observed GPU names, count, timestamp, and MIG-mode field were consistent with the declared GPU capacity snapshot. -> expected verdict: SUPPORTED
  Evidence source: `examples/gpu_acceptance_lambda_a10_supported`

Receipt 2: The observed GPU names, count, timestamp, and MIG-mode field were sufficient to decide the declared capacity snapshot when MIG is enabled. -> expected verdict: UNKNOWN
  Missing evidence: `gpu_probe_observation.gi_ci_instances`

Receipt 3: The GPU serial numbers observed during probe execution matched the serial numbers declared in the collateral schedule. -> expected verdict: CONTRADICTED
  Conflict: declared serial set includes `GPU-H100-SXM-0008`; observed serial set includes `GPU-H100-SXM-XXXX` instead
  Label: SYNTHETIC - clearly labeled

## Section 2 - Folder + File List

```text
examples/compute_labs_demo_packet_v0/
|-- README.md                         -> 5-minute walkthrough: open the claim summary, run the commands, read the three receipt cards and IE excerpt.
|-- claim_summary.md                  -> Claim text, demo narrative, three-receipt story, and explicit scope limits.
|-- compute_labs_demo_packet_spec.md  -> Working packet specification for the demo claim, file list, receipt sources, and generation commands.
|-- evidence_manifest.json            -> Manifest listing each referenced evidence packet and labeling source type as real, synthetic, or declared.
|-- commands.txt                      -> Exact scan and compile commands with no missing flags.
|-- receipt_cards/
|   |-- capacity_supported.txt        -> Receipt card generated from the real redacted Lambda A10 capacity packet.
|   |-- power_unknown.txt             -> Demo-label receipt card for the current unknown case; generated from the MIG-enabled capacity ambiguity packet until a power claim pack exists.
|   `-- power_contradicted_synthetic.txt -> Demo-label receipt card for the current synthetic contradiction case; generated from the serial-collateral mismatch packet until a power claim pack exists.
|-- receipt_json/
|   |-- capacity_supported.json       -> Full JSON receipt for the supported Lambda A10 capacity packet.
|   |-- power_unknown.json            -> Full JSON receipt for the current unknown MIG ambiguity packet.
|   `-- power_contradicted_synthetic.json -> Full JSON receipt for the current synthetic serial mismatch packet.
|-- ie_report_excerpt.md              -> Independent Engineer-style one-page finding with evidence reviewed, findings, limits, and requested next evidence.
`-- reviewer_note.md                  -> Short reviewer context explaining that this is a neutral Compute Labs-style demo, not an audit or relationship claim.
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

`receipt_cards/power_unknown.txt`

- Existing ARC example: `examples/gpu_acceptance_mig_unknown`
- Claim type: `gpu_capacity_acceptance`
- Current meaning: unknown because MIG is enabled and instance-level GI/CI evidence is not present; this stands in for the "unknown from missing independent tier" demo slot until `gpu_power_utilization_consistency` exists in this repo.
- Command:

```bash
./compile examples/gpu_acceptance_mig_unknown \
  --claim-type gpu_capacity_acceptance \
  --card
```

`receipt_cards/power_contradicted_synthetic.txt`

- Existing ARC example: `examples/gpu_serial_match_contradicted`
- Claim type: `gpu_serial_collateral_match`
- Current meaning: synthetic contradiction because declared GPU serial evidence conflicts with observed GPU serial evidence; this stands in for the synthetic contradiction demo slot until `gpu_power_utilization_consistency` exists in this repo.
- Command:

```bash
./compile examples/gpu_serial_match_contradicted \
  --claim-type gpu_serial_collateral_match \
  --card
```

## Section 3 - Evidence Manifest

| File | Source | Label | Notes |
|---|---|---|---|
| `gpu_telemetry.json` | Lambda A10 output | REAL - Lambda output, redacted | Exists in ARC examples as `examples/gpu_acceptance_lambda_a10_supported/gpu_probe_observation.json`; stable hardware identifiers, serials, UUIDs, SSH details, and account details are omitted. |
| `declaration.json` | Manually declared capacity fields | HAND-ENTERED DECLARATION | Derived from `examples/gpu_acceptance_lambda_a10_supported/gpu_inventory.json`; caveat noted because a hand-entered declaration is evidence of the declared claim, not provider-side truth. |
| `mig_ambiguity_telemetry.json` | Synthetic H100 MIG-enabled capacity packet | SYNTHETIC - labeled | Existing ARC example `examples/gpu_acceptance_mig_unknown/gpu_probe_observation.json`; used to show `unknown` when MIG is enabled without instance-level GI/CI evidence. |
| `serial_declared.json` | Synthetic collateral schedule | SYNTHETIC - labeled | Existing ARC example `examples/gpu_serial_match_contradicted/gpu_inventory.json`; used only for the labeled serial-mismatch contradiction. |
| `serial_observed.json` | Synthetic serial probe observation | SYNTHETIC - labeled | Existing ARC example `examples/gpu_serial_match_contradicted/gpu_probe_observation.json`; conflicts with the declared serial set. |
| `probe_manifest.json` | Synthetic probe commitment | SYNTHETIC - labeled | Existing ARC example `examples/gpu_serial_match_contradicted/probe_manifest.json`; binds the synthetic serial probe. |
| `power_readings.csv` | Synthetic power readings | SYNTHETIC - labeled | Placeholder for a future `gpu_power_utilization_consistency` packet; do not present as real or Compute Labs data. |

No fake Compute Labs data. No unlabeled synthetic evidence.

## Section 4 - Commands (Exact)

### Intended Day 2 Commands

Scanner:

```bash
./ashiba scan examples/compute_labs_demo_packet_v0 --json
```

Receipt 1 - supported capacity:

```bash
./compile examples/compute_labs_demo_packet_v0 \
  --claim-type gpu_capacity_acceptance \
  --card
```

Receipt 2 - unknown power:

```bash
./compile examples/gpu_power_consistency_unknown_missing_power \
  --claim-type gpu_power_utilization_consistency \
  --card
```

Receipt 3 - synthetic contradiction:

```bash
./compile examples/gpu_power_consistency_contradicted \
  --claim-type gpu_power_utilization_consistency \
  --card
```

### Tested Today

`./ashiba scan examples/compute_labs_demo_packet_v0 --json`

- Status today: BLOCKED
- Actual result: exits nonzero with `input_status: "no_parseable_inputs"`
- Reason: `examples/compute_labs_demo_packet_v0` does not yet contain JSON evidence files.

`./compile examples/compute_labs_demo_packet_v0 --claim-type gpu_capacity_acceptance --card`

- Status today: BLOCKED
- Actual result: `ERROR: no JSON files found in examples/compute_labs_demo_packet_v0`
- Reason: the packet directory has no shaped compiler artifacts yet.

`./compile examples/gpu_power_consistency_unknown_missing_power --claim-type gpu_power_utilization_consistency --card`

- Status today: BLOCKED
- Actual result: `ERROR: examples/gpu_power_consistency_unknown_missing_power is not a file or directory`
- Reason: the power-consistency unknown fixture does not exist in this repo.

`./compile examples/gpu_power_consistency_contradicted --claim-type gpu_power_utilization_consistency --card`

- Status today: BLOCKED
- Expected current result: missing example directory and missing claim pack.
- Reason: this repo does not currently include `gpu_power_utilization_consistency` under `claim_packs/`, and no `examples/gpu_power_consistency_*` directories exist.

### Commands That Work Today

Supported capacity card:

```bash
./compile examples/gpu_acceptance_lambda_a10_supported \
  --claim-type gpu_capacity_acceptance \
  --card
```

Current unknown substitute card:

```bash
./compile examples/gpu_acceptance_mig_unknown \
  --claim-type gpu_capacity_acceptance \
  --card
```

Current synthetic contradiction substitute card:

```bash
./compile examples/gpu_serial_match_contradicted \
  --claim-type gpu_serial_collateral_match \
  --card
```

Day 2 blocker: either build `gpu_power_utilization_consistency` and its fixtures before using the intended commands, or rename the demo receipt slots away from "power" and use the current MIG/serial examples honestly.

## Section 5 - What Is Out of Scope

- ARC does not prove Compute Labs' real assets have any defect.
- ARC does not prove GPU ownership or legal title.
- ARC does not prove future yield or uptime.
- ARC does not prove physical custody location.
- ARC does not prove workload-specific performance.
- This is a demo for Compute Labs, not about Compute Labs.

## Section 6 - Biggest Risk / Open Question

The thing most likely to break on Day 2 is that the intended power-utilization receipt commands cannot run until `gpu_power_utilization_consistency` and its `gpu_power_consistency_*` fixtures exist, while the current `examples/compute_labs_demo_packet_v0` folder also needs shaped JSON evidence before scanner and compile commands can target it directly.
