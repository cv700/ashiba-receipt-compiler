# Ashiba Receipt Compiler

Private technical preview. This repository contains local-first prototype
software for scanning operational logs, identifying missing evidence, and
compiling bounded receipts for narrow operational claims.

It does not call models. It does not send logs to a server. It does not certify
security, safety, intent, custody, authenticity, or general system reliability.

## What It Does

Drop in CloudTrail, OpenTelemetry, GitHub Actions, Kubernetes audit logs, SIEM
JSONL, or agent/tool traces. Ashiba groups side-effect actions, checks whether
operational claims are receipt-ready, and emits bounded receipts:
`supported`, `contradicted`, `unknown`, or `not_applicable`.

The narrow question is:

> Do the available logs and artifacts support this operational claim, contradict
> it, or leave it unknown?

The intended workflow has two local steps:

```bash
./ashiba scan ./logs --policy policy.json --report --out /tmp/ashiba_report
./compile ./evidence --card
```

`./ashiba scan` reads existing logs and tells you which actions are
receipt-ready, which claims are blocked, and which probes are missing.
`./compile` turns evidence that is already in compiler artifact shape into a
receipt with a verdict, basis, input binding, missing evidence, and boundary
language.

Ashiba is not a replacement for CloudTrail, OTEL, Sigstore, SLSA, TEEs, SIEM,
SOC 2, or GRC workflows. Those systems produce or organize evidence. Ashiba
compiles a bounded decision artifact over that evidence.

## Thirty-Second Demo

Run this from the repository root:

```bash
./demo_30s.sh
```

The demo shows:

- a scan over CloudTrail-style and deployment-style logs;
- a generated missing-evidence report;
- a bounded receipt card for a supported authorization claim;
- fail-closed behavior on invalid input.

## Reference Probe Demo

Run this to see the full scan -> gap -> probe -> receipt loop:

```bash
./demo_reference_probe.sh
```

The demo starts with a blocked `authorization_bound_action` claim, runs a small
authorization-boundary probe, rescans the emitted evidence, and then compiles a
bounded receipt from the probe artifacts.

## Canonical Authorization Gap Demo

This is the smallest concrete incident story in the repo:

```bash
./compile examples/cloudtrail_otel_authorization_gap \
  --claim-type authorization_bound_action \
  --card
```

The packet includes CloudTrail-shaped evidence, OTEL-shaped evidence, a policy
grant, normalized parsed action, and tool-call binding. The action executes
90 seconds after grant expiry, so the receipt is `contradicted`.

Use this example when explaining the product to someone new:

```text
Logs say the action happened.
Policy says the grant expired.
The receipt says the authorization claim is contradicted.
The boundary says not to overread that into general agent unsafety.
```

For field-by-field receipt semantics, see `docs/receipt_anatomy.md`.
For why this is not meant to be another logging standard, see
`docs/not_a_standard.md`.

## Current Commands

Scan logs and write a report:

```bash
./ashiba scan readiness_packets/deployment_ready_auth_gaps_2026-05-18/logs \
  --policy readiness_packets/deployment_ready_auth_gaps_2026-05-18/policy.json \
  --report \
  --out /tmp/ashiba_report
```

Compile a receipt card:

```bash
./compile examples/cyber_renderer_authz_supported --card
```

Print only the verdict:

```bash
./compile examples/cyber_renderer_authz_supported --verdict
```

Pipe imported CloudTrail evidence into the compiler:

```bash
./import_cloudtrail examples/cloudtrail_sample.json \
  --policy examples/real_world_policy_sample.json | ./compile - --verdict
```

Run the smoke test suite:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 test_receipt_compiler.py
```

## Claim Families

A claim pack is the versioned JSON verifier contract for a claim family. The
claim type is the stable name used on the CLI, such as
`gpu_capacity_acceptance`; the claim pack is the concrete JSON file under
`claim_packs/` that defines its evidence contract, deterministic pass pipeline,
and receipt boundary renderer.

The current preview includes:

- `authorization_bound_action`: was a tool/action executed under an active,
  bound authorization grant?
- `deployment_matches_reviewed_commit`: did the deployed commit match the
  reviewed commit?
- `human_approval_before_external_side_effect`: was approval recorded before an
  external side effect?
- `parser_repair_visibility`: was parser repair logged with provenance?
- `prefix_continuity`: did the next prompt preserve the expected token prefix?

### GPU Collateral Claims (v0)

Three claim packs exercise the GPU-backed lending and acceptance verification shape:

- `gpu_serial_collateral_match`: verifies that GPU serial numbers observed
  during probe execution match the serials declared in the collateral schedule.
  This catches collateral-identity discrepancies.
- `gpu_node_health_diagnostic`: verifies that a GPU node passed DCGM Level 2
  health diagnostics with ECC error counts below stated thresholds at probe
  time. This catches point-in-time hardware-health failures.
- `gpu_capacity_acceptance`: verifies that observed GPU names, count, timestamp,
  and MIG-mode field are consistent with a declared GPU capacity snapshot. This
  supports the full local path from `import_nvidia_smi` artifacts through
  `ashiba scan` readiness and `./compile` receipt output.

These are synthetic, point-in-time, node-level demos. They do not assess cluster
health, goodput, residual value, firmware authenticity, or ongoing performance.
The receipt boundary section is part of the output and should not be treated as
boilerplate.

## Verdicts

Receipts use four states:

- `supported`: required evidence is present and deterministic passes support the
  claim.
- `contradicted`: evidence conflicts with the claim.
- `unknown`: evidence is missing, malformed, or insufficient.
- `not_applicable`: the artifact class does not instantiate the claim.

Important invariant:

> If the scanner says a claim is not decidable for a packet, the compiler must
> not emit `supported` for the same claim on that same packet.

## Execution Context

Receipts may include an optional `execution_context` extension object. This is
domain-specific context for test conditions and anti-gaming disclosures. It is
not ordinary claim evidence and does not change verdict logic.

If an artifact directory contains `execution_context.json`, the compiler binds
that file in `artifact_manifest`, stores it as `execution_context`, and keeps it
out of the normal `artifacts` object used by verdict-determining passes.

The first supported schema is `gpu_goodput_context_v0`, used to disclose limits
such as node coverage, freshly rebooted nodes, ECC reboot suspects, negligible
fabric load, missing software stack capture, missing challenge nonce, and
missing pre-committed probe manifest.

## Repository Layout

```text
ashiba                         Readiness scanner CLI
compile                        One-line receipt compiler CLI
receipt_scan.py                Scanner implementation
receipt_compile.py             Lower-level compiler entrypoint
receipt_ir.py                  Receipt data model
passes.py                      Deterministic compiler passes
verdict.py                     Verdict generation
boundary.py                    Boundary-language generation
receipt_validate.py            Receipt structural/source-binding validator
receipt_explain.py             Human-readable gap/card output
import_*                       Log and trace importers
claim_packs/                   Declarative claim definitions
examples/                      Synthetic examples and fixtures
readiness_packets/             Scanner demo packets
real_world_packets/            Customer-style synthetic packet
environments/                  Local deterministic environment prototype
```

## Verification Gate

Before sharing changes, run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 test_receipt_compiler.py
PYTHONDONTWRITEBYTECODE=1 python3 demo_gallery.py --json
PYTHONDONTWRITEBYTECODE=1 python3 scripts/discover_claim_contract.py --json
PYTHONDONTWRITEBYTECODE=1 python3 demo_real_world_importers.py
PYTHONDONTWRITEBYTECODE=1 python3 environments/trace_receipt_minimizer_v0/test_score.py
PYTHONDONTWRITEBYTECODE=1 ./demo_30s.sh
PYTHONDONTWRITEBYTECODE=1 python3 -m py_compile \
  ashiba receipt_scan.py compile receipt_validate.py receipt_compile.py \
  passes.py claim_types.py claim_contracts.py side_effect_envelope.py import_cloudtrail import_github_actions import_otel \
  import_kubernetes_audit import_siem_jsonl import_anthropic import_openai \
  import_eventlog import_langsmith importer_common.py demo_real_world_importers.py \
  demo.py constants.py receipt_ir.py verdict.py boundary.py renderer_families.py demo_gallery.py \
  demo_llm_comparison.py receipt_explain.py scripts/discover_claim_contract.py test_receipt_compiler.py \
  environments/trace_receipt_minimizer_v0/*.py
find . -type d -name __pycache__ -prune -exec rm -rf {} +
```

Expected gallery summary:

```text
41 receipts from 36 incident directories
supported: 17 | contradicted: 11 | unknown: 12 | not_applicable: 1
compiler_errors: 0 | validation_errors: 0
```

## Discovering Contracts

Before adding a new schema field, run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/discover_claim_contract.py --json
```

The report derives required runtime facts from active claim packs and pass
metadata, then separates proposed SideEffectEnvelope fields that no current
claim consumes yet.

## Known Preview Rough Edges

- The importers are intentionally conservative. They preserve missing evidence
  as missing evidence instead of inventing policy, revocation, or binding facts.
- This is a local prototype, not a packaged service. Use the root-level scripts
  directly.

## Private Preview Notice

This is prototype research software for private review. See `LICENSE` and
`PRIVATE_PREVIEW_NOTICE.md`.
