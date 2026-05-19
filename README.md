# Ashiba Receipt Compiler

Private technical preview. This repository contains local-first prototype
software for scanning operational logs, identifying missing evidence, and
compiling bounded receipts for narrow operational claims.

It does not call models. It does not send logs to a server. It does not certify
security, safety, intent, custody, authenticity, or general system reliability.

## What It Does

Ashiba answers a narrow question:

> Do the available logs and artifacts support this operational claim, contradict
> it, or leave it unknown?

The intended workflow has two steps:

```bash
./ashiba scan ./logs --policy policy.json --report --out /tmp/ashiba_report
./compile ./evidence --card
```

`./ashiba scan` reads existing logs and tells you which claims are decidable and
which probes are missing. `./compile` turns evidence that is already in compiler
artifact shape into a receipt with a verdict, basis, input binding, missing
evidence, and boundary language.

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

Claim definitions live in `claim_packs/`. The current preview includes:

- `authorization_bound_action`: was a tool/action executed under an active,
  bound authorization grant?
- `deployment_matches_reviewed_commit`: did the deployed commit match the
  reviewed commit?
- `human_approval_before_external_side_effect`: was approval recorded before an
  external side effect?
- `parser_repair_visibility`: was parser repair logged with provenance?
- `prefix_continuity`: did the next prompt preserve the expected token prefix?

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
PYTHONDONTWRITEBYTECODE=1 python3 demo_real_world_importers.py
PYTHONDONTWRITEBYTECODE=1 python3 environments/trace_receipt_minimizer_v0/test_score.py
PYTHONDONTWRITEBYTECODE=1 ./demo_30s.sh
PYTHONDONTWRITEBYTECODE=1 python3 -m py_compile \
  ashiba receipt_scan.py compile receipt_validate.py receipt_compile.py \
  passes.py claim_types.py import_cloudtrail import_github_actions import_otel \
  import_kubernetes_audit import_siem_jsonl import_anthropic import_openai \
  import_eventlog import_langsmith importer_common.py demo_real_world_importers.py \
  demo.py constants.py receipt_ir.py verdict.py boundary.py demo_gallery.py \
  demo_llm_comparison.py receipt_explain.py test_receipt_compiler.py \
  environments/trace_receipt_minimizer_v0/*.py
find . -type d -name __pycache__ -prune -exec rm -rf {} +
```

Expected gallery summary:

```text
25 receipts from 24 incident directories
supported: 6 | contradicted: 8 | unknown: 10 | not_applicable: 1
compiler_errors: 0 | validation_errors: 0
```

## Known Preview Rough Edges

- Some fixture directory names predate the stricter authorization-binding rule.
  The manifest is authoritative when a legacy name says `supported` but the
  current verdict is `unknown`.
- The importers are intentionally conservative. They preserve missing evidence
  as missing evidence instead of inventing policy, revocation, or binding facts.
- This is a local prototype, not a packaged service. Use the root-level scripts
  directly.

## Private Preview Notice

This is prototype research software for private review. See `LICENSE` and
`PRIVATE_PREVIEW_NOTICE.md`.
