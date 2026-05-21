# Receipt Compiler v7 Status

Date: 2026-05-20

## Summary

Implemented generic execution-context support without changing existing verdict
logic. The receipt schema now has one optional domain extension point:

```json
"execution_context": {
  "schema_id": "gpu_goodput_context_v0"
}
```

GPU goodput anti-gaming fields live inside this extension object instead of as
top-level `ReceiptIR` fields. This keeps the base receipt schema neutral across
cyber, deployment, parser, prefix, and future compute claim families.

This branch also stacks a GPU collateral receipt v0 demo on top of that
execution-context layer. It adds two synthetic claim packs:

- `gpu_serial_collateral_match`
- `gpu_node_health_diagnostic`

Those claim packs demonstrate receipt semantics for collateral identity and
point-in-time node diagnostics. They are not GPU probes, scanprobe integration,
or real hardware ingestion.

## Behavior

- Existing receipts without `execution_context` remain unchanged.
- `execution_context.json` is bound in `artifact_manifest` but excluded from
  verdict-determining `artifacts`.
- `execution_context_disclosure` runs only when context is present.
- The disclosure pass emits `status: "ok"` and no `verdict_effect`.
- GPU context disclosures are appended to `boundary.does_not_support`.
- Unknown context schemas are preserved and get one generic disclosure.

## GPU Goodput Context Disclosures

For `schema_id: "gpu_goodput_context_v0"`, the compiler discloses:

- partial node coverage;
- freshly rebooted nodes;
- ECC reboot suspects;
- negligible fabric load;
- missing software stack capture;
- missing challenge nonce;
- missing pre-committed probe manifest.

## Example

Added `examples/execution_context_gpu_disclosure/`, which compiles a supported
authorization receipt while adding GPU anti-gaming boundary disclosures. This is
schema/disclosure coverage only, not a GPU probe implementation.

Added `examples/cloudtrail_otel_authorization_gap/`, a canonical contradicted
authorization demo with CloudTrail-shaped evidence, OTEL-shaped evidence,
policy evidence, normalized action evidence, and tool-call binding.

The stacked GPU collateral receipt branch adds seven synthetic GPU collateral
fixtures for serial matching and node-health diagnostics. These are point-in-
time receipt demos only, not real DCGM/NVML integrations.

## Verification

Passed:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 test_receipt_compiler.py
PYTHONDONTWRITEBYTECODE=1 python3 demo_gallery.py --json
PYTHONDONTWRITEBYTECODE=1 python3 demo_real_world_importers.py
PYTHONDONTWRITEBYTECODE=1 python3 -m py_compile receipt_ir.py passes.py receipt_compile.py receipt_scan.py receipt_validate.py claim_types.py verdict.py boundary.py compile demo_gallery.py test_receipt_compiler.py
git diff --check
```

Gallery summary:

```text
34 receipts from 33 incident directories
supported: 14 | contradicted: 11 | unknown: 8 | not_applicable: 1
compiler errors: 0 | validation errors: 0
```

## Not Implemented

- No GPU probes.
- No real DCGM/NVML hardware integration.
- No scanprobe integration.
- No change to verdict logic.
- No public release action.

## Fixture Binding Note

Legacy clean/supported authorization fixtures now include explicit grant-binding
evidence. The paired bad fixtures also include binding evidence, so their
contradicted verdicts isolate the intended failure: expired grant timing or
untrusted literal action source.

The `grant_binding_present` pass now enforces the cross-boundary decision ID:
`authorization.execution_time_decision_id` must match
`tool_call.invocation_context.decision_id`. A missing tool-call decision ID is
`unknown`; an explicit mismatch is `contradicted`.
