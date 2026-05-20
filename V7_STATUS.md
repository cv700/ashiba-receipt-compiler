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
26 receipts from 25 incident directories
supported: 7 | contradicted: 8 | unknown: 10 | not_applicable: 1
compiler errors: 0 | validation errors: 0
```

## Not Implemented

- No GPU probes.
- No GPU claim pack.
- No scanprobe integration.
- No change to verdict logic.
- No public release action.
