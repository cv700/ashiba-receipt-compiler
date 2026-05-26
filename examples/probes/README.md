# Reference Probes

Reference probes show the smallest runtime instrumentation that can turn a
scanner gap into receipt-ready evidence.

## Authorization Boundary Probe

The `authorization_boundary_probe.py` script demonstrates the missing runtime
evidence for `authorization_bound_action`.

It reads a grant-like policy and a CloudTrail-shaped side effect, then writes:

- `policy.json` with explicit `authorization.revoked_at`,
  `authorization.execution_time_decision_id`, `authorization.render_time_grant_hash`,
  and `authorization.grant_active_at_execution`;
- `logs/cloudtrail_lambda_invoke.json` with the same decision id carried into
  the action invocation;
- `artifacts/` with compiler-shaped verifier artifacts for a bounded receipt.

Run from the repository root:

```bash
rm -rf /tmp/ashiba_reference_probe_demo
python3 examples/probes/authorization_boundary_probe.py \
  --policy readiness_packets/hero_authz_before_2026-05-26/policy.json \
  --cloudtrail readiness_packets/hero_authz_before_2026-05-26/logs/cloudtrail_lambda_invoke.json \
  --out /tmp/ashiba_reference_probe_demo

./ashiba scan /tmp/ashiba_reference_probe_demo/logs \
  --policy /tmp/ashiba_reference_probe_demo/policy.json

./compile /tmp/ashiba_reference_probe_demo/artifacts \
  --claim-type authorization_bound_action \
  --card
```

This is a boundary probe, not a post-hoc log patch. In a real integration, the
same evidence is emitted before the external action executes.

## Epistemic Boundaries

- Scan readiness means the evidence is sufficient to decide a claim, not that
  the claim is supported.
- The same probe can emit evidence that compiles to `supported` or
  `contradicted`.
- A supported `authorization_bound_action` receipt does not prove the action was
  correct, safe, intended by the model, secure, or representative of other runs.
- The demo writes derived fixture files only to show the evidence shape. In
  production, the boundary emits these fields before the side effect executes.

To see the negative case:

```bash
python3 examples/probes/authorization_boundary_probe.py \
  --policy readiness_packets/hero_authz_before_2026-05-26/policy.json \
  --cloudtrail readiness_packets/hero_authz_before_2026-05-26/logs/cloudtrail_lambda_invoke.json \
  --revoked-at 2026-05-14T17:00:30Z \
  --out /tmp/ashiba_reference_probe_revoked_demo

./ashiba scan /tmp/ashiba_reference_probe_revoked_demo/logs \
  --policy /tmp/ashiba_reference_probe_revoked_demo/policy.json

./compile /tmp/ashiba_reference_probe_revoked_demo/artifacts \
  --claim-type authorization_bound_action \
  --verdict
```

Expected receipt verdict:

```text
CONTRADICTED
```
