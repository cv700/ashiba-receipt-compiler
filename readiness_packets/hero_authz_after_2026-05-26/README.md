# Hero Authorization Demo: After

This packet is the second scan in the hero demo. It uses the same high-risk
Lambda side effect as the before packet, but adds the telemetry ARC asked for:

- explicit non-revocation export via `authorization.revoked_at: null`;
- authorization decision export via `authorization.execution_time_decision_id`;
- runtime binding via `side_effects.0.invocation.decision_id`.

Expected result:

- `authorization_bound_action` is decidable;
- `human_approval_before_external_side_effect` is decidable;
- there are no missing probes for the inferred claim set.

Run from the repository root:

```bash
./ashiba scan readiness_packets/hero_authz_after_2026-05-26/logs \
  --policy readiness_packets/hero_authz_after_2026-05-26/policy.json
```
