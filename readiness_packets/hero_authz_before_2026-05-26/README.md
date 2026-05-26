# Hero Authorization Demo: Before

This packet is the first scan in the hero demo. A high-risk Lambda side effect
executed and a grant-like policy exists, but the runtime boundary is not
receipt-ready:

- the policy does not export explicit revocation state;
- the action has no approval or decision binding at the tool-call boundary.

Expected result:

- `authorization_bound_action` is blocked;
- ARC asks for `authorization.revoked_at`;
- ARC asks for an authorization-to-action binding.

Run from the repository root:

```bash
./ashiba scan readiness_packets/hero_authz_before_2026-05-26/logs \
  --policy readiness_packets/hero_authz_before_2026-05-26/policy.json
```
