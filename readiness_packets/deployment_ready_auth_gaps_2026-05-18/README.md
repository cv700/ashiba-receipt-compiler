# Readiness Packet: Deployment Ready, Authorization Gaps

This packet exercises the intended first scanner experience:

```bash
./ashiba scan readiness_packets/deployment_ready_auth_gaps_2026-05-18/logs --policy readiness_packets/deployment_ready_auth_gaps_2026-05-18/policy.json
```

Expected shape:

- `deployment_matches_reviewed_commit` can be decided.
- `authorization_bound_action` cannot be decided because revocation state and
  authorization-to-action binding are missing.
