# Canonical Demo: CloudTrail + OTEL Authorization Gap

This packet shows the smallest useful story:

- CloudTrail says a Lambda-side effect happened.
- OTEL says the downstream Stripe call happened.
- The policy export says the grant expired at `17:00:00Z`.
- The normalized action executed at `17:01:30Z`.
- The receipt is `contradicted`, with a narrow boundary.

Run:

```bash
./compile examples/cloudtrail_otel_authorization_gap --claim-type authorization_bound_action --card
```

The receipt does not say the agent is unsafe in general. It says this action was
not supported by the active-grant evidence in this packet.
