# Hero Authorization Demo

This is the live CLI path for the `authorization_bound_action` story.

The point of the demo is not that ARC rubber-stamps an action. The point is
that ARC refuses to call a high-risk side effect authorized until the logs bind
the authorization or approval decision to the exact action that ran.

## Quick Path

Run the full live path from the repository root:

```bash
./demo_30s.sh
```

Expected sections:

```text
== 1. Before: scan missing authorization boundary telemetry ==
== 2. After: scan with revocation state and action binding ==
== 3. Compile a bounded receipt card for the same action ==
== 4. Bad input fails closed ==
```

To see the missing probe implemented as a runnable boundary wrapper, run:

```bash
./demo_reference_probe.sh
```

That path starts from the same blocked packet, runs
`examples/probes/authorization_boundary_probe.py`, scans the probe output, and
then compiles a supported receipt from the emitted artifacts.

## Story

1. A high-risk Lambda action executed: `hero-authz-charge-001`.
2. A grant-like policy exists.
3. The first scan is missing explicit revocation state and action-bound approval.
4. ARC blocks `authorization_bound_action` instead of pretending it is
   supported.
5. Adding the missing telemetry makes the second scan decidable.

## First Scan: Missing Boundary Telemetry

Run from the repository root:

```bash
./ashiba scan readiness_packets/hero_authz_before_2026-05-26/logs \
  --policy readiness_packets/hero_authz_before_2026-05-26/policy.json
```

Expected shape:

```text
Action readiness:
- 0 decidable, 1 blocked
  - blocked hero-authz-charge-001 lambda.amazonaws.com:Invoke: missing authorization.revoked_at, authorization-to-action binding

You cannot decide:
- authorization_bound_action
  missing authorization.revoked_at
  missing authorization-to-action binding

Probe-able next:
- add revocation_state export
- log authorization decision_id or approval_id on the tool call
```

Interpretation: ARC found the side effect and the grant window, but it cannot
prove that the grant was not revoked or that a nearby authorization governed
this exact action.

## Second Scan: Added Telemetry

Run:

```bash
./ashiba scan readiness_packets/hero_authz_after_2026-05-26/logs \
  --policy readiness_packets/hero_authz_after_2026-05-26/policy.json
```

Expected shape:

```text
Action readiness:
- 1 decidable, 0 blocked
  - ready hero-authz-charge-001 lambda.amazonaws.com:Invoke

You can decide:
- authorization_bound_action
- human_approval_before_external_side_effect

Probe-able next:
- (none)
```

The added telemetry is intentionally small:

```text
authorization.revoked_at = null
authorization.execution_time_decision_id = decision-hero-authz-001
authorization.grant_active_at_execution  = true
side_effects.0.invocation.decision_id    = decision-hero-authz-001
```

Interpretation: the logs now say the revocation state was checked, and the
authorization decision binds to the exact side effect.

## Receipt Card

The scanner works over raw operational logs. The compiler receipt needs
compiler-shaped verifier artifacts, including the stronger fields described in
[authorization_binding_contract.md](authorization_binding_contract.md).

For the supported receipt card for the same action story, run:

```bash
./compile readiness_packets/hero_authz_supported_2026-05-26/artifacts --card
```

Expected verdict:

```text
Verdict: supported
Basis: all required evidence was present and all required deterministic passes were satisfied
```

Use this as the receipt-card close after the before/after scan loop. The raw
hero CloudTrail packet is scan-ready after the second scan; the receipt card
uses compiler-shaped verifier artifacts for the same action ID:
`hero-authz-charge-001`.

## Known Limits

ARC does not prove that the action was correct, safe, intended by the model, or
generally secure. It only checks whether the supplied evidence supports a
narrow operational claim for this specific action.

Missing evidence means `unknown`, not success. A mismatched runtime decision ID
means `contradicted`, not success.

Receipt-ready means the claim can be decided. It does not mean the claim will
be supported. For example, if the same reference probe emits a `revoked_at`
timestamp before the action execution time, `./ashiba scan` has enough evidence
to decide `authorization_bound_action`, but `./compile` returns
`CONTRADICTED`.

## Good Live Ending

After the second scan, ask:

```text
Where do your logs record action_id, approval_id or decision_id, revoked_at,
and execution time?
```

That is the intended alpha-user moment: "Can I run this on my logs?"
