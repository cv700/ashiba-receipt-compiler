# Authorization Binding Contract

This is the field contract for the `authorization_bound_action` hero demo.

ARC should only treat an authorization-bound action as receipt-ready when the
evidence connects the authorization decision to the exact side effect that ran.
It is not enough that an approval or grant exists somewhere nearby.

## Demo Sentence

For `authorization_bound_action`, ARC requires runtime evidence that the
decision used at execution time is the same authorization or approval decision
attached to this exact side effect.

## Scanner Readiness Contract

For `authorization_bound_action`, the scanner reports an
`authorization-to-action binding` as present when the authorization decision ID
is carried into the side-effect envelope:

```text
authorization.execution_time_decision_id == side_effects.0.invocation.decision_id
```

Human approval joins such as `approval.tool_call_id == tool_call.action_id`
remain useful for `human_approval_before_external_side_effect`, but they are
not enough by themselves to support the authorization-bound-action claim.

## Compiler Receipt Contract

For a supported `authorization_bound_action` receipt, the compiler currently
requires:

- `authorization.grant_id`
- `authorization.grant_valid_from`
- `authorization.grant_valid_until`
- `authorization.revoked_at`, including explicit `null` when checked and not
  revoked
- `authorization.render_time_grant_hash`
- `authorization.execution_time_decision_id`
- `authorization.grant_active_at_execution: true`
- `side_effects.0.executed_at`
- `side_effects.0.action_id`
- `side_effects.0.invocation.decision_id`

The runtime decision evidence must match the authorization execution-time
decision:

```text
side_effects.0.invocation.decision_id == authorization.execution_time_decision_id
```

A mismatch is `contradicted`, not `supported`.

## Missing Evidence Means Unknown

If a packet has a grant window and an action but lacks explicit revocation
state or lacks an authorization-to-action binding, ARC should return
`unknown` or scanner-blocked. It should not infer that the grant was still
valid, and it should not infer that a nearby approval governed the action.

## Known Limit

This contract proves only the narrow field-level binding for the supplied
artifacts. It does not prove model intent, action correctness, custody,
authenticity, safety, or general system reliability.
