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

The scanner reports an `authorization-to-action binding` as present when one of
these joins can be made:

- `approval.tool_call_id` equals `tool_call.action_id`
- `approval.approval_id` or `approval.decision_id` equals
  `tool_call.approval_id`, `tool_call.invocation_context.approval_id`, or
  `tool_call.invocation_context.decision_id`
- `authorization.decision_id` equals `tool_call.invocation_context.decision_id`,
  `tool_call.approval_id`, or `tool_call.invocation_context.approval_id`

The hero after packet uses the first form:

```text
approval.tool_call_id = hero-authz-charge-001
tool_call.action_id   = hero-authz-charge-001
```

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
- `parsed_actions.0.executed_at`
- `tool_call.action_id`

If runtime decision evidence is present on the tool call, it must match the
authorization execution-time decision:

```text
tool_call.invocation_context.decision_id == authorization.execution_time_decision_id
```

or:

```text
tool_call.decision_id == authorization.execution_time_decision_id
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
