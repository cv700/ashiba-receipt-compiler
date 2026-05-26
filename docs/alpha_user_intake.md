# Alpha User Intake

Use this when someone asks whether ARC can run on their logs. The goal is to
find one high-risk side effect, identify the evidence systems around it, and
learn whether the logs can be made receipt-ready.

## One-Sentence Setup

ARC checks narrow operational claims against supplied evidence. For the first
alpha pass, we want one action where authorization or approval should have
controlled whether the side effect was allowed to run.

## Pick One Side Effect

Ask:

- What is one high-risk action you care about?
- Which system executes it?
- What is the concrete operation name?
- What resource or customer object does it affect?
- What would make this action scary if it ran without the right authorization?

Good examples:

- create a Stripe charge
- invoke a production Lambda
- change IAM permissions
- deploy to production
- delete or export customer data
- execute a Kubernetes admin action

## Action Runtime Logs

Ask for the log source that proves the side effect happened.

Questions:

- Where is the runtime/action log?
- Is there a stable `action_id`, `tool_call_id`, `eventID`, `requestID`,
  `span_id`, or equivalent?
- Is there an execution timestamp?
- Is the timestamp UTC, or can it be normalized to UTC?
- What tool/function/API name is recorded?
- Are request parameters or resource identifiers logged?

Fields ARC wants:

```text
tool_call.action_id
parsed_actions.0.action_id
parsed_actions.0.executed_at
parsed_actions.0.tool
```

## Authorization Or Approval Logs

Ask where the allow/deny decision lives.

Questions:

- Is authorization a grant, a human approval, a policy decision, or something
  else?
- Is there a stable `approval_id` or `decision_id`?
- Is the decision recorded as approved/denied?
- Who or what issued the decision?
- What scope did it cover?
- What time window did it cover?
- Can the runtime log record which decision ID was used at execution?

Fields ARC wants:

```text
authorization.grant_id
authorization.grant_valid_from
authorization.grant_valid_until
authorization.decision_id
approval.approval_id
approval.tool_call_id
approval.approved_at
approval.decision
approval.actor
tool_call.invocation_context.decision_id
tool_call.invocation_context.approval_id
```

## Revocation State

Ask this explicitly. It is easy to miss.

Questions:

- Can the system export whether the grant was revoked before execution?
- If it was not revoked, can the log say that explicitly with `null`?
- If it was revoked, is `revoked_at` recorded as a UTC timestamp?
- Is revocation checked at render time, execution time, or both?

Field ARC wants:

```text
authorization.revoked_at
```

Use explicit `null` when revocation was checked and no revocation existed.
Missing `revoked_at` means unknown.

## Binding The Decision To The Exact Action

This is the hero question.

Ask:

- Can we join the approval or authorization decision to the exact side effect?
- Does `approval.tool_call_id` equal the action ID that executed?
- Does the runtime log include `decision_id` or `approval_id`?
- Could two nearby approvals be confused with each other?
- What would ARC use to prove this approval governed this action, not a
  different action?

Acceptable joins for scan readiness include:

```text
approval.tool_call_id == tool_call.action_id
approval.approval_id == tool_call.invocation_context.approval_id
authorization.decision_id == tool_call.invocation_context.decision_id
```

For compiler receipt support, runtime decision evidence must not contradict:

```text
tool_call.invocation_context.decision_id == authorization.execution_time_decision_id
```

## What To Send For A First Packet

Ask for a small, sanitized packet:

- one action runtime log
- one authorization or approval log
- one policy/grant record if separate
- any revocation export
- any deployment/review log only if the story includes deployment
- a short note naming the claim they want ARC to test

Preferred format:

```text
logs/
  action.json or action.jsonl
  approval.json
  revocation.json
policy.json
README.md
```

## Expected First ARC Output

Set expectations before running it.

Likely first outcomes:

- `supported`: required evidence is present and deterministic passes support
  the narrow claim.
- `contradicted`: supplied evidence conflicts with the claim.
- `unknown`: evidence is missing, malformed, ambiguous, or not joined tightly
  enough.

`unknown` is a useful result. It tells us what telemetry to add.

## Known Limits To Say Out Loud

ARC does not prove:

- model intent
- semantic correctness of the action
- custody or authenticity of logs
- general security posture
- general system reliability
- that omitted evidence would have supported the claim

ARC only checks bounded claims against the supplied evidence.

## Product Notes To Capture

During the call, write down:

- Which missing field surprised them?
- Which field would be easiest to add?
- Which join is impossible in their current system?
- Which claim do they actually want to show an auditor or platform owner?
- What phrase made them ask, "Can I run this on my logs?"
