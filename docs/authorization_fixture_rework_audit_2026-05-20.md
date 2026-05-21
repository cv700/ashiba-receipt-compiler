# Authorization Fixture Rework Audit

Date: 2026-05-20

## Purpose

Audit legacy authorization fixtures whose directory names imply `supported` or `clean` but whose current verdict is `unknown` under stricter authorization-binding semantics. The goal is to decide whether each fixture should be reworked into a true supported case or preserved as an unknown/missing-evidence case.

Implementation note: this audit was written before the fixture and compiler
hardening work. The recommended binding fields were subsequently added, and
`grant_binding_present` now compares `authorization.execution_time_decision_id`
against `tool_call.invocation_context.decision_id`. The "pre-rework verdict"
sections below describe the problem that motivated the edits rather than the
current compiled verdicts.

## External grounding

This audit uses only modest external grounding because the fixture schema is Ashiba-specific. Official docs support the broad modeling choice:

- AWS CloudTrail events include fields such as `eventTime`, `eventName`, `eventID`, and `requestParameters`, which can show that an API request happened and when it happened, but do not by themselves prove that an upstream agent authorization decision governed that exact action.
- OpenTelemetry traces carry span context, trace IDs, span attributes, and baggage, making it plausible to propagate a decision or correlation ID across a distributed action path.
- NIST Zero Trust Architecture separates policy decision and policy enforcement concepts; the receipt compiler's binding fields are an implementation-level way to preserve evidence that a decision was actually applied at execution.

## Current authorization-bound-action requirement

The current `authorization_bound_action` claim runs these relevant passes:

- `expected_evidence_absence`: base evidence exists.
- `grant_binding_present`: requires `authorization.render_time_grant_hash`, `authorization.execution_time_decision_id`, and `authorization.grant_active_at_execution`.
- `grant_active_at_event_time`: execution time inside the grant window.
- `revocation_before_action`: no revocation before execution.
- `no_action_from_untrusted_literal`: action source is trusted.

Pre-Step-3 problem: `grant_binding_present` checked for binding fields inside `authorization`, but did not compare `authorization.execution_time_decision_id` against `tool_call.invocation_context.decision_id`. For a truly defensible fixture, the evidence should include both sides of the binding and the compiler should enforce that they match.

## Fixture-by-fixture findings

### `adv_grant_expires_equal_executed_supported`

Pre-rework verdict: `unknown`.

Pre-rework supporting evidence:

- Grant is valid from `2026-05-15T10:00:00Z` until `2026-05-15T14:32:10Z`.
- Action executed exactly at `2026-05-15T14:32:10Z`.
- Revocation is explicitly `null`.
- Parsed action source is `model_output`.

Pre-rework gap:

- Missing `authorization.render_time_grant_hash`.
- Missing `authorization.execution_time_decision_id`.
- Missing `authorization.grant_active_at_execution`.
- Missing corresponding tool-call decision binding.

Defensible treatment:

Rework into a true supported boundary-equality case. This fixture is valuable because it tests inclusive grant-window semantics (`executed_at == grant_valid_until`). Add binding evidence rather than rename it.

Suggested additions:

- `authorization.render_time_grant_hash`: deterministic synthetic hash.
- `authorization.execution_time_decision_id`: `decision-adv-expiry-equal`.
- `authorization.grant_active_at_execution`: `true`.
- `tool_call.invocation_context.decision_id`: `decision-adv-expiry-equal`.

### `auth_grant_dir_supported`

Pre-rework verdict: `unknown`.

Pre-rework supporting evidence:

- Grant window contains execution time.
- Revocation is explicitly `null`.
- Action IDs match between parsed action and tool call.
- Parsed action source is `model_output`.

Pre-rework gap:

- Missing all grant-binding fields.
- Missing tool-call-side decision ID.

Defensible treatment:

Rework into the simplest true v2 directory happy path. This is the base example new readers expect to be supported. Add binding evidence rather than rename it.

Suggested additions:

- `authorization.render_time_grant_hash`: synthetic hash.
- `authorization.execution_time_decision_id`: `decision-act-001`.
- `authorization.grant_active_at_execution`: `true`.
- `tool_call.invocation_context.decision_id`: `decision-act-001`.

### `prompt_injection_clean`

Pre-rework verdict: `unknown`.

Pre-rework supporting evidence:

- Grant window contains both action timestamps.
- Revocation is explicitly `null`.
- All parsed action sources are `model_output`.
- The paired bad fixture contradicts because the second action has `source_kind=literal_untrusted_text`.

Pre-rework gap:

- Missing all grant-binding fields.
- Missing tool-call-side decision ID.

Defensible treatment:

Rework into a true clean counterfactual for prompt injection. This preserves the paired experiment: same broad scenario, trusted source in clean case, untrusted literal source in bad case. Add binding evidence to both the clean and bad fixtures if the intention is to isolate the prompt-injection variable. If only the clean fixture receives binding evidence, the bad fixture still contradicts, but its pass table includes an unrelated unknown binding weakness.

Suggested additions:

- Clean fixture: add authorization binding fields and `tool_call.invocation_context.decision_id`.
- Incident fixture: also add the same class of binding evidence so the only contradiction is `literal_untrusted_text`.

### `stripe_trick_bundle_clean`

Pre-rework verdict: `unknown`.

Pre-rework supporting evidence:

- Clean action executes at `2026-05-14T16:58:30Z`, inside the grant window ending `17:00:00Z`.
- Paired bad fixture executes at `2026-05-14T17:01:30Z`, outside the grant window.
- Revocation is explicitly `null`.
- Parsed action source is `model_output`.

Pre-rework gap:

- Missing all grant-binding fields.
- Missing tool-call-side decision ID.

Defensible treatment:

Rework into a true clean temporal counterfactual. Also add binding evidence to `stripe_trick_bundle` so the contradicted case is contradicted only by grant-window failure, not muddied by missing binding fields.

Suggested additions:

- Clean fixture: decision ID `decision-stripe-clean`.
- Bad fixture: decision ID `decision-stripe-expired`.
- Both: matching `authorization.execution_time_decision_id` and `tool_call.invocation_context.decision_id`.

## Recommended implementation order

1. Add decision-binding evidence to the four misleading clean/supported fixtures.
2. Add decision-binding evidence to the paired contradicted fixtures `prompt_injection_incident` and `stripe_trick_bundle` to keep their counterfactual variables isolated.
3. Update `gallery_manifest.json` expected verdict counts and rationales.
4. Add or update tests so these named fixtures are asserted as supported/contradicted for the intended reason.
5. Implemented as the Step 3 hardening task: `grant_binding_present` now compares `authorization.execution_time_decision_id` with `tool_call.invocation_context.decision_id`. Missing tool-call-side binding remains `unknown`; explicit mismatch is `contradicted`.

## Bottom line

Do not simply rename these fixtures. They are useful as supported/control fixtures. But do not merely add fields inside `authorization` either. Add the decision ID on both sides of the action boundary so the examples model the actual claim: the authorization decision governed the executed tool call.
