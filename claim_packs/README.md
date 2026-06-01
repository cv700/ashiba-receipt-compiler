# Claim Packs

A claim pack is ARC's versioned verifier contract for one class of bounded
receipt claims. It is a declarative JSON config that defines the claim
statement, evidence contract, applicability conditions, deterministic pass
pipeline, pass parameters, and boundary renderer family for a claim type.

A claim pack is not an evidence bundle, receipt, prompt, customer use case, or
loose invariant. Evidence is supplied separately; the claim pack defines how ARC
evaluates that evidence.

Each `*.json` file declares:

- `name`: claim type name used by `--claim-type` and `incident_manifest.json`.
- `renderer_family`: required registered family used by receipt boundary policy.
- `claim`: `id` and human-readable `text`.
- `expected_evidence`: dotted artifact paths required for support.
- `applicability_evidence`: paths that instantiate the artifact class.
- Action-level packs should point at `side_effects.0.*` fields from
  SideEffectEnvelope v1. Legacy `parsed_actions` and `tool_call` inputs are
  normalized into that envelope by the compiler/scanner boundary.
- Multi-action inputs compile one action-scoped receipt per envelope; within
  each receipt, `side_effects.0` means the selected side effect.
- `support_requirements`: optional extra support/readiness contracts. A
  requirement can use `path` with `presence: "path_exists"` when explicit null is
  meaningful, `all_of` for grouped required fields, and `same_value` for a
  cross-boundary equality check.
- `evidence_guidance`: optional scanner guidance keyed by an `expected_evidence`
  path or `support_requirements.id`, with `probe`, `why`, and
  `suggested_log_shape` fields.
- `passes`: ordered deterministic pass IDs from `passes.py`.
- `pass_params`: optional per-pass parameters.

Pass IDs are validated against `PassSpec` metadata in `passes.py`. If a pass
declares `required_paths`, the claim pack must cover those paths through either
`expected_evidence` or `support_requirements`; otherwise the pack fails closed
at registry load time.

The compiler loads this directory by default and falls back to built-in copies
only if a default pack is absent.
