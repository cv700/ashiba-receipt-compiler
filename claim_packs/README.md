# Claim Packs

Claim packs are declarative JSON configs for receipt claim types.

Each `*.json` file declares:

- `name`: claim type name used by `--claim-type` and `incident_manifest.json`.
- `claim`: `id` and human-readable `text`.
- `expected_evidence`: dotted artifact paths required for support.
- `applicability_evidence`: paths that instantiate the artifact class.
- `passes`: ordered deterministic pass IDs from `passes.py`.
- `pass_params`: optional per-pass parameters.

The compiler loads this directory by default and falls back to built-in copies
only if a default pack is absent.
