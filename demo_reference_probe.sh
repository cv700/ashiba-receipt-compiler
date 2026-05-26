#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT" || exit 1

out_dir="/tmp/ashiba_reference_probe_demo"
rm -rf "$out_dir"

echo "== 1. Existing logs: authorization claim is blocked =="
PYTHONDONTWRITEBYTECODE=1 ./ashiba scan \
  readiness_packets/hero_authz_before_2026-05-26/logs \
  --policy readiness_packets/hero_authz_before_2026-05-26/policy.json

echo
echo "== 2. Run reference authorization-boundary probe =="
PYTHONDONTWRITEBYTECODE=1 python3 examples/probes/authorization_boundary_probe.py \
  --policy readiness_packets/hero_authz_before_2026-05-26/policy.json \
  --cloudtrail readiness_packets/hero_authz_before_2026-05-26/logs/cloudtrail_lambda_invoke.json \
  --out "$out_dir"

echo
echo "== 3. Probe output: authorization claim is receipt-ready =="
PYTHONDONTWRITEBYTECODE=1 ./ashiba scan "$out_dir/logs" --policy "$out_dir/policy.json"

echo
echo "== 4. Compile bounded receipt from probe artifacts =="
PYTHONDONTWRITEBYTECODE=1 ./compile "$out_dir/artifacts" \
  --claim-type authorization_bound_action \
  --card

echo
echo "== 5. Epistemic check: decidable does not mean supported =="
revoked_out_dir="/tmp/ashiba_reference_probe_revoked_demo"
rm -rf "$revoked_out_dir"
PYTHONDONTWRITEBYTECODE=1 python3 examples/probes/authorization_boundary_probe.py \
  --policy readiness_packets/hero_authz_before_2026-05-26/policy.json \
  --cloudtrail readiness_packets/hero_authz_before_2026-05-26/logs/cloudtrail_lambda_invoke.json \
  --revoked-at 2026-05-14T17:00:30Z \
  --out "$revoked_out_dir"
PYTHONDONTWRITEBYTECODE=1 ./ashiba scan "$revoked_out_dir/logs" --policy "$revoked_out_dir/policy.json"
PYTHONDONTWRITEBYTECODE=1 ./compile "$revoked_out_dir/artifacts" \
  --claim-type authorization_bound_action \
  --verdict
