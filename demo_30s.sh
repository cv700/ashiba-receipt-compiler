#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT" || exit 1

echo "== 1. Before: scan missing authorization boundary telemetry =="
report_dir="/tmp/ashiba_demo_30s_report"
rm -rf "$report_dir"
PYTHONDONTWRITEBYTECODE=1 ./ashiba scan \
  readiness_packets/hero_authz_before_2026-05-26/logs \
  --policy readiness_packets/hero_authz_before_2026-05-26/policy.json \
  --report \
  --out "$report_dir"

echo
echo "Report preview:"
sed -n '1,37p' "$report_dir/ashiba_report.md"

echo
echo "== 2. After: scan with revocation state and action binding =="
PYTHONDONTWRITEBYTECODE=1 ./ashiba scan \
  readiness_packets/hero_authz_after_2026-05-26/logs \
  --policy readiness_packets/hero_authz_after_2026-05-26/policy.json

echo
echo "== 3. Compile a bounded receipt card for the same action =="
PYTHONDONTWRITEBYTECODE=1 ./compile readiness_packets/hero_authz_supported_2026-05-26/artifacts --card

echo
echo "== 4. Bad input fails closed =="
tmpdir="$(mktemp -d)"
bad_stdout="$(mktemp)"
bad_stderr="$(mktemp)"
trap 'rm -rf "$tmpdir"; rm -f "$bad_stdout" "$bad_stderr"' EXIT
printf '{bad json' > "$tmpdir/bad.json"
if PYTHONDONTWRITEBYTECODE=1 ./ashiba scan "$tmpdir" >"$bad_stdout" 2>"$bad_stderr"; then
  cat "$bad_stdout"
  cat "$bad_stderr" >&2
  echo "ERROR: invalid input unexpectedly scanned successfully" >&2
  exit 1
fi
cat "$bad_stdout"
cat "$bad_stderr" >&2
echo "Bad input produced nonzero exit as expected."
