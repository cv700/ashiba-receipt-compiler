#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT" || exit 1

echo "== 1. Scan messy logs for decidable claims =="
report_dir="/tmp/ashiba_demo_30s_report"
rm -rf "$report_dir"
PYTHONDONTWRITEBYTECODE=1 ./ashiba scan \
  readiness_packets/deployment_ready_auth_gaps_2026-05-18/logs \
  --policy readiness_packets/deployment_ready_auth_gaps_2026-05-18/policy.json \
  --report \
  --out "$report_dir"

echo
echo "Report preview:"
sed -n '1,37p' "$report_dir/ashiba_report.md"

echo
echo "== 2. Compile a bounded receipt card =="
PYTHONDONTWRITEBYTECODE=1 ./compile examples/cyber_renderer_authz_supported --card

echo
echo "== 3. Bad input fails closed =="
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
