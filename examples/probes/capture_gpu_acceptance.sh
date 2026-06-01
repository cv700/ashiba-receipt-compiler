#!/usr/bin/env bash
set -euo pipefail

out_dir="${1:-acceptance_packet}"
logs_dir="$out_dir/logs"
mkdir -p "$logs_dir"

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$logs_dir/observed_at.txt"

redact_gpu_identifiers() {
  sed -E \
    -e 's/GPU-[A-Za-z0-9_-]+/GPU-REDACTED/g' \
    -e 's#<uuid>[^<]+</uuid>#<uuid>REDACTED</uuid>#g' \
    -e 's#<serial>[^<]+</serial>#<serial>REDACTED</serial>#g'
}

fields="index,name"
fields="$fields,memory.total,mig.mode.current"
fields="$fields,persistence_mode,ecc.mode.current"
fields="$fields,pcie.link.gen.current,pcie.link.gen.max"
fields="$fields,pcie.link.width.current,pcie.link.width.max"
fields="$fields,vbios_version,driver_version,timestamp"

nvidia-smi --query-gpu="$fields" --format=csv > "$logs_dir/nvidia_smi_query.csv"
nvidia-smi -q -x | redact_gpu_identifiers > "$logs_dir/nvidia_smi_full.xml"
nvidia-smi -L | redact_gpu_identifiers > "$logs_dir/nvidia_smi_list.txt"
nvidia-smi topo -m > "$logs_dir/topo.txt" 2>&1 || true
uname -a > "$logs_dir/host_info.txt"

: > "$logs_dir/mig_instances.txt"
nvidia-smi mig -lgi >> "$logs_dir/mig_instances.txt" 2>/dev/null || true
nvidia-smi mig -lci >> "$logs_dir/mig_instances.txt" 2>/dev/null || true

cat > "$out_dir/README.md" <<'EOF'
# GPU Acceptance Packet

Tier A capture for ARC GPU capacity acceptance.

Tier B deferred for demo-v0: dmesg, DCGM, and NCCL capture.
Stable cross-file hash redaction is intentionally out of scope for demo-v0.
EOF

echo "wrote $out_dir"
