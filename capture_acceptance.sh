#!/usr/bin/env bash
set -euo pipefail

out_dir="${1:-acceptance_packet}"
logs_dir="$out_dir/logs"
mkdir -p "$logs_dir"

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$logs_dir/observed_at.txt"

nvidia-smi --query-gpu=index,uuid,serial,name,memory.total,mig.mode.current,persistence_mode,ecc.mode.current,pcie.link.gen.current,pcie.link.gen.max,pcie.link.width.current,pcie.link.width.max,vbios_version,driver_version,timestamp --format=csv > "$logs_dir/nvidia_smi_query.csv"
nvidia-smi -q -x > "$logs_dir/nvidia_smi_full.xml"
nvidia-smi topo -m > "$logs_dir/topo.txt"

: > "$logs_dir/mig_instances.txt"
nvidia-smi mig -lgi >> "$logs_dir/mig_instances.txt" 2>/dev/null || true
nvidia-smi mig -lci >> "$logs_dir/mig_instances.txt" 2>/dev/null || true

cat > "$out_dir/README.md" <<'EOF'
# GPU Acceptance Packet

Tier A capture for ARC GPU capacity acceptance.

Tier B deferred for demo-v0: dmesg, DCGM, and NCCL capture.
TODO: consistent-hash redaction with one salt.
EOF

echo "wrote $out_dir"
