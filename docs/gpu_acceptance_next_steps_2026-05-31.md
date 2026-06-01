# GPU Acceptance Next Steps

Date: 2026-05-31

Branch: `codex/gpu-acceptance-hardening`

## Objective

Close the GPU capacity acceptance loop with one real Lambda packet before running
more provider experiments.

## Do Tonight

1. Run the real Lambda packet through the current hardened branch.
   - Input: `/Users/coop/Downloads/acceptance_packet_lambda.tgz`
   - Reconstruct or provide `reservation.json`.
   - Run `import_nvidia_smi`.
   - Compile `gpu_capacity_acceptance`.
   - Run `ashiba scan` on the packet.
   - Confirm the current claim-pack scanner guidance still produces useful gaps.

2. Create one demo-gallery entry from the Lambda packet.
   - Keep it small and redacted.
   - Preserve `nvidia_smi_query.csv`, `nvidia_smi_list.txt`, `nvidia_smi_full.xml`,
     `topo.txt`, `host_info.txt`, and `mig_instances.txt`.
   - Include the generated `gpu_inventory.json` and `gpu_probe_observation.json`.
   - Avoid adding provider secrets, account IDs, raw SSH details, or stable hardware
     IDs unless redacted.

3. Do the declared-evidence reconstruction test.
   - Create `declared_evidence_lambda.txt` from Lambda dashboard/order evidence.
   - Rebuild `reservation.json` from that file without looking at `nvidia-smi`.
   - Compare the rebuilt declaration against the one used for compile.
   - Record whether declaration provenance is `manual_declaration`,
     `dashboard_text`, or another future source class.

4. Do one final thermonuclear review pass on the PR diff.
   - Look for scanner-specific product prose creeping back into `receipt_scan.py`.
   - Check claim-pack semantics against pass behavior.
   - Check file growth and new helper boundaries.

## Do Not Do Tonight

- Do not run Lambda, RunPod, and Vast just to get three provider logos.
- Do not treat provider success as proof of declared-side truth.
- Do not add provider API declaration binding yet.
- Do not expand the scanner into a provider-specific importer project.

## Decision Rule

Run another provider only if the Lambda packet reveals a provider-output issue
that synthetic fixtures cannot exercise, such as container-restricted
`nvidia-smi`, missing timestamp columns, missing MIG fields, or permission
barriers around health evidence.

Otherwise, spend the next work block on packaging the Lambda loop cleanly:

`real packet -> scan readiness/gaps -> import -> compile -> bounded receipt`
