# Live Attestation Spike — Findings (2026-06-10/11)

Goal: bind a live NVIDIA GPU attestation to nonce + manifest + identity bridge
and compile it into an ARC receipt. Two rented platforms tested. Neither
produced an attestation — and the *reasons* are the finding.

All raw evidence in this directory: `h100_spike/` (Lambda) and `b200_spike/`
(RunPod), each with logs, capability queries, command transcripts, and hashes.
Nonce custody: all challenge nonces were generated on the relying-party laptop
before each run (`nonce_precommitment_20260610.txt`).

## Finding 1 — Standard Hopper VMs cannot produce attestation

Platform: Lambda on-demand 1x H100 SXM (80GB), Ubuntu 22.04, driver 580.105.08.

- nvattest 1.2.2's NVML evidence path refuses outside CC/PPCIe mode:
  `"GPU is neither in CC nor in PPCIe mode"` (result_code 509).
- The GPU is CC-capable, but the host exposes no CPU TEE:
  `CPU CC capabilities: None` → `CC Environment: UNAVAILABLE`.
- Mode cannot be set from the guest (driver exposes no mode-set option;
  CC requires SEV-SNP/TDX at the host, which the provider does not provision).
- The CC-off path (corelib) supports **Blackwell only** in nvattest 1.2.x:
  `--gpu-architecture TEXT:{blackwell}`.

Evidence: `h100_spike/cc_capability_queries.txt`, `h100_spike/run_1/remote_attest_log.txt`.

## Finding 2 — Containerized Blackwell rentals cannot produce attestation

Platform: RunPod Secure Cloud 1x B200, Ubuntu 24.04 container, driver 580.126.20.

- corelib loads after `apt-get install libcorelib1` (the library dlopens as
  `libcorelib.so.1`; packaged in NVIDIA-enabled apt repos).
- corelib's SPDM transport runs over **PCIe DOE registers in extended config
  space**. In the container:
  - the GPU's PCI function (0000:e3:00.0) is absent from `/sys/bus/pci/devices/`;
  - config-space reads cap at the legacy 64 bytes (extended space reads 0);
  - `cap_sys_admin` and `cap_sys_rawio` are dropped.
- Result: `DoeTransport: Failed to initialize` → `Corelib Initialization
  Failed` / `Corelib Error` (result_codes 607/608). Structural, not fixable
  in-container.

Evidence: `b200_spike/container_wall_findings.txt`, `b200_spike/corelib_doe_trace.log`.

## Finding 3 — KVM VMs open the DOE path; verification blocked by a firmware/service gap (2026-06-11)

Platform: Nebius us-central1 1x B200 preemptible VM, Ubuntu 24.04, driver 580.159.04,
VBIOS 97.00.D9.00.35, libcorelib1 1.0.0.1772474517.

What worked — the platform wall from Findings 1–2 does NOT apply to real VMs:

- Extended PCIe config space fully exposed (4096 bytes as root; note the
  kernel caps non-root reads at 64 bytes — measure with sudo).
- **corelib evidence collection over PCIe DOE succeeded**: signed SPDM
  GET_MEASUREMENTS evidence (~2KB) plus device certificate chain, collected
  with relying-party nonces.
- **Exact nonce echo validated live**: the full 64-hex challenge appears
  verbatim in the evidence (`ev_nodriver_array.json` nonce == challenge,
  byte-for-byte). The "zero-padding" rule in earlier assumptions is an
  artifact of short-nonce submissions; with full-length nonces the echo is
  exact.

What did not — no verified claims, no EAT token, no UEID:

- The SPDM response omits the opaque-data section (driver/VBIOS versions,
  etc.). NVIDIA's local verifier rejects the evidence at parse
  ("OpaqueData is empty"), and NRAS rejects it server-side
  (code 5006, `GPU_DRIVER_VERSION_NOT_AVAILABLE`).
- Ruled out: persistence daemon (stopped — no change), loaded kernel driver
  (fully unloaded — no change), client-side version injection (patched the
  SDK getters with env fallbacks — NRAS still 5006, because it parses the
  signed blob server-side; patch preserved in `b200_nebius/sdk_fallback_patch.diff`).
- Conclusion: firmware/service maturity gap in the corelib-over-DOE path for
  this VBIOS (97.00.D9.00.35) — the evidence NVIDIA's collector produces is
  evidence NVIDIA's verifier rejects. Vendor-side; a clean GitHub
  issue/forum post against NVIDIA/attestation-sdk with this evidence is the
  next step, or retry when libcorelib/VBIOS updates land.

Evidence: `b200_nebius/` (collect/attest logs at every stage, raw evidence
JSON with nonce echo, SDK patch diff, environment record).

## Market-structure implication

The two dominant rental form factors — standard VMs (Hopper fleet) and
containers (much of the Blackwell spot/secure market) — are both structurally
unable to produce GPU device attestation. Attestation-backed identity and
freshness receipts are obtainable only from platforms that deliberately
support them:

- Blackwell on bare metal or a real KVM VM whose passthrough exposes extended
  config space / DOE (candidate: Nebius B200 VMs — untested),
- CC-enabled Hopper (confidential VMs, e.g. Azure NCC H100 v5),
- providers who enable CC at the host.

For ARC this validates the verdict design rather than undermining it: for
most providers the honest verdict on attested-identity claims is UNKNOWN with
a concrete cure request ("supply attestation from a CC-enabled or
DOE-accessible platform"), and "can your platform produce device attestation?"
becomes a checkable lender-diligence question.

## Corrected assumptions (live data vs. what we had encoded)

| Assumption (pre-spike) | Reality (validated live) |
|---|---|
| nonce: 16-byte hex OK | minimum 32 bytes (64 hex chars), result_code 4 otherwise |
| EAT nonce = challenge zero-padded | unresolved — padding story likely an artifact of short nonces; needs a real token |
| `--output-format json` per subcommand | global `--format json` before the subcommand |
| `nvattest --version` | `nvattest version` (subcommand) |
| corelib usable via `attest` directly | corelib only via `collect-evidence`, then `attest --gpu-evidence-source file` |
| corelib = generic CC-off path | Blackwell only in nvattest 1.2.x |
| attest output = claims JSON | envelope: `{claims, detached_eat, result_code, result_message}`; `detached_eat` is the raw-token candidate for `--raw-token` |
| fixture driver 590.12 | 580.105.08 (H100/Lambda), 580.126.20 (B200/RunPod) |

All of these are now encoded in `examples/probes/capture_gpu_attestation.sh`,
including fail-fast preflights for the two platform walls.

## Status

- Receipt machinery (importer, identity bridge, nonce binding, negative
  controls): validated against synthetic fixtures; full suite green.
- Live token validation: **still blocked** — stop condition in
  `docs/gpu_attestation_evidence_status_2026-06-10.md` remains ACTIVE.
- Next live step: Nebius (or similar) B200 **VM**, ~30 min with the patched
  script; or Azure NCC H100 v5 for the true-Hopper CC path.
- Spend: < $10 total across both spikes.
