# GPU Attestation Evidence Status — 2026-06-10

## Validation status: NOT YET VALIDATED — stop condition ACTIVE

GPU attestation is not validated ARC evidence until one live run binds
nonce + manifest + identity bridge end-to-end. All current attestation
fixtures are synthetic, nvattest-shaped data. The verdict logic is tested
(18 importer/pipeline tests + pass-unit assertions, all passing); the
evidence pipeline against a real token is not.

## Live spike result (2026-06-10/11): three platforms, no verified token yet

Three rented platforms were tested live (full writeup:
`live_runs/SPIKE_FINDINGS_2026-06-10.md`; raw evidence in `live_runs/`):

1. **Standard Hopper VM (Lambda 1x H100)** — cannot produce attestation.
   NVML evidence requires CC/PPCIe mode; the GPU is CC-capable but the host
   exposes no CPU TEE (`CPU CC capabilities: None`), and the CC-off corelib
   path is Blackwell-only in nvattest 1.2.x.
2. **Containerized Blackwell (RunPod 1x B200)** — cannot produce attestation.
   corelib's SPDM transport needs PCIe DOE access in extended config space;
   the container hides the GPU PCI function, caps config reads at 64 bytes,
   and drops `cap_sys_admin`/`cap_sys_rawio`.
3. **Blackwell KVM VM (Nebius 1x B200)** — evidence collection WORKS
   (signed SPDM evidence + device cert over DOE; exact 64-hex nonce echo
   validated live), but verification is blocked vendor-side: the firmware's
   out-of-band response omits the opaque-data section and both the local
   verifier and NRAS (code 5006) reject evidence without it. No claims, no
   EAT token, no UEID yet.

Implication: the two dominant rental form factors are structurally unable to
produce device attestation, and even on the form factor that can (real VM),
the Blackwell out-of-band verification chain is not yet end-to-end usable.
For most providers the honest ARC verdict on attested-identity claims is
UNKNOWN plus a cure request naming the platform requirement. "Can your
platform produce device attestation?" is now a checkable diligence question.

Several CLI/protocol assumptions were corrected against live behavior
(32-byte nonce minimum, corelib two-step collect→attest flow, global
`--format json`, response envelope with `detached_eat`, `libcorelib1`
packaging) — all encoded in the runbook.

What only a successful live run can still confirm:

- the exact EAT nonce echo rule (exact match expected with full-length
  nonces; `nonce_bound()` in `gpu_pass_utils.py` also tolerates zero-padding
  and is the freshness hinge);
- UEID stability across runs and across reboots (the identity bridge is
  worthless if UEIDs drift);
- real field shapes for multi-GPU nodes, cert-chain status strings, and
  whether the token carries its own issued-at timestamp (if it does, prefer
  it over operator-supplied `collected_at` for the window check);
- the hwmodel string for current SKUs (the expected-class check assumes the
  class name appears in hwmodel, e.g. "H100" in "GH100 A01 GSP BROM").

Runbook: `examples/probes/capture_gpu_attestation.sh` (platform preflights,
repeat runs, tool version, environment notes, UEID stability check,
import-ready output). Next viable platforms: a Blackwell **VM or bare metal**
with DOE-accessible passthrough (candidate: Nebius B200), or CC-enabled
Hopper (Azure NCC H100 v5).

## The bounded claims

1. `claim.gpu_attested_identity_window` (built): did this bridged GPU
   identity produce a fresh, nonce-bound attestation during the contract
   window? Identity + freshness only.
2. Capacity delivery (future, needs probes): did the provider deliver the
   contracted H100 capacity in the window? Composes claim 1's passes with
   delivery/probe/power passes. Attestation evidence can never satisfy the
   capacity passes, so a composed claim cannot go SUPPORTED on attestation
   alone — that is the structural line, not a documentation promise.

Where the attestation/capacity line is enforced (all four places):

- claim text and pack description scope the claim to identity + freshness;
- the SATISFIED pass detail states "identity and freshness only, not
  delivered capacity";
- the `gpu_lending_decision_context_v0` disclosure adds the capacity
  boundary to every receipt that carries the lending decision rule;
- no pass in the attestation pack reads capacity evidence, and no capacity
  pack lists attestation paths as satisfying evidence.

## What the receipt now binds (and what it still trusts)

Verdict-determining chain for SUPPORTED — every link must hold:

cert chain valid → EAT nonce bound to challenge (strict padding, importer
`nonce_match` also honored) → token's own verifier verdict true → firmware
measurement success → attested hwmodel matches expected class → every
declared contract GPU ID has a bridge entry → every bridged UEID present in
the attested set → collected within the contract window → no expected
evidence absent (25 paths) → no future or malformed timestamps.

Residual trust assumptions — these are control boundaries (reliance on
systems we cannot observe), not evidence gaps, and each has an owner:

1. **Token authenticity.** The compiler judges parsed claims; it does not
   re-verify the EAT signature. A fabricated claims JSON with consistent
   fields would compile SUPPORTED. Partially mitigated: `import_nvattest
   --raw-token` hashes the raw signed token as the evidence of record and
   cross-checks the parsed claims against the JWT payload — a definite
   conflict compiles CONTRADICTED (`token_payload_consistent: false`), so
   parsed evidence can no longer drift from a retained token. What remains
   open is signature verification itself: a fabricated token plus matching
   fabricated claims still passes. EAT signature verification against NVIDIA
   NRAS keys inside the importer is the single highest-value hardening step
   remaining, and needs a real token from the live run to build against.
2. **Bridge authorship.** Whoever writes the identity bridge chooses which
   UEID "is" contract GPU N. A provider-authored bridge can map contract IDs
   to any cards it controls. The bridge must be fixed at
   onboarding/perfection time by the lender or a third party and held
   constant; `mapping_source`, `mapping_time`, `mapper` exist so the receipt
   names whose assertion identity rests on. Same custody logic as the power
   threat model: independently-custodied or it proves little.
3. **Nonce custody.** The code-level circularity (challenge written into the
   attestation artifact) is fixed, but process-level circularity returns if
   the operator generates the nonce after attesting and back-fills the
   manifest. The challenge nonce must be generated by the relying party (or
   anchored outside the operator's control) before the run. The capture
   script's `ARC_NONCES` path exists for exactly this; `nonce_custody.txt`
   records which mode was used. Cross-receipt nonce reuse is invisible to a
   single receipt — uniqueness is a registry-level check.
4. **Attestation relay.** A nonce-bound, signed token proves "an NVIDIA GPU
   with this UEID answered this challenge now." It does not prove that GPU
   sits in the rack serving this contract — a provider with root can proxy
   the challenge to a different machine. Detection lives in cross-evidence
   consistency (power, topology, delivery probes), not in attestation alone.
5. **Operator clock.** `collected_at` is operator-supplied; the window check
   trusts it. If the live run shows the token or NRAS response carries its
   own timestamp, switch the window check to that.
6. **Double-pledge.** Nothing in one receipt shows the same UEID is not
   collateral in another deal. UEID-uniqueness across receipts is a
   registry-level check, cheap to add once receipts accumulate.

## Negative controls (all tested, `test_nvattest_importer.py`)

| Control | Verdict |
|---|---|
| replayed attestation (EAT nonce echoes old challenge) | CONTRADICTED |
| wrong challenge nonce | CONTRADICTED |
| challenge is bare prefix of EAT nonce (loose match attack) | importer nonce_match=False → CONTRADICTED |
| missing attestation | UNKNOWN |
| cert chain expired/revoked | CONTRADICTED |
| cert chain indeterminate (parser cannot decide) | UNKNOWN |
| identity bridge missing | UNKNOWN |
| declared GPU ID bridged to UEID absent from attested set | CONTRADICTED |
| declared GPU ID with no bridge entry | UNKNOWN |
| NVIDIA overall attestation result false | CONTRADICTED |
| firmware measurement result not success | CONTRADICTED |
| attested hwmodel mismatches expected GPU class | CONTRADICTED |
| attestation collected outside contract window | UNKNOWN |
| parsed claims conflict with raw token payload | CONTRADICTED |
| raw token present but not JWT-shaped (no consistency basis) | hashed only, no consistency verdict |

## Artifacts

- importer: `import_nvattest` (EAT nonce stored, never the challenge;
  UEIDs as `attested_ueids`, never `attested_serials`; manifest carries
  contract/window, declared GPU IDs, expected class, challenge nonce,
  command, operator, tool/driver versions, raw+parsed evidence hashes,
  `claim_ref`)
- pass: `gpu_attestation_binding` (`gpu_passes.py`)
- claim pack: `claim_packs/gpu_attested_identity_window.json` (replaces
  `gpu_serial_collateral_attested_match`, which compared UEIDs to serials)
- before/after packet:
  `readiness_packets/gpu_attestation_before_after_2026-06-10/`
- live-run runbook: `examples/probes/capture_gpu_attestation.sh`
