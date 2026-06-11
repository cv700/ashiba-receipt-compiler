#!/usr/bin/env python3
"""Tests for the NVIDIA attestation EAT token importer and attestation binding.

Negative controls covered (one per fraud/replay/gap mode):
  - replayed attestation (EAT nonce from an old challenge) -> CONTRADICTED
  - wrong challenge nonce -> CONTRADICTED
  - missing attestation -> UNKNOWN
  - cert chain failed (expired/revoked) -> CONTRADICTED
  - cert chain indeterminate (parser cannot decide) -> UNKNOWN
  - identity bridge missing -> UNKNOWN
  - declared GPU ID maps to a UEID absent from the attested set -> CONTRADICTED
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from test_support import run_compile_process, run_import_nvattest_process


SAMPLE_UEID = "6553331079044780778828634442627054552420306731400000000000000000"

SAMPLE_EAT_CLAIM = {
    "dbgstat": "disabled",
    "eat_nonce": "a1b2c3d4e5f6a7b800000000000000000000000000000000000000000000000000",
    "hwmodel": "GH100 A01 GSP BROM",
    "measres": "success",
    "secboot": True,
    "ueid": SAMPLE_UEID,
    "x-nvidia-gpu-driver-version": "590.12",
    "x-nvidia-gpu-vbios-version": "96.00.A5.00.01",
    "x-nvidia-gpu-arch-check": True,
    "x-nvidia-overall-att-result": True,
    "x-nvidia-gpu-attestation-report-cert-chain": {
        "x-nvidia-cert-status": "valid",
        "x-nvidia-cert-ocsp-status": "good",
        "x-nvidia-cert-expiration-date": "9999-12-31T23:59:59Z",
    },
}

CHALLENGE_NONCE = "a1b2c3d4e5f6a7b8"
EAT_NONCE = SAMPLE_EAT_CLAIM["eat_nonce"]
CONTRACT_GPU_ID = "GPU-H100-SXM-0001"
COLLECTED_AT = "2026-06-01T10:00:00Z"

MANIFEST_ARGS = (
    "--contract-id", "LOAN-2026-0042",
    "--window-start", "2026-06-01T00:00:00Z",
    "--window-end", "2026-06-08T00:00:00Z",
    "--declared-gpu-id", CONTRACT_GPU_ID,
    "--expected-gpu-class", "H100",
    "--operator", "lender-ops@example.com",
    "--tool-version", "nvattest 1.2.0",
    "--command", "nvattest attest --device gpu --verifier remote --gpu-evidence-source=corelib "
                 f"--nonce {CHALLENGE_NONCE} --output-format json",
    "--collected-at", COLLECTED_AT,
)


def _write_claims(tmp_path: Path, claims=None) -> Path:
    claims_path = tmp_path / "claims.json"
    claims_path.write_text(json.dumps(SAMPLE_EAT_CLAIM if claims is None else claims), encoding="utf-8")
    return claims_path


def _write_bridge(tmp_path: Path, mappings=None, **overrides) -> Path:
    bridge = {
        "schedule_id": "UCC1-2026-0042",
        "mapping_source": "provider asset register export, ticket OPS-1001",
        "mapping_time": "2026-05-30T09:00:00Z",
        "mapper": "lender-ops@example.com",
        "mappings": mappings
        or [
            {
                "contract_gpu_id": CONTRACT_GPU_ID,
                "provider_asset_id": "prov-asset-1",
                "ueid": SAMPLE_UEID,
            }
        ],
    }
    bridge.update(overrides)
    bridge_path = tmp_path / "bridge.json"
    bridge_path.write_text(json.dumps(bridge), encoding="utf-8")
    return bridge_path


def _import_full(tmp_path: Path, out_dir: Path, claims=None, nonce: str = CHALLENGE_NONCE, bridge: bool = True):
    claims_path = _write_claims(tmp_path, claims)
    args = [str(claims_path), "--nonce", nonce, *MANIFEST_ARGS, "--out", str(out_dir)]
    if bridge:
        args.extend(["--identity-bridge", str(_write_bridge(tmp_path))])
    return run_import_nvattest_process(*args)


def _compile_verdict(out_dir: Path) -> str:
    compiled = run_compile_process(str(out_dir), "--claim-type", "gpu_attested_identity_window", "-v")
    assert compiled.returncode == 0, compiled.stderr
    return compiled.stdout.strip()


def test_importer_stores_eat_nonce_not_challenge() -> None:
    """The attestation artifact must carry the token's nonce, not the challenge."""
    with tempfile.TemporaryDirectory() as tmp:
        claims_path = _write_claims(Path(tmp))
        result = run_import_nvattest_process(
            str(claims_path), "--nonce", CHALLENGE_NONCE, "--collected-at", COLLECTED_AT
        )
        assert result.returncode == 0, result.stderr
        artifacts = json.loads(result.stdout)

        att = artifacts["gpu_attestation"]
        assert att["attestation_nonce"] == EAT_NONCE
        assert att["attestation_nonce"] != CHALLENGE_NONCE
        assert att["nonce_match"] is True
        assert att["attested_ueids"] == [SAMPLE_UEID]
        assert "attested_serials" not in att
        assert att["cert_chain_verified"] is True
        assert att["gpu_count"] == 1
        assert att["hwmodel"] == "GH100 A01 GSP BROM"
        assert att["measres"] == "success"
        assert att["driver_version"] == "590.12"
        assert att["overall_result"] is True
        assert att["source"] == "nvidia_nras_v4"
        assert att["debug_disabled"] is True

        pm = artifacts["probe_manifest"]
        assert pm["challenge_nonce"] == CHALLENGE_NONCE
        assert pm["probe_id"] == "gpu_attestation_nvattest_v0"
        assert pm["claim_ref"] == "claim.gpu_attested_identity_window"
        assert pm["raw_evidence_sha256"].startswith("sha256:")
        assert pm["parsed_evidence_sha256"].startswith("sha256:")
        assert pm["driver_version"] == "590.12"


def test_importer_manifest_binding_fields() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / "evidence"
        result = _import_full(tmp_path, out_dir)
        assert result.returncode == 0, result.stderr

        pm = json.loads((out_dir / "probe_manifest.json").read_text(encoding="utf-8"))["probe_manifest"]
        assert pm["contract_id"] == "LOAN-2026-0042"
        assert pm["window_start"] == "2026-06-01T00:00:00Z"
        assert pm["window_end"] == "2026-06-08T00:00:00Z"
        assert pm["declared_gpu_ids"] == [CONTRACT_GPU_ID]
        assert pm["expected_gpu_class"] == "H100"
        assert pm["operator"] == "lender-ops@example.com"
        assert pm["tool_version"] == "nvattest 1.2.0"
        assert "nvattest attest" in pm["command"]
        assert pm["committed_at"] == COLLECTED_AT

        bridge = json.loads((out_dir / "identity_bridge.json").read_text(encoding="utf-8"))["identity_bridge"]
        assert bridge["mappings"][0]["contract_gpu_id"] == CONTRACT_GPU_ID
        assert bridge["mappings"][0]["ueid"] == SAMPLE_UEID
        assert bridge["mapping_source"]
        assert bridge["mapping_time"]
        assert bridge["mapper"]


def test_importer_nonce_padding_is_strict() -> None:
    """A challenge that is a bare prefix of the EAT nonce must not count as bound."""
    with tempfile.TemporaryDirectory() as tmp:
        claims_path = _write_claims(Path(tmp))
        result = run_import_nvattest_process(
            str(claims_path), "--nonce", "a1b2c3d4", "--collected-at", COLLECTED_AT
        )
        assert result.returncode == 0, result.stderr
        att = json.loads(result.stdout)["gpu_attestation"]
        # remainder after "a1b2c3d4" is "e5f6a7b80...0", not all zeros
        assert att["nonce_match"] is False


def test_importer_multi_gpu() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        claims = [SAMPLE_EAT_CLAIM, {**SAMPLE_EAT_CLAIM, "ueid": "GPU-B-UEID"}]
        claims_path = _write_claims(Path(tmp), claims)
        result = run_import_nvattest_process(
            str(claims_path), "--nonce", CHALLENGE_NONCE, "--collected-at", COLLECTED_AT
        )
        assert result.returncode == 0, result.stderr
        artifacts = json.loads(result.stdout)
        assert len(artifacts["gpu_attestation"]["attested_ueids"]) == 2
        assert artifacts["gpu_attestation"]["gpu_count"] == 2
        assert artifacts["gpu_attestation"]["nonce_match"] is True


def test_importer_no_ueid_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        claim = {k: v for k, v in SAMPLE_EAT_CLAIM.items() if k != "ueid"}
        claims_path = _write_claims(Path(tmp), claim)
        result = run_import_nvattest_process(
            str(claims_path), "--nonce", CHALLENGE_NONCE, "--collected-at", COLLECTED_AT
        )
        assert result.returncode == 1
        assert "ueid" in result.stderr


def test_importer_empty_claims_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        claims_path = _write_claims(Path(tmp), [])
        result = run_import_nvattest_process(
            str(claims_path), "--nonce", CHALLENGE_NONCE, "--collected-at", COLLECTED_AT
        )
        assert result.returncode == 1
        assert "no GPU claims" in result.stderr


def test_importer_malformed_bridge_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        claims_path = _write_claims(tmp_path)
        bridge_path = tmp_path / "bridge.json"
        bridge_path.write_text(json.dumps({"mappings": [{"contract_gpu_id": "GPU-1"}]}), encoding="utf-8")
        result = run_import_nvattest_process(
            str(claims_path), "--nonce", CHALLENGE_NONCE, "--identity-bridge", str(bridge_path)
        )
        assert result.returncode == 1
        assert "ueid" in result.stderr


def test_live_shape_evidence_compiles_supported() -> None:
    """Import -> bridge -> manifest -> compile -> SUPPORTED for matching evidence."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / "evidence"
        result = _import_full(tmp_path, out_dir)
        assert result.returncode == 0, result.stderr
        assert _compile_verdict(out_dir) == "SUPPORTED"


def test_negative_control_replayed_attestation_contradicted() -> None:
    """Replay: EAT nonce echoes an old challenge while the manifest carries a new one."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / "evidence"
        result = _import_full(tmp_path, out_dir, nonce="0000111122223333")
        assert result.returncode == 0, result.stderr
        att = json.loads((out_dir / "gpu_attestation.json").read_text(encoding="utf-8"))["gpu_attestation"]
        assert att["nonce_match"] is False
        assert att["attestation_nonce"] == EAT_NONCE
        assert _compile_verdict(out_dir) == "CONTRADICTED"


def test_negative_control_wrong_nonce_contradicted() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / "evidence"
        result = _import_full(tmp_path, out_dir, nonce="ffffffffffffffff")
        assert result.returncode == 0, result.stderr
        assert _compile_verdict(out_dir) == "CONTRADICTED"


def test_negative_control_missing_attestation_unknown() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / "evidence"
        result = _import_full(tmp_path, out_dir)
        assert result.returncode == 0, result.stderr
        (out_dir / "gpu_attestation.json").unlink()
        assert _compile_verdict(out_dir) == "UNKNOWN"


def test_negative_control_cert_chain_failed_contradicted() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / "evidence"
        claim = {
            **SAMPLE_EAT_CLAIM,
            "x-nvidia-gpu-attestation-report-cert-chain": {
                "x-nvidia-cert-status": "expired",
                "x-nvidia-cert-ocsp-status": "good",
            },
        }
        result = _import_full(tmp_path, out_dir, claims=claim)
        assert result.returncode == 0, result.stderr
        att = json.loads((out_dir / "gpu_attestation.json").read_text(encoding="utf-8"))["gpu_attestation"]
        assert att["cert_chain_verified"] is False
        assert _compile_verdict(out_dir) == "CONTRADICTED"


def test_negative_control_cert_chain_indeterminate_unknown() -> None:
    """When the parser cannot decide cert validity, the verdict must not be SUPPORTED."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / "evidence"
        claim = {k: v for k, v in SAMPLE_EAT_CLAIM.items() if k != "x-nvidia-gpu-attestation-report-cert-chain"}
        result = _import_full(tmp_path, out_dir, claims=claim)
        assert result.returncode == 0, result.stderr
        att = json.loads((out_dir / "gpu_attestation.json").read_text(encoding="utf-8"))["gpu_attestation"]
        assert att["cert_chain_verified"] is None
        assert _compile_verdict(out_dir) == "UNKNOWN"


def test_negative_control_identity_bridge_missing_unknown() -> None:
    """UEIDs without a bridge cannot resolve to contract identity; never SUPPORTED."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / "evidence"
        result = _import_full(tmp_path, out_dir, bridge=False)
        assert result.returncode == 0, result.stderr
        assert _compile_verdict(out_dir) == "UNKNOWN"


def _write_jwt(tmp_path: Path, payload) -> Path:
    import base64

    def seg(obj) -> str:
        raw = json.dumps(obj).encode("utf-8") if not isinstance(obj, bytes) else obj
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    token = ".".join([seg({"alg": "ES384", "typ": "JWT"}), seg(payload), seg(b"unverified-signature")])
    token_path = tmp_path / "token.jwt"
    token_path.write_text(token, encoding="utf-8")
    return token_path


def test_raw_token_payload_consistency_recorded() -> None:
    """The raw token becomes the hashed evidence of record and the parsed claims must match it."""
    import hashlib

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / "evidence"
        claims_path = _write_claims(tmp_path)
        token_path = _write_jwt(tmp_path, SAMPLE_EAT_CLAIM)
        result = run_import_nvattest_process(
            str(claims_path), "--nonce", CHALLENGE_NONCE, *MANIFEST_ARGS,
            "--identity-bridge", str(_write_bridge(tmp_path)),
            "--raw-token", str(token_path), "--out", str(out_dir),
        )
        assert result.returncode == 0, result.stderr

        att = json.loads((out_dir / "gpu_attestation.json").read_text(encoding="utf-8"))["gpu_attestation"]
        assert att["token_payload_consistent"] is True

        pm = json.loads((out_dir / "probe_manifest.json").read_text(encoding="utf-8"))["probe_manifest"]
        token_hash = "sha256:" + hashlib.sha256(token_path.read_bytes()).hexdigest()
        assert pm["raw_evidence_sha256"] == token_hash
        assert pm["claims_input_sha256"].startswith("sha256:")
        assert _compile_verdict(out_dir) == "SUPPORTED"


def test_negative_control_token_payload_conflict_contradicted() -> None:
    """Parsed claims that disagree with the raw token payload must contradict."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / "evidence"
        claims_path = _write_claims(tmp_path)
        tampered_payload = {**SAMPLE_EAT_CLAIM, "measres": "failure", "x-nvidia-overall-att-result": False}
        token_path = _write_jwt(tmp_path, tampered_payload)
        result = run_import_nvattest_process(
            str(claims_path), "--nonce", CHALLENGE_NONCE, *MANIFEST_ARGS,
            "--identity-bridge", str(_write_bridge(tmp_path)),
            "--raw-token", str(token_path), "--out", str(out_dir),
        )
        assert result.returncode == 0, result.stderr
        att = json.loads((out_dir / "gpu_attestation.json").read_text(encoding="utf-8"))["gpu_attestation"]
        assert att["token_payload_consistent"] is False
        assert _compile_verdict(out_dir) == "CONTRADICTED"


def test_raw_token_non_jwt_is_hashed_without_consistency_claim() -> None:
    """A binary raw token is bound by hash; no consistency verdict is invented."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / "evidence"
        claims_path = _write_claims(tmp_path)
        token_path = tmp_path / "evidence.bin"
        token_path.write_bytes(b"\x00\x01binary-evidence-blob\xff")
        result = run_import_nvattest_process(
            str(claims_path), "--nonce", CHALLENGE_NONCE, *MANIFEST_ARGS,
            "--identity-bridge", str(_write_bridge(tmp_path)),
            "--raw-token", str(token_path), "--out", str(out_dir),
        )
        assert result.returncode == 0, result.stderr
        att = json.loads((out_dir / "gpu_attestation.json").read_text(encoding="utf-8"))["gpu_attestation"]
        assert "token_payload_consistent" not in att
        pm = json.loads((out_dir / "probe_manifest.json").read_text(encoding="utf-8"))["probe_manifest"]
        assert pm["raw_evidence_sha256"].startswith("sha256:")
        assert _compile_verdict(out_dir) == "SUPPORTED"


def test_negative_control_bridged_identity_mismatch_contradicted() -> None:
    """The bridge maps the declared GPU ID to a UEID the attestation does not contain."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / "evidence"
        claims_path = _write_claims(tmp_path)
        bridge_path = _write_bridge(
            tmp_path,
            mappings=[
                {
                    "contract_gpu_id": CONTRACT_GPU_ID,
                    "provider_asset_id": "prov-asset-1",
                    "ueid": "9999999999999999999999999999999999999999999999999999999999999999",
                }
            ],
        )
        result = run_import_nvattest_process(
            str(claims_path), "--nonce", CHALLENGE_NONCE, *MANIFEST_ARGS,
            "--identity-bridge", str(bridge_path), "--out", str(out_dir),
        )
        assert result.returncode == 0, result.stderr
        assert _compile_verdict(out_dir) == "CONTRADICTED"


def run_nvattest_importer_tests() -> None:
    test_importer_stores_eat_nonce_not_challenge()
    test_importer_manifest_binding_fields()
    test_importer_nonce_padding_is_strict()
    test_importer_multi_gpu()
    test_importer_no_ueid_fails()
    test_importer_empty_claims_fails()
    test_importer_malformed_bridge_fails()
    test_live_shape_evidence_compiles_supported()
    test_negative_control_replayed_attestation_contradicted()
    test_negative_control_wrong_nonce_contradicted()
    test_negative_control_missing_attestation_unknown()
    test_negative_control_cert_chain_failed_contradicted()
    test_negative_control_cert_chain_indeterminate_unknown()
    test_negative_control_identity_bridge_missing_unknown()
    test_raw_token_payload_consistency_recorded()
    test_negative_control_token_payload_conflict_contradicted()
    test_raw_token_non_jwt_is_hashed_without_consistency_claim()
    test_negative_control_bridged_identity_mismatch_contradicted()
