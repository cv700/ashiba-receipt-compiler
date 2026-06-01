#!/usr/bin/env python3
"""GPU capacity acceptance smoke tests."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from constants import (
    PASS_CONTRADICTED,
    PASS_SATISFIED,
    PASS_UNKNOWN,
    SUPPORTED,
    UNKNOWN,
)
from passes import gpu_not_mig_sliced, gpu_sku_count_match
from receipt_ir import ReceiptIR
from test_support import (
    ENV,
    ROOT,
    run_ashiba_process,
    run_compile_process,
    run_import_nvidia_smi_process,
    run_receipt_json,
)


def _pass_ir(artifacts: dict) -> ReceiptIR:
    return ReceiptIR(receipt_id="test", claim_type="test", claim={}, expected_evidence=[], artifacts=artifacts)


def test_gpu_capacity_acceptance_gallery_fixtures() -> None:
    cases = [
        (
            "gpu_acceptance_supported",
            SUPPORTED,
            0,
            {"gpu_sku_count_match": PASS_SATISFIED, "gpu_not_mig_sliced": PASS_SATISFIED},
        ),
        (
            "gpu_acceptance_mig_unknown",
            UNKNOWN,
            0,
            {"gpu_sku_count_match": PASS_SATISFIED, "gpu_not_mig_sliced": PASS_UNKNOWN},
        ),
        (
            "gpu_acceptance_unknown",
            UNKNOWN,
            1,
            {"gpu_sku_count_match": PASS_UNKNOWN, "gpu_not_mig_sliced": PASS_SATISFIED},
        ),
    ]

    for directory, verdict, absence_count, expected_pass_statuses in cases:
        receipt = run_receipt_json("--artifacts-dir", f"examples/{directory}", "--claim-type", "gpu_capacity_acceptance")
        assert receipt["verdict"]["status"] == verdict, (directory, receipt)
        assert len(receipt.get("absence", [])) == absence_count, (directory, receipt)
        pass_results = {result["pass_id"]: result for result in receipt["pass_results"]}
        for pass_id, expected_status in expected_pass_statuses.items():
            assert pass_results[pass_id]["status"] == expected_status, (directory, pass_results[pass_id])
        if directory == "gpu_acceptance_mig_unknown":
            mig_result = pass_results["gpu_not_mig_sliced"]
            assert mig_result["verdict_effect"] == UNKNOWN
            assert "MIG enabled" in mig_result["detail"]
        if directory == "gpu_acceptance_unknown":
            missing = {record["expected_path"] for record in receipt["absence"]}
            assert "gpu_inventory.declared_sku" in missing


def test_gpu_capacity_acceptance_pass_units() -> None:
    supported = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 8,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H100 SXM5 80GB HBM3"] * 8,
            "observed_count": 8,
            "observed_mig_modes": ["Disabled"] * 8,
        },
    })
    assert gpu_sku_count_match(supported).status == PASS_SATISFIED
    assert gpu_not_mig_sliced(supported).status == PASS_SATISFIED

    a10_supported = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "A10-PCIe",
            "declared_count": 1,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA A10"],
            "observed_count": 1,
        },
    })
    assert gpu_sku_count_match(a10_supported).status == PASS_UNKNOWN

    a10_family_supported = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "A10",
            "declared_count": 1,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA A10"],
            "observed_count": 1,
        },
    })
    assert gpu_sku_count_match(a10_family_supported).status == PASS_SATISFIED

    wrong_sku = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 8,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H100 SXM5 80GB HBM3"] * 7 + ["NVIDIA A100 80GB PCIe"],
            "observed_count": 8,
        },
    })
    assert gpu_sku_count_match(wrong_sku).status == PASS_CONTRADICTED

    wrong_variant = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 1,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H100 PCIe 80GB HBM3"],
            "observed_count": 1,
        },
    })
    assert gpu_sku_count_match(wrong_variant).status == PASS_CONTRADICTED

    missing_variant = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 1,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H100 80GB HBM3"],
            "observed_count": 1,
        },
    })
    assert gpu_sku_count_match(missing_variant).status == PASS_UNKNOWN

    short_count = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 8,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H100 SXM5 80GB HBM3"] * 7,
            "observed_count": 7,
        },
    })
    assert gpu_sku_count_match(short_count).status == PASS_CONTRADICTED

    over_count = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 8,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H100 SXM5 80GB HBM3"] * 9,
            "observed_count": 9,
        },
    })
    over_count_result = gpu_sku_count_match(over_count)
    assert over_count_result.status == PASS_CONTRADICTED
    assert "does not equal declared count" in over_count_result.detail

    partial_names = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 8,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H100 SXM5 80GB HBM3"],
            "observed_count": 8,
        },
    })
    assert gpu_sku_count_match(partial_names).status == PASS_UNKNOWN

    misleading_name = _pass_ir({
        "gpu_inventory": {
            "declared_sku": "H100-SXM5-80GB",
            "declared_count": 1,
        },
        "gpu_probe_observation": {
            "observed_names": ["NVIDIA H1000 test fixture"],
            "observed_count": 1,
        },
    })
    assert gpu_sku_count_match(misleading_name).status == PASS_CONTRADICTED

    mig_na = _pass_ir({"gpu_probe_observation": {"observed_mig_modes": ["[N/A]", "Disabled"], "observed_count": 2}})
    assert gpu_not_mig_sliced(mig_na).status == PASS_SATISFIED

    mig_enabled = _pass_ir({"gpu_probe_observation": {"observed_mig_modes": ["Disabled", "Enabled"], "observed_count": 2}})
    assert gpu_not_mig_sliced(mig_enabled).status == PASS_UNKNOWN

    partial_mig = _pass_ir({"gpu_probe_observation": {"observed_mig_modes": ["Disabled"], "observed_count": 8}})
    assert gpu_not_mig_sliced(partial_mig).status == PASS_UNKNOWN

    assert gpu_not_mig_sliced(_pass_ir({"gpu_probe_observation": {"observed_mig_modes": []}})).status == PASS_UNKNOWN
    assert gpu_sku_count_match(_pass_ir({})).status == PASS_UNKNOWN


def test_nvidia_smi_importer_bridge() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        reservation_path = tmp_path / "reservation.json"
        reservation_path.write_text(
            json.dumps({
                "declared_sku": "H100-SXM5-80GB",
                "declared_count": 8,
                "declared_topology_class": "HGX H100 NVL8",
                "declared_region": "us-east",
            }),
            encoding="utf-8",
        )
        csv_path = tmp_path / "nvidia_smi_query.csv"
        rows = [
            "index,uuid,name,mig.mode.current,timestamp",
            *[
                f"{index},GPU-{index:04d},NVIDIA H100 SXM5 80GB HBM3,Disabled,2026/05/26 14:02:46.123"
                for index in range(8)
            ],
        ]
        csv_path.write_text("\n".join(rows), encoding="utf-8")

        imported = run_import_nvidia_smi_process(str(csv_path), "--reservation", str(reservation_path))
        assert imported.returncode == 0, imported.stderr
        artifacts = json.loads(imported.stdout)
        assert artifacts["gpu_inventory"]["declared_sku"] == "H100-SXM5-80GB"
        assert artifacts["gpu_probe_observation"]["observed_count"] == 8
        assert artifacts["gpu_probe_observation"]["observed_at"] == "2026-05-26T14:02:46Z"
        assert artifacts["gpu_probe_observation"]["observation_row_spread_seconds"] == 0.0

        piped = run_compile_process(
            "-",
            "--claim-type",
            "gpu_capacity_acceptance",
            "-v",
            input_text=imported.stdout,
        )
        assert piped.returncode == 0, piped.stderr
        assert piped.stdout.strip() == "SUPPORTED"

        out_dir = tmp_path / "artifacts"
        written = run_import_nvidia_smi_process(str(csv_path), "--reservation", str(reservation_path), "--out", str(out_dir))
        assert written.returncode == 0, written.stderr
        assert (out_dir / "gpu_inventory.json").is_file()
        assert (out_dir / "gpu_probe_observation.json").is_file()
        compiled = run_compile_process(str(out_dir), "--claim-type", "gpu_capacity_acceptance", "-v")
        assert compiled.returncode == 0, compiled.stderr
        assert compiled.stdout.strip() == "SUPPORTED"

        bad_timestamp_path = tmp_path / "bad_timestamp.csv"
        bad_timestamp_path.write_text(
            "\n".join([
                "index,uuid,name,mig.mode.current,timestamp",
                "0,GPU-0000,NVIDIA H100 SXM5 80GB HBM3,Disabled,yesterday",
            ]),
            encoding="utf-8",
        )
        bad_timestamp = run_import_nvidia_smi_process(str(bad_timestamp_path), "--reservation", str(reservation_path))
        assert bad_timestamp.returncode == 1
        assert bad_timestamp.stdout == ""
        assert "could not normalize timestamp" in bad_timestamp.stderr

        divergent_timestamp_path = tmp_path / "divergent_timestamp.csv"
        divergent_timestamp_path.write_text(
            "\n".join([
                "index,uuid,name,mig.mode.current,timestamp",
                "0,GPU-0000,NVIDIA H100 SXM5 80GB HBM3,Disabled,2026/05/26 14:02:46.123",
                "1,GPU-0001,NVIDIA H100 SXM5 80GB HBM3,Disabled,2026/05/26 14:04:00.123",
            ]),
            encoding="utf-8",
        )
        divergent_timestamp = run_import_nvidia_smi_process(str(divergent_timestamp_path), "--reservation", str(reservation_path))
        assert divergent_timestamp.returncode == 1
        assert divergent_timestamp.stdout == ""
        assert "not one acceptance snapshot" in divergent_timestamp.stderr

        tolerated_spread_path = tmp_path / "tolerated_timestamp_spread.csv"
        tolerated_spread_path.write_text(
            "\n".join([
                "index,uuid,name,mig.mode.current,timestamp",
                "0,GPU-0000,NVIDIA H100 SXM5 80GB HBM3,Disabled,2026/05/26 14:02:46.123",
                "1,GPU-0001,NVIDIA H100 SXM5 80GB HBM3,Disabled,2026/05/26 14:02:48.123",
            ]),
            encoding="utf-8",
        )
        tolerated_spread = run_import_nvidia_smi_process(str(tolerated_spread_path), "--reservation", str(reservation_path))
        assert tolerated_spread.returncode == 0, tolerated_spread.stderr
        spread_artifacts = json.loads(tolerated_spread.stdout)
        assert spread_artifacts["gpu_probe_observation"]["observed_at"] == "2026-05-26T14:02:46Z"
        assert spread_artifacts["gpu_probe_observation"]["observation_row_spread_seconds"] == 2.0

        required_columns = {
            "name": "index,uuid,mig.mode.current,timestamp\n0,GPU-0000,Disabled,2026/05/26 14:02:46.123",
            "timestamp": "index,uuid,name,mig.mode.current\n0,GPU-0000,NVIDIA H100 SXM5 80GB HBM3,Disabled",
            "mig.mode.current": "index,uuid,name,timestamp\n0,GPU-0000,NVIDIA H100 SXM5 80GB HBM3,2026/05/26 14:02:46.123",
        }
        for column, text in required_columns.items():
            missing_column_path = tmp_path / f"missing_{column.replace('.', '_')}.csv"
            missing_column_path.write_text(text, encoding="utf-8")
            missing_column = run_import_nvidia_smi_process(str(missing_column_path), "--reservation", str(reservation_path))
            assert missing_column.returncode == 1
            assert missing_column.stdout == ""
            assert f"missing required {column}" in missing_column.stderr


def test_capture_acceptance_writes_tier_a_packet() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        fake_nvidia_smi = bin_dir / "nvidia-smi"
        fake_nvidia_smi.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  --query-gpu=*) echo "index, uuid, serial, name, memory.total [MiB], mig.mode.current, timestamp"
                 echo "0, GPU-fake, 123, NVIDIA A10, 23028 MiB, [N/A], 2026/05/31 22:23:21.446" ;;
  "-q -x") echo "<nvidia_smi_log></nvidia_smi_log>" ;;
  "-L") echo "GPU 0: NVIDIA A10 (UUID: GPU-fake)" ;;
  "topo -m") echo "topology unavailable in fake test"; exit 7 ;;
  "mig -lgi") echo "No GPU instances found" ;;
  "mig -lci") echo "No compute instances found" ;;
  *) echo "unexpected nvidia-smi args: $*" >&2; exit 2 ;;
esac
""",
            encoding="utf-8",
        )
        fake_nvidia_smi.chmod(0o755)

        env = {**ENV, "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin"}
        packet = tmp_path / "packet"
        proc = subprocess.run(
            ["/bin/bash", "capture_acceptance.sh", str(packet)],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        assert proc.returncode == 0, proc.stderr
        logs = packet / "logs"
        assert (logs / "nvidia_smi_query.csv").is_file()
        assert (logs / "nvidia_smi_full.xml").is_file()
        assert (logs / "nvidia_smi_list.txt").read_text(encoding="utf-8").startswith("GPU 0:")
        assert "topology unavailable" in (logs / "topo.txt").read_text(encoding="utf-8")
        assert (logs / "host_info.txt").read_text(encoding="utf-8").strip()
        assert "No GPU instances" in (logs / "mig_instances.txt").read_text(encoding="utf-8")


def test_capture_acceptance_fails_closed_when_nvidia_smi_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        fake_nvidia_smi = bin_dir / "nvidia-smi"
        fake_nvidia_smi.write_text("#!/usr/bin/env bash\nexit 42\n", encoding="utf-8")
        fake_nvidia_smi.chmod(0o755)

        env = {**ENV, "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin"}
        proc = subprocess.run(
            ["/bin/bash", "capture_acceptance.sh", str(tmp_path / "packet")],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        assert proc.returncode == 42
        assert "wrote" not in proc.stdout


def test_ashiba_scan_recognizes_gpu_capacity_artifacts() -> None:
    proc = run_ashiba_process("scan", "examples/gpu_acceptance_supported", "--json")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert "gpu_capacity_acceptance" in result["can_decide"]
    assert result["cannot_decide"] == []
    assert result["summary"]["actions_found"] == 0
    assert result["summary"]["input_kinds"]["GPU artifact"] == 2
    assert result["probeable_next"] == []
    evidence = {
        label
        for observation in result["detected_inputs"]
        for label in observation["evidence"]
    }
    assert {"gpu_inventory", "gpu_probe_observation"} <= evidence

    text = run_ashiba_process("scan", "examples/gpu_acceptance_supported")
    assert text.returncode == 0, text.stderr
    assert "- Claim families ready: gpu_capacity_acceptance" in text.stdout
    assert "- no side-effect actions recognized" in text.stdout

    health = run_ashiba_process("scan", "examples/gpu_node_health_supported", "--json")
    assert health.returncode == 0, health.stderr
    health_result = json.loads(health.stdout)
    assert "gpu_node_health_diagnostic" in health_result["can_decide"]
    assert health_result["summary"]["input_kinds"]["GPU artifact"] == 4


def test_ashiba_scan_gpu_capacity_partial_packet_probe() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "gpu_inventory.json").write_text(
            json.dumps({
                "declared_sku": "A10",
                "declared_count": 1,
                "declared_region": "Virginia, USA",
            }),
            encoding="utf-8",
        )

        proc = run_ashiba_process("scan", str(root), "--json")
        assert proc.returncode == 0, proc.stderr
        result = json.loads(proc.stdout)
        blocked = [item for item in result["cannot_decide"] if item["claim"] == "gpu_capacity_acceptance"]
        assert len(blocked) == 1, result
        assert blocked[0]["missing"] == [
            "gpu_probe_observation.observed_names",
            "gpu_probe_observation.observed_count",
            "gpu_probe_observation.observed_mig_modes",
            "gpu_probe_observation.observed_at",
        ]
        assert "run nvidia-smi acceptance capture and import observed GPU names" in result["probeable_next"]
        assert "run nvidia-smi acceptance capture and import observed GPU count" in result["probeable_next"]
        assert "capture nvidia-smi MIG mode and nvidia-smi -L output" in result["probeable_next"]
        assert "capture nvidia-smi timestamp for the acceptance snapshot" in result["probeable_next"]
        assert any("nvidia-smi acceptance capture" in item for item in result["punch_list"])
        assert result["summary"]["input_kinds"]["GPU artifact"] == 1


def run_gpu_acceptance_tests() -> None:
    test_gpu_capacity_acceptance_gallery_fixtures()
    test_gpu_capacity_acceptance_pass_units()
    test_nvidia_smi_importer_bridge()
    test_capture_acceptance_writes_tier_a_packet()
    test_capture_acceptance_fails_closed_when_nvidia_smi_fails()
    test_ashiba_scan_recognizes_gpu_capacity_artifacts()
    test_ashiba_scan_gpu_capacity_partial_packet_probe()


def main() -> int:
    run_gpu_acceptance_tests()
    print("gpu acceptance smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
