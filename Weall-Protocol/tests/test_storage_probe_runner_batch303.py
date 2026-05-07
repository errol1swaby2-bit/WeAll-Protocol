
from __future__ import annotations

import json
import subprocess
import os
import sys
from pathlib import Path

import pytest

from weall.runtime.storage_probe_runner import (
    StorageProbeRunnerError,
    cleanup_expired_probes,
    generate_probe_response,
    prepare_capacity_probe,
    probe_metrics,
    verify_probe_response,
)


def _challenge(**overrides: object) -> dict:
    data = {
        "challenge_id": "probe-303",
        "account_id": "@op",
        "node_pubkey": "node-pub",
        "declared_capacity_bytes": 1024 * 1024,
        "reserved_capacity_bytes": 1024 * 1024,
        "sample_count": 3,
        "sample_size_bytes": 128,
        "probe_offsets": [0, 4096, 1024 * 1024 - 128],
        "challenge_seed": "seed-303",
        "expires_height": 50,
    }
    data.update(overrides)
    return data


def test_probe_rejects_capacity_above_available_space(tmp_path: Path) -> None:
    with pytest.raises(StorageProbeRunnerError, match="insufficient_available_disk"):
        prepare_capacity_probe(tmp_path, _challenge(reserved_capacity_bytes=10_000, declared_capacity_bytes=10_000, probe_offsets=[0, 4096, 9872]), available_capacity_bytes=9_999)


def test_probe_writes_segments_inside_storage_root_and_generates_verifiable_response(tmp_path: Path) -> None:
    challenge = _challenge()
    manifest = prepare_capacity_probe(tmp_path, challenge, available_capacity_bytes=2 * 1024 * 1024)
    assert manifest["reserved_capacity_bytes"] == challenge["reserved_capacity_bytes"]
    assert manifest["total_probe_bytes"] == challenge["sample_count"] * challenge["sample_size_bytes"]
    for segment in manifest["segments"]:
        path = (tmp_path / segment["path"]).resolve()
        path.relative_to(tmp_path.resolve())
        assert path.exists()
        assert path.stat().st_size == challenge["sample_size_bytes"]
    response = generate_probe_response(tmp_path, challenge["challenge_id"])
    verification = verify_probe_response(challenge, response)
    assert verification["verification_status"] == "verified"
    assert verification["verified_capacity_bytes"] == challenge["reserved_capacity_bytes"]
    assert verification["sample_count"] == challenge["sample_count"]


def test_probe_response_fails_when_segment_is_missing(tmp_path: Path) -> None:
    challenge = _challenge()
    manifest = prepare_capacity_probe(tmp_path, challenge, available_capacity_bytes=2 * 1024 * 1024)
    first = tmp_path / manifest["segments"][0]["path"]
    first.unlink()
    with pytest.raises(StorageProbeRunnerError, match="probe_segment_missing"):
        generate_probe_response(tmp_path, challenge["challenge_id"])


def test_probe_response_fails_when_segment_is_corrupted(tmp_path: Path) -> None:
    challenge = _challenge()
    manifest = prepare_capacity_probe(tmp_path, challenge, available_capacity_bytes=2 * 1024 * 1024)
    first = tmp_path / manifest["segments"][0]["path"]
    first.write_bytes(b"corrupt")
    with pytest.raises(StorageProbeRunnerError, match="probe_segment_corrupt"):
        generate_probe_response(tmp_path, challenge["challenge_id"])


def test_probe_rejects_path_traversal_challenge_id(tmp_path: Path) -> None:
    with pytest.raises(StorageProbeRunnerError, match="unsafe_challenge_id"):
        prepare_capacity_probe(tmp_path, _challenge(challenge_id="../escape"), available_capacity_bytes=2 * 1024 * 1024)


def test_cleanup_removes_expired_probe_material(tmp_path: Path) -> None:
    challenge = _challenge(challenge_id="probe-expired", expires_height=3)
    prepare_capacity_probe(tmp_path, challenge, available_capacity_bytes=2 * 1024 * 1024)
    assert (tmp_path / "probes" / "probe-expired").exists()
    result = cleanup_expired_probes(tmp_path, current_height=4)
    assert result["removed"] == ["probe-expired"]
    assert not (tmp_path / "probes" / "probe-expired").exists()


def test_cli_prepare_respond_verify_and_metrics(tmp_path: Path) -> None:
    challenge = _challenge(challenge_id="probe-cli")
    challenge_path = tmp_path / "challenge.json"
    challenge_path.write_text(json.dumps(challenge), encoding="utf-8")
    root = Path(__file__).resolve().parents[1]
    prepare_proc = subprocess.run(
        [sys.executable, "scripts/storage_probe_runner_check.py", "prepare", "--storage-root", str(tmp_path), "--challenge", str(challenge_path), "--available-capacity-bytes", str(2 * 1024 * 1024)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    assert json.loads(prepare_proc.stdout)["challenge"]["challenge_id"] == "probe-cli"
    response_proc = subprocess.run(
        [sys.executable, "scripts/storage_probe_runner_check.py", "respond", "--storage-root", str(tmp_path), "--challenge-id", "probe-cli"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    response_path = tmp_path / "response.json"
    response_path.write_text(response_proc.stdout, encoding="utf-8")
    verify_proc = subprocess.run(
        [sys.executable, "scripts/storage_probe_runner_check.py", "verify", "--challenge", str(challenge_path), "--response", str(response_path)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    assert json.loads(verify_proc.stdout)["verification_status"] == "verified"
    metrics = probe_metrics(tmp_path)
    assert metrics["active_probe_count"] == 1
    assert metrics["probe_bytes_on_disk"] > 0
