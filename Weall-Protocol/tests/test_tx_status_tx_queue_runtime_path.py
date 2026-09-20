from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_public_tx_status_tx_queue_read_is_best_effort() -> None:
    tx = _read("src/weall/api/routes_public_parts/tx.py")

    assert "def _read_tx_queue_best_effort()" in tx
    assert "except OSError:" in tx
    assert "_tx_queue_record_for(_read_tx_queue_best_effort(), tx_id)" in tx


def test_runtime_queue_defaults_stay_outside_repository_data_tree() -> None:
    tx = _read("src/weall/api/routes_public_parts/tx.py")
    poh = _read("src/weall/api/routes_public_parts/poh.py")

    for src in (tx, poh):
        assert 'or "data"' not in src
        assert 'Path.home() / ".local" / "share" / "weall" / "runtime"' in src

    assert '"observer_tx_queue.json"' in tx
    assert '"webrtc_signal_bridge_tx_queue.json"' in poh


def test_docker_genesis_runtime_paths_are_writable_volume_bound() -> None:
    compose = _read("docker-compose.genesis.yml")

    assert "WEALL_DB_PATH=/var/lib/weall/genesis.db" in compose
    assert "WEALL_RUNTIME_DIR=/var/lib/weall" in compose
    assert "WEALL_TX_QUEUE_PATH=/var/lib/weall/observer_tx_queue.json" in compose
    assert "weall-genesis-data:/var/lib/weall" in compose
    assert "WEALL_TX_QUEUE_PATH=./data" not in compose
    assert "WEALL_RUNTIME_DIR=./data" not in compose


def test_docker_genesis_boot_gate_probes_tx_status_read_only_safety() -> None:
    gate = _read("scripts/docker_genesis_api_boot_gate.sh")

    assert "/v1/tx/status/docker-genesis-boot-gate-nonexistent-tx" in gate
    assert "verify tx-status read-only safety" in gate
    assert "unexpected tx status payload" in gate
    assert "docker_genesis_tx_status_gate_failed" in gate
