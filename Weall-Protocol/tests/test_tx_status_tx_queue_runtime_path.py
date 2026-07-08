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


def test_tx_status_only_uses_observer_queue_overlay_on_observer_edge_nodes() -> None:
    tx = _read("src/weall/api/routes_public_parts/tx.py")

    assert "outbound = _tx_queue_summary_for_tx(t) if _observer_edge_mode() else None" in tx
    assert "must not\n    # downgrade an authoritative upstream/genesis tx-index hit" in tx


def test_local_two_frontend_rehearsal_uses_per_node_runtime_and_tx_queue_paths() -> None:
    script = _read("scripts/devnet_local_two_frontend_rehearsal.sh")

    assert 'WEALL_RUNTIME_DIR="${DEVNET_DIR}/node1/runtime"' in script
    assert 'WEALL_TX_QUEUE_PATH="${DEVNET_DIR}/node1/runtime/observer_tx_queue.json"' in script
    assert 'WEALL_RUNTIME_DIR="${DEVNET_DIR}/node2/runtime"' in script
    assert 'WEALL_TX_QUEUE_PATH="${DEVNET_DIR}/node2/runtime/observer_tx_queue.json"' in script


def test_observer_reconcile_marks_matching_local_confirmation_synced() -> None:
    tx = _read("src/weall/api/routes_public_parts/tx.py")

    assert "def _tx_queue_local_confirmation_matches_upstream" in tx
    assert "def _mark_tx_queue_locally_synced_if_matching_upstream" in tx
    assert "local_confirmation_matches_upstream" in tx
    assert "matched_local = _mark_tx_queue_locally_synced_if_matching_upstream(t, local, outbound)" in tx
    assert "matched_local = _mark_tx_queue_locally_synced_if_matching_upstream(t, idx, outbound)" in tx
    assert "It does not grant authority from local state alone." in tx
