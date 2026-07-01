from __future__ import annotations

from pathlib import Path
from typing import Any

from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root


Json = dict[str, Any]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, *, chain_id: str, name: str) -> WeAllExecutor:
    root = _repo_root()
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"node-{name}",
        chain_id=chain_id,
        tx_index_path=str(root / "generated" / "tx_index.json"),
    )


def _seed_confirmed_account(ex: WeAllExecutor, signer: str) -> None:
    accepted = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": 1,
            "payload": {"pubkey": f"k:{signer}:root"},
        }
    )
    assert accepted.get("ok") is True, accepted
    meta = ex.produce_block(max_txs=10, allow_empty=False)
    assert meta.ok is True, meta
    assert int(ex.read_state()["accounts"][signer]["nonce"]) == 1


def _batch_inputs() -> list[Json]:
    return [
        {
            "tx_type": "ACCOUNT_DEVICE_REGISTER",
            "signer": "@batcher",
            "nonce": 2,
            "payload": {
                "device_id": "browser:batcher:1",
                "device_type": "browser",
                "label": "Browser 1",
                "pubkey": "k:batcher:device:1",
            },
        },
        {
            "tx_type": "ACCOUNT_DEVICE_REGISTER",
            "signer": "@batcher",
            "nonce": 2,
            "payload": {
                "device_id": "browser:batcher:1",
                "device_type": "browser",
                "label": "Browser 1",
                "pubkey": "k:batcher:device:1",
            },
        },
        {
            "tx_type": "ACCOUNT_DEVICE_REGISTER",
            "signer": "@batcher",
            "nonce": 2,
            "payload": {
                "device_id": "browser:batcher:conflict",
                "device_type": "browser",
                "label": "Conflicting browser",
                "pubkey": "k:batcher:device:conflict",
            },
        },
        {
            "tx_type": "ACCOUNT_SESSION_KEY_ISSUE",
            "signer": "@batcher",
            "nonce": 3,
            "payload": {"session_key": "session:batcher:1", "ttl_s": 3600},
        },
        {
            "tx_type": "ACCOUNT_SESSION_KEY_ISSUE",
            "signer": "@batcher",
            "nonce": 5,
            "payload": {"session_key": "session:batcher:gap", "ttl_s": 3600},
        },
    ]


def _project_results(results: list[Json]) -> list[Json]:
    projected: list[Json] = []
    for result in results:
        projected.append(
            {
                "ok": bool(result.get("ok")),
                "error": result.get("error"),
                "already_known": bool(result.get("already_known", False)),
                "tx_id": result.get("tx_id"),
                "details": result.get("details") or {},
            }
        )
    return projected


def _candidate_order(ex: WeAllExecutor) -> list[str]:
    return [str(tx.get("tx_id") or "") for tx in ex.mempool.fetch_for_block(limit=20, candidate_height=int(ex.read_state().get("height") or 0) + 1)]


def test_batch_submit_matches_serial_submit_results_order_and_state_root(tmp_path: Path) -> None:
    chain_id = "batch-submit-equivalence"
    serial = _executor(tmp_path, chain_id=chain_id, name="serial")
    batched = _executor(tmp_path, chain_id=chain_id, name="batched")
    _seed_confirmed_account(serial, "@batcher")
    _seed_confirmed_account(batched, "@batcher")

    serial_inputs = _batch_inputs()
    batch_inputs = _batch_inputs()

    serial_results = [serial.submit_tx(tx, ingress="mempool") for tx in serial_inputs]
    batch_results = batched.submit_txs_batch(batch_inputs, ingress="mempool", include_timings=True)

    assert _project_results(batch_results) == _project_results(serial_results)
    assert _candidate_order(batched) == _candidate_order(serial)

    assert batch_results[-1].get("ok") is False
    assert batch_results[-1].get("error") == "bad_nonce"
    assert batch_results[1].get("already_known") is True
    assert batch_results[2].get("error") == "mempool_signer_nonce_conflict"

    timings = batch_results[0].get("timings_ms")
    assert isinstance(timings, dict)
    for field in [
        "tx_submit_total_wall_ms",
        "tx_signature_verify_wall_ms",
        "tx_canonicalize_or_hash_wall_ms",
        "tx_nonce_check_wall_ms",
        "tx_mempool_insert_wall_ms",
        "tx_reject_wall_ms",
        "tx_duplicate_check_wall_ms",
    ]:
        assert field in timings
        assert isinstance(timings[field], (int, float))
        assert timings[field] >= 0

    serial_meta = serial.produce_block(max_txs=20, allow_empty=False)
    batch_meta = batched.produce_block(max_txs=20, allow_empty=False)
    assert serial_meta.ok is True, serial_meta
    assert batch_meta.ok is True, batch_meta
    assert compute_state_root(batched.read_state()) == compute_state_root(serial.read_state())
