from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.bft_hotstuff import CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP
from weall.runtime.block_hash import compute_block_hash
from weall.runtime.block_id import compute_block_id
from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_mldsa_keypair


def _seed_validator_state(ex: WeAllExecutor, validators: list[str], pubs: dict[str, str]) -> None:
    st = ex.state
    st.setdefault("roles", {}).setdefault("validators", {})["active_set"] = list(validators)
    c = st.setdefault("consensus", {})
    c.setdefault("validators", {}).setdefault("registry", {})
    for v in validators:
        c["validators"]["registry"].setdefault(v, {})["pubkey"] = pubs[v]
    c.setdefault("validator_set", {})["active_set"] = list(validators)
    c["validator_set"]["epoch"] = 7
    c["validator_set"]["set_hash"] = ex._current_validator_set_hash() or ""
    c.setdefault("phase", {})["current"] = CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP
    ex._ledger_store.write(st)
    ex.state = ex._ledger_store.read()


def _block(
    *,
    height: int,
    prev_block_id: str = "",
    validator_epoch: int = 0,
    validator_set_hash: str = "",
) -> dict:
    block_ts_ms = 1000 * max(1, height)
    receipts_root = "22" * 32
    header = {
        "chain_id": "phase-cache",
        "height": int(height),
        "prev_block_hash": "",
        "block_ts_ms": block_ts_ms,
        "tx_ids": [],
        "receipts_root": receipts_root,
        "state_root": f"s-{height}",
    }
    block_hash = compute_block_hash(header=header)
    block_id = compute_block_id(
        chain_id="phase-cache",
        height=int(height),
        prev_block_id=prev_block_id,
        prev_block_hash="",
        ts_ms=block_ts_ms,
        tx_ids=[],
        receipts_root=receipts_root,
    )
    return {
        "block_id": block_id,
        "height": int(height),
        "prev_block_id": prev_block_id,
        "block_hash": block_hash,
        "block_ts_ms": block_ts_ms,
        "header": header,
        "txs": [],
        "receipts": [],
        "validator_epoch": validator_epoch,
        "validator_set_hash": validator_set_hash,
    }


def test_bootstrap_phase_keeps_unlabeled_pending_blocks_for_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="v1",
        chain_id="phase-cache",
        tx_index_path=str(Path("generated/tx_index.json")),
    )
    pubs: dict[str, str] = {}
    for vid in ("v1", "v2", "v3", "v4"):
        pub, _sk = deterministic_mldsa_keypair(label=f"batch32-{vid}")
        pubs[vid] = pub
    _seed_validator_state(ex, ["v1", "v2", "v3", "v4"], pubs)
    monkeypatch.setenv("WEALL_MODE", "prod")

    blk = _block(
        height=1,
        validator_epoch=ex._current_validator_epoch(),
        validator_set_hash=ex._current_validator_set_hash(),
    )
    assert ex.bft_cache_remote_block(blk, expected_block_hash=str(blk["block_hash"])) is True

    diag = ex.bft_diagnostics()
    assert diag["pending_remote_blocks"] == [blk["block_id"]]
    assert diag["pending_remote_block_hashes"] == [blk["block_hash"]]
    assert ex._bft_pending_block_json_by_hash(str(blk["block_hash"])) is not None
