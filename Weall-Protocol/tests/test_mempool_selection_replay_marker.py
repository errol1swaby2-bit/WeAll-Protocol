from __future__ import annotations

import copy
from pathlib import Path

from weall.crypto.sig import canonical_tx_message
from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _mk_executor(tmp_path: Path, name: str, *, chain_id: str = "batch113-marker") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=name,
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _submit_signed_register(ex: WeAllExecutor, signer: str = "@freshuser") -> None:
    pubkey, priv = deterministic_ed25519_keypair(label=signer)
    payload = {"pubkey": pubkey}
    msg = canonical_tx_message(
        chain_id=ex.chain_id,
        tx_type="ACCOUNT_REGISTER",
        signer=signer,
        nonce=1,
        payload=payload,
        parent=None,
    )
    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": 1,
            "payload": payload,
            "chain_id": ex.chain_id,
            "sig": priv.sign(msg).hex(),
        }
    )
    assert sub["ok"] is True


def test_apply_block_restores_leader_mempool_selection_marker_byte_for_byte(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEMPOOL_SELECTION_POLICY", "canonical")
    leader = _mk_executor(tmp_path, "leader")
    follower = _mk_executor(tmp_path, "follower")

    _submit_signed_register(leader)
    block, new_state, applied_ids, invalid_ids, err = leader.build_block_candidate(
        max_txs=10,
        allow_empty=False,
        force_ts_ms=max(1, leader.chain_time_floor_ms()) + 1,
    )
    assert err == ""
    assert isinstance(block, dict)
    assert isinstance(block.get("mempool_selection"), dict)

    meta = leader.commit_block_candidate(
        block=block,
        new_state=new_state,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert meta.ok is True

    replay = follower.apply_block(copy.deepcopy(block))
    assert replay.ok is True

    assert leader.read_state() == follower.read_state()
    leader_meta = leader.read_state().get("meta") or {}
    follower_meta = follower.read_state().get("meta") or {}
    assert leader_meta.get("mempool_selection_last") == follower_meta.get("mempool_selection_last")
