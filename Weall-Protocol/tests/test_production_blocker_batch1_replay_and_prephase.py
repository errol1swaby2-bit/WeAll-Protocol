from __future__ import annotations

import copy
from pathlib import Path

import pytest

from weall.crypto.sig import canonical_tx_message
from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _mk_executor(tmp_path: Path, name: str, *, chain_id: str = "prod-blocker-batch1") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=name,
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _submit_signed_register(ex: WeAllExecutor, signer: str = "@freshuser") -> None:
    pubkey, priv = deterministic_ed25519_keypair(label=signer)
    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": signer,
        "nonce": 1,
        "payload": {"pubkey": pubkey},
        "chain_id": ex.chain_id,
    }
    msg = canonical_tx_message(
        chain_id=ex.chain_id,
        tx_type="ACCOUNT_REGISTER",
        signer=signer,
        nonce=1,
        payload={"pubkey": pubkey},
        parent=None,
    )
    signed = {**tx, "sig": priv.sign(msg).hex()}
    sub = ex.submit_tx(signed)
    assert sub["ok"] is True


def test_prod_local_block_replays_on_fresh_node_byte_for_byte(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
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
    assert isinstance(new_state, dict)

    leader_meta = leader.commit_block_candidate(
        block=block,
        new_state=new_state,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert leader_meta.ok is True

    replay_meta = follower.apply_block(copy.deepcopy(block))
    assert replay_meta.ok is True

    leader_block = leader.get_latest_block()
    follower_block = follower.get_latest_block()
    assert isinstance(leader_block, dict)
    assert isinstance(follower_block, dict)
    assert leader_block == follower_block
    assert leader.read_state() == follower.read_state()


def test_prod_build_block_candidate_fails_closed_on_corrupt_system_queue_pre_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _mk_executor(tmp_path, "leader")
    ex.state["system_queue"] = ["corrupt"]

    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=max(1, ex.chain_time_floor_ms()) + 1,
    )

    assert block is None
    assert new_state is None
    assert applied_ids == []
    assert invalid_ids == []
    assert err == "system_emitter_pre_failed:SystemQueueCorruptionError"


def test_build_block_candidate_normalizes_corrupt_poh_shapes_deterministically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex_a = _mk_executor(tmp_path, "node-a", chain_id="prod-blocker-batch1-poh")
    ex_b = _mk_executor(tmp_path, "node-b", chain_id="prod-blocker-batch1-poh")

    corrupt_poh = {
        "tier2_cases": ["bad", {"unexpected": True}],
        "tier3_cases": "bad",
    }
    ex_a.state["poh"] = copy.deepcopy(corrupt_poh)
    ex_b.state["poh"] = copy.deepcopy(corrupt_poh)

    ts_ms = max(1, ex_a.chain_time_floor_ms()) + 1
    blk_a, st_a, applied_a, invalid_a, err_a = ex_a.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=ts_ms,
    )
    blk_b, st_b, applied_b, invalid_b, err_b = ex_b.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=ts_ms,
    )

    assert err_a == ""
    assert err_b == ""
    assert applied_a == []
    assert applied_b == []
    assert invalid_a == []
    assert invalid_b == []
    assert isinstance(blk_a, dict)
    assert isinstance(blk_b, dict)
    assert isinstance(st_a, dict)
    assert isinstance(st_b, dict)
    assert st_a.get("poh") == st_b.get("poh") == {"tier2_cases": {}, "tier3_cases": {}}
    assert blk_a == blk_b
