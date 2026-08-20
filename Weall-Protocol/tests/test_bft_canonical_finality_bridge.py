from __future__ import annotations

import copy
from pathlib import Path

from weall.runtime.bft_finality_bridge import schedule_bft_finality_receipt
from weall.runtime.constitutional_clock import procedure_height
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.executor import WeAllExecutor
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.tx.canon import load_tx_index_json


def _index_path() -> str:
    return str((Path(__file__).resolve().parents[1] / "generated" / "tx_index.json").resolve())


def _state() -> dict:
    return {
        "height": 3,
        "tip": "B3",
        "tip_hash": "h3",
        "tip_ts_ms": 3,
        "chain_id": "chain-A",
        "blocks": {
            "B1": {"height": 1, "prev_block_id": "", "block_ts_ms": 1},
            "B2": {"height": 2, "prev_block_id": "B1", "block_ts_ms": 2},
            "B3": {"height": 3, "prev_block_id": "B2", "block_ts_ms": 3},
        },
        "finalized": {"height": 0, "block_id": ""},
        "system_queue": [],
        "accounts": {"SYSTEM": {"nonce": 0}},
        "roles": {},
        "params": {"enforce_finality_attestations": True, "blocks_per_epoch": 3},
        "consensus": {
            "validator_set": {"active_set": ["@a", "@b", "@c", "@d"]},
            "validators": {"registry": {}},
            "phase": {"current": "bft_active", "history": []},
            "epochs": {"current": 0, "events": []},
        },
    }


def _qc() -> dict:
    return {"block_id": "B3", "parent_id": "B2"}


def test_justify_qc_schedules_canonical_finalize_and_epoch_open_at_executable_height() -> None:
    state = _state()
    qid = schedule_bft_finality_receipt(state, justify_qc=_qc(), next_height=4)
    assert qid

    queue = state["system_queue"]
    assert len(queue) == 1
    assert queue[0]["tx_type"] == "BLOCK_FINALIZE"
    assert queue[0]["payload"] == {"block_id": "B1", "height": 1}
    assert queue[0]["due_height"] == 4
    assert queue[0]["phase"] == "pre"
    assert queue[0]["parent"] == "B3"

    idx = load_tx_index_json(Path(_index_path()))
    pre = system_tx_emitter(state, idx, next_height=4, phase="pre")
    assert [env.tx_type for env in pre] == ["BLOCK_FINALIZE"]
    apply_tx(state, pre[0])

    assert state["finalized"] == {"height": 1, "block_id": "B1"}
    assert procedure_height(state) == 1

    # HotStuff finality lags execution. The legacy due-height=2 would already be
    # in the past while building height 4; the bridge schedules the epoch-open in
    # the current block's post phase so it cannot become permanently stranded.
    post = system_tx_emitter(state, idx, next_height=4, phase="post")
    assert "EPOCH_OPEN" in [env.tx_type for env in post]
    for env in post:
        if env.tx_type == "EPOCH_OPEN":
            apply_tx(state, env)
    assert state["consensus"]["epochs"]["current"] == 1


def _install_state(ex: WeAllExecutor) -> None:
    ex.state = copy.deepcopy(_state())
    ex._ledger_store.write(ex.state)


def test_leader_build_and_follower_replay_derive_identical_canonical_finality(
    tmp_path: Path, monkeypatch
) -> None:
    import weall.runtime.block_builder as block_builder
    import weall.runtime.block_replay as block_replay

    # This test targets deterministic finality derivation, not VRF/PQ crypto.
    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: False)
    monkeypatch.setattr(block_replay, "runtime_vrf_required", lambda: False)
    monkeypatch.setattr(block_replay, "effective_bft_enabled", lambda **_kwargs: True)
    monkeypatch.setattr(
        block_replay, "_call_admit_bft_commit_block", lambda **_kwargs: (True, None)
    )

    leader = WeAllExecutor(
        db_path=str(tmp_path / "leader.db"),
        node_id="@a",
        chain_id="chain-A",
        tx_index_path=_index_path(),
    )
    follower = WeAllExecutor(
        db_path=str(tmp_path / "follower.db"),
        node_id="@b",
        chain_id="chain-A",
        tx_index_path=_index_path(),
    )
    _install_state(leader)
    _install_state(follower)

    block, leader_state, applied, invalid, err = leader.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=4,
        bft_justify_qc=_qc(),
    )
    assert err == ""
    assert block is not None and leader_state is not None
    assert invalid == []
    assert [tx["tx_type"] for tx in block["txs"]] == ["BLOCK_FINALIZE", "EPOCH_OPEN"]
    assert leader_state["finalized"] == {"height": 1, "block_id": "B1"}
    assert leader_state["consensus"]["epochs"]["current"] == 1

    # Proposal transport carries the QC outside the canonical header. Follower
    # BFT admission verifies it before this bridge is invoked.
    block["justify_qc"] = _qc()
    meta = follower.apply_block(copy.deepcopy(block))
    assert meta.ok is True
    assert meta.applied_count == len(applied)
    assert follower.state["finalized"] == leader_state["finalized"]
    assert follower.state["consensus"]["epochs"] == leader_state["consensus"]["epochs"]
    assert follower.state["height"] == leader_state["height"] == 4


def test_bft_finalize_receipt_rejects_unknown_target_without_mutation() -> None:
    state = _state()
    before = copy.deepcopy(state)
    env = {
        "tx_type": "BLOCK_FINALIZE",
        "signer": "SYSTEM",
        "nonce": 0,
        "payload": {
            "block_id": "ghost",
            "height": 1,
            "_system_queue_id": "q:ghost",
        },
        "sig": "",
        "parent": "B3",
        "system": True,
    }
    try:
        apply_tx(state, env)
    except Exception:
        pass
    else:
        raise AssertionError("unknown BFT finalization target must fail closed")
    assert state["finalized"] == before["finalized"]
    assert state["system_queue"] == before["system_queue"]


def test_follower_rejects_proposal_that_carries_finalizing_qc_but_omits_required_receipt(
    tmp_path: Path, monkeypatch
) -> None:
    import weall.runtime.block_builder as block_builder
    import weall.runtime.block_replay as block_replay

    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: False)
    monkeypatch.setattr(block_replay, "runtime_vrf_required", lambda: False)
    monkeypatch.setattr(block_replay, "effective_bft_enabled", lambda **_kwargs: True)
    monkeypatch.setattr(
        block_replay, "_call_admit_bft_commit_block", lambda **_kwargs: (True, None)
    )

    proposer = WeAllExecutor(
        db_path=str(tmp_path / "proposer.db"),
        node_id="@a",
        chain_id="chain-A",
        tx_index_path=_index_path(),
    )
    follower = WeAllExecutor(
        db_path=str(tmp_path / "follower.db"),
        node_id="@b",
        chain_id="chain-A",
        tx_index_path=_index_path(),
    )
    _install_state(proposer)
    _install_state(follower)

    # Build a self-consistent height-4 candidate without the finality bridge,
    # then attach the deciding QC exactly as a hostile proposer could have done
    # before follower replay enforced finality-receipt completeness.
    block, _new_state, _applied, invalid, err = proposer.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=4,
    )
    assert err == ""
    assert invalid == []
    assert block is not None
    assert all(tx.get("tx_type") != "BLOCK_FINALIZE" for tx in block["txs"])
    block["justify_qc"] = _qc()

    before = copy.deepcopy(follower.state)
    meta = follower.apply_block(copy.deepcopy(block))
    assert meta.ok is False
    assert meta.error == "bad_block:required_bft_finality_receipt_missing_or_duplicated"
    assert follower.state == before
