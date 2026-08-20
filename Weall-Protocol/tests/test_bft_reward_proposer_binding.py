from __future__ import annotations

import copy
from pathlib import Path

from weall.ledger.constants import (
    INITIAL_ISSUANCE_PER_EPOCH,
    ISSUANCE_EPOCH_BLOCKS,
    TREASURY_ACCOUNT_ID,
)
from weall.runtime.executor import WeAllExecutor


def _index_path() -> str:
    return str((Path(__file__).resolve().parents[1] / "generated" / "tx_index.json").resolve())


def _state(chain_id: str) -> dict:
    return {
        "chain_id": chain_id,
        "height": ISSUANCE_EPOCH_BLOCKS - 1,
        "tip": "",
        "tip_hash": "",
        "tip_ts_ms": 1,
        "time": 1,
        "system_queue": [],
        "accounts": {
            "@validator": {"balance": 0, "nonce": 0},
            TREASURY_ACCOUNT_ID: {"balance": 0, "nonce": 0},
            "SYSTEM": {"nonce": 0},
        },
        "roles": {},
        "params": {
            "genesis_time": 0,
            "economic_unlock_time": 0,
            "economics_enabled": True,
        },
        "economics": {"monetary_policy": {"issued": 0}},
        "consensus": {
            "validator_set": {"active_set": ["@validator"]},
            "validators": {"registry": {"@validator": {"pubkey": "validator-key"}}},
        },
    }


def _executor(tmp_path: Path, *, chain_id: str, state: dict) -> WeAllExecutor:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="node-1",
        chain_id=chain_id,
        tx_index_path=_index_path(),
    )
    ex.state = copy.deepcopy(state)
    ex._ledger_store.write(ex.state)  # type: ignore[attr-defined]
    return ex


def _distribution(block: dict) -> dict:
    for tx in block.get("txs") or []:
        if isinstance(tx, dict) and tx.get("tx_type") == "BLOCK_REWARD_DISTRIBUTE":
            payload = tx.get("payload")
            assert isinstance(payload, dict)
            return payload
    raise AssertionError("missing BLOCK_REWARD_DISTRIBUTE")


def test_bft_reward_distribution_binds_actual_proposer_on_leader_and_follower(
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

    state = _state("reward-proposer-binding")
    leader = _executor(tmp_path / "leader", chain_id=state["chain_id"], state=state)
    follower = _executor(tmp_path / "follower", chain_id=state["chain_id"], state=state)

    block, leader_state, _applied, invalid, err = leader.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=2,
        proposer="@validator",
    )

    assert err == ""
    assert block is not None and leader_state is not None
    assert invalid == []

    distribution = _distribution(block)
    assert distribution["proposer"] == "@validator"
    transfers = {str(x["to"]): int(x["amount"]) for x in distribution["transfers"]}
    assert transfers["@validator"] == INITIAL_ISSUANCE_PER_EPOCH // 5
    assert transfers[TREASURY_ACCOUNT_ID] == INITIAL_ISSUANCE_PER_EPOCH - transfers["@validator"]

    block["proposer"] = "@validator"
    result = follower.apply_block(copy.deepcopy(block))
    assert result.ok is True, result.error
    assert follower.state == leader_state
    assert follower.state["accounts"]["@validator"]["balance"] == transfers["@validator"]


def test_blank_proposer_retains_non_bft_treasury_fallback(tmp_path: Path, monkeypatch) -> None:
    import weall.runtime.block_builder as block_builder

    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: False)

    state = _state("reward-no-proposer")
    leader = _executor(tmp_path / "leader", chain_id=state["chain_id"], state=state)

    block, _leader_state, _applied, invalid, err = leader.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=2,
    )

    assert err == ""
    assert block is not None
    assert invalid == []
    distribution = _distribution(block)
    assert distribution["proposer"] == ""
    assert all(str(x["to"]) != "@validator" for x in distribution["transfers"])


def test_bft_leader_threads_local_validator_into_candidate_builder() -> None:
    from types import SimpleNamespace

    from weall.runtime.bft_runtime_adapter import bft_leader_propose

    captured: dict[str, object] = {}

    class _FakeLeader:
        _bft = SimpleNamespace(
            view=0,
            last_proposed_view=-1,
            last_proposed_block_id="",
            last_proposed_block_hash="",
        )

        def _validator_signing_permitted(self) -> bool:
            return True

        def _active_validators(self) -> list[str]:
            return ["@validator"]

        def _local_validator_account(self) -> str:
            return "@validator"

        def _bft_best_justify_qc_json(self):
            return None

        def build_block_candidate(self, **kwargs):
            captured.update(kwargs)
            return None, None, [], [], "empty"

    assert bft_leader_propose(_FakeLeader(), max_txs=7) is None
    assert captured["max_txs"] == 7
    assert captured["allow_empty"] is True
    assert captured["proposer"] == "@validator"
