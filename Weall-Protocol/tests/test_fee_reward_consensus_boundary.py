"""Real executor candidate/follower replay of an activated fee-backed epoch.

The test seeds the *same synthetic pre-epoch snapshot* on independent
persistent executors. It exercises the real block builder and block replay,
but it is not a live BFT network or proof of historical activation migration.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from weall.ledger.constants import (
    FEE_REWARD_POOL_ACCOUNT_ID,
    ISSUANCE_EPOCH_BLOCKS,
    MAX_SUPPLY,
    MINT_POOL_ACCOUNT_ID,
)
from weall.ledger.fee_reward_pool import FEE_REWARD_POOL_CONTRACT_VERSION
from weall.runtime.executor import WeAllExecutor


def _executor(root: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(root / f"{name}.db"),
        node_id=name,
        chain_id="local-fee-consensus-boundary",
        tx_index_path=str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"),
    )


def _seed_activated_epoch_boundary(leader: WeAllExecutor, follower: WeAllExecutor) -> dict:
    state = deepcopy(leader.state)
    state["height"] = ISSUANCE_EPOCH_BLOCKS - 1
    state["time"] = 1
    state["params"]["genesis_time"] = 0
    state["params"]["economic_unlock_time"] = 0
    state["params"]["economics_enabled"] = True
    state["params"]["fee_sink_account"] = FEE_REWARD_POOL_ACCOUNT_ID
    state["params"]["fee_reward_pool_contract_version"] = FEE_REWARD_POOL_CONTRACT_VERSION
    state["economics"] = {"monetary_policy": {"issued": MAX_SUPPLY, "max_supply": MAX_SUPPLY}}
    state["accounts"][MINT_POOL_ACCOUNT_ID] = {"balance": 0}
    state["accounts"][FEE_REWARD_POOL_ACCOUNT_ID] = {
        "account_type": "system",
        "system_role": "fee_reward_pool",
        "balance": 17,
    }
    state["accounts"]["TREASURY"] = {"balance": 0}
    state["system_queue"] = []
    for ex in (leader, follower):
        ex._ledger_store.write_state_snapshot(deepcopy(state))
        ex.state = ex._ledger_store.read()
    return state


def test_real_candidate_and_follower_apply_agree_on_fee_only_epoch(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_LOCAL_FEE_REWARD_POOL_GENESIS", "1")
    leader = _executor(tmp_path, "leader")
    follower = _executor(tmp_path, "follower")
    original = _seed_activated_epoch_boundary(leader, follower)

    block, new_state, applied_ids, invalid_ids, err = leader.build_block_candidate(
        max_txs=0,
        allow_empty=True,
    )
    assert err == "", err
    assert isinstance(block, dict)
    assert isinstance(new_state, dict)
    rewards = [
        tx
        for tx in block["txs"]
        if tx.get("tx_type") in {"BLOCK_REWARD_MINT", "BLOCK_REWARD_DISTRIBUTE"}
    ]
    assert [tx["tx_type"] for tx in rewards] == [
        "BLOCK_REWARD_MINT",
        "BLOCK_REWARD_DISTRIBUTE",
    ]
    assert rewards[0]["payload"]["amount"] == 0
    assert rewards[1]["payload"]["fees"] == 17

    committed = leader.commit_block_candidate(
        block=block,
        new_state=new_state,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert committed.ok is True, committed.error
    applied = follower.apply_block(deepcopy(block))
    assert applied.ok is True, applied.error
    assert leader.read_state() == follower.read_state()
    resulting = follower.read_state()
    assert resulting["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 0
    assert resulting["economics"]["monetary_policy"]["issued"] == MAX_SUPPLY
    starting_balance = sum(
        account["balance"]
        for account in original["accounts"].values()
        if type(account.get("balance")) is int
    )
    ending_balance = sum(
        account["balance"]
        for account in resulting["accounts"].values()
        if type(account.get("balance")) is int
    )
    assert ending_balance == starting_balance
