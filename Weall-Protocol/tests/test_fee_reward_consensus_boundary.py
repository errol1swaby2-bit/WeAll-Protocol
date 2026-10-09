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
from weall.runtime.state_hash import compute_state_root, consensus_state_root_view


def _executor(root: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(root / f"{name}.db"),
        node_id=name,
        chain_id="local-fee-consensus-boundary",
        tx_index_path=str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"),
    )


def _seed_activated_epoch_boundary(
    leader: WeAllExecutor,
    follower: WeAllExecutor,
    *,
    height: int = ISSUANCE_EPOCH_BLOCKS - 1,
) -> dict:
    state = deepcopy(leader.state)
    state["height"] = height
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
    tmp_path: Path,
    monkeypatch,
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


def test_sequential_30_block_fee_epoch_survives_follower_restart(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Real 30-block candidate, durable commit, follower apply and restart.

    Starting issuance/fee balances are explicitly seeded at genesis; this is
    a local activated-chain fixture, not governed migration replay.
    """
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_LOCAL_FEE_REWARD_POOL_GENESIS", "1")
    leader = _executor(tmp_path, "history-leader")
    follower = _executor(tmp_path, "history-follower")
    starting = _seed_activated_epoch_boundary(leader, follower, height=0)

    for height in range(1, ISSUANCE_EPOCH_BLOCKS + 1):
        block, state_after, applied_ids, invalid_ids, err = leader.build_block_candidate(
            max_txs=0,
            allow_empty=True,
        )
        assert err == "", (height, err)
        assert isinstance(block, dict)
        assert isinstance(state_after, dict)
        reward_types = [
            tx["tx_type"]
            for tx in block["txs"]
            if tx.get("tx_type") in {"BLOCK_REWARD_MINT", "BLOCK_REWARD_DISTRIBUTE"}
        ]
        if height == ISSUANCE_EPOCH_BLOCKS:
            assert reward_types == ["BLOCK_REWARD_MINT", "BLOCK_REWARD_DISTRIBUTE"]
        else:
            assert reward_types == []

        committed = leader.commit_block_candidate(
            block=block,
            new_state=state_after,
            applied_ids=applied_ids,
            invalid_ids=invalid_ids,
        )
        assert committed.ok is True, (height, committed.error)
        replayed = follower.apply_block(deepcopy(block))
        assert replayed.ok is True, (height, replayed.error)
        assert leader.read_state() == follower.read_state(), height

    post_epoch = leader.read_state()
    assert post_epoch["height"] == ISSUANCE_EPOCH_BLOCKS
    assert post_epoch["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 0
    assert post_epoch["economics"]["monetary_policy"]["issued"] == MAX_SUPPLY
    assert sum(
        account["balance"]
        for account in post_epoch["accounts"].values()
        if type(account.get("balance")) is int
    ) == sum(
        account["balance"]
        for account in starting["accounts"].values()
        if type(account.get("balance")) is int
    )

    # Re-opening each committed database is the durable recovery boundary,
    # not an in-memory state copy.
    leader_restarted = _executor(tmp_path, "history-leader")
    follower_restarted = _executor(tmp_path, "history-follower")
    # Startup updates one node-local lifecycle bit that is explicitly excluded
    # from the consensus state-root projection. All other stored ledger fields
    # must remain exactly equal to the pre-restart committed snapshot.
    def without_local_shutdown_flag(snapshot: dict) -> dict:
        copied = deepcopy(snapshot)
        copied.get("meta", {}).pop("last_shutdown_clean", None)
        return copied

    for restarted in (leader_restarted, follower_restarted):
        recovered = restarted.read_state()
        assert without_local_shutdown_flag(recovered) == without_local_shutdown_flag(
            post_epoch
        )
        assert consensus_state_root_view(recovered) == consensus_state_root_view(
            post_epoch
        )
        assert compute_state_root(recovered) == compute_state_root(post_epoch)
    assert leader_restarted.read_state() == follower_restarted.read_state()

    # A subsequent empty block must not reward the same settled epoch.
    block, state_after, applied_ids, invalid_ids, err = leader_restarted.build_block_candidate(
        max_txs=0,
        allow_empty=True,
    )
    assert err == "", err
    assert isinstance(block, dict)
    assert all(
        tx.get("tx_type") not in {"BLOCK_REWARD_MINT", "BLOCK_REWARD_DISTRIBUTE"}
        for tx in block["txs"]
    )
    committed = leader_restarted.commit_block_candidate(
        block=block,
        new_state=state_after,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert committed.ok is True, committed.error
    replayed = follower_restarted.apply_block(deepcopy(block))
    assert replayed.ok is True, replayed.error
    assert leader_restarted.read_state() == follower_restarted.read_state()
