from __future__ import annotations

from weall.ledger.constants import INITIAL_ISSUANCE_PER_EPOCH, ISSUANCE_EPOCH_BLOCKS, MAX_SUPPLY
from weall.runtime.system_tx_engine import schedule_block_rewards_system_txs


def _state(*, chain_id: str | None) -> dict:
    state = {
        "height": 0,
        "time": 1,
        "params": {"genesis_time": 0, "economic_unlock_time": 0, "economics_enabled": True},
        "accounts": {"@validator": {"balance": 0}, "TREASURY": {"balance": 0}},
        "roles": {
            "node_operators": {"active_set": []},
            "jurors": {"active_set": []},
            "creators": {"active_set": []},
        },
        "economics": {"monetary_policy": {"issued": 0, "max_supply": MAX_SUPPLY}},
        "system_queue": [],
    }
    if chain_id is not None:
        state["chain_id"] = chain_id
    return state


def _schedule(state: dict) -> None:
    schedule_block_rewards_system_txs(
        state,
        next_height=ISSUANCE_EPOCH_BLOCKS,
        proposer="@validator",
        phase="post",
    )


def test_a10_f003_production_chain_cannot_schedule_legacy_reward_allocation(monkeypatch) -> None:
    state = _state(chain_id="weall-prod")

    monkeypatch.setenv("WEALL_MODE", "test")
    _schedule(state)

    assert state["system_queue"] == []


def test_a10_f003_public_testnet_cannot_schedule_legacy_reward_allocation(monkeypatch) -> None:
    state = _state(chain_id="weall-testnet-v1")

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    _schedule(state)

    assert state["system_queue"] == []


def test_a10_f003_scope_lock_is_independent_of_process_mode(monkeypatch) -> None:
    first = _state(chain_id="weall-prod")
    second = _state(chain_id="weall-prod")

    monkeypatch.setenv("WEALL_MODE", "test")
    _schedule(first)
    monkeypatch.setenv("WEALL_MODE", "prod")
    _schedule(second)

    assert first["system_queue"] == second["system_queue"] == []


def test_a10_f003_noncanonical_local_fixture_retains_legacy_compatibility() -> None:
    state = _state(chain_id=None)

    _schedule(state)

    by_type = {tx["tx_type"]: tx for tx in state["system_queue"]}
    assert set(by_type) == {"BLOCK_REWARD_MINT", "BLOCK_REWARD_DISTRIBUTE"}
    mint = by_type["BLOCK_REWARD_MINT"]["payload"]
    distribute = by_type["BLOCK_REWARD_DISTRIBUTE"]["payload"]
    assert mint["amount"] == INITIAL_ISSUANCE_PER_EPOCH

    # This intentionally documents the compatibility-only legacy behavior that
    # A10-F003 makes unreachable on launch-chain identities. With empty work
    # buckets, all value still flows to proposer/treasury in the local model.
    assert sum(row["amount"] for row in distribute["transfers"]) == INITIAL_ISSUANCE_PER_EPOCH
