from __future__ import annotations

from pathlib import Path

from weall.runtime.apply.groups import apply_groups
from weall.runtime.executor import WeAllExecutor
from weall.runtime.group_treasury_scheduler import group_spend_plan_hash
from weall.runtime.tx_admission_types import TxEnvelope


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _execute_env(*, payload: dict, nonce: int) -> TxEnvelope:
    return TxEnvelope(
        tx_type="GROUP_TREASURY_SPEND_EXECUTE",
        signer="SYSTEM",
        nonce=nonce,
        payload=dict(payload),
        system=True,
        chain_id="weall-prod",
    )


def test_governance_approved_group_spend_is_one_shot_across_restart(tmp_path: Path) -> None:
    """A10-F005: persisted governance-approved value movement must not replay twice."""

    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    db_path = str(tmp_path / "a10-treasury-restart.db")

    executor = WeAllExecutor(
        db_path=db_path,
        node_id="@validator",
        chain_id="weall-prod",
        tx_index_path=tx_index_path,
    )
    state = executor.read_state()
    state["chain_id"] = "weall-prod"
    state["time"] = 100
    params = state.get("params")
    if not isinstance(params, dict):
        params = {}
        state["params"] = params
    params["economic_unlock_time"] = 0
    params["economics_enabled"] = True

    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        accounts = {}
        state["accounts"] = accounts
    accounts["@recipient"] = {
        "balance": 0,
        "nonce": 0,
        "poh_tier": 2,
        "banned": False,
        "locked": False,
    }

    state["treasury_wallets"] = {
        "TREASURY_GROUP::group-1": {
            "wallet_id": "TREASURY_GROUP::group-1",
            "balance": 25,
        }
    }
    spend = {
        "spend_id": "spend-1",
        "group_id": "group-1",
        "treasury_id": "TREASURY_GROUP::group-1",
        "to": "@recipient",
        "amount": 10,
        "status": "proposed",
        "signatures": {"@signer": {"at_nonce": 1}},
        "allowed_signers": ["@signer"],
        "threshold": 1,
        "created_at_height": 0,
        "earliest_execute_height": 0,
    }
    approved_hash = group_spend_plan_hash(spend)
    spend["governance_approval"] = {
        "proposal_id": "proposal-1",
        "group_id": "group-1",
        "treasury_id": "TREASURY_GROUP::group-1",
        "to": "@recipient",
        "amount": 10,
        "spend_plan_hash": approved_hash,
    }
    state["group_treasury_spends"] = {"spend-1": spend}
    payload = {
        "spend_id": "spend-1",
        "_governance_proposal_id": "proposal-1",
        "_approved_spend_plan_hash": approved_hash,
    }

    first = apply_groups(state, _execute_env(payload=payload, nonce=1))
    assert first == {
        "applied": "GROUP_TREASURY_SPEND_EXECUTE",
        "spend_id": "spend-1",
        "to": "@recipient",
        "amount": 10,
    }
    assert state["treasury_wallets"]["TREASURY_GROUP::group-1"]["balance"] == 15
    assert state["accounts"]["@recipient"]["balance"] == 10
    assert state["group_treasury_spends"]["spend-1"]["status"] == "executed"

    executor.state = state
    executor._ledger_store.write(executor.state)

    restarted = WeAllExecutor(
        db_path=db_path,
        node_id="@validator",
        chain_id="weall-prod",
        tx_index_path=tx_index_path,
    )
    restarted_state = restarted.read_state()
    assert restarted_state["treasury_wallets"]["TREASURY_GROUP::group-1"]["balance"] == 15
    assert restarted_state["accounts"]["@recipient"]["balance"] == 10
    assert restarted_state["group_treasury_spends"]["spend-1"]["status"] == "executed"

    replay = apply_groups(restarted_state, _execute_env(payload=payload, nonce=2))
    assert replay == {
        "applied": "GROUP_TREASURY_SPEND_EXECUTE",
        "spend_id": "spend-1",
        "deduped": True,
    }
    assert restarted_state["treasury_wallets"]["TREASURY_GROUP::group-1"]["balance"] == 15
    assert restarted_state["accounts"]["@recipient"]["balance"] == 10

    restarted.state = restarted_state
    restarted._ledger_store.write(restarted.state)

    restarted_again = WeAllExecutor(
        db_path=db_path,
        node_id="@validator",
        chain_id="weall-prod",
        tx_index_path=tx_index_path,
    )
    final_state = restarted_again.read_state()
    assert final_state["treasury_wallets"]["TREASURY_GROUP::group-1"]["balance"] == 15
    assert final_state["accounts"]["@recipient"]["balance"] == 10
    assert final_state["group_treasury_spends"]["spend-1"]["status"] == "executed"
