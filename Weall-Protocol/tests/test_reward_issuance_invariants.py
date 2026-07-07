from __future__ import annotations

import pytest

from weall.ledger.constants import INITIAL_ISSUANCE_PER_EPOCH, MAX_SUPPLY, MINT_POOL_ACCOUNT_ID
from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.apply.rewards import RewardsApplyError, apply_rewards
from weall.runtime.tx_admission_types import TxEnvelope


def _active_state() -> dict:
    return {
        "time": 1,
        "height": 30,
        "params": {"genesis_time": 0, "economic_unlock_time": 0, "economics_enabled": True},
        "accounts": {
            MINT_POOL_ACCOUNT_ID: {"balance": 0},
            "@validator": {"balance": 0},
            "@operator": {"balance": 0},
            "@juror": {"balance": 0},
            "@creator": {"balance": 0},
            "TREASURY": {"balance": 0},
        },
        "economics": {"monetary_policy": {"issued": 0, "max_supply": MAX_SUPPLY}},
    }


def _locked_state() -> dict:
    st = _active_state()
    st["time"] = 0
    st["params"]["economic_unlock_time"] = 999
    st["params"]["economics_enabled"] = False
    return st


def _sys(tx_type: str, payload: dict, nonce: int = 1) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer="SYSTEM", nonce=nonce, payload=payload, system=True)


def _mint_payload(epoch: int = 0, amount: int = INITIAL_ISSUANCE_PER_EPOCH) -> dict:
    height = (epoch + 1) * 30
    return {
        "block_id": f"issuance_epoch:{epoch}",
        "height": height,
        "issuance_epoch": epoch,
        "epoch_id": f"issuance_epoch:{epoch}",
        "amount": amount,
    }


def test_block_reward_mint_is_locked_before_activation() -> None:
    st = _locked_state()

    with pytest.raises(Exception):
        apply_rewards(st, _sys("BLOCK_REWARD_MINT", _mint_payload()))

    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 0


def test_public_transfer_and_reward_activation_remain_locked() -> None:
    st = _locked_state()
    st["accounts"]["@alice"] = {"balance": 100, "poh_tier": 1, "banned": False, "locked": False}
    st["accounts"]["@bob"] = {"balance": 0, "poh_tier": 1, "banned": False, "locked": False}

    with pytest.raises(EconomicsApplyError):
        apply_economics(
            st,
            TxEnvelope(
                tx_type="BALANCE_TRANSFER",
                signer="@alice",
                nonce=1,
                payload={"to": "@bob", "amount": 1},
            ),
        )

    with pytest.raises(Exception):
        apply_rewards(st, _sys("BLOCK_REWARD_MINT", _mint_payload(epoch=0), nonce=2))

    assert st["accounts"]["@alice"]["balance"] == 100
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 0


def test_epoch_issuance_mint_credits_issuance_and_mint_pool() -> None:
    st = _active_state()

    res = apply_rewards(st, _sys("BLOCK_REWARD_MINT", _mint_payload(epoch=0)))

    assert res["applied"] == "BLOCK_REWARD_MINT"
    assert res["deduped"] is False
    assert res["issuance_epoch"] == 0
    assert st["economics"]["monetary_policy"]["issued"] == INITIAL_ISSUANCE_PER_EPOCH
    assert st["economics"]["monetary_policy"]["last_issuance_epoch"] == 0
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == INITIAL_ISSUANCE_PER_EPOCH
    assert st["rewards"]["stats"]["minted_total"] == INITIAL_ISSUANCE_PER_EPOCH


def test_exact_block_reward_mint_replay_is_deduped_without_extra_supply() -> None:
    st = _active_state()
    payload = _mint_payload(epoch=0)

    first = apply_rewards(st, _sys("BLOCK_REWARD_MINT", payload, nonce=1))
    replay = apply_rewards(st, _sys("BLOCK_REWARD_MINT", payload, nonce=2))

    assert first["deduped"] is False
    assert replay["deduped"] is True
    assert st["economics"]["monetary_policy"]["issued"] == INITIAL_ISSUANCE_PER_EPOCH
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == INITIAL_ISSUANCE_PER_EPOCH
    assert st["rewards"]["stats"]["minted_total"] == INITIAL_ISSUANCE_PER_EPOCH


def test_duplicate_issuance_epoch_rejects_different_mint() -> None:
    st = _active_state()
    apply_rewards(st, _sys("BLOCK_REWARD_MINT", _mint_payload(epoch=0), nonce=1))

    duplicate = _mint_payload(epoch=0)
    duplicate["block_id"] = "different-block-for-same-epoch"

    with pytest.raises(RewardsApplyError) as ei:
        apply_rewards(st, _sys("BLOCK_REWARD_MINT", duplicate, nonce=2))

    assert ei.value.reason == "duplicate_issuance_epoch"
    assert st["economics"]["monetary_policy"]["issued"] == INITIAL_ISSUANCE_PER_EPOCH
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == INITIAL_ISSUANCE_PER_EPOCH


def test_epoch_issuance_can_stop_exactly_at_cap() -> None:
    st = _active_state()
    st["economics"]["monetary_policy"]["issued"] = MAX_SUPPLY - 10

    res = apply_rewards(st, _sys("BLOCK_REWARD_MINT", _mint_payload(epoch=1, amount=10)))

    assert res["amount"] == 10
    assert st["economics"]["monetary_policy"]["issued"] == MAX_SUPPLY
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 10


def test_epoch_issuance_rejects_cap_overflow_without_partial_mutation() -> None:
    st = _active_state()
    st["economics"]["monetary_policy"]["issued"] = MAX_SUPPLY - 10

    with pytest.raises(RewardsApplyError) as ei:
        apply_rewards(st, _sys("BLOCK_REWARD_MINT", _mint_payload(epoch=1, amount=11)))

    assert ei.value.reason == "mint_exceeds_max_supply"
    assert "issuance_epoch:1" not in st.get("rewards", {}).get("block_rewards_by_id", {})
    assert st["economics"]["monetary_policy"]["issued"] == MAX_SUPPLY - 10
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 0


def test_block_reward_distribute_conserves_minted_pool() -> None:
    st = _active_state()
    apply_rewards(st, _sys("BLOCK_REWARD_MINT", _mint_payload(epoch=0), nonce=1))

    share = INITIAL_ISSUANCE_PER_EPOCH // 5
    payload = {
        "block_id": "issuance_epoch:0",
        "issuance_epoch": 0,
        "transfers": [
            {"to": "@validator", "amount": share},
            {"to": "@operator", "amount": share},
            {"to": "@juror", "amount": share},
            {"to": "@creator", "amount": share},
            {"to": "TREASURY", "amount": INITIAL_ISSUANCE_PER_EPOCH - share * 4},
        ],
        "debits": [{"from": MINT_POOL_ACCOUNT_ID, "amount": INITIAL_ISSUANCE_PER_EPOCH}],
    }
    res = apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", payload, nonce=2))

    assert res["distributed_total"] == INITIAL_ISSUANCE_PER_EPOCH
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 0
    assert st["accounts"]["@validator"]["balance"] == share
    assert st["accounts"]["@operator"]["balance"] == share
    assert st["accounts"]["@juror"]["balance"] == share
    assert st["accounts"]["@creator"]["balance"] == share
    assert st["accounts"]["TREASURY"]["balance"] == INITIAL_ISSUANCE_PER_EPOCH - share * 4
    assert st["rewards"]["stats"]["distributed_total"] == INITIAL_ISSUANCE_PER_EPOCH


def test_block_reward_distribute_rejects_unfunded_distribution() -> None:
    st = _active_state()

    with pytest.raises(RewardsApplyError) as ei:
        apply_rewards(
            st,
            _sys(
                "BLOCK_REWARD_DISTRIBUTE",
                {
                    "block_id": "issuance_epoch:unfunded",
                    "transfers": [{"to": "@validator", "amount": 100}],
                    "debits": [{"from": MINT_POOL_ACCOUNT_ID, "amount": 100}],
                },
            ),
        )

    assert ei.value.reason == "insufficient_funds_for_debit"
    assert st["accounts"]["@validator"]["balance"] == 0


def test_block_reward_distribute_replay_is_deduped_without_double_credit() -> None:
    st = _active_state()
    apply_rewards(st, _sys("BLOCK_REWARD_MINT", _mint_payload(epoch=0), nonce=1))

    payload = {
        "block_id": "issuance_epoch:0",
        "transfers": [{"to": "@validator", "amount": INITIAL_ISSUANCE_PER_EPOCH}],
        "debits": [{"from": MINT_POOL_ACCOUNT_ID, "amount": INITIAL_ISSUANCE_PER_EPOCH}],
    }

    first = apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", payload, nonce=2))
    replay = apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", payload, nonce=3))

    assert first["deduped"] is False
    assert replay["deduped"] is True
    assert st["accounts"]["@validator"]["balance"] == INITIAL_ISSUANCE_PER_EPOCH
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 0
    assert st["rewards"]["stats"]["distributed_total"] == INITIAL_ISSUANCE_PER_EPOCH
