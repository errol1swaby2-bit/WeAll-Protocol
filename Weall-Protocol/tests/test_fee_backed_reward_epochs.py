from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from weall.ledger.fee_reward_pool import (
    FEE_REWARD_POOL_CONTRACT_VERSION,
    validated_fee_reward_pool_balance,
)
from weall.runtime import genesis_bootstrap
from weall.ledger.constants import (
    FEE_REWARD_POOL_ACCOUNT_ID,
    INITIAL_ISSUANCE_PER_EPOCH,
    ISSUANCE_EPOCH_BLOCKS,
    MAX_SUPPLY,
    MINT_POOL_ACCOUNT_ID,
)
from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.apply.identity import apply_identity
from weall.runtime.apply.rewards import RewardsApplyError, apply_rewards
from weall.runtime.errors import ApplyError
from weall.runtime.system_tx_engine import (
    SystemSchedulerError,
    schedule_block_rewards_system_txs,
)
from weall.runtime.tx_admission_types import TxEnvelope


def _state(*, issued: int = MAX_SUPPLY, fee_balance: int = 0, configured: bool = True) -> dict:
    params = {
        "genesis_time": 0,
        "economic_unlock_time": 0,
        "economics_enabled": True,
    }
    if configured:
        params["fee_sink_account"] = FEE_REWARD_POOL_ACCOUNT_ID
        params["fee_reward_pool_contract_version"] = FEE_REWARD_POOL_CONTRACT_VERSION
    return {
        "height": 0,
        "time": 1,
        "chain_id": "local-fee-reward-fixture",
        "params": params,
        "accounts": {
            MINT_POOL_ACCOUNT_ID: {"balance": 0},
            FEE_REWARD_POOL_ACCOUNT_ID: {
                "account_type": "system",
                "system_role": "fee_reward_pool",
                "balance": fee_balance,
            },
            "@payer": {"balance": 100},
            "@validator": {"balance": 0},
            "@recipient": {"balance": 0},
            "TREASURY": {"balance": 0},
        },
        "roles": {
            "node_operators": {"active_set": []},
            "jurors": {"active_set": []},
            "creators": {"active_set": []},
        },
        "economics": {"monetary_policy": {"issued": issued, "max_supply": MAX_SUPPLY}},
        "system_queue": [],
    }


def _schedule(state: dict) -> dict[str, dict]:
    schedule_block_rewards_system_txs(
        state, next_height=ISSUANCE_EPOCH_BLOCKS, proposer="@validator", phase="post"
    )
    return {row["tx_type"]: row["payload"] for row in state["system_queue"]}


def _sys(tx_type: str, payload: dict, nonce: int) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer="SYSTEM", nonce=nonce, payload=payload, system=True)


def test_fee_only_epoch_mints_zero_and_pays_from_existing_supply() -> None:
    st = _state(fee_balance=17)
    before_total = sum(account["balance"] for account in st["accounts"].values())
    payloads = _schedule(st)
    mint = payloads["BLOCK_REWARD_MINT"]
    dist = payloads["BLOCK_REWARD_DISTRIBUTE"]

    assert mint["amount"] == 0
    assert dist["subsidy"] == 0
    assert dist["fees"] == 17
    assert dist["total"] == 17
    assert dist["debits"] == [{"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 17}]
    assert sum(row["amount"] for row in dist["transfers"]) == 17

    apply_rewards(st, _sys("BLOCK_REWARD_MINT", mint, 1))
    first = apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", dist, 2))
    again = apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", dist, 3))

    assert first["distributed_total"] == 17
    assert again["deduped"] is True
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 0
    assert st["economics"]["monetary_policy"]["issued"] == MAX_SUPPLY
    assert sum(account["balance"] for account in st["accounts"].values()) == before_total


def test_mixed_epoch_funds_subsidy_and_fees_from_separate_sources() -> None:
    st = _state(issued=0, fee_balance=19)
    payloads = _schedule(st)
    mint = payloads["BLOCK_REWARD_MINT"]
    dist = payloads["BLOCK_REWARD_DISTRIBUTE"]

    assert mint["amount"] == INITIAL_ISSUANCE_PER_EPOCH
    assert dist["total"] == INITIAL_ISSUANCE_PER_EPOCH + 19
    assert dist["debits"] == [
        {"from": MINT_POOL_ACCOUNT_ID, "amount": INITIAL_ISSUANCE_PER_EPOCH},
        {"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 19},
    ]
    apply_rewards(st, _sys("BLOCK_REWARD_MINT", mint, 1))
    apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", dist, 2))
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 0
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 0
    assert st["economics"]["monetary_policy"]["issued"] == INITIAL_ISSUANCE_PER_EPOCH


def test_real_fee_payment_funds_fee_only_reward_without_issuance() -> None:
    st = _state(fee_balance=0)
    fee = TxEnvelope(
        tx_type="FEE_PAY", signer="@payer", nonce=1, system=False, payload={"amount": 17}
    )
    receipt = apply_economics(st, fee)
    assert receipt == {
        "applied": "FEE_PAY",
        "from": "@payer",
        "to": FEE_REWARD_POOL_ACCOUNT_ID,
        "amount": 17,
    }
    assert st["accounts"]["@payer"]["balance"] == 83
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 17

    payloads = _schedule(st)
    apply_rewards(st, _sys("BLOCK_REWARD_MINT", payloads["BLOCK_REWARD_MINT"], 2))
    apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", payloads["BLOCK_REWARD_DISTRIBUTE"], 3))
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 0
    assert st["accounts"]["@payer"]["balance"] == 83
    assert st["economics"]["monetary_policy"]["issued"] == MAX_SUPPLY
    assert sum(row["balance"] for row in st["accounts"].values()) == 100


def test_fee_pool_cannot_be_swept_without_canonical_configuration() -> None:
    st = _state(issued=0, fee_balance=23, configured=False)
    payloads = _schedule(st)
    assert payloads["BLOCK_REWARD_DISTRIBUTE"]["fees"] == 0
    assert payloads["BLOCK_REWARD_DISTRIBUTE"]["debits"] == [
        {"from": MINT_POOL_ACCOUNT_ID, "amount": INITIAL_ISSUANCE_PER_EPOCH}
    ]


def test_empty_fee_only_epoch_does_not_create_a_reward() -> None:
    st = _state()
    assert _schedule(st) == {}


def test_duplicate_scheduling_does_not_double_reserve_fee_pool() -> None:
    st = _state(fee_balance=31)
    first = _schedule(st)
    second = _schedule(st)
    assert first == second
    assert len(st["system_queue"]) == 2


def test_reward_planning_is_deterministic_for_identical_states() -> None:
    a = _state(fee_balance=13)
    b = deepcopy(a)
    assert _schedule(a) == _schedule(b)
    assert a["system_queue"] == b["system_queue"]


def test_fee_only_rewards_remain_subject_to_economics_lock() -> None:
    st = _state(fee_balance=99)
    st["params"]["economics_enabled"] = False
    assert _schedule(st) == {}


def test_invalid_canonical_fee_pool_fails_closed() -> None:
    st = _state(fee_balance=8)
    del st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]
    with pytest.raises(SystemSchedulerError, match="canonical_fee_reward_pool_missing"):
        _schedule(st)


def test_user_cannot_spend_from_or_transfer_into_fee_reward_pool() -> None:
    st = _state(fee_balance=50)
    for signer, recipient in (
        (FEE_REWARD_POOL_ACCOUNT_ID, "@recipient"),
        ("@payer", FEE_REWARD_POOL_ACCOUNT_ID),
    ):
        with pytest.raises(EconomicsApplyError, match="reserved_fee_pool_transfer_forbidden"):
            apply_economics(
                st,
                TxEnvelope(
                    tx_type="BALANCE_TRANSFER",
                    signer=signer,
                    nonce=1,
                    system=False,
                    payload={"to_account_id": recipient, "amount": 1},
                ),
            )
    with pytest.raises(EconomicsApplyError, match="reserved_fee_pool_cannot_pay_fees"):
        apply_economics(
            st,
            TxEnvelope(
                tx_type="FEE_PAY",
                signer=FEE_REWARD_POOL_ACCOUNT_ID,
                nonce=1,
                system=False,
                payload={"amount": 1},
            ),
        )


def test_legacy_unactivated_fee_destination_preserves_historical_behavior() -> None:
    st = _state(configured=False)
    receipt = apply_economics(
        st,
        TxEnvelope(
            tx_type="FEE_PAY",
            signer="@payer",
            nonce=1,
            system=False,
            payload={"amount": 1, "to_account_id": FEE_REWARD_POOL_ACCOUNT_ID},
        ),
    )
    assert receipt["amount"] == 1
    assert st["accounts"]["@payer"]["balance"] == 99
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 1


def test_reward_distribution_rejects_unaccounted_excess_debit_without_mutation() -> None:
    st = _state(fee_balance=20)
    payload = {
        "block_id": "issuance_epoch:excess",
        "transfers": [{"to": "@validator", "amount": 10}],
        "debits": [{"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 20}],
    }
    with pytest.raises(RewardsApplyError, match="distribution_debits_exceed_credits"):
        apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", payload, 1))
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 20
    assert st["accounts"]["@validator"]["balance"] == 0
    assert "issuance_epoch:excess" not in st.get("rewards", {}).get(
        "block_reward_distributions_by_id", {}
    )


def test_human_cannot_register_reserved_system_fee_pool_id() -> None:
    st = _state()
    del st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]
    with pytest.raises(ApplyError, match="reserved_system_account_id"):
        apply_identity(
            st,
            TxEnvelope(
                tx_type="ACCOUNT_REGISTER",
                signer=FEE_REWARD_POOL_ACCOUNT_ID,
                nonce=1,
                system=False,
                payload={"pubkey": "untrusted"},
            ),
        )
    assert FEE_REWARD_POOL_ACCOUNT_ID not in st["accounts"]


@pytest.mark.parametrize(
    "fake_pool",
    [
        {"balance": 5, "account_type": "human"},
        {"balance": 5, "account_type": "system", "system_role": "different"},
        {
            "balance": 5,
            "account_type": "system",
            "system_role": "fee_reward_pool",
            "keys": {"by_id": {"attacker": "pubkey"}},
        },
        {"balance": True, "account_type": "system", "system_role": "fee_reward_pool"},
        {"balance": -1, "account_type": "system", "system_role": "fee_reward_pool"},
    ],
)
def test_squatted_or_malformed_pool_cannot_fund_rewards(fake_pool: dict) -> None:
    st = _state()
    st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID] = fake_pool
    with pytest.raises(SystemSchedulerError, match="canonical_fee_reward_pool_"):
        _schedule(st)
    assert st["system_queue"] == []


def test_untrusted_fee_pool_cannot_receive_fees() -> None:
    st = _state()
    st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID] = {
        "account_type": "human",
        "balance": 0,
        "keys": ["attacker"],
    }
    with pytest.raises(EconomicsApplyError, match="fee_reward_pool_not_system_owned"):
        apply_economics(
            st,
            TxEnvelope(
                tx_type="FEE_PAY",
                signer="@payer",
                nonce=1,
                payload={"amount": 7},
                system=False,
            ),
        )
    assert st["accounts"]["@payer"]["balance"] == 100


def test_arbitrary_user_account_cannot_be_reward_debit_source() -> None:
    st = _state(fee_balance=0)
    with pytest.raises(RewardsApplyError, match="reward_funding_source_not_allowed"):
        apply_rewards(
            st,
            _sys(
                "BLOCK_REWARD_DISTRIBUTE",
                {
                    "block_id": "unsupported-source",
                    "transfers": [{"to": "@validator", "amount": 10}],
                    "debits": [{"from": "@payer", "amount": 10}],
                },
                1,
            ),
        )
    assert st["accounts"]["@payer"]["balance"] == 100
    assert st["accounts"]["@validator"]["balance"] == 0


@pytest.mark.parametrize("destination", [MINT_POOL_ACCOUNT_ID, FEE_REWARD_POOL_ACCOUNT_ID])
def test_internal_pool_cannot_be_reward_recipient(destination: str) -> None:
    st = _state(fee_balance=50)
    with pytest.raises(RewardsApplyError, match="reward_internal_pool_recipient_forbidden"):
        apply_rewards(
            st,
            _sys(
                "BLOCK_REWARD_DISTRIBUTE",
                {
                    "block_id": "bad-internal-recipient",
                    "transfers": [{"to": destination, "amount": 10}],
                    "debits": [{"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 10}],
                },
                1,
            ),
        )
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 50


def test_legacy_unactivated_reward_replay_preserves_old_debit_contract() -> None:
    st = _state(fee_balance=30, configured=False)
    result = apply_rewards(
        st,
        _sys(
            "BLOCK_REWARD_DISTRIBUTE",
            {
                "block_id": "legacy-unactivated",
                "transfers": [{"to": "@validator", "amount": 30}],
                "debits": [{"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 30}],
            },
            1,
        ),
    )
    assert result["distributed_total"] == 30
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 0

def test_new_genesis_fee_pool_is_opt_in_and_state_committed(monkeypatch) -> None:
    monkeypatch.setattr(genesis_bootstrap, "_mode", lambda: "dev")
    stub = SimpleNamespace(
        chain_id="local-fee-reward-fixture",
        _current_genesis_bootstrap_profile=lambda: {"enabled": False},
        _requested_helper_execution_profile=lambda: {},
    )
    monkeypatch.delenv("WEALL_LOCAL_FEE_REWARD_POOL_GENESIS", raising=False)
    legacy = genesis_bootstrap._initial_state(stub)
    assert FEE_REWARD_POOL_ACCOUNT_ID not in legacy["accounts"]
    assert "fee_reward_pool_contract_version" not in legacy["params"]

    monkeypatch.setenv("WEALL_LOCAL_FEE_REWARD_POOL_GENESIS", "1")
    a = genesis_bootstrap._initial_state(stub)
    b = genesis_bootstrap._initial_state(stub)
    assert a == b
    assert a["params"]["fee_reward_pool_contract_version"] == 1
    assert a["params"]["fee_sink_account"] == FEE_REWARD_POOL_ACCOUNT_ID
    assert validated_fee_reward_pool_balance(a) == 0
    assert a["accounts"][FEE_REWARD_POOL_ACCOUNT_ID] == {
        "account_type": "system",
        "system_role": "fee_reward_pool",
        "balance": 0,
    }


@pytest.mark.parametrize("mode,chain_id", [
    ("prod", "local-fee-reward-fixture"),
    ("dev", "weall-prod"),
    ("dev", "weall-testnet-v1"),
])
def test_pool_genesis_rejects_nonlocal_or_nondev_activation(monkeypatch, mode, chain_id) -> None:
    monkeypatch.setattr(genesis_bootstrap, "_mode", lambda: mode)
    monkeypatch.setenv("WEALL_LOCAL_FEE_REWARD_POOL_GENESIS", "1")
    stub = SimpleNamespace(
        chain_id=chain_id,
        _current_genesis_bootstrap_profile=lambda: {"enabled": False},
        _requested_helper_execution_profile=lambda: {},
    )
    with pytest.raises(genesis_bootstrap.ExecutorError, match="fee reward pool local genesis"):
        genesis_bootstrap._initial_state(stub)


def test_legacy_ledger_with_uncommitted_pool_version_does_not_activate() -> None:
    st = _state(fee_balance=29)
    del st["params"]["fee_reward_pool_contract_version"]
    assert "BLOCK_REWARD_DISTRIBUTE" not in _schedule(st)
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 29


def test_boolean_contract_version_cannot_activate_fee_pool() -> None:
    st = _state(fee_balance=14)
    st["params"]["fee_reward_pool_contract_version"] = True
    assert "BLOCK_REWARD_DISTRIBUTE" not in _schedule(st)
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 14


def test_fee_pool_profile_rejects_even_empty_key_fields() -> None:
    st = _state(fee_balance=5)
    st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["keys"] = {}
    with pytest.raises(ValueError, match="fee_reward_pool_has_user_authority"):
        validated_fee_reward_pool_balance(st)
