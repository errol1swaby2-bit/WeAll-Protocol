from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from weall.ledger.constants import (
    FEE_REWARD_POOL_ACCOUNT_ID,
    INITIAL_ISSUANCE_PER_EPOCH,
    ISSUANCE_EPOCH_BLOCKS,
    MAX_SUPPLY,
    MINT_POOL_ACCOUNT_ID,
)
from weall.ledger.fee_reward_pool import (
    FEE_REWARD_POOL_CONTRACT_VERSION,
    validated_fee_reward_pool_balance,
)
from weall.runtime import genesis_bootstrap
from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.apply.identity import apply_identity
from weall.runtime.apply.rewards import RewardsApplyError, apply_rewards
from weall.runtime.errors import ApplyError
from weall.runtime.system_tx_engine import (
    SystemQueueCorruptionError,
    SystemSchedulerError,
    build_system_queue_lookup,
    schedule_block_rewards_system_txs,
    system_tx_emitter,
    validate_system_queue_recovery_state,
    validate_system_tx_queue_binding,
)
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex


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


@pytest.mark.parametrize(
    "mode,chain_id",
    [
        ("prod", "local-fee-reward-fixture"),
        ("dev", "weall-prod"),
        ("dev", "weall-testnet-v1"),
    ],
)
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


def test_fee_bearing_transfer_funds_pool_without_extra_issuance() -> None:
    st = _state(fee_balance=0)
    st["economics"]["fee_policy"] = {"transfer_fee_int": 3}
    before_total = sum(account["balance"] for account in st["accounts"].values())
    receipt = apply_economics(
        st,
        TxEnvelope(
            tx_type="BALANCE_TRANSFER",
            signer="@payer",
            nonce=1,
            system=False,
            payload={"to_account_id": "@recipient", "amount": 10},
        ),
    )
    assert receipt["amount"] == 10
    assert receipt["fee_amount"] == 3
    assert st["accounts"]["@payer"]["balance"] == 87
    assert st["accounts"]["@recipient"]["balance"] == 10
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 3
    assert sum(account["balance"] for account in st["accounts"].values()) == before_total
    dist = _schedule(st)["BLOCK_REWARD_DISTRIBUTE"]
    assert dist["fees"] == 3
    assert dist["debits"] == [{"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 3}]


def test_other_fee_destination_does_not_enter_canonical_reward_budget() -> None:
    st = _state(fee_balance=0)
    apply_economics(
        st,
        TxEnvelope(
            tx_type="FEE_PAY",
            signer="@payer",
            nonce=1,
            system=False,
            payload={"amount": 7, "to_account_id": "@recipient"},
        ),
    )
    assert st["accounts"]["@recipient"]["balance"] == 7
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 0
    assert _schedule(st) == {}
    assert st["economics"]["monetary_policy"]["issued"] == MAX_SUPPLY


def test_late_fee_is_not_swept_by_earlier_queued_epoch() -> None:
    st = _state(fee_balance=11)
    first = _schedule(st)
    assert first["BLOCK_REWARD_DISTRIBUTE"]["fees"] == 11

    apply_economics(
        st,
        TxEnvelope(
            tx_type="FEE_PAY",
            signer="@payer",
            nonce=1,
            system=False,
            payload={"amount": 5},
        ),
    )
    # Queue is already fixed to the snapshot at the epoch boundary.
    assert _schedule(st) == first
    apply_rewards(st, _sys("BLOCK_REWARD_MINT", first["BLOCK_REWARD_MINT"], 2))
    apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", first["BLOCK_REWARD_DISTRIBUTE"], 3))
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 5

    schedule_block_rewards_system_txs(
        st, next_height=2 * ISSUANCE_EPOCH_BLOCKS, proposer="@validator", phase="post"
    )
    second = [
        row["payload"]
        for row in st["system_queue"]
        if row["tx_type"] == "BLOCK_REWARD_DISTRIBUTE"
        and row["payload"]["epoch_id"] == "issuance_epoch:1"
    ]
    assert len(second) == 1
    assert second[0]["fees"] == 5
    assert second[0]["debits"] == [{"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 5}]


def test_two_nodes_replay_fee_only_epoch_to_identical_state() -> None:
    original = _state(fee_balance=29)
    a = deepcopy(original)
    b = deepcopy(original)
    queued_a = _schedule(a)
    queued_b = _schedule(b)
    assert queued_a == queued_b
    for node, queued in ((a, queued_a), (b, queued_b)):
        apply_rewards(node, _sys("BLOCK_REWARD_MINT", queued["BLOCK_REWARD_MINT"], 1))
        apply_rewards(
            node,
            _sys("BLOCK_REWARD_DISTRIBUTE", queued["BLOCK_REWARD_DISTRIBUTE"], 2),
        )
    assert a == b
    assert a["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 0
    assert a["economics"]["monetary_policy"]["issued"] == MAX_SUPPLY


@pytest.mark.parametrize("tx_type", ["CREATOR_REWARD_ALLOCATE", "TREASURY_REWARD_ALLOCATE"])
@pytest.mark.parametrize("direction", ["credit", "debit"])
def test_secondary_reward_allocators_cannot_move_activated_fee_pool(
    tx_type: str, direction: str
) -> None:
    st = _state(fee_balance=17)
    original_accounts = deepcopy(st["accounts"])
    if direction == "credit":
        transfers = [{"to": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 3}]
        debits = [{"from": "@payer", "amount": 3}]
    else:
        transfers = [{"to": "@recipient", "amount": 3}]
        debits = [{"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 3}]

    with pytest.raises(RewardsApplyError, match="reserved_fee_pool_allocation_forbidden"):
        apply_rewards(
            st,
            _sys(
                tx_type,
                {"block_id": "other-reward", "transfers": transfers, "debits": debits},
                11,
            ),
        )
    assert st["accounts"] == original_accounts


def test_forfeiture_cannot_burn_activated_fee_pool() -> None:
    st = _state(fee_balance=17)
    original_accounts = deepcopy(st["accounts"])
    with pytest.raises(RewardsApplyError, match="reserved_fee_pool_forfeiture_forbidden"):
        apply_rewards(
            st,
            _sys(
                "FORFEITURE_APPLY",
                {"account_id": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 3},
                12,
            ),
        )
    assert st["accounts"] == original_accounts


def test_unactivated_secondary_allocation_retains_legacy_fee_pool_behavior() -> None:
    st = _state(configured=False, fee_balance=17)
    result = apply_rewards(
        st,
        _sys(
            "CREATOR_REWARD_ALLOCATE",
            {
                "block_id": "legacy-other-reward",
                "transfers": [{"to": "@recipient", "amount": 3}],
                "debits": [{"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 3}],
            },
            13,
        ),
    )
    assert result["credited_total"] == 3
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 14
    assert st["accounts"]["@recipient"]["balance"] == 3


@pytest.mark.parametrize("tx_type", ["CREATOR_REWARD_ALLOCATE", "TREASURY_REWARD_ALLOCATE"])
def test_activated_secondary_allocation_is_atomic_on_aggregate_insufficiency(
    tx_type: str,
) -> None:
    st = _state(fee_balance=23)
    original_accounts = deepcopy(st["accounts"])
    with pytest.raises(RewardsApplyError, match="insufficient_funds_for_debit"):
        apply_rewards(
            st,
            _sys(
                tx_type,
                {
                    "block_id": "aggregate-overdraw",
                    "transfers": [{"to": "@recipient", "amount": 120}],
                    "debits": [
                        {"from": "@payer", "amount": 60},
                        {"from": "@payer", "amount": 60},
                    ],
                },
                14,
            ),
        )
    assert st["accounts"] == original_accounts


@pytest.mark.parametrize("tx_type", ["CREATOR_REWARD_ALLOCATE", "TREASURY_REWARD_ALLOCATE"])
def test_activated_secondary_allocation_rejects_unequal_totals_before_writes(
    tx_type: str,
) -> None:
    st = _state(fee_balance=23)
    original_accounts = deepcopy(st["accounts"])
    with pytest.raises(RewardsApplyError, match="credits_must_equal_debits"):
        apply_rewards(
            st,
            _sys(
                tx_type,
                {
                    "block_id": "imbalance",
                    "transfers": [{"to": "@recipient", "amount": 5}],
                    "debits": [{"from": "@payer", "amount": 4}],
                },
                15,
            ),
        )
    assert st["accounts"] == original_accounts


@pytest.mark.parametrize("tx_type", ["CREATOR_REWARD_ALLOCATE", "TREASURY_REWARD_ALLOCATE"])
def test_activated_secondary_allocation_settles_exact_existing_supply(
    tx_type: str,
) -> None:
    st = _state(fee_balance=23)
    original_total = sum(record["balance"] for record in st["accounts"].values())
    result = apply_rewards(
        st,
        _sys(
            tx_type,
            {
                "block_id": "valid-secondary",
                "transfers": [{"to": "@recipient", "amount": 13}],
                "debits": [{"from": "@payer", "amount": 13}],
            },
            16,
        ),
    )
    assert result["credited_total"] == 13
    assert st["accounts"]["@recipient"]["balance"] == 13
    assert st["accounts"]["@payer"]["balance"] == 87
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 23
    assert sum(record["balance"] for record in st["accounts"].values()) == original_total


@pytest.mark.parametrize("tx_type", ["CREATOR_REWARD_ALLOCATE", "TREASURY_REWARD_ALLOCATE"])
def test_activated_secondary_allocation_rejects_bool_amount_without_mutation(
    tx_type: str,
) -> None:
    st = _state(fee_balance=23)
    original_accounts = deepcopy(st["accounts"])
    with pytest.raises(RewardsApplyError, match="reward_allocation_invalid_entry"):
        apply_rewards(
            st,
            _sys(
                tx_type,
                {
                    "block_id": "bool-amount",
                    "transfers": [{"to": "@recipient", "amount": True}],
                    "debits": [{"from": "@payer", "amount": 1}],
                },
                17,
            ),
        )
    assert st["accounts"] == original_accounts


@pytest.mark.parametrize(
    ("direction", "row"),
    [
        ("credit", {"to": "@validator", "amount": 10.9}),
        ("debit", {"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 10.9}),
        ("credit", {"to": "@validator", "amount": "10"}),
        ("debit", {"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": True}),
        ("credit", {"to": "@validator", "amount": 0}),
        ("debit", {"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": -2}),
        ("credit", {"to": "@validator"}),
        ("debit", None),
    ],
)
def test_activated_reward_distribution_rejects_invalid_rows_without_account_writes(
    direction: str, row: object
) -> None:
    st = _state(fee_balance=25)
    before = deepcopy(st["accounts"])
    payload = {
        "block_id": "malformed-distribution",
        "transfers": [{"to": "@validator", "amount": 10}],
        "debits": [{"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 10}],
    }
    payload["transfers" if direction == "credit" else "debits"] = [row]
    with pytest.raises(RewardsApplyError, match="reward_distribution_invalid_row"):
        apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", payload, 50))
    assert st["accounts"] == before
    assert "malformed-distribution" not in st.get("rewards", {}).get(
        "block_reward_distributions_by_id", {}
    )


@pytest.mark.parametrize("field", ["transfers", "debits"])
def test_activated_reward_distribution_requires_explicit_funding_rows(
    field: str,
) -> None:
    st = _state(fee_balance=25)
    before = deepcopy(st["accounts"])
    payload = {
        "block_id": "missing-funding-rows",
        "transfers": [{"to": "@validator", "amount": 10}],
        "debits": [{"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 10}],
    }
    del payload[field]
    with pytest.raises(RewardsApplyError, match="reward_distribution_funding_rows_required"):
        apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", payload, 51))
    assert st["accounts"] == before


def test_activated_reward_distribution_missing_mint_pool_never_creates_account() -> None:
    st = _state(fee_balance=0)
    del st["accounts"][MINT_POOL_ACCOUNT_ID]
    before = deepcopy(st["accounts"])
    payload = {
        "block_id": "missing-mint-funding",
        "transfers": [{"to": "@validator", "amount": 10}],
        "debits": [{"from": MINT_POOL_ACCOUNT_ID, "amount": 10}],
    }
    with pytest.raises(RewardsApplyError, match="reward_funding_account_missing"):
        apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", payload, 52))
    assert st["accounts"] == before


def test_activated_reward_distribution_rejects_noninteger_mint_balance() -> None:
    st = _state(fee_balance=0)
    st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] = True
    before = deepcopy(st["accounts"])
    payload = {
        "block_id": "invalid-mint-balance",
        "transfers": [{"to": "@validator", "amount": 1}],
        "debits": [{"from": MINT_POOL_ACCOUNT_ID, "amount": 1}],
    }
    with pytest.raises(RewardsApplyError, match="reward_funding_balance_invalid"):
        apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", payload, 53))
    assert st["accounts"] == before


def test_unactivated_reward_distribution_keeps_legacy_fractional_row_parsing() -> None:
    st = _state(fee_balance=20, configured=False)
    receipt = apply_rewards(
        st,
        _sys(
            "BLOCK_REWARD_DISTRIBUTE",
            {
                "block_id": "legacy-fractional-rows",
                "transfers": [{"to": "@validator", "amount": 7.9}],
                "debits": [{"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 7.9}],
            },
            54,
        ),
    )
    assert receipt["distributed_total"] == 7
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 13
    assert st["accounts"]["@validator"]["balance"] == 7


@pytest.mark.parametrize("balance", [True, "12", 12.5, -1, None])
def test_activated_reward_distribution_rejects_invalid_recipient_balances(
    balance: object,
) -> None:
    st = _state(fee_balance=30)
    st["accounts"]["@validator"]["balance"] = balance
    before = deepcopy(st["accounts"])
    with pytest.raises(RewardsApplyError, match="reward_recipient_balance_invalid"):
        apply_rewards(
            st,
            _sys(
                "BLOCK_REWARD_DISTRIBUTE",
                {
                    "block_id": "bad-recipient-state",
                    "transfers": [{"to": "@validator", "amount": 12}],
                    "debits": [{"from": FEE_REWARD_POOL_ACCOUNT_ID, "amount": 12}],
                },
                61,
            ),
        )
    assert st["accounts"] == before
    assert "bad-recipient-state" not in st.get("rewards", {}).get(
        "block_reward_distributions_by_id", {}
    )


def test_fee_only_reward_queue_emission_and_binding_survive_snapshot_replay() -> None:
    st = _state(fee_balance=29)
    st["height"] = ISSUANCE_EPOCH_BLOCKS - 1
    canon = TxIndex.load_from_file(
        str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")
    )
    proposed = system_tx_emitter(
        st,
        canon,
        next_height=ISSUANCE_EPOCH_BLOCKS,
        phase="post",
        proposer="@validator",
    )
    assert [tx.tx_type for tx in proposed] == [
        "BLOCK_REWARD_MINT",
        "BLOCK_REWARD_DISTRIBUTE",
    ]
    assert proposed[0].payload["amount"] == 0
    assert proposed[1].payload["fees"] == 29

    lookup = build_system_queue_lookup(st)
    for tx in proposed:
        ok, reason = validate_system_tx_queue_binding(
            st,
            canon,
            tx,
            next_height=ISSUANCE_EPOCH_BLOCKS,
            phase="post",
            queue_objects_by_id=lookup,
        )
        assert (ok, reason) == (True, "")

    # Two independently reloaded snapshots apply exactly the emitted system
    # envelopes, not a fabricated direct-applier-only reward payload.
    reloaded_a = deepcopy(st)
    reloaded_b = deepcopy(st)
    for tx in proposed:
        assert apply_rewards(reloaded_a, tx) == apply_rewards(reloaded_b, tx)
    assert reloaded_a == reloaded_b
    assert reloaded_a["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 0
    assert reloaded_a["economics"]["monetary_policy"]["issued"] == MAX_SUPPLY
    assert sum(acct["balance"] for acct in reloaded_a["accounts"].values()) == 129

    reemitted = system_tx_emitter(
        st,
        canon,
        next_height=ISSUANCE_EPOCH_BLOCKS,
        phase="post",
        proposer="@validator",
    )
    assert reemitted == []


def test_queued_fee_reward_payload_tampering_is_rejected_before_replay() -> None:
    st = _state(fee_balance=19)
    st["height"] = ISSUANCE_EPOCH_BLOCKS - 1
    canon = TxIndex.load_from_file(
        str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")
    )
    proposed = system_tx_emitter(
        st,
        canon,
        next_height=ISSUANCE_EPOCH_BLOCKS,
        phase="post",
        proposer="@validator",
    )
    dist = next(tx for tx in proposed if tx.tx_type == "BLOCK_REWARD_DISTRIBUTE")
    forged_payload = deepcopy(dist.payload)
    forged_payload["fees"] = 20
    forged = TxEnvelope(
        tx_type=dist.tx_type,
        signer=dist.signer,
        nonce=dist.nonce,
        payload=forged_payload,
        sig=dist.sig,
        parent=dist.parent,
        system=True,
    )
    ok, reason = validate_system_tx_queue_binding(
        st,
        canon,
        forged,
        next_height=ISSUANCE_EPOCH_BLOCKS,
        phase="post",
        queue_objects_by_id=build_system_queue_lookup(st),
    )
    assert (ok, reason) == (False, "system_queue_payload_mismatch")
    assert st["accounts"][FEE_REWARD_POOL_ACCOUNT_ID]["balance"] == 19


def test_fee_reward_queue_recovery_rejects_overdue_unemitted_distribution() -> None:
    st = _state(fee_balance=13)
    st["height"] = ISSUANCE_EPOCH_BLOCKS - 1
    schedule_block_rewards_system_txs(
        st,
        next_height=ISSUANCE_EPOCH_BLOCKS,
        proposer="@validator",
        phase="post",
    )
    with pytest.raises(SystemQueueCorruptionError, match="system_queue_item_past_due_at_recovery"):
        validate_system_queue_recovery_state(st, committed_height=ISSUANCE_EPOCH_BLOCKS)
    assert len(st["system_queue"]) == 2
    assert all(item.get("emitted_height") is None for item in st["system_queue"])


@pytest.mark.parametrize("amount", [True, 7.9, "7", None])
def test_activated_fee_payment_rejects_coerced_amount_without_account_changes(
    amount: object,
) -> None:
    st = _state()
    before = deepcopy(st["accounts"])
    with pytest.raises(EconomicsApplyError, match="fee_pay_amount_must_be_integer"):
        apply_economics(
            st,
            TxEnvelope(
                tx_type="FEE_PAY",
                signer="@payer",
                nonce=70,
                system=False,
                payload={"amount": amount},
            ),
        )
    assert st["accounts"] == before


@pytest.mark.parametrize("balance", [True, "100", 100.9, -1, None])
def test_activated_fee_payment_rejects_invalid_payer_balance(
    balance: object,
) -> None:
    st = _state()
    st["accounts"]["@payer"]["balance"] = balance
    before = deepcopy(st["accounts"])
    with pytest.raises(EconomicsApplyError, match="fee_pay_payer_balance_invalid"):
        apply_economics(
            st,
            TxEnvelope(
                tx_type="FEE_PAY",
                signer="@payer",
                nonce=71,
                system=False,
                payload={"amount": 7},
            ),
        )
    assert st["accounts"] == before


@pytest.mark.parametrize("balance", [True, "0", 1.2, -1, None])
def test_activated_fee_payment_rejects_invalid_alternate_sink_balance(
    balance: object,
) -> None:
    st = _state()
    st["accounts"]["@recipient"]["balance"] = balance
    before = deepcopy(st["accounts"])
    with pytest.raises(EconomicsApplyError, match="fee_pay_sink_balance_invalid"):
        apply_economics(
            st,
            TxEnvelope(
                tx_type="FEE_PAY",
                signer="@payer",
                nonce=72,
                system=False,
                payload={"amount": 7, "to_account_id": "@recipient"},
            ),
        )
    assert st["accounts"] == before


def test_activated_fee_payment_rejects_self_destination_without_fake_receipt() -> None:
    st = _state()
    before = deepcopy(st["accounts"])
    with pytest.raises(EconomicsApplyError, match="fee_pay_self_destination_forbidden"):
        apply_economics(
            st,
            TxEnvelope(
                tx_type="FEE_PAY",
                signer="@payer",
                nonce=73,
                system=False,
                payload={"amount": 7, "to_account_id": "@payer"},
            ),
        )
    assert st["accounts"] == before
    assert st.get("economics", {}).get("fee_payments", []) == []


def test_activated_fee_payment_requires_signer_to_authorize_origin() -> None:
    st = _state()
    before = deepcopy(st["accounts"])
    with pytest.raises(EconomicsApplyError, match="fee_pay_signer_required"):
        apply_economics(
            st,
            TxEnvelope(
                tx_type="FEE_PAY",
                signer="",
                nonce=74,
                system=False,
                payload={"amount": 7, "from_account_id": "@payer"},
            ),
        )
    assert st["accounts"] == before


@pytest.mark.parametrize("amount", [True, 8.9, "8"])
def test_activated_balance_transfer_rejects_coerced_amount(
    amount: object,
) -> None:
    st = _state()
    before = deepcopy(st["accounts"])
    with pytest.raises(EconomicsApplyError, match="balance_transfer_amount_must_be_integer"):
        apply_economics(
            st,
            TxEnvelope(
                tx_type="BALANCE_TRANSFER",
                signer="@payer",
                nonce=75,
                system=False,
                payload={"to_account_id": "@recipient", "amount": amount},
            ),
        )
    assert st["accounts"] == before


@pytest.mark.parametrize("account_id", ["@payer", "@recipient"])
@pytest.mark.parametrize("balance", [True, "12", 12.5, -1, None])
def test_activated_balance_transfer_rejects_invalid_account_balance(
    account_id: str,
    balance: object,
) -> None:
    st = _state()
    st["accounts"][account_id]["balance"] = balance
    before = deepcopy(st["accounts"])
    with pytest.raises(EconomicsApplyError, match="balance_transfer_account_balance_invalid"):
        apply_economics(
            st,
            TxEnvelope(
                tx_type="BALANCE_TRANSFER",
                signer="@payer",
                nonce=76,
                system=False,
                payload={"to_account_id": "@recipient", "amount": 4},
            ),
        )
    assert st["accounts"] == before


@pytest.mark.parametrize("fee", [True, "3", 3.3, -1])
def test_activated_balance_transfer_rejects_invalid_fee_policy(fee: object) -> None:
    st = _state()
    st["economics"]["fee_policy"] = {"transfer_fee_int": fee}
    before = deepcopy(st["accounts"])
    with pytest.raises(EconomicsApplyError, match="balance_transfer_fee_policy_invalid"):
        apply_economics(
            st,
            TxEnvelope(
                tx_type="BALANCE_TRANSFER",
                signer="@payer",
                nonce=77,
                system=False,
                payload={"to_account_id": "@recipient", "amount": 8},
            ),
        )
    assert st["accounts"] == before


def test_unactivated_fee_payment_and_balance_transfer_keep_legacy_amount_coercion() -> None:
    st = _state(configured=False)
    fee = apply_economics(
        st,
        TxEnvelope(
            tx_type="FEE_PAY",
            signer="@payer",
            nonce=78,
            system=False,
            payload={"amount": 7.9, "to_account_id": "@recipient"},
        ),
    )
    transfer = apply_economics(
        st,
        TxEnvelope(
            tx_type="BALANCE_TRANSFER",
            signer="@payer",
            nonce=79,
            system=False,
            payload={"amount": "5", "to_account_id": "@recipient"},
        ),
    )
    assert fee["amount"] == 7
    assert transfer["amount"] == 5
    assert st["accounts"]["@payer"]["balance"] == 88
    assert st["accounts"]["@recipient"]["balance"] == 12


@pytest.mark.parametrize("issued", [True, "0", 0.75, -1, MAX_SUPPLY + 1])
def test_activated_issuance_scheduler_rejects_invalid_supply_counter(
    issued: object,
) -> None:
    st = _state(issued=0, fee_balance=8)
    st["economics"]["monetary_policy"]["issued"] = issued
    before = deepcopy(st)
    with pytest.raises(SystemSchedulerError, match="fee_reward_issuance_policy_invalid"):
        _schedule(st)
    assert st == before


@pytest.mark.parametrize("max_supply", [True, str(MAX_SUPPLY), 0, MAX_SUPPLY + 1])
def test_activated_issuance_scheduler_rejects_invalid_supply_cap(
    max_supply: object,
) -> None:
    st = _state(issued=0, fee_balance=8)
    st["economics"]["monetary_policy"]["max_supply"] = max_supply
    before = deepcopy(st)
    with pytest.raises(SystemSchedulerError, match="fee_reward_issuance_policy_invalid"):
        _schedule(st)
    assert st == before


def test_activated_issuance_scheduler_rejects_missing_monetary_policy() -> None:
    st = _state(issued=0, fee_balance=8)
    del st["economics"]["monetary_policy"]
    before = deepcopy(st)
    with pytest.raises(SystemSchedulerError, match="fee_reward_issuance_policy_missing"):
        _schedule(st)
    assert st == before


@pytest.mark.parametrize("amount", [True, 7.9, "7", None, -1])
def test_activated_reward_mint_rejects_noninteger_or_negative_amount(
    amount: object,
) -> None:
    st = _state(issued=0)
    before_accounts = deepcopy(st["accounts"])
    before_policy = deepcopy(st["economics"]["monetary_policy"])
    payload = {
        "block_id": "invalid-mint-amount",
        "issuance_epoch": 0,
        "height": ISSUANCE_EPOCH_BLOCKS,
        "amount": amount,
    }
    with pytest.raises(RewardsApplyError, match="reward_mint_amount_must_be_nonnegative_integer"):
        apply_rewards(st, _sys("BLOCK_REWARD_MINT", payload, 81))
    assert st["accounts"] == before_accounts
    assert st["economics"]["monetary_policy"] == before_policy
    assert "invalid-mint-amount" not in st.get("rewards", {}).get("block_rewards_by_id", {})


@pytest.mark.parametrize("issued", [True, "0", 0.1, -1, MAX_SUPPLY + 1])
def test_activated_reward_mint_rejects_invalid_issued_before_writes(
    issued: object,
) -> None:
    st = _state(issued=0)
    st["economics"]["monetary_policy"]["issued"] = issued
    before_accounts = deepcopy(st["accounts"])
    before_policy = deepcopy(st["economics"]["monetary_policy"])
    with pytest.raises(RewardsApplyError, match="reward_mint_policy_invalid"):
        apply_rewards(
            st,
            _sys(
                "BLOCK_REWARD_MINT",
                {"block_id": "bad-issued", "issuance_epoch": 0, "amount": 7},
                82,
            ),
        )
    assert st["accounts"] == before_accounts
    assert st["economics"]["monetary_policy"] == before_policy
    assert "bad-issued" not in st.get("rewards", {}).get("block_rewards_by_id", {})


@pytest.mark.parametrize("balance", [True, "0", 1.5, -1, None])
def test_activated_reward_mint_rejects_invalid_pool_balance_before_writes(
    balance: object,
) -> None:
    st = _state(issued=0)
    st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] = balance
    before_accounts = deepcopy(st["accounts"])
    before_policy = deepcopy(st["economics"]["monetary_policy"])
    with pytest.raises(RewardsApplyError, match="reward_mint_pool_balance_invalid"):
        apply_rewards(
            st,
            _sys(
                "BLOCK_REWARD_MINT",
                {"block_id": "bad-mint-funding", "issuance_epoch": 0, "amount": 7},
                83,
            ),
        )
    assert st["accounts"] == before_accounts
    assert st["economics"]["monetary_policy"] == before_policy
    assert "bad-mint-funding" not in st.get("rewards", {}).get("block_rewards_by_id", {})


def test_activated_reward_mint_requires_existing_pool_for_positive_issuance() -> None:
    st = _state(issued=0)
    del st["accounts"][MINT_POOL_ACCOUNT_ID]
    before = deepcopy(st["accounts"])
    with pytest.raises(RewardsApplyError, match="reward_mint_pool_missing"):
        apply_rewards(
            st,
            _sys(
                "BLOCK_REWARD_MINT",
                {"block_id": "missing-mint-funding", "issuance_epoch": 0, "amount": 7},
                84,
            ),
        )
    assert st["accounts"] == before
    assert st["economics"]["monetary_policy"]["issued"] == 0


def test_activated_reward_mint_rejects_missing_policy_before_issuance() -> None:
    st = _state(issued=0)
    del st["economics"]["monetary_policy"]
    before = deepcopy(st["accounts"])
    with pytest.raises(RewardsApplyError, match="reward_mint_policy_missing"):
        apply_rewards(
            st,
            _sys(
                "BLOCK_REWARD_MINT",
                {"block_id": "missing-mint-policy", "issuance_epoch": 0, "amount": 7},
                85,
            ),
        )
    assert st["accounts"] == before
    assert "monetary_policy" not in st["economics"]


def test_unactivated_reward_mint_preserves_legacy_numeric_coercion() -> None:
    st = _state(issued=0, configured=False)
    result = apply_rewards(
        st,
        _sys(
            "BLOCK_REWARD_MINT",
            {"block_id": "legacy-fractional-mint", "issuance_epoch": 0, "amount": 7.9},
            86,
        ),
    )
    assert result["amount"] == 7
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 7
    assert st["economics"]["monetary_policy"]["issued"] == 7


def test_activated_mint_exact_duplicate_is_idempotent() -> None:
    st = _state(issued=0)
    payload = {
        "block_id": "same-mint-payload",
        "issuance_epoch": 0,
        "height": ISSUANCE_EPOCH_BLOCKS,
        "amount": 7,
    }
    first = apply_rewards(st, _sys("BLOCK_REWARD_MINT", deepcopy(payload), 90))
    after_first = deepcopy(st)
    replay = apply_rewards(st, _sys("BLOCK_REWARD_MINT", deepcopy(payload), 91))
    assert first["deduped"] is False
    assert replay["deduped"] is True
    assert st["accounts"] == after_first["accounts"]
    assert st["economics"] == after_first["economics"]
    assert st["rewards"]["block_rewards_by_id"] == after_first["rewards"]["block_rewards_by_id"]
    assert st["economics"]["monetary_policy"]["issued"] == 7


@pytest.mark.parametrize("tamper", ["amount", "epoch", "height", "fees"])
def test_activated_mint_duplicate_rejects_conflicting_payload(
    tamper: str,
) -> None:
    st = _state(issued=0)
    payload = {
        "block_id": "duplicate-mint",
        "issuance_epoch": 0,
        "height": ISSUANCE_EPOCH_BLOCKS,
        "amount": 7,
        "fees": 0,
    }
    apply_rewards(st, _sys("BLOCK_REWARD_MINT", deepcopy(payload), 92))
    before = deepcopy(st)
    forged = deepcopy(payload)
    if tamper == "amount":
        forged["amount"] = 8
    elif tamper == "epoch":
        forged["issuance_epoch"] = 1
    elif tamper == "height":
        forged["height"] = 2 * ISSUANCE_EPOCH_BLOCKS
    else:
        forged["fees"] = 1

    with pytest.raises(RewardsApplyError, match="reward_mint_duplicate_payload_mismatch"):
        apply_rewards(st, _sys("BLOCK_REWARD_MINT", forged, 93))
    assert st == before


def test_activated_distribution_exact_duplicate_is_idempotent() -> None:
    st = _state(fee_balance=17)
    payloads = _schedule(st)
    mint = payloads["BLOCK_REWARD_MINT"]
    distribution = payloads["BLOCK_REWARD_DISTRIBUTE"]
    apply_rewards(st, _sys("BLOCK_REWARD_MINT", deepcopy(mint), 94))
    apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", deepcopy(distribution), 95))
    before = deepcopy(st)
    duplicate = apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", deepcopy(distribution), 96))
    assert duplicate["deduped"] is True
    assert st == before


@pytest.mark.parametrize("tamper", ["fee", "recipient", "funding", "height"])
def test_activated_distribution_duplicate_rejects_conflicting_payload(
    tamper: str,
) -> None:
    st = _state(fee_balance=17)
    payloads = _schedule(st)
    mint = payloads["BLOCK_REWARD_MINT"]
    distribution = payloads["BLOCK_REWARD_DISTRIBUTE"]
    apply_rewards(st, _sys("BLOCK_REWARD_MINT", deepcopy(mint), 97))
    apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", deepcopy(distribution), 98))
    before = deepcopy(st)
    forged = deepcopy(distribution)
    if tamper == "fee":
        forged["fees"] = 18
    elif tamper == "recipient":
        forged["transfers"][0]["amount"] += 1
    elif tamper == "funding":
        forged["debits"][0]["amount"] = 16
    else:
        forged["height"] = 2 * ISSUANCE_EPOCH_BLOCKS

    with pytest.raises(RewardsApplyError, match="reward_distribution_duplicate_payload_mismatch"):
        apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", forged, 99))
    assert st == before


def test_unactivated_reward_replay_keeps_prior_duplicate_payload_behavior() -> None:
    st = _state(issued=0, configured=False)
    original = {"block_id": "legacy-duplicate-id", "issuance_epoch": 0, "amount": 7}
    apply_rewards(st, _sys("BLOCK_REWARD_MINT", deepcopy(original), 100))
    conflicting = {**original, "amount": 9}
    replay = apply_rewards(st, _sys("BLOCK_REWARD_MINT", conflicting, 101))
    assert replay["deduped"] is True
    assert st["economics"]["monetary_policy"]["issued"] == 7
