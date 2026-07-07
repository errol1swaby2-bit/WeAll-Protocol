from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.ledger.constants import MINT_POOL_ACCOUNT_ID
from weall.net.handshake import (
    HandshakeConfig,
    HandshakeState,
    build_hello,
    process_inbound_hello,
)
from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.apply.governance import apply_governance
from weall.runtime.apply.groups import apply_groups
from weall.runtime.apply.rewards import RewardsApplyError, apply_rewards
from weall.runtime.apply.treasury import TreasuryApplyError, apply_treasury
from weall.runtime.errors import ApplyError
from weall.runtime.executor import WeAllExecutor
from weall.runtime.system_tx_engine import (
    enqueue_system_tx,
    system_tx_emitter,
    validate_system_tx_queue_binding,
)
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex

ROOT = Path(__file__).resolve().parents[1]


def _tx_index() -> TxIndex:
    return TxIndex.load_from_file(str(ROOT / "generated" / "tx_index.json"))


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict | None = None,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload or {},
        sig="sig",
        parent=parent if parent is not None else (f"parent:{nonce}" if system else None),
        system=system,
    )


def _sum_account_balances(state: dict) -> int:
    return sum(int(acct.get("balance", 0)) for acct in state.get("accounts", {}).values() if isinstance(acct, dict))


def _sum_treasury_balances(state: dict) -> int:
    return sum(int(w.get("balance", 0)) for w in state.get("treasury_wallets", {}).values() if isinstance(w, dict))


def test_high_impact_system_txs_are_queue_bound_and_mutation_rejected() -> None:
    canon = _tx_index()
    high_impact_payloads = {
        "ECONOMICS_ACTIVATION": {"enable": True},
        "TREASURY_SPEND_EXECUTE": {"spend_id": "spend-1"},
        "GROUP_TREASURY_SPEND_EXECUTE": {"spend_id": "gspend-1"},
        "GOV_EXECUTE": {"proposal_id": "proposal-1"},
        "ROLE_JUROR_ACTIVATE": {"account_id": "@juror"},
        "ROLE_NODE_OPERATOR_ACTIVATE": {"account_id": "@operator"},
        "ROLE_VALIDATOR_ACTIVATE": {"account_id": "@validator"},
        "ROLE_EMISSARY_REMOVE": {"account_id": "@emissary"},
        "ACCOUNT_BAN": {"account_id": "@bad", "reason": "test"},
        "REPUTATION_DELTA_APPLY": {"account_id": "@bad", "delta": -100, "reason": "test"},
        "ROLE_ELIGIBILITY_REVOKE": {"account_id": "@bad", "role": "validator", "reason": "test"},
        "VALIDATOR_SET_UPDATE": {"validators": ["@v1", "@v2", "@v3", "@v4"]},
    }

    for tx_type, payload in high_impact_payloads.items():
        state = {"height": 10, "params": {"economics_enabled": False}, "system_queue": []}
        enqueue_system_tx(
            state,
            tx_type=tx_type,
            payload=payload,
            due_height=11,
            signer="SYSTEM",
            parent="governance:proposal-1",
            phase="post",
            once=True,
        )
        emitted = [tx for tx in system_tx_emitter(state, canon, next_height=11, phase="post") if tx.tx_type == tx_type]
        assert len(emitted) == 1, tx_type

        ok, why = validate_system_tx_queue_binding(state, canon, emitted[0], next_height=11, phase="post")
        assert (ok, why) == (True, ""), tx_type

        missing = TxEnvelope(
            tx_type=emitted[0].tx_type,
            signer=emitted[0].signer,
            nonce=emitted[0].nonce,
            payload={k: v for k, v in emitted[0].payload.items() if k != "_system_queue_id"},
            sig=emitted[0].sig,
            parent=emitted[0].parent,
            system=True,
        )
        ok, why = validate_system_tx_queue_binding(state, canon, missing, next_height=11, phase="post")
        assert (ok, why) == (False, "missing_system_queue_id"), tx_type

        mutated_payload = dict(emitted[0].payload)
        mutated_payload["attacker_chosen_field"] = "mutated"
        mutated = TxEnvelope(
            tx_type=emitted[0].tx_type,
            signer=emitted[0].signer,
            nonce=emitted[0].nonce,
            payload=mutated_payload,
            sig=emitted[0].sig,
            parent=emitted[0].parent,
            system=True,
        )
        ok, why = validate_system_tx_queue_binding(state, canon, mutated, next_height=11, phase="post")
        assert (ok, why) == (False, "system_queue_payload_mismatch"), tx_type


def test_proposal_voted_governance_execution_enqueues_queue_bound_economics_and_treasury_actions() -> None:
    state = {
        "height": 20,
        "chain_id": "weall-prod",
        "time": 1_800_000_000,
        "params": {
            "mode": "production",
            "genesis_time": 1_700_000_000,
            "economic_unlock_time": 1_700_000_000,
            "economics_enabled": True,
        },
        "accounts": {"@val1": {"poh_tier": 2, "banned": False, "locked": False}, "SYSTEM": {"poh_tier": 0}},
        "roles": {"validators": {"active_set": ["@val1"]}},
        "gov_proposals_by_id": {},
        "system_queue": [],
    }
    actions = [
        {"tx_type": "ECONOMICS_ACTIVATION", "payload": {"enable": True}},
        {"tx_type": "TREASURY_SPEND_EXECUTE", "payload": {"spend_id": "spend-1"}},
    ]

    apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@val1",
            1,
            {"proposal_id": "p-exec", "title": "execute actions", "rules": {"start_stage": "voting"}, "actions": actions},
        ),
    )
    proposal = state["gov_proposals_by_id"]["p-exec"]
    proposal["stage"] = "tallied"
    proposal["tallies"] = [{"height": 21, "payload": {"proposal_id": "p-exec", "passed": True}}]

    before_queue_len = len(state.get("system_queue", []))
    result = apply_governance(state, _env("GOV_EXECUTE", "SYSTEM", 2, {"proposal_id": "p-exec"}, system=True, parent="gov:p-exec"))
    assert result == {"applied": True, "proposal_id": "p-exec"}
    assert len(state.get("system_queue", [])) - before_queue_len == 3  # two actions plus GOV_EXECUTION_RECEIPT

    canon = _tx_index()
    emitted = system_tx_emitter(state, canon, next_height=22, phase="post")
    emitted_by_type = {tx.tx_type: tx for tx in emitted}
    assert "ECONOMICS_ACTIVATION" in emitted_by_type
    assert "TREASURY_SPEND_EXECUTE" in emitted_by_type
    assert "GOV_EXECUTION_RECEIPT" in emitted_by_type
    for tx_type in ("ECONOMICS_ACTIVATION", "TREASURY_SPEND_EXECUTE", "GOV_EXECUTION_RECEIPT"):
        ok, why = validate_system_tx_queue_binding(state, canon, emitted_by_type[tx_type], next_height=22, phase="post")
        assert (ok, why) == (True, ""), tx_type


def test_wecoin_wallet_treasury_reward_and_fee_conservation() -> None:
    locked = {
        "height": 1,
        "time": 1,
        "params": {"economic_unlock_time": 999, "economics_enabled": False},
        "accounts": {
            "@alice": {"balance": 100, "nonce": 0, "poh_tier": 1, "banned": False, "locked": False},
            "@bob": {"balance": 0, "nonce": 0, "poh_tier": 1, "banned": False, "locked": False},
        },
        "treasury_wallets": {"TREASURY_PROTOCOL": {"wallet_id": "TREASURY_PROTOCOL", "balance": 50}},
        "treasury": {"spends": {"spend-locked": {"treasury_id": "TREASURY_PROTOCOL", "status": "proposed", "allowed_signers": ["@alice"], "threshold": 1, "signatures": {"@alice": {}}, "earliest_execute_height": 0, "to": "@bob", "amount": 10}}},
    }
    with pytest.raises(EconomicsApplyError):
        apply_economics(locked, _env("BALANCE_TRANSFER", "@alice", 1, {"to": "@bob", "amount": 1}))
    with pytest.raises(EconomicsApplyError):
        apply_economics(locked, _env("FEE_PAY", "@alice", 2, {"from_account": "@alice", "amount": 1}))
    with pytest.raises(Exception) as reward_exc:
        apply_rewards(locked, _env("BLOCK_REWARD_MINT", "SYSTEM", 3, {"block_id": "b-locked", "amount": 1}, system=True))
    assert "economics" in str(reward_exc.value).lower()
    with pytest.raises(Exception) as treasury_exc:
        apply_treasury(locked, _env("TREASURY_SPEND_EXECUTE", "SYSTEM", 4, {"spend_id": "spend-locked"}, system=True))
    assert "economics" in str(treasury_exc.value).lower()

    state = {
        "height": 10,
        "time": 1000,
        "params": {"economic_unlock_time": 0, "economics_enabled": True},
        "economics": {"monetary_policy": {"issued": 0, "max_supply": 21_000_000}, "fee_policy": {}},
        "accounts": {
            "@alice": {"balance": 1000, "nonce": 0, "poh_tier": 1, "banned": False, "locked": False},
            "@bob": {"balance": 0, "nonce": 0, "poh_tier": 1, "banned": False, "locked": False},
            "fee_sink": {"balance": 0, "nonce": 0, "poh_tier": 0, "banned": False, "locked": False},
            MINT_POOL_ACCOUNT_ID: {"balance": 0, "nonce": 0, "poh_tier": 0, "banned": False, "locked": False},
        },
        "treasury_wallets": {
            "TREASURY_PROTOCOL": {"wallet_id": "TREASURY_PROTOCOL", "balance": 500},
            "TREASURY_GROUP::g1": {"wallet_id": "TREASURY_GROUP::g1", "balance": 300},
        },
        "treasury": {"spends": {"spend-1": {"treasury_id": "TREASURY_PROTOCOL", "status": "proposed", "allowed_signers": ["@alice"], "threshold": 1, "signatures": {"@alice": {}}, "earliest_execute_height": 1, "to": "@bob", "amount": 125}}},
        "group_treasury_spends": {"gspend-1": {"group_id": "g1", "treasury_id": "TREASURY_GROUP::g1", "status": "proposed", "allowed_signers": ["@alice"], "threshold": 1, "signatures": {"@alice": {}}, "earliest_execute_height": 1, "to": "@bob", "amount": 70}},
    }
    before_accounts = _sum_account_balances(state)
    apply_economics(state, _env("BALANCE_TRANSFER", "@alice", 1, {"to": "@bob", "amount": 40}))
    assert _sum_account_balances(state) == before_accounts

    apply_economics(state, _env("FEE_PAY", "@alice", 2, {"from_account_id": "@alice", "amount": 10, "to_account_id": "fee_sink"}))
    assert _sum_account_balances(state) == before_accounts

    apply_rewards(state, _env("BLOCK_REWARD_MINT", "SYSTEM", 3, {"block_id": "b1", "amount": 100, "height": 10}, system=True))
    assert state["economics"]["monetary_policy"]["issued"] == 100
    assert _sum_account_balances(state) == before_accounts + 100

    apply_rewards(
        state,
        _env(
            "BLOCK_REWARD_DISTRIBUTE",
            "SYSTEM",
            4,
            {"block_id": "b1", "transfers": [{"to": "@bob", "amount": 25}], "debits": [{"from": MINT_POOL_ACCOUNT_ID, "amount": 25}]},
            system=True,
        ),
    )
    assert _sum_account_balances(state) == before_accounts + 100

    before_combined = _sum_account_balances(state) + _sum_treasury_balances(state)
    apply_treasury(state, _env("TREASURY_SPEND_EXECUTE", "SYSTEM", 5, {"spend_id": "spend-1"}, system=True))
    apply_groups(state, _env("GROUP_TREASURY_SPEND_EXECUTE", "SYSTEM", 6, {"spend_id": "gspend-1"}, system=True))
    assert _sum_account_balances(state) + _sum_treasury_balances(state) == before_combined

    for field in ("post_fee_int", "governance_vote_fee_int", "account_register_fee_int", "peer_advertise_fee_int"):
        with pytest.raises(EconomicsApplyError) as exc:
            apply_economics(state, _env("FEE_POLICY_SET", "SYSTEM", 7, {field: 1}, system=True))
        assert exc.value.reason == "civic_social_governance_actions_must_remain_fee_free"


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def test_validator_bft_signing_fails_closed_until_four_active_authorized_validators(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "1")
    monkeypatch.delenv("WEALL_OBSERVER_MODE", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)
    monkeypatch.delenv("WEALL_NODE_PUBKEY", raising=False)

    tx_index = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index)
    ex = WeAllExecutor(db_path=str(tmp_path / "weall.db"), node_id="node-v1", chain_id="weall-prod", tx_index_path=str(tx_index))
    ex.state.setdefault("roles", {}).setdefault("validators", {})["active_set"] = ["@v1", "@v2", "@v3", "@v4"]
    ex.state.setdefault("consensus", {}).setdefault("phase", {})["current"] = "bft_active"
    assert ex.validator_signing_enabled() is False
    assert ex.bft_diagnostics()["signing_block_reason"] == "local_validator_identity_not_active"

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub-v1")
    ex.state.setdefault("consensus", {}).setdefault("validators", {})["registry"] = {"@v1": {"pubkey": "pub-v1"}}
    ex.state["roles"]["validators"]["active_set"] = ["@v1", "@v2", "@v3"]
    assert ex.validator_signing_enabled() is False
    assert ex.bft_diagnostics()["signing_block_reason"] == "validator_count_below_bft_minimum:3/4"

    ex.state["roles"]["validators"]["active_set"] = ["@v1", "@v2", "@v3", "@v4"]
    assert ex.validator_signing_enabled() is True


def test_stale_profile_tx_index_and_validator_set_handshakes_fail_closed() -> None:
    local = HandshakeConfig(
        chain_id="weall-prod",
        schema_version="1",
        tx_index_hash="txhash-current",
        peer_id="local",
        protocol_version="1.0.0",
        protocol_profile_hash="profile-current",
        validator_epoch=7,
        validator_set_hash="vset-current",
        bft_enabled=True,
        require_protocol_profile_match=True,
        require_validator_epoch_match_for_bft=True,
    )

    stale_profile = build_hello(
        HandshakeConfig(
            chain_id="weall-prod",
            schema_version="1",
            tx_index_hash="txhash-current",
            peer_id="stale-profile",
            protocol_version="1.0.0",
            protocol_profile_hash="profile-old",
            validator_epoch=7,
            validator_set_hash="vset-current",
            bft_enabled=True,
        )
    )
    state = HandshakeState(local)
    ack = process_inbound_hello(state, stale_profile)
    assert ack.ok is False
    assert ack.reason == "protocol_profile_hash_mismatch"

    stale_tx_index = build_hello(
        HandshakeConfig(
            chain_id="weall-prod",
            schema_version="1",
            tx_index_hash="txhash-old",
            peer_id="stale-tx-index",
            protocol_version="1.0.0",
            protocol_profile_hash="profile-current",
            validator_epoch=7,
            validator_set_hash="vset-current",
            bft_enabled=True,
        )
    )
    state = HandshakeState(local)
    ack = process_inbound_hello(state, stale_tx_index)
    assert ack.ok is False
    assert ack.reason == "tx_index_hash_mismatch"

    stale_validator_set = build_hello(
        HandshakeConfig(
            chain_id="weall-prod",
            schema_version="1",
            tx_index_hash="txhash-current",
            peer_id="stale-validator-set",
            protocol_version="1.0.0",
            protocol_profile_hash="profile-current",
            validator_epoch=7,
            validator_set_hash="vset-old",
            bft_enabled=True,
        )
    )
    state = HandshakeState(local)
    ack = process_inbound_hello(state, stale_validator_set)
    assert ack.ok is False
    assert ack.reason == "validator_set_hash_mismatch"


def test_helper_contract_map_keeps_global_authority_serial_and_bounded() -> None:
    helper_map = json.loads((ROOT / "generated" / "helper_contract_map.json").read_text(encoding="utf-8"))
    summary = helper_map["summary"]
    assert summary["tx_count"] == 236
    assert summary["global_authority_parallel_count"] == 0
    assert summary["unknown_family_count"] == 0
    assert summary["effective_lane_counts"]["SERIAL"] >= summary["helper_eligible_count"]
    assert summary["proven_helper_eligible_count"] <= summary["helper_eligible_count"]
