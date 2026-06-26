from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.executor import WeAllExecutor
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.validator_readiness_runner import build_validator_readiness_receipt

ROOT = Path(__file__).resolve().parents[1]


def _env(tx_type: str, signer: str, nonce: int, payload: dict | None = None, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope.from_json(
        {
            "tx_type": tx_type,
            "signer": signer,
            "nonce": nonce,
            "payload": payload or {},
            "sig": "sig",
            "system": bool(system),
            "parent": parent if parent is not None else (f"p:{tx_type}:{nonce}" if system else None),
        }
    )


def _validator_state() -> dict:
    return {
        "height": 10,
        "chain_id": "weall-prod",
        "accounts": {
            "@op": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "balance": 0,
                "reputation_milli": 10_000,
                "devices": {
                    "by_id": {
                        "node-pub-1": {
                            "device_id": "node-pub-1",
                            "device_type": "node",
                            "pubkey": "node-pub-1",
                            "revoked": False,
                        }
                    }
                },
            },
            "SYSTEM": {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False},
        },
        "roles": {
            "node_operators": {
                "active_set": ["@op"],
                "by_id": {
                    "@op": {
                        "account_id": "@op",
                        "enrolled": True,
                        "active": True,
                        "responsibilities": {
                            "validator": {
                                "opted_in": True,
                                "active": True,
                                "readiness_status": "verified",
                                "readiness_expires_height": 100,
                                "readiness_receipt_hash": "sha256:placeholder",
                                "manifest_hash": "sha256:manifest",
                                "tx_index_hash": "sha256:tx-index",
                                "runtime_profile_hash": "sha256:profile",
                                "chain_id": "weall-prod",
                                "schema_version": "1",
                                "protocol_version": "1",
                                "node_pubkey": "node-pub-1",
                                "bft_pubkey": "bft-pub-1",
                            }
                        },
                    }
                },
            },
            "validators": {"active_set": []},
        },
        "params": {
            "validator_candidate_lifecycle_gate_enabled": True,
            "validator_candidate_node_id_must_match_node_pubkey": True,
        },
        "validators": {"registry": {}},
        "consensus": {"validators": {"registry": {}}},
    }


def _make_readiness_payload() -> dict:
    return build_validator_readiness_receipt(
        account_id="@op",
        node_pubkey="node-pub-1",
        bft_pubkey="bft-pub-1",
        chain_id="weall-prod",
        schema_version="1",
        protocol_version="1",
        manifest_hash="sha256:manifest",
        tx_index_hash="sha256:tx-index",
        runtime_profile_hash="sha256:profile",
        readiness_expires_height=100,
    )


def test_validator_candidate_register_requires_active_validator_responsibility() -> None:
    st = _validator_state()
    st["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["validator"]["active"] = False

    with pytest.raises(ApplyError) as exc:
        apply_tx(
            st,
            _env(
                "VALIDATOR_CANDIDATE_REGISTER",
                "@op",
                1,
                {"node_id": "node-pub-1", "pubkey": "bft-pub-1", "endpoints": ["https://node.example"]},
            ),
        )

    assert exc.value.reason == "validator_candidate_requires_active_validator_responsibility"


def test_validator_candidate_register_requires_readiness_bft_pubkey_binding() -> None:
    st = _validator_state()

    with pytest.raises(ApplyError) as exc:
        apply_tx(
            st,
            _env(
                "VALIDATOR_CANDIDATE_REGISTER",
                "@op",
                1,
                {"node_id": "node-pub-1", "pubkey": "wrong-bft-pub", "endpoints": ["https://node.example"]},
            ),
        )

    assert exc.value.reason == "validator_candidate_pubkey_must_match_readiness_bft_pubkey"


def test_validator_candidate_register_passes_after_operator_opt_in_readiness_and_node_binding() -> None:
    st = _validator_state()
    # Use a real readiness payload shape and hash to prove the record can be produced by the runner.
    readiness = _make_readiness_payload()
    st["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["validator"].update(readiness)
    st["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["validator"].update(
        {"opted_in": True, "active": True, "readiness_status": "verified"}
    )

    out = apply_tx(
        st,
        _env(
            "VALIDATOR_CANDIDATE_REGISTER",
            "@op",
            1,
            {"node_id": "node-pub-1", "pubkey": "bft-pub-1", "endpoints": ["https://node.example"]},
        ),
    )

    assert out["applied"] == "VALIDATOR_CANDIDATE_REGISTER"
    assert out["status"] == "candidate"
    assert st["validators"]["registry"]["@op"]["active"] is False
    assert "@op" not in st["roles"]["validators"]["active_set"]


def test_production_genesis_pins_candidate_and_bft_public_beta_gates() -> None:
    genesis = json.loads((ROOT / "configs" / "genesis.ledger.prod.json").read_text(encoding="utf-8"))
    params = genesis["params"]
    assert params["validator_candidate_lifecycle_gate_enabled"] is True
    assert params["validator_candidate_node_id_must_match_node_pubkey"] is True
    assert params["bft_signing_public_beta_gate_enabled"] is True
    assert params["public_mainnet_enabled"] is False


def _econ_state() -> dict:
    genesis_time = 1_700_000_000
    unlock_time = genesis_time + 90 * 24 * 60 * 60
    return {
        "height": 1,
        "chain_id": "weall-prod",
        "time": genesis_time,
        "params": {
            "genesis_time": genesis_time,
            "economic_unlock_time": unlock_time,
            "economics_enabled": False,
        },
        "economics": {"fee_policy": {"transfer_fee_int": 0}},
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "balance": 100},
            "bob": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "balance": 0},
            "SYSTEM": {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False, "balance": 0},
        },
    }


def test_wecoin_transfer_requires_unlock_and_governance_activation() -> None:
    st = _econ_state()
    with pytest.raises(ApplyError) as before_unlock:
        apply_tx(st, _env("BALANCE_TRANSFER", "alice", 1, {"to": "bob", "amount": 5}))
    assert before_unlock.value.reason in {"economics_time_locked", "economics are time-locked", "economics are disabled"}

    st["time"] = st["params"]["economic_unlock_time"]
    with pytest.raises(ApplyError) as before_activation:
        apply_tx(st, _env("BALANCE_TRANSFER", "alice", 1, {"to": "bob", "amount": 5}))
    assert before_activation.value.reason in {"economics_disabled", "economics are disabled"}

    with pytest.raises(ApplyError) as user_activation:
        apply_tx(st, _env("ECONOMICS_ACTIVATION", "alice", 2, {"enable": True}))
    assert user_activation.value.reason in {"system_tx_required", "system_only"}

    apply_tx(st, _env("ECONOMICS_ACTIVATION", "SYSTEM", 3, {"enable": True}, system=True, parent="gov:activation"))
    out = apply_tx(st, _env("BALANCE_TRANSFER", "alice", 4, {"to": "bob", "amount": 5}))
    assert out == {"applied": "BALANCE_TRANSFER", "from": "alice", "to": "bob", "amount": 5}
    assert st["accounts"]["alice"]["balance"] == 95
    assert st["accounts"]["bob"]["balance"] == 5


def test_wecoin_fee_policy_cannot_fee_gate_civic_social_governance_actions() -> None:
    st = _econ_state()
    st["time"] = st["params"]["economic_unlock_time"]
    apply_tx(st, _env("ECONOMICS_ACTIVATION", "SYSTEM", 1, {"enable": True}, system=True, parent="gov:activation"))

    for field in ("post_fee_int", "governance_vote_fee_int", "account_register_fee_int", "peer_advertise_fee_int"):
        local = copy.deepcopy(st)
        with pytest.raises(ApplyError) as exc:
            apply_tx(local, _env("FEE_POLICY_SET", "SYSTEM", 2, {field: 1}, system=True, parent=f"gov:fee:{field}"))
        assert exc.value.reason == "civic_social_governance_actions_must_remain_fee_free"


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def test_prod_bft_signing_requires_local_identity_active_set_bft_phase_and_min_validators(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "1")
    monkeypatch.delenv("WEALL_OBSERVER_MODE", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)
    monkeypatch.delenv("WEALL_NODE_PUBKEY", raising=False)
    monkeypatch.delenv("WEALL_NODE_PRIVKEY", raising=False)

    tx_index = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index)
    ex = WeAllExecutor(db_path=str(tmp_path / "weall.db"), node_id="observer-node", chain_id="weall-prod", tx_index_path=str(tx_index))
    ex.state.setdefault("roles", {}).setdefault("validators", {})["active_set"] = ["@v1", "@v2", "@v3", "@v4"]
    ex.state.setdefault("consensus", {}).setdefault("phase", {})["current"] = "bft_active"

    assert ex.validator_signing_enabled() is False
    assert ex.bft_diagnostics()["signing_block_reason"] == "local_validator_identity_not_active"

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub-v1")
    ex.state.setdefault("consensus", {}).setdefault("validators", {})["registry"] = {"@v1": {"pubkey": "pub-v1"}}
    assert ex.validator_signing_enabled() is True
