from __future__ import annotations

import hashlib
import importlib.util

import pytest

from weall.api.routes_public_parts.accounts import build_operator_promotion_status
from weall.runtime.node_operator_responsibilities import VALIDATOR_REPUTATION_REQUIRED_MILLI
from weall.crypto.sig import sign_tx_envelope_dict
from weall.crypto.signature_profiles import PQ_MLDSA_V1
from weall.runtime.domain_apply import apply_tx
from weall.runtime.sigverify import verify_tx_signature
from weall.testing.sigtools import deterministic_mldsa_keypair

ACCOUNT = "@observer"
NODE_DEVICE_ID = "node:@observer"
CHAIN_ID = "weall-testnet-v1"
NETWORK_ID = "weall-public-observer-testnet-v1"


HAS_MLDSA = importlib.util.find_spec("cryptography.hazmat.primitives.asymmetric.mldsa") is not None


def _pseudo_pub(label: str) -> str:
    return "pseudo-mldsa-pub:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _keypair(label: str) -> tuple[str, str]:
    if not HAS_MLDSA:
        return _pseudo_pub(label), "pseudo-priv-unavailable"
    pub, priv = deterministic_mldsa_keypair(label=label)
    return pub, str(priv)


def _state(*, tier: int = 2, rep: int = 1000) -> dict:
    account_pub, _ = _keypair(ACCOUNT)
    node_pub, _ = _keypair(NODE_DEVICE_ID)
    return {
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "params": {"require_signatures": True, "chain_id": CHAIN_ID, "network_id": NETWORK_ID},
        "height": 10,
        "accounts": {
            ACCOUNT: {
                "nonce": 0,
                "poh_tier": int(tier),
                "reputation_milli": int(rep),
                "banned": False,
                "locked": False,
                "keys": [{"sig_profile": PQ_MLDSA_V1, "pubkeys": {"mldsa": account_pub}, "active": True}],
                "devices": {
                    "by_id": {
                        NODE_DEVICE_ID: {
                            "device_type": "node",
                            "pubkey": node_pub,
                            "revoked": False,
                        }
                    }
                },
            }
        },
        "roles": {"node_operators": {"by_id": {}, "active_set": []}, "validators": {"by_id": {}, "active_set": []}},
    }


def _sign(tx_type: str, payload: dict, *, signer: str = ACCOUNT, label: str = ACCOUNT, nonce: int = 1) -> dict:
    tx = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "payload": payload,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "sig_profile": PQ_MLDSA_V1,
        "sig": "test-signature-unavailable",
        "pubkey": _pseudo_pub(label),
    }
    if not HAS_MLDSA:
        return tx
    _pub, priv = _keypair(label)
    return sign_tx_envelope_dict(tx=tx, privkey=priv, encoding="hex")


def _node_pubkey() -> str:
    pub, _ = _keypair(NODE_DEVICE_ID)
    return pub


def test_tier2_node_device_enroll_then_activation_controls_service_reboot() -> None:
    st = _state(tier=2, rep=1000)
    node_pub = _node_pubkey()

    enroll = _sign("ROLE_NODE_OPERATOR_ENROLL", {"account_id": ACCOUNT}, nonce=1)
    if HAS_MLDSA:
        assert verify_tx_signature(st, enroll) is True
    apply_tx(st, enroll)

    pending = build_operator_promotion_status(st, ACCOUNT, requested_node_pubkey=node_pub, owner_authenticated=True)
    assert pending["node_key_registered"] is True
    assert pending["node_operator_enrolled"] is True
    assert pending["node_operator_active"] is False
    assert pending["service_reboot_allowed"] is False
    assert pending["next_step"] == "Waiting for protocol activation"

    apply_tx(st, {"tx_type": "ROLE_NODE_OPERATOR_ACTIVATE", "signer": "SYSTEM", "nonce": 2, "payload": {"account_id": ACCOUNT}, "system": True})
    active = build_operator_promotion_status(st, ACCOUNT, requested_node_pubkey=node_pub, owner_authenticated=True)
    assert active["node_operator_active"] is True
    assert active["service_reboot_allowed"] is True
    assert active["validator_reboot_allowed"] is False
    assert active["next_step"] == "Validator opt-in available"


def test_validator_opt_in_account_signature_accepted_but_reputation_and_readiness_block_authority() -> None:
    st = _state(tier=2, rep=1000)
    node_pub = _node_pubkey()
    apply_tx(st, _sign("ROLE_NODE_OPERATOR_ENROLL", {"account_id": ACCOUNT}, nonce=1))
    apply_tx(st, {"tx_type": "ROLE_NODE_OPERATOR_ACTIVATE", "signer": "SYSTEM", "nonce": 2, "payload": {"account_id": ACCOUNT}, "system": True})

    tx = _sign(
        "NODE_OPERATOR_VALIDATOR_OPT_IN",
        {
            "account_id": ACCOUNT,
            "validator_opt_in": True,
            "node_pubkey": node_pub,
            "validator_readiness_commitment": "sha256:readiness",
        },
        nonce=3,
    )
    if HAS_MLDSA:
        assert verify_tx_signature(st, tx) is True
    result = apply_tx(st, tx)
    assert result["applied"] == "NODE_OPERATOR_VALIDATOR_OPT_IN"

    status = build_operator_promotion_status(st, ACCOUNT, requested_node_pubkey=node_pub, owner_authenticated=True)
    assert status["validator_opted_in"] is True
    assert status["validator_readiness_status"] == "pending"
    assert status["validator_reputation_actual_milli"] >= 1000
    assert status["validator_reputation_actual_milli"] < status["validator_reputation_required_milli"]
    assert status["validator_reputation_required_milli"] == VALIDATOR_REPUTATION_REQUIRED_MILLI
    assert status["validator_active"] is False
    assert status["validator_reboot_allowed"] is False
    assert "validator:validator_reputation_insufficient" in status["blocking_reasons"]
    assert "bad_sig" not in " ".join(status["blocking_reasons"])


def test_storage_opt_in_account_signature_accepted_but_capacity_proof_blocks_allocation() -> None:
    st = _state(tier=2, rep=6000)
    node_pub = _node_pubkey()
    apply_tx(st, _sign("ROLE_NODE_OPERATOR_ENROLL", {"account_id": ACCOUNT}, nonce=1))
    apply_tx(st, {"tx_type": "ROLE_NODE_OPERATOR_ACTIVATE", "signer": "SYSTEM", "nonce": 2, "payload": {"account_id": ACCOUNT}, "system": True})

    tx = _sign(
        "NODE_OPERATOR_STORAGE_OPT_IN",
        {
            "account_id": ACCOUNT,
            "storage_opt_in": True,
            "node_pubkey": node_pub,
            "declared_capacity_bytes": 500_000_000,
            "storage_endpoint_commitment": "sha256:endpoint",
        },
        nonce=3,
    )
    if HAS_MLDSA:
        assert verify_tx_signature(st, tx) is True
    result = apply_tx(st, tx)
    assert result["applied"] == "NODE_OPERATOR_STORAGE_OPT_IN"

    status = build_operator_promotion_status(st, ACCOUNT, requested_node_pubkey=node_pub, owner_authenticated=True)
    assert status["storage_opted_in"] is True
    assert status["storage_declared_capacity_bytes"] == 500_000_000
    assert status["storage_proof_status"] == "probe_pending"
    assert status["storage_active"] is False
    assert "storage:capacity_proof_pending" in status["blocking_reasons"]


@pytest.mark.skipif(not HAS_MLDSA, reason="ML-DSA provider unavailable in this Python environment")
def test_invalid_signer_and_node_key_cannot_sign_account_authority_opt_ins() -> None:
    st = _state(tier=2, rep=6000)
    node_pub = _node_pubkey()
    apply_tx(st, _sign("ROLE_NODE_OPERATOR_ENROLL", {"account_id": ACCOUNT}, nonce=1))
    apply_tx(st, {"tx_type": "ROLE_NODE_OPERATOR_ACTIVATE", "signer": "SYSTEM", "nonce": 2, "payload": {"account_id": ACCOUNT}, "system": True})

    signed_by_node_key = _sign(
        "NODE_OPERATOR_VALIDATOR_OPT_IN",
        {"account_id": ACCOUNT, "validator_opt_in": True, "node_pubkey": node_pub},
        label=NODE_DEVICE_ID,
        nonce=3,
    )
    assert signed_by_node_key["signer"] == ACCOUNT
    assert verify_tx_signature(st, signed_by_node_key) is False

    signed_for_other_account = _sign(
        "NODE_OPERATOR_STORAGE_OPT_IN",
        {"account_id": "@attacker", "storage_opt_in": True, "node_pubkey": node_pub, "declared_capacity_bytes": 1},
        signer=ACCOUNT,
        nonce=3,
    )
    assert verify_tx_signature(st, signed_for_other_account) is True
    with pytest.raises(Exception) as exc:
        apply_tx(st, signed_for_other_account)
    assert "only_account_can_update_storage_responsibility" in str(exc.value)
