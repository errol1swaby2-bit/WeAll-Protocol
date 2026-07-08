from __future__ import annotations

from weall.api.routes_public_parts.accounts import build_operator_promotion_status
from weall.runtime.domain_apply import apply_tx
from weall.runtime.node_operator_responsibilities import VALIDATOR_REPUTATION_REQUIRED_MILLI
from weall.runtime.validator_readiness_runner import build_validator_readiness_receipt

ACCOUNT = "@op"
NODE_PUBKEY = "node-pub"
BFT_PUBKEY = "bft-pub"


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> dict:
    return {"tx_type": tx_type, "signer": signer, "nonce": nonce, "payload": payload, "system": system, "sig": ""}


def _state(*, rep: int = VALIDATOR_REPUTATION_REQUIRED_MILLI) -> dict:
    return {
        "height": 10,
        "accounts": {
            ACCOUNT: {
                "nonce": 0,
                "poh_tier": 2,
                "reputation_milli": int(rep),
                "banned": False,
                "locked": False,
                "devices": {
                    "by_id": {
                        "node:@op": {"device_type": "node", "pubkey": NODE_PUBKEY, "revoked": False},
                    }
                },
            }
        },
        "roles": {
            "node_operators": {
                "active_set": [ACCOUNT],
                "by_id": {ACCOUNT: {"account_id": ACCOUNT, "enrolled": True, "active": True}},
            },
            "validators": {"active_set": [], "by_id": {}},
        },
    }


def _readiness_payload() -> dict:
    payload = build_validator_readiness_receipt(
        account_id=ACCOUNT,
        node_pubkey=NODE_PUBKEY,
        bft_pubkey=BFT_PUBKEY,
        chain_id="weall-testnet-v1",
        schema_version="1",
        protocol_version="1.25.0",
        manifest_hash="sha256:manifest",
        tx_index_hash="sha256:tx-index",
        runtime_profile_hash="sha256:runtime-profile",
        readiness_expires_height=100,
    )
    payload["verification_status"] = "verified"
    return payload


def _opt_in(st: dict, *, nonce: int = 1) -> None:
    apply_tx(
        st,
        _env(
            "NODE_OPERATOR_VALIDATOR_OPT_IN",
            ACCOUNT,
            nonce,
            {"account_id": ACCOUNT, "validator_opt_in": True, "node_pubkey": NODE_PUBKEY},
        ),
    )


def test_validator_threshold_is_single_deterministic_activation_gate() -> None:
    st = _state(rep=VALIDATOR_REPUTATION_REQUIRED_MILLI)
    _opt_in(st)

    result = apply_tx(st, _env("VALIDATOR_READINESS_VERIFY", "SYSTEM", 2, _readiness_payload(), system=True))

    activation = result["deterministic_validator_activation"]
    assert activation["activated"] is True
    assert activation["reputation_required_milli"] == VALIDATOR_REPUTATION_REQUIRED_MILLI
    assert st["roles"]["validators"]["active_set"] == [ACCOUNT]
    assert st["roles"]["validators"]["by_id"][ACCOUNT]["active"] is True
    assert st["roles"]["validators"]["by_id"][ACCOUNT]["deterministic_activation"] is True

    status = build_operator_promotion_status(st, ACCOUNT, requested_node_pubkey=NODE_PUBKEY, owner_authenticated=True)
    assert status["validator_reputation_required_milli"] == VALIDATOR_REPUTATION_REQUIRED_MILLI
    assert status["validator_active"] is True
    assert status["validator_reboot_allowed"] is True
    assert status["next_step"] == "Validator reboot available"


def test_validator_opt_in_below_single_threshold_records_blocker_not_candidate_limbo() -> None:
    st = _state(rep=VALIDATOR_REPUTATION_REQUIRED_MILLI - 1)
    _opt_in(st)

    result = apply_tx(st, _env("VALIDATOR_READINESS_VERIFY", "SYSTEM", 2, _readiness_payload(), system=True))

    activation = result["deterministic_validator_activation"]
    assert activation["activated"] is False
    assert activation["reputation_required_milli"] == VALIDATOR_REPUTATION_REQUIRED_MILLI
    assert activation["reputation_actual_milli"] == VALIDATOR_REPUTATION_REQUIRED_MILLI - 1
    assert "validator_reputation_insufficient" in activation["blocking_reasons"]
    assert st["roles"]["validators"]["active_set"] == []

    status = build_operator_promotion_status(st, ACCOUNT, requested_node_pubkey=NODE_PUBKEY, owner_authenticated=True)
    assert status["validator_active"] is False
    assert status["validator_reboot_allowed"] is False
    assert "validator:validator_reputation_insufficient" in status["blocking_reasons"]
    assert status["next_step"] == "Validator opt-in recorded; readiness/reputation pending"


def test_reputation_crossing_single_threshold_after_readiness_triggers_activation() -> None:
    st = _state(rep=VALIDATOR_REPUTATION_REQUIRED_MILLI - 500)
    _opt_in(st)
    ready = apply_tx(st, _env("VALIDATOR_READINESS_VERIFY", "SYSTEM", 2, _readiness_payload(), system=True))
    assert ready["deterministic_validator_activation"]["activated"] is False
    assert st["roles"]["validators"]["active_set"] == []

    delta = apply_tx(
        st,
        _env(
            "REPUTATION_DELTA_APPLY",
            "SYSTEM",
            3,
            {
                "account_id": ACCOUNT,
                "delta_milli": 500,
                "reason": "operator_rehearsal_proof_accepted",
                "event_code": "VALIDATOR_PASSED_REHEARSAL",
                "source_flow": "validator",
                "source_object_id": "readiness:1",
            },
            system=True,
        ),
    )

    activation = delta["deterministic_validator_activation"]
    assert activation["activated"] is True
    assert st["accounts"][ACCOUNT]["reputation_milli"] == VALIDATOR_REPUTATION_REQUIRED_MILLI
    assert st["roles"]["validators"]["active_set"] == [ACCOUNT]
    assert st["roles"]["validators"]["by_id"][ACCOUNT]["activation_source"] == "reputation_delta_apply"
