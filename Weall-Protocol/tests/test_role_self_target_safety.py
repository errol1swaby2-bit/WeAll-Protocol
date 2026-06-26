from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx


def _env(tx_type: str, payload: dict, *, signer: str, nonce: int = 1) -> dict:
    return {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "payload": payload,
        "sig": "sig",
        "system": False,
    }


def _state() -> dict:
    return {
        "accounts": {
            "@attacker": {"nonce": 0, "poh_tier": 2, "reputation_milli": 6000},
            "@victim": {
                "nonce": 0,
                "poh_tier": 2,
                "reputation_milli": 6000,
                "devices": {
                    "by_id": {
                        "node:victim": {
                            "device_type": "node",
                            "pubkey": "victim-node-pub",
                            "revoked": False,
                        }
                    }
                },
            },
        },
        "roles": {
            "node_operators": {
                "by_id": {
                    "@victim": {
                        "account_id": "@victim",
                        "enrolled": True,
                        "active": True,
                    }
                },
                "active_set": ["@victim"],
            },
            "jurors": {"by_id": {}, "active_set": []},
        },
    }


def test_role_node_operator_enroll_rejects_foreign_account_target_batch349() -> None:
    st = _state()

    with pytest.raises(Exception) as exc:
        apply_tx(
            st,
            _env(
                "ROLE_NODE_OPERATOR_ENROLL",
                {"account_id": "@victim"},
                signer="@attacker",
            ),
        )

    assert "only_account_can_enroll_node_operator" in str(exc.value)
    rec = st["roles"]["node_operators"]["by_id"]["@victim"]
    assert rec == {"account_id": "@victim", "enrolled": True, "active": True}
    assert st["accounts"]["@attacker"]["nonce"] == 0


def test_role_node_operator_enroll_rejects_foreign_validator_intent_batch349() -> None:
    st = _state()

    with pytest.raises(Exception) as exc:
        apply_tx(
            st,
            _env(
                "ROLE_NODE_OPERATOR_ENROLL",
                {
                    "account_id": "@victim",
                    "validator_opt_in": True,
                    "node_pubkey": "victim-node-pub",
                    "validator_readiness_commitment": "sha256:readiness",
                },
                signer="@attacker",
            ),
        )

    assert "only_account_can_enroll_node_operator" in str(exc.value)
    victim = st["roles"]["node_operators"]["by_id"]["@victim"]
    assert "responsibilities" not in victim
    assert st["accounts"]["@attacker"]["nonce"] == 0


def test_role_juror_enroll_rejects_foreign_account_target_batch349() -> None:
    st = _state()

    with pytest.raises(Exception) as exc:
        apply_tx(
            st,
            _env(
                "ROLE_JUROR_ENROLL",
                {"account_id": "@victim"},
                signer="@attacker",
            ),
        )

    assert "only_account_can_enroll_juror" in str(exc.value)
    assert "@victim" not in st["roles"]["jurors"]["by_id"]
    assert st["accounts"]["@attacker"]["nonce"] == 0


def test_role_enrollment_self_targets_still_apply_batch349() -> None:
    st = _state()

    op_result = apply_tx(
        st,
        _env("ROLE_NODE_OPERATOR_ENROLL", {"account_id": "@attacker"}, signer="@attacker"),
    )
    assert op_result["applied"] == "ROLE_NODE_OPERATOR_ENROLL"
    assert st["roles"]["node_operators"]["by_id"]["@attacker"]["enrolled"] is True

    juror_result = apply_tx(
        st,
        _env("ROLE_JUROR_ENROLL", {"juror": "@attacker"}, signer="@attacker", nonce=2),
    )
    assert juror_result["applied"] == "ROLE_JUROR_ENROLL"
    assert st["roles"]["jurors"]["by_id"]["@attacker"]["enrolled"] is True
