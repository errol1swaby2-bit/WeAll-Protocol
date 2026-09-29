from __future__ import annotations

import pytest

from weall.runtime.apply.governance import apply_governance
from weall.runtime.apply.identity import apply_identity
from weall.runtime.errors import ApplyError
from weall.runtime.session_keys import session_record_for
from weall.runtime.tx_admission_types import TxEnvelope


def _env(
    tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        tx_id=f"p2:{tx_type}:{nonce}",
        system=system,
        parent="GOV_EXECUTE" if system else None,
    )


def _identity_state() -> dict:
    return {
        "height": 10,
        "time": 1000,
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "keys": {"by_id": {"k1": {"pubkey": "pk1", "revoked": False}}},
            }
        },
    }


def test_p2_sec003_session_policy_defaults_and_caps_ttl() -> None:
    state = _identity_state()
    state = apply_identity(
        state,
        _env("ACCOUNT_SECURITY_POLICY_SET", "@alice", 1, {"session_ttl_s": 120}),
    )
    state = apply_identity(
        state,
        _env("ACCOUNT_SESSION_KEY_ISSUE", "@alice", 2, {"session_key": "omitted"}),
    )
    assert (
        session_record_for(state["accounts"]["@alice"]["session_keys"], "omitted")["ttl_s"] == 120
    )

    state = apply_identity(
        state,
        _env("ACCOUNT_SESSION_KEY_ISSUE", "@alice", 3, {"session_key": "short", "ttl_s": 60}),
    )
    assert session_record_for(state["accounts"]["@alice"]["session_keys"], "short")["ttl_s"] == 60

    state = apply_identity(
        state,
        _env("ACCOUNT_SESSION_KEY_ISSUE", "@alice", 4, {"session_key": "capped", "ttl_s": 3600}),
    )
    assert session_record_for(state["accounts"]["@alice"]["session_keys"], "capped")["ttl_s"] == 120


def test_p2_sec003_rejects_misleading_or_retired_security_controls() -> None:
    state = _identity_state()
    with pytest.raises(ApplyError, match="mandatory_recovery_lock_cannot_be_disabled"):
        apply_identity(
            state,
            _env("ACCOUNT_SECURITY_POLICY_SET", "@alice", 1, {"lock_on_recovery_request": False}),
        )
    with pytest.raises(ApplyError, match="guardian_unlock_policy_retired"):
        apply_identity(
            state,
            _env(
                "ACCOUNT_SECURITY_POLICY_SET",
                "@alice",
                1,
                {"require_guardian_threshold_for_unlock": True},
            ),
        )
    with pytest.raises(ApplyError, match="session_ttl_policy_must_be_positive"):
        apply_identity(
            state, _env("ACCOUNT_SECURITY_POLICY_SET", "@alice", 1, {"session_ttl_s": 0})
        )


def _governance_state() -> dict:
    return {
        "height": 20,
        "params": {
            "poh": {"tier2_n_jurors": 5, "live_n_jurors": 5},
            "gov_action_allowlist": ["GOV_RULES_SET", "GOV_QUORUM_SET"],
        },
        "treasury": {"params": {"timelock_blocks": 2}},
        "accounts": {
            "alice": {"poh_tier": 2, "banned": False, "locked": False},
            "bob": {"poh_tier": 2, "banned": False, "locked": False},
        },
    }


def test_p2_gov003_rules_set_updates_operational_parameter_paths() -> None:
    state = _governance_state()
    apply_governance(
        state,
        _env(
            "GOV_RULES_SET",
            "SYSTEM",
            1,
            {
                "params": {"poh": {"tier2_n_jurors": 7}},
                "treasury": {"params": {"timelock_blocks": 9}},
            },
            system=True,
        ),
    )
    assert state["params"]["poh"]["tier2_n_jurors"] == 7
    assert state["params"]["poh"]["live_n_jurors"] == 5
    assert state["treasury"]["params"]["timelock_blocks"] == 9
    assert state["gov_config"]["rules"]["params"]["poh"]["tier2_n_jurors"] == 7


def test_p2_gov004_new_proposals_snapshot_governed_quorum_policy() -> None:
    state = _governance_state()
    apply_governance(
        state, _env("GOV_QUORUM_SET", "SYSTEM", 1, {"quorum_percent": 60}, system=True)
    )
    apply_governance(
        state, _env("GOV_PROPOSAL_CREATE", "alice", 1, {"proposal_id": "p:old", "rules": {}})
    )
    assert state["gov_proposals_by_id"]["p:old"]["rules"]["quorum_percent"] == 60

    apply_governance(
        state, _env("GOV_QUORUM_SET", "SYSTEM", 2, {"quorum_percent": 70}, system=True)
    )
    assert state["gov_proposals_by_id"]["p:old"]["rules"]["quorum_percent"] == 60

    apply_governance(
        state, _env("GOV_PROPOSAL_CREATE", "alice", 2, {"proposal_id": "p:new", "rules": {}})
    )
    assert state["gov_proposals_by_id"]["p:new"]["rules"]["quorum_percent"] == 70

    apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "alice",
            3,
            {"proposal_id": "p:explicit", "rules": {"quorum_percent": 40}},
        ),
    )
    assert state["gov_proposals_by_id"]["p:explicit"]["rules"]["quorum_percent"] == 40
