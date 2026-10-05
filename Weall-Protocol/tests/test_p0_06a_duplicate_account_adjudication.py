from __future__ import annotations

import pytest

from weall.runtime.apply.poh import _grant_active_poh_tier
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError


def _env(
    tx_type: str,
    payload: dict[str, object],
    *,
    signer: str,
    nonce: int,
    system: bool = False,
    parent: str | None = None,
) -> dict[str, object]:
    env: dict[str, object] = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "sig": "",
        "payload": payload,
        "system": system,
    }
    if parent is not None:
        env["parent"] = parent
    return env


def _state() -> dict[str, object]:
    accounts = {
        "primary": {"nonce": 0, "poh_tier": 2, "poh_status": "active"},
        "duplicate": {"nonce": 0, "poh_tier": 2, "poh_status": "active"},
        "challenger": {"nonce": 0, "poh_tier": 2, "poh_status": "active"},
    }
    return {
        "state_version": 1,
        "height": 100,
        "accounts": accounts,
        "poh": {
            "account_status": {
                account_id: {
                    "account_id": account_id,
                    "poh_tier": 2,
                    "status": "active",
                    "verified_at_height": 1,
                    "expires_at_height": 0,
                }
                for account_id in accounts
            }
        },
    }


def _open_duplicate_challenge(state: dict[str, object]) -> str:
    opened = apply_tx(
        state,
        _env(
            "POH_CHALLENGE_OPEN",
            {
                "account_id": "duplicate",
                "reference_account_id": "primary",
                "reason": "duplicate-human-suspected",
            },
            signer="challenger",
            nonce=1,
        ),
    )
    return str(opened["challenge_id"])


def _resolve(
    state: dict[str, object], challenge_id: str, resolution: str, *, note: str = ""
) -> dict[str, object]:
    payload: dict[str, object] = {"challenge_id": challenge_id, "resolution": resolution}
    if note:
        payload["note"] = note
    return apply_tx(
        state,
        _env(
            "POH_CHALLENGE_RESOLVE",
            payload,
            signer="SYSTEM",
            nonce=2,
            system=True,
            parent="poh:duplicate-identity-adjudication",
        ),
    )


def test_duplicate_challenge_binds_both_accounts_and_upheld_resolution_blocks_reaward() -> None:
    state = _state()
    challenge_id = _open_duplicate_challenge(state)

    challenge = state["poh"]["challenges"][challenge_id]  # type: ignore[index]
    assert challenge["account_id"] == "duplicate"
    assert challenge["reference_account_id"] == "primary"
    assert challenge["challenge_kind"] == "duplicate_identity"

    resolved = _resolve(state, challenge_id, "upheld", note="same human confirmed")
    assert resolved["consequence"]["type"] == "poh_status_revoked"  # type: ignore[index]
    assert state["accounts"]["duplicate"]["poh_tier"] == 0  # type: ignore[index]
    assert state["accounts"]["duplicate"]["poh_status"] == "revoked"  # type: ignore[index]

    duplicate_root = state["poh"]["duplicate_identity_adjudications"]  # type: ignore[index]
    relation = duplicate_root["by_duplicate_account"]["duplicate"]
    assert relation["status"] == "confirmed_duplicate"
    assert relation["reference_account_id"] == "primary"
    assert relation["challenge_id"] == challenge_id

    with pytest.raises(ApplyError) as excinfo:
        _grant_active_poh_tier(state, account_id="duplicate", tier=2)
    assert excinfo.value.reason == "duplicate_identity_authority_blocked"


def test_duplicate_challenge_dismissal_creates_no_duplicate_identity_relation() -> None:
    state = _state()
    challenge_id = _open_duplicate_challenge(state)

    resolved = _resolve(state, challenge_id, "dismissed")
    assert resolved["consequence"] == {"type": "none", "applied": False}
    assert state["accounts"]["duplicate"]["poh_tier"] == 2  # type: ignore[index]
    duplicate_root = state["poh"].get("duplicate_identity_adjudications", {})  # type: ignore[index]
    assert duplicate_root.get("by_duplicate_account", {}).get("duplicate") is None


def test_duplicate_challenge_requires_distinct_registered_reference_account() -> None:
    state = _state()

    with pytest.raises((ApplyError, ValueError)):
        apply_tx(
            state,
            _env(
                "POH_CHALLENGE_OPEN",
                {
                    "account_id": "duplicate",
                    "reference_account_id": "duplicate",
                    "reason": "duplicate-human-suspected",
                },
                signer="challenger",
                nonce=1,
            ),
        )

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _env(
                "POH_CHALLENGE_OPEN",
                {
                    "account_id": "duplicate",
                    "reference_account_id": "missing",
                    "reason": "duplicate-human-suspected",
                },
                signer="challenger",
                nonce=2,
            ),
        )
    assert excinfo.value.reason == "reference_account_not_registered"


def test_overturn_removes_duplicate_authority_block_but_does_not_restore_tier() -> None:
    state = _state()
    challenge_id = _open_duplicate_challenge(state)
    _resolve(state, challenge_id, "upheld")

    overturned = _resolve(
        state,
        challenge_id,
        "dismissed",
        note="appeal accepted; duplicate determination was a false positive",
    )
    assert overturned["consequence"]["type"] == "duplicate_identity_overturned"  # type: ignore[index]
    assert state["accounts"]["duplicate"]["poh_tier"] == 0  # type: ignore[index]
    relation = state["poh"]["duplicate_identity_adjudications"]["by_duplicate_account"][  # type: ignore[index]
        "duplicate"
    ]
    assert relation["status"] == "overturned"

    _grant_active_poh_tier(state, account_id="duplicate", tier=2)
    assert state["accounts"]["duplicate"]["poh_tier"] == 2  # type: ignore[index]
    assert state["accounts"]["duplicate"]["poh_status"] == "active"  # type: ignore[index]


def test_confirmed_duplicate_cannot_be_used_as_reference_for_another_duplicate() -> None:
    state = _state()
    state["accounts"]["third"] = {"nonce": 0, "poh_tier": 2, "poh_status": "active"}  # type: ignore[index]
    challenge_id = _open_duplicate_challenge(state)
    _resolve(state, challenge_id, "upheld")

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _env(
                "POH_CHALLENGE_OPEN",
                {
                    "account_id": "third",
                    "reference_account_id": "duplicate",
                    "reason": "duplicate-human-suspected",
                },
                signer="challenger",
                nonce=3,
            ),
        )
    assert excinfo.value.reason == "reference_account_is_confirmed_duplicate"


def test_duplicate_challenge_requires_verified_human_challenger() -> None:
    state = _state()
    state["accounts"]["unverified"] = {"nonce": 0, "poh_tier": 0, "poh_status": "none"}  # type: ignore[index]

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _env(
                "POH_CHALLENGE_OPEN",
                {
                    "account_id": "duplicate",
                    "reference_account_id": "primary",
                    "reason": "duplicate-human-suspected",
                },
                signer="unverified",
                nonce=1,
            ),
        )
    assert excinfo.value.reason == "duplicate_challenge_requires_verified_human"


def test_duplicate_challenge_open_is_non_punitive_and_entropy_deferred() -> None:
    state = _state()
    challenge_id = _open_duplicate_challenge(state)

    challenge = state["poh"]["challenges"][challenge_id]  # type: ignore[index]
    assert challenge["adjudication_status"] == "pending_unpredictable_entropy"
    assert challenge["reviewer_selection_status"] == "deferred_pending_a20_entropy"
    assert challenge["authority_effect"] == "none_pending_adjudication"
    assert state["accounts"]["duplicate"]["poh_tier"] == 2  # type: ignore[index]
    assert state["accounts"]["duplicate"]["poh_status"] == "active"  # type: ignore[index]


def test_duplicate_pair_allows_only_one_active_direction_and_reopens_after_dismissal() -> None:
    state = _state()
    challenge_id = _open_duplicate_challenge(state)

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _env(
                "POH_CHALLENGE_OPEN",
                {
                    "account_id": "primary",
                    "reference_account_id": "duplicate",
                    "reason": "same-pair-reversed",
                },
                signer="challenger",
                nonce=2,
            ),
        )
    assert excinfo.value.reason == "duplicate_identity_challenge_already_open"

    _resolve(state, challenge_id, "dismissed")
    reopened = apply_tx(
        state,
        _env(
            "POH_CHALLENGE_OPEN",
            {
                "account_id": "primary",
                "reference_account_id": "duplicate",
                "reason": "new-evidence-after-dismissal",
            },
            signer="challenger",
            nonce=3,
        ),
    )
    assert reopened["challenge_id"] != challenge_id


def test_duplicate_challenge_resolution_is_apply_layer_system_only() -> None:
    state = _state()
    challenge_id = _open_duplicate_challenge(state)

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _env(
                "POH_CHALLENGE_RESOLVE",
                {"challenge_id": challenge_id, "resolution": "upheld"},
                signer="challenger",
                nonce=2,
                system=False,
                parent="poh:duplicate-identity-adjudication",
            ),
        )
    assert excinfo.value.reason == "system_only"
