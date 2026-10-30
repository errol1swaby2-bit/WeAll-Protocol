"""Issue #63: reputation replay representation and adjacent receipt identity probes.

Focused, in-memory domain apply only. No signed SYSTEM provenance, persistence,
canonical executor replay, BFT cross-node execution, or release authorization.
"""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from weall.runtime.apply.reputation import (
    ReputationApplyError,
    apply_reputation,
    apply_reputation_delta_system,
)
from weall.runtime.tx_admission import TxEnvelope


def _state(*, legacy: bool = False) -> dict:
    acct = {
        "nonce": 7,
        "poh_tier": 2,
        "banned": False,
        "locked": False,
        "reputation": 0.0 if legacy else "0",
        "reputation_milli": 0,
        "balance": 93,
        "keys": [],
    }
    return {"height": 12, "accounts": {"@alice": acct}}


def _tx(kind: str, payload: dict, *, nonce: int = 1) -> TxEnvelope:
    return TxEnvelope(
        tx_type=kind,
        signer="SYSTEM",
        nonce=nonce,
        payload=payload,
        system=True,
        parent="issue63:synthetic-parent",
        sig="not-validated-by-domain-handler",
    )


def _bytes(state: dict) -> bytes:
    """A JSON byte-equivalence probe, NOT the production consensus hash."""
    return json.dumps(
        state, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


@pytest.mark.parametrize("delta_milli", [-100000, -1250, 0, 1250, 100000])
def test_first_delta_writes_canonical_account_text_and_duplicate_is_byte_noop(
    delta_milli: int,
) -> None:
    state = _state()
    payload = {
        "account_id": "@alice",
        "delta_id": f"issue63:delta:{delta_milli}",
        "delta_milli": delta_milli,
        "reason": "focused-representation-fixture",
    }
    first = apply_reputation(state, _tx("REPUTATION_DELTA_APPLY", payload))
    assert first is not None and first["deduped"] is False
    account = state["accounts"]["@alice"]
    assert isinstance(account["reputation"], str)
    assert account["reputation_milli"] == delta_milli
    before = copy.deepcopy(state)
    before_bytes = _bytes(state)
    before_digest = hashlib.sha256(before_bytes).hexdigest()

    repeated = apply_reputation(state, _tx("REPUTATION_DELTA_APPLY", payload, nonce=2))
    assert repeated is not None and repeated["deduped"] is True
    assert state == before
    assert _bytes(state) == before_bytes
    assert hashlib.sha256(_bytes(state)).hexdigest() == before_digest
    assert len(state["reputation"]["deltas"]) == 1


def test_duplicate_legacy_float_representation_is_a_strict_noop() -> None:
    state = _state(legacy=True)
    state["accounts"]["@alice"]["reputation"] = -100.0
    state["accounts"]["@alice"]["reputation_milli"] = -100000
    state["accounts"]["@alice"]["banned"] = True
    state["reputation"] = {
        "deltas": [
            {
                "delta_id": "issue63:historical",
                "account_id": "@alice",
                "delta_milli": -100000,
                "reason": "legacy",
            }
        ],
        "threshold_crossings": [],
        "role_eligibility": {},
        "bans": {},
    }
    before = _bytes(state)
    result = apply_reputation(
        state,
        _tx(
            "REPUTATION_DELTA_APPLY",
            {"account_id": "@alice", "delta_id": "issue63:historical", "delta_milli": -100000},
            nonce=9,
        ),
    )
    assert result is not None and result["deduped"] is True
    assert type(state["accounts"]["@alice"]["reputation"]) is float
    assert _bytes(state) == before


def test_exported_system_delta_replay_keeps_canonical_account_representation() -> None:
    state = _state()
    evidence = {
        "delta_id": "issue63:system:one",
        "source": "issue63:synthetic-test",
    }
    first = apply_reputation_delta_system(
        state,
        account_id="@alice",
        delta=-1.25,
        reason="synthetic-system-delta",
        evidence=evidence,
        at_nonce=3,
    )
    assert first["deduped"] is False
    assert state["accounts"]["@alice"]["reputation"] == "-1.25"
    assert state["accounts"]["@alice"]["reputation_milli"] == -1250
    before = _bytes(state)
    result = apply_reputation_delta_system(
        state,
        account_id="@alice",
        delta=-1.25,
        reason="synthetic-system-delta",
        evidence=evidence,
        at_nonce=4,
    )
    assert result["deduped"] is True
    assert _bytes(state) == before


def test_duplicate_does_not_materialize_missing_target_account() -> None:
    state = _state()
    state["reputation"] = {
        "deltas": [
            {
                "delta_id": "issue63:orphan",
                "account_id": "@missing",
                "delta_milli": -1000,
            }
        ],
        "threshold_crossings": [],
        "role_eligibility": {},
        "bans": {},
    }
    before = _bytes(state)
    result = apply_reputation(
        state,
        _tx(
            "REPUTATION_DELTA_APPLY",
            {"account_id": "@missing", "delta_id": "issue63:orphan", "delta_milli": -1000},
        ),
    )
    assert result is not None and result["deduped"] is True
    assert "@missing" not in state["accounts"]
    assert _bytes(state) == before


def test_same_delta_id_must_not_silently_accept_different_target() -> None:
    state = _state()
    payload = {
        "account_id": "@alice",
        "delta_id": "issue63:collision",
        "delta_milli": -1000,
        "reason": "first",
    }
    apply_reputation(state, _tx("REPUTATION_DELTA_APPLY", payload))
    before = _bytes(state)
    with pytest.raises(ReputationApplyError):
        apply_reputation(
            state,
            _tx(
                "REPUTATION_DELTA_APPLY",
                {**payload, "account_id": "@bob"},
                nonce=2,
            ),
        )
    assert _bytes(state) == before


def test_duplicate_ban_receipt_cannot_rewrite_audit_reason() -> None:
    state = _state()
    payload = {"account_id": "@alice", "reason": "first"}
    apply_reputation(state, _tx("ACCOUNT_BAN", payload, nonce=5))
    before = _bytes(state)
    with pytest.raises(ReputationApplyError):
        apply_reputation(
            state,
            _tx("ACCOUNT_BAN", {**payload, "reason": "rewritten"}, nonce=5),
        )
    assert _bytes(state) == before


def test_rejected_missing_delta_does_not_mutate_any_state() -> None:
    state = _state()
    before = _bytes(state)
    with pytest.raises(ReputationApplyError):
        apply_reputation(
            state,
            _tx(
                "REPUTATION_DELTA_APPLY",
                {"account_id": "@alice", "delta_id": "issue63:missing-delta"},
            ),
        )
    assert _bytes(state) == before


@pytest.mark.parametrize(
    "changed",
    [
        {"delta_milli": -2000},
        {"reason": "tampered"},
        {"source_object_id": "another-object"},
    ],
)
def test_duplicate_delta_id_with_conflicting_effect_rejects_atomically(
    changed: dict,
) -> None:
    state = _state()
    first = {
        "account_id": "@alice",
        "delta_id": "issue65:effect",
        "delta_milli": -1000,
        "reason": "first",
        "source_object_id": "original-object",
    }
    apply_reputation(state, _tx("REPUTATION_DELTA_APPLY", first, nonce=1))
    before = _bytes(state)
    with pytest.raises(ReputationApplyError) as error:
        apply_reputation(
            state,
            _tx("REPUTATION_DELTA_APPLY", {**first, **changed}, nonce=2),
        )
    assert error.value.reason == "duplicate_delta_id_conflict"
    assert _bytes(state) == before


def test_duplicate_ban_same_receipt_is_full_noop() -> None:
    state = _state()
    receipt = {"account_id": "@alice", "reason": "confirmed"}
    result = apply_reputation(state, _tx("ACCOUNT_BAN", receipt, nonce=13))
    assert result is not None and result["deduped"] is False
    before = _bytes(state)
    repeated = apply_reputation(state, _tx("ACCOUNT_BAN", receipt, nonce=13))
    assert repeated is not None and repeated["deduped"] is True
    assert _bytes(state) == before


def test_duplicate_ban_receipt_reason_conflict_fails_closed() -> None:
    state = _state()
    apply_reputation(
        state, _tx("ACCOUNT_BAN", {"account_id": "@alice", "reason": "first"}, nonce=14)
    )
    before = _bytes(state)
    with pytest.raises(ReputationApplyError) as error:
        apply_reputation(
            state, _tx("ACCOUNT_BAN", {"account_id": "@alice", "reason": "second"}, nonce=14)
        )
    assert error.value.reason == "duplicate_ban_receipt_conflict"
    assert _bytes(state) == before


def test_exported_system_duplicate_id_collision_is_rejected_without_mutation() -> None:
    state = _state()
    evidence = {"delta_id": "issue65:system:collision", "source": "consensus"}
    apply_reputation_delta_system(
        state,
        account_id="@alice",
        delta=-1.0,
        reason="slash",
        evidence=evidence,
        at_nonce=11,
    )
    before = _bytes(state)
    with pytest.raises(ReputationApplyError) as error:
        apply_reputation_delta_system(
            state,
            account_id="@bob",
            delta=-1.0,
            reason="slash",
            evidence=evidence,
            at_nonce=12,
        )
    assert error.value.reason == "duplicate_delta_id_conflict"
    assert _bytes(state) == before


def test_rejected_account_ban_without_target_does_not_initialize_root() -> None:
    state = _state()
    before = _bytes(state)
    with pytest.raises(ReputationApplyError):
        apply_reputation(
            state,
            _tx("ACCOUNT_BAN", {"reason": "missing-target"}, nonce=2),
        )
    assert _bytes(state) == before
