from __future__ import annotations

import pytest

from weall.runtime.apply.governance import ApplyError
from weall.runtime.domain_apply import apply_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _mk_state() -> dict:
    return {
        "height": 0,
        "time": 0,
        "params": {"system_signer": "SYSTEM", "economics_enabled": True, "economic_unlock_time": 0},
        "accounts": {"alice": {"nonce": 0, "poh_tier": 3}, "bob": {"nonce": 0, "poh_tier": 3}},
    }


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system)


def test_gov_proposal_withdraw_rejects_after_close_batch109() -> None:
    st = _mk_state()
    apply_tx(st, _env("GOV_PROPOSAL_CREATE", "alice", 1, {"proposal_id": "p-close", "title": "t"}))
    apply_tx(st, _env("GOV_STAGE_SET", "SYSTEM", 1, {"proposal_id": "p-close", "stage": "voting", "_due_height": 1}, system=True))
    apply_tx(st, _env("GOV_VOTING_CLOSE", "SYSTEM", 1, {"proposal_id": "p-close", "_due_height": 1}, system=True))

    with pytest.raises(ApplyError) as exc:
        apply_tx(st, _env("GOV_PROPOSAL_WITHDRAW", "alice", 2, {"proposal_id": "p-close"}))
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "proposal_not_withdrawable"


def test_gov_vote_revoke_rejects_after_finalize_batch109() -> None:
    st = _mk_state()
    apply_tx(st, _env("GOV_PROPOSAL_CREATE", "alice", 1, {"proposal_id": "p-fin", "title": "t"}))
    apply_tx(st, _env("GOV_STAGE_SET", "SYSTEM", 1, {"proposal_id": "p-fin", "stage": "voting", "_due_height": 1}, system=True))
    apply_tx(st, _env("GOV_VOTE_CAST", "bob", 1, {"proposal_id": "p-fin", "vote": "yes"}))
    apply_tx(st, _env("GOV_PROPOSAL_FINALIZE", "SYSTEM", 1, {"proposal_id": "p-fin", "_due_height": 1}, system=True))

    with pytest.raises(ApplyError) as exc:
        apply_tx(st, _env("GOV_VOTE_REVOKE", "bob", 2, {"proposal_id": "p-fin"}))
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "proposal_vote_state_frozen"


def test_gov_finalize_rejects_withdrawn_proposal_batch109() -> None:
    st = _mk_state()
    apply_tx(st, _env("GOV_PROPOSAL_CREATE", "alice", 1, {"proposal_id": "p-wd", "title": "t"}))
    apply_tx(st, _env("GOV_PROPOSAL_WITHDRAW", "alice", 2, {"proposal_id": "p-wd"}))

    with pytest.raises(ApplyError) as exc:
        apply_tx(st, _env("GOV_PROPOSAL_FINALIZE", "SYSTEM", 1, {"proposal_id": "p-wd", "_due_height": 1}, system=True))
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "withdrawn_proposal_cannot_finalize"
