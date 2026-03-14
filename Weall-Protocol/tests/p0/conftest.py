from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError

Json = Dict[str, Any]


def _sorted_json(obj: Any) -> str:
    # Canonical stable string for deterministic equality checks.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def assert_state_equal(a: Json, b: Json) -> None:
    assert _sorted_json(a) == _sorted_json(b)


def assert_state_not_equal(a: Json, b: Json) -> None:
    assert _sorted_json(a) != _sorted_json(b)


def env(
    tx_type: str,
    payload: Optional[Json] = None,
    *,
    signer: str = "alice",
    nonce: int = 1,
    system: bool = False,
    parent: Optional[str] = None,
) -> Json:
    e: Json = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "sig": "",
        "payload": payload or {},
        "system": bool(system),
    }
    if parent is not None:
        e["parent"] = parent
    return e


@dataclass(frozen=True)
class TxF:
    """Tiny tx factory for P0 tests (keep it small, grow as needed)."""

    def balance_transfer(self, frm: str, to: str, amount: int, *, nonce: int) -> Json:
        return env(
            "BALANCE_TRANSFER",
            {"from": frm, "to": to, "amount": amount},
            signer=frm,
            nonce=nonce,
            system=False,
        )

    def gov_proposal_create(self, proposer: str, proposal_id: str, *, nonce: int) -> Json:
        # Keep payload minimal; governance applier tolerates missing fields.
        return env(
            "GOV_PROPOSAL_CREATE",
            {"proposal_id": proposal_id, "title": "p0", "body": "p0", "kind": "generic"},
            signer=proposer,
            nonce=nonce,
            system=False,
        )

    def gov_vote_cast(self, voter: str, proposal_id: str, vote: str, *, nonce: int) -> Json:
        return env(
            "GOV_VOTE_CAST",
            {"proposal_id": proposal_id, "vote": vote},
            signer=voter,
            nonce=nonce,
            system=False,
        )

    def gov_voting_close(self, proposal_id: str, *, nonce: int) -> Json:
        # system-only per canon enforcement (origin=SYSTEM / system_only)
        return env(
            "GOV_VOTING_CLOSE",
            {"proposal_id": proposal_id},
            signer="SYSTEM",
            nonce=nonce,
            system=True,
            parent="txid:gov_block",
        )

    def gov_tally_publish(self, proposal_id: str, *, nonce: int, tally: Optional[Json] = None) -> Json:
        return env(
            "GOV_TALLY_PUBLISH",
            {"proposal_id": proposal_id, "tally": tally or {"yes": 1, "no": 0}},
            signer="SYSTEM",
            nonce=nonce,
            system=True,
            parent="txid:gov_block",
        )


@pytest.fixture()
def txf() -> TxF:
    return TxF()


@pytest.fixture()
def base_state() -> Json:
    """
    Minimal deterministic state baseline.

    IMPORTANT:
    - economics are time-locked unless state['time'] and unlock/enable flags permit.
    - For P0 determinism harness we enable economics in a deterministic way so that
      BALANCE_TRANSFER is usable as a stable state mutation.
    """
    st: Json = {}

    # Enable economics deterministically:
    # - unlock time is 0
    # - economics_enabled true
    # - current time > 0
    st["params"] = {
        "economic_unlock_time": 0,
        "economics_enabled": True,
        # also set system signer so apply-time canon checks can pass
        "system_signer": "SYSTEM",
    }
    st["time"] = 1

    # seed accounts used in tests
    st["accounts"] = {
        "alice": {"balance": 1000, "nonce": 0, "poh_tier": 3},
        "bob": {"balance": 500, "nonce": 0, "poh_tier": 3},
        "carol": {"balance": 0, "nonce": 0, "poh_tier": 3},
    }
    return st


def apply_ok(state: Json, envelope: Json) -> Json:
    out = apply_tx(state, envelope)
    assert isinstance(out, dict)
    assert out.get("applied") == str(envelope["tx_type"]).strip().upper()
    return out


def apply_err(state: Json, envelope: Json) -> ApplyError:
    with pytest.raises(ApplyError) as ei:
        apply_tx(state, envelope)
    return ei.value


def clone_state(state: Json) -> Json:
    return copy.deepcopy(state)
