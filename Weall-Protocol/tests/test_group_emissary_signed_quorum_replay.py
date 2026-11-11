"""Signed canonical admission and independent-process quorum replay rehearsal.

This fixture seeds pre-existing accounts and membership, signs election txs with
test ML-DSA keys, uses actual block-context admission and bounded rollback, and
compares independent interpreter state roots. It is NOT a BFT node/QC test.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.apply.groups import apply_groups
from weall.runtime.domain_apply import apply_tx_atomic_meta_bounded_rollback
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_contracts import load_default_tx_index
from weall.testing.sigtools import deterministic_mldsa_keypair

ROOT = Path(__file__).resolve().parents[1]
VOTERS = [f"@v{i:02d}" for i in range(6)]
CANDIDATES = VOTERS[:5]
CHAIN = "weall-testnet-v1"


def _signed(kind: str, signer: str, nonce: int, payload: dict) -> dict:
    _, private = deterministic_mldsa_keypair(label=signer)
    return sign_tx_envelope_dict(
        tx={
            "tx_type": kind,
            "signer": signer,
            "nonce": nonce,
            "payload": payload,
            "chain_id": CHAIN,
            "network_id": CHAIN,
        },
        privkey=private.private_bytes_raw().hex(),
    )


def _fixture() -> dict:
    accounts = {}
    for actor in ["@operator", *VOTERS]:
        pubkey, _ = deterministic_mldsa_keypair(label=actor)
        accounts[actor] = {
            "nonce": 0,
            "balance": 1_000_000,
            "poh_tier": 3 if actor == "@operator" else 2,
            "reputation": "10.000",
            "reputation_milli": 10_000,
            "banned": False,
            "locked": False,
            "keys": [
                {
                    "sig_profile": "pq-mldsa-v1",
                    "pubkeys": {"mldsa": pubkey},
                    "active": True,
                }
            ],
        }
    accounts["@v05"]["poh_tier"] = 1
    state = {
        "height": 100,
        "time": 1_000_000,
        "chain_id": CHAIN,
        "network_id": CHAIN,
        "params": {
            "chain_id": CHAIN,
            "system_signer": "SYSTEM",
            "group_emissary_quorum_activation_height": 101,
        },
        "accounts": accounts,
        "roles": {"groups_by_id": {}, "treasuries_by_id": {}},
        "social": {},
        "content": {},
        "groups": {},
        "notifications": {},
        "storage": {},
        "networking": {},
        "economics": {},
        "rewards": {},
        "treasury": {},
        "governance": {},
        "disputes": {},
        "protocol": {},
        "consensus": {},
        "system_queue": [],
    }
    # Group registration and membership are SEEDED, not signed lifecycle proof.
    apply_groups(
        state,
        TxEnvelope(
            tx_type="GROUP_CREATE",
            signer="@operator",
            nonce=0,
            payload={"group_id": "g:signed", "charter": "replay fixture"},
        ),
    )
    state["roles"]["groups_by_id"]["g:signed"]["members"] = {
        voter: {"joined_at_nonce": 1} for voter in VOTERS
    }
    return state


def _admit_and_execute(state: dict, signed: dict) -> dict:
    envelope = TxEnvelope.from_json(signed)
    verdict = admit_tx(
        envelope, state, canon=load_default_tx_index(), context="block"
    )
    assert verdict.ok, f"{envelope.tx_type}: {verdict}"
    applied = apply_tx_atomic_meta_bounded_rollback(state, envelope)
    assert isinstance(applied, dict)
    assert applied.get("applied") == envelope.tx_type
    return applied


def _run(turnout: int) -> dict:
    state = _fixture()
    group = state["roles"]["groups_by_id"]["g:signed"]
    original_signers = list(group["signers"])
    original_treasury = list(
        state["roles"]["treasuries_by_id"][group["treasury_id"]]["signers"]
    )
    _admit_and_execute(
        state,
        _signed(
            "GROUP_EMISSARY_ELECTION_CREATE",
            "@operator",
            1,
            {
                "group_id": "g:signed",
                "election_id": "e:signed",
                "seats": 5,
                "candidates": CANDIDATES,
                "start_height": 101,
                "end_height": 103,
            },
        ),
    )
    election = state["group_emissary_elections"]["e:signed"]
    assert election["voter_snapshot"] == CANDIDATES
    assert election["required_votes"] == 4
    for voter in CANDIDATES[:turnout]:
        _admit_and_execute(
            state,
            _signed(
                "GROUP_EMISSARY_BALLOT_CAST",
                voter,
                1,
                {"election_id": "e:signed", "ranking": CANDIDATES},
            ),
        )
    state["height"] = 102
    receipt = _admit_and_execute(
        state,
        _signed(
            "GROUP_EMISSARY_ELECTION_FINALIZE",
            "@operator",
            2,
            {"group_id": "g:signed", "election_id": "e:signed"},
        ),
    )
    group = state["roles"]["groups_by_id"]["g:signed"]
    treasury = state["roles"]["treasuries_by_id"][group["treasury_id"]]
    if turnout == 3:
        assert receipt["status"] == "no_decision"
        assert receipt["reason"] == "quorum_unmet"
        assert group["signers"] == original_signers
        assert treasury["signers"] == original_treasury
    else:
        assert receipt["status"] == "finalized"
        assert group["signers"] == receipt["winners"]
        assert treasury["signers"] == receipt["winners"]
    return {
        "turnout": turnout,
        "required": election["required_votes"],
        "status": receipt["status"],
        "winners": receipt.get("winners", []),
        "signed_block_admissions": turnout + 2,
        "state_root": str(compute_state_root(state)),
        "scope": "signed_block_admission_bounded_apply_not_BFT_finality",
    }


@pytest.mark.parametrize("turnout", [3, 4])
def test_signed_quorum_same_root_in_independent_interpreters(turnout: int) -> None:
    local = _run(turnout)
    external = []
    for seed in ("13", "91"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        run = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--replay", str(turnout)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
            env=environment,
        )
        external.append(json.loads(run.stdout.strip()))
    assert local == external[0] == external[1]


def test_mutated_signed_ballot_rejected_by_block_admission() -> None:
    state = _fixture()
    signed = _signed(
        "GROUP_EMISSARY_BALLOT_CAST",
        "@v00",
        1,
        {"election_id": "e:signed", "ranking": CANDIDATES},
    )
    signed["payload"]["ranking"] = list(reversed(CANDIDATES))
    verdict = admit_tx(
        TxEnvelope.from_json(signed),
        state,
        canon=load_default_tx_index(),
        context="block",
    )
    assert verdict.ok is False
    assert verdict.code == "bad_sig"


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--replay":
    print(json.dumps(_run(int(sys.argv[2])), sort_keys=True))
