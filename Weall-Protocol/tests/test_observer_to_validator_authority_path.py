from __future__ import annotations

from types import SimpleNamespace

from weall.runtime.bft_hotstuff import BFT_MIN_VALIDATORS
from weall.runtime.block_admission import _get_active_validators_from_state
from weall.runtime.domain_apply import apply_tx
from weall.runtime.executor import WeAllExecutor
from weall.runtime.poh.state import effective_poh_tier
from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.validator_readiness_runner import build_validator_readiness_receipt


def _env(
    tx_type: str,
    payload: dict,
    *,
    signer: str = "@observer",
    nonce: int = 1,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    if system and not parent:
        parent = f"p:{max(0, int(nonce) - 1)}"
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent=parent,
        system=system,
    )


def _state() -> dict:
    accounts = {
        "j1": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 5000},
        "j2": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 5000},
        "j3": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 5000},
        "live-j1": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 5000},
    }
    return {
        "chain_id": "weall-prod-test",
        "height": 10,
        "tip": "d" * 64,
        "accounts": accounts,
        "poh": {},
        "roles": {},
        "consensus": {"validator_set": {"active_set": [], "epoch": 0, "set_hash": ""}},
        "params": {
            "validator_candidate_lifecycle_gate_enabled": True,
            "validator_candidate_node_id_must_match_node_pubkey": True,
            "poh": {
                "async_n_jurors": 3,
                "async_min_reviews": 3,
                "async_approval_threshold": 2,
                "async_rejection_threshold": 2,
                "async_expiry_window_blocks": 100,
                "live_min_rep_milli": 0,
                "live_pass_threshold_num": 2,
                "live_pass_threshold_den": 3,
            },
        },
    }


def _async_tier1(st: dict) -> None:
    case_id = "async:@observer"
    assert apply_tx(
        st,
        _env(
            "POH_ASYNC_REQUEST_OPEN",
            {"account_id": "@observer", "case_id": case_id, "challenge_id": "prompt:observer"},
            nonce=5,
        ),
    )["applied"] == "POH_ASYNC_REQUEST_OPEN"
    assert apply_tx(
        st,
        _env(
            "POH_ASYNC_EVIDENCE_DECLARE",
            {
                "case_id": case_id,
                "evidence_id": "evi:observer",
                "evidence_commitment": "commit:evidence:observer",
                "response_commitment": "commit:response:observer",
            },
            nonce=6,
        ),
    )["applied"] == "POH_ASYNC_EVIDENCE_DECLARE"
    assert apply_tx(
        st,
        _env(
            "POH_ASYNC_EVIDENCE_BIND",
            {"case_id": case_id, "evidence_id": "evi:observer", "target_id": case_id},
            nonce=7,
        ),
    )["applied"] == "POH_ASYNC_EVIDENCE_BIND"
    apply_tx(
        st,
        _env(
            "POH_ASYNC_JUROR_ASSIGN",
            {"case_id": case_id, "jurors": ["j1", "j2", "j3"]},
            signer="SYSTEM",
            nonce=1,
            system=True,
            parent="POH_ASYNC_REQUEST_OPEN",
        ),
    )
    for juror in ("j1", "j2", "j3"):
        apply_tx(st, _env("POH_ASYNC_JUROR_ACCEPT", {"case_id": case_id}, signer=juror, nonce=1))
    for juror, verdict in (("j1", "approve"), ("j2", "approve"), ("j3", "reject")):
        apply_tx(
            st,
            _env(
                "POH_ASYNC_REVIEW_SUBMIT",
                {"case_id": case_id, "verdict": verdict, "review_commitment": f"commit:{juror}"},
                signer=juror,
                nonce=2,
            ),
        )
    final = apply_tx(
        st,
        _env("POH_ASYNC_FINALIZE", {"case_id": case_id}, signer="SYSTEM", nonce=2, system=True, parent="POH_ASYNC_REVIEW_SUBMIT"),
    )
    assert final["tier_awarded"] == 1
    assert effective_poh_tier(st, "@observer") == 1


def _live_tier2(st: dict) -> None:
    opened = apply_tx(
        st,
        _env(
            "POH_LIVE_REQUEST_OPEN",
            {
                "account_id": "@observer",
                "session_commitment": "sc:observer",
                "room_commitment": "room:observer",
                "prompt_commitment": "prompt:observer",
            },
            nonce=8,
        ),
    )
    assert opened["applied"] == "POH_LIVE_REQUEST_OPEN"
    case_id = str(opened["case_id"])
    apply_tx(
        st,
        _env(
            "POH_LIVE_SESSION_INIT",
            {"case_id": case_id, "account_id": "@observer", "session_commitment": "sc:observer", "ts_ms": 1},
            signer="SYSTEM",
            nonce=3,
            system=True,
            parent="POH_LIVE_REQUEST_OPEN",
        ),
    )
    apply_tx(
        st,
        _env(
            "POH_LIVE_JUROR_ASSIGN",
            {"case_id": case_id, "jurors": ["live-j1"]},
            signer="SYSTEM",
            nonce=4,
            system=True,
            parent="POH_LIVE_SESSION_INIT",
        ),
    )
    apply_tx(st, _env("POH_LIVE_JUROR_ACCEPT", {"case_id": case_id, "ts_ms": 2}, signer="live-j1", nonce=1))
    apply_tx(
        st,
        _env(
            "POH_LIVE_ATTENDANCE_MARK",
            {"case_id": case_id, "juror_id": "live-j1", "attended": True, "session_commitment": "sc:observer", "ts_ms": 3},
            signer="live-j1",
            nonce=2,
        ),
    )
    apply_tx(
        st,
        _env(
            "POH_LIVE_VERDICT_SUBMIT",
            {"case_id": case_id, "verdict": "pass", "session_commitment": "sc:observer", "ts_ms": 4},
            signer="live-j1",
            nonce=3,
        ),
    )
    final = apply_tx(
        st,
        _env("POH_LIVE_FINALIZE", {"case_id": case_id, "ts_ms": 5}, signer="SYSTEM", nonce=5, system=True, parent="POH_LIVE_VERDICT_SUBMIT"),
    )
    assert final["tier_awarded"] == 2
    assert int(st["accounts"]["@observer"]["poh_tier"]) == 2


def test_observer_account_progresses_to_validator_eligible_but_not_consensus_active_until_validator_set_update() -> None:
    st = _state()
    node_pubkey = "node-pub-observer"
    bft_pubkey = "bft-pub-observer"

    apply_tx(st, _env("ACCOUNT_REGISTER", {"pubkey": "account-pub"}, nonce=1))
    assert "@observer" in st["accounts"]
    assert int(st["accounts"]["@observer"]["poh_tier"]) == 0
    apply_tx(
        st,
        _env(
            "ACCOUNT_DEVICE_REGISTER",
            {"device_id": "node:@observer", "device_type": "node", "label": "observer node", "pubkey": node_pubkey},
            nonce=2,
        ),
    )
    assert st["accounts"]["@observer"]["devices"]["by_id"]["node:@observer"]["pubkey"] == node_pubkey
    assert apply_tx(
        st,
        _env(
            "PEER_ADVERTISE",
            {"peer_id": "node:@observer", "device_id": "node:@observer", "node_pubkey": node_pubkey, "endpoint": "https://observer.example"},
            nonce=3,
        ),
    )["applied"] == "PEER_ADVERTISE"
    assert apply_tx(st, _env("PEER_REQUEST_CONNECT", {"peer_id": "genesis", "endpoint": "https://genesis.example"}, nonce=4))["applied"] == "PEER_REQUEST_CONNECT"

    _async_tier1(st)
    _live_tier2(st)

    assert apply_tx(st, _env("ROLE_NODE_OPERATOR_ENROLL", {"account_id": "@observer"}, nonce=9))["applied"] == "ROLE_NODE_OPERATOR_ENROLL"
    assert apply_tx(
        st,
        _env("ROLE_NODE_OPERATOR_ACTIVATE", {"account_id": "@observer"}, signer="SYSTEM", nonce=6, system=True, parent="ROLE_NODE_OPERATOR_ENROLL"),
    )["applied"] == "ROLE_NODE_OPERATOR_ACTIVATE"
    assert apply_tx(
        st,
        _env(
            "NODE_OPERATOR_VALIDATOR_OPT_IN",
            {"account_id": "@observer", "node_pubkey": node_pubkey, "reputation_required_milli": 0},
            nonce=10,
        ),
    )["applied"] == "NODE_OPERATOR_VALIDATOR_OPT_IN"

    receipt = build_validator_readiness_receipt(
        account_id="@observer",
        node_pubkey=node_pubkey,
        bft_pubkey=bft_pubkey,
        chain_id="weall-prod-test",
        schema_version="1",
        protocol_version="1.25.0",
        manifest_hash="manifest-hash",
        tx_index_hash="tx-index-hash",
        runtime_profile_hash="profile-hash",
        readiness_expires_height=1000,
    )
    receipt["readiness_status"] = "verified"
    assert apply_tx(st, _env("VALIDATOR_READINESS_VERIFY", receipt, signer="SYSTEM", nonce=7, system=True, parent="NODE_OPERATOR_VALIDATOR_OPT_IN"))["verified"] is True
    assert apply_tx(
        st,
        _env(
            "ROLE_VALIDATOR_ACTIVATE",
            {"account_id": "@observer", "node_pubkey": node_pubkey, "reputation_required_milli": 0},
            signer="SYSTEM",
            nonce=8,
            system=True,
            parent="VALIDATOR_READINESS_VERIFY",
        ),
    )["applied"] == "ROLE_VALIDATOR_ACTIVATE"

    # Role activation alone is not consensus-set authority when an explicit consensus validator_set exists.
    assert st["roles"]["validators"]["active_set"] == ["@observer"]
    assert _get_active_validators_from_state(st) == []
    assert WeAllExecutor._active_validators(SimpleNamespace(state=st)) == []

    assert apply_tx(
        st,
        _env(
            "VALIDATOR_CANDIDATE_REGISTER",
            {"node_id": node_pubkey, "pubkey": bft_pubkey, "endpoints": ["https://observer.example"]},
            nonce=11,
        ),
    )["applied"] == "VALIDATOR_CANDIDATE_REGISTER"
    approved = apply_tx(
        st,
        _env("VALIDATOR_CANDIDATE_APPROVE", {"account": "@observer", "activate_at_epoch": 1}, signer="SYSTEM", nonce=9, system=True, parent="gov:approve-observer"),
    )
    assert approved["applied"] == "VALIDATOR_CANDIDATE_APPROVE"
    assert st["consensus"]["validator_set"]["pending"]["active_set"] == ["@observer"]

    opened = apply_tx(st, _env("EPOCH_OPEN", {"epoch": 1}, signer="SYSTEM", nonce=10, system=True, parent="epoch:open:1"))
    assert opened["validator_set_activated"]["active_set"] == ["@observer"]
    assert _get_active_validators_from_state(st) == ["@observer"]
    assert WeAllExecutor._active_validators(SimpleNamespace(state=st)) == ["@observer"]
    assert len(_get_active_validators_from_state(st)) < BFT_MIN_VALIDATORS
