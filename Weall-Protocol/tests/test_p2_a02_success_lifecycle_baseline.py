from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from weall.runtime.account_registration_work import (
    ACCOUNT_REGISTRATION_WORK_VERSION,
    account_registration_work_digest,
    leading_zero_bits,
)
from weall.runtime.domain_apply import apply_tx_atomic_meta_bounded_rollback
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_contracts import load_default_tx_index
from weall.testing.sigtools import ensure_account_has_test_key, sign_tx_dict
from weall.runtime.validator_readiness_runner import build_validator_readiness_receipt

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "generated" / "tx_semantic_assurance_v1_5.json"


def _account(*, tier: int = 2, balance: int = 1_000_000) -> dict[str, Any]:
    return {
        "nonce": 0,
        "balance": balance,
        "poh_tier": tier,
        "reputation": "10.000",
        "reputation_milli": 10_000,
        "banned": False,
        "locked": False,
    }


def _base_state() -> dict[str, Any]:
    actors = {
        "@tester",
        "@target",
        "@juror1",
        "@validator1",
        "@member",
        "@owner",
        "a",
        "alice",
        "bob",
        "j1",
        "j2",
        "j3",
        "j4",
        "j5",
        "j6",
        "j7",
        "j8",
        "j9",
        "j10",
    }
    return {
        "height": 10,
        "time": 1_000_000,
        "chain_id": "weall-testnet-v1",
        "network_id": "weall-testnet-v1",
        "params": {
            "chain_id": "weall-testnet-v1",
            "economics_enabled": True,
            "genesis_time": 0,
            "economic_unlock_time": 0,
            "system_signer": "SYSTEM",
            "group_treasury_timelock_blocks": 1,
        },
        "accounts": {actor: _account() for actor in sorted(actors)},
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


def _tx(
    tx_type: str,
    payload: dict[str, Any] | None = None,
    *,
    signer: str | None = None,
    system: bool = False,
    parent: str | None = None,
    nonce: int = 1,
) -> TxEnvelope:
    if system and parent is None:
        parent = "PARENT-A02"
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer if signer is not None else ("SYSTEM" if system else "@tester"),
        nonce=nonce,
        payload=copy.deepcopy(payload or {}),
        sig_profile="" if system else "pq-mldsa-v1",
        parent=parent,
        system=system,
        chain_id="weall-testnet-v1",
    )


def _apply(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any] | None = None,
    *,
    signer: str | None = None,
    system: bool = False,
    parent: str | None = None,
    nonce: int = 1,
) -> None:
    apply_tx_atomic_meta_bounded_rollback(
        state,
        _tx(
            tx_type,
            payload,
            signer=signer,
            system=system,
            parent=parent,
            nonce=nonce,
        ),
    )


def _prepare_governance(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    proposal_id = "proposal-a16"

    if tx_type in {"PROTOCOL_UPGRADE_DECLARE", "PROTOCOL_UPGRADE_ACTIVATE"}:
        declare = {
            "upgrade_id": "upgrade-a16",
            "target_version": "2.0.0",
        }
        if tx_type == "PROTOCOL_UPGRADE_DECLARE":
            payload.update(declare)
            return "SYSTEM", payload
        _apply(state, "PROTOCOL_UPGRADE_DECLARE", declare, system=True)
        payload.update(
            {
                "upgrade_id": "upgrade-a16",
                "target_version": "2.0.0",
                "activation_height": 12,
            }
        )
        return "SYSTEM", payload

    if tx_type in {"CONSTITUTION_UPGRADE_DECLARE", "CONSTITUTION_UPGRADE_ACTIVATE"}:
        state["params"]["m3_civic_governance_strict"] = False
        declare = {
            "constitution_id": "constitution-a16",
            "constitution_version": "0.2.0",
            "document_hash": "1" * 64,
            "traceability_hash": "2" * 64,
        }
        if tx_type == "CONSTITUTION_UPGRADE_DECLARE":
            payload.update(declare)
            return "SYSTEM", payload
        _apply(state, "CONSTITUTION_UPGRADE_DECLARE", declare, system=True)
        payload.update(
            {
                "constitution_id": "constitution-a16",
                "constitution_version": "0.2.0",
                "activation_height": 12,
            }
        )
        return "SYSTEM", payload

    if tx_type == "GOV_PROPOSAL_CREATE":
        payload.setdefault("proposal_id", proposal_id)
        payload.setdefault("title", "P2 lifecycle proposal")
        payload.setdefault("body", "Executable lifecycle fixture")
        return "@tester", payload

    proposal_dependent = {
        "GOV_PROPOSAL_EDIT",
        "GOV_PROPOSAL_COMMENT",
        "GOV_PROPOSAL_WITHDRAW",
        "GOV_STAGE_SET",
        "GOV_VOTE_CAST",
        "GOV_VOTE_REVOKE",
        "GOV_VOTING_CLOSE",
        "GOV_TALLY_PUBLISH",
        "GOV_EXECUTE",
        "GOV_PROPOSAL_FINALIZE",
    }
    if tx_type not in proposal_dependent:
        return "@tester", payload

    _apply(
        state,
        "GOV_PROPOSAL_CREATE",
        {
            "proposal_id": proposal_id,
            "title": "P2 lifecycle proposal",
            "body": "Executable lifecycle fixture",
        },
    )
    payload["proposal_id"] = proposal_id

    if tx_type == "GOV_PROPOSAL_EDIT":
        payload.setdefault("title", "P2 edited proposal")
        return "@tester", payload

    if tx_type == "GOV_PROPOSAL_COMMENT":
        payload.setdefault("body", "P2 lifecycle comment")
        return "@tester", payload

    if tx_type == "GOV_PROPOSAL_WITHDRAW":
        return "@tester", payload

    if tx_type == "GOV_STAGE_SET":
        payload.setdefault("stage", "voting")
        return "SYSTEM", payload

    _apply(
        state,
        "GOV_STAGE_SET",
        {"proposal_id": proposal_id, "stage": "voting", "_due_height": 11},
        system=True,
    )

    if tx_type == "GOV_VOTE_CAST":
        payload["vote"] = "yes"
        return "@tester", payload

    if tx_type in {
        "GOV_VOTE_REVOKE",
        "GOV_VOTING_CLOSE",
        "GOV_TALLY_PUBLISH",
        "GOV_EXECUTE",
        "GOV_PROPOSAL_FINALIZE",
    }:
        _apply(
            state,
            "GOV_VOTE_CAST",
            {"proposal_id": proposal_id, "vote": "yes"},
            signer="@tester",
        )

    if tx_type == "GOV_VOTE_REVOKE":
        return "@tester", payload

    if tx_type in {
        "GOV_TALLY_PUBLISH",
        "GOV_EXECUTE",
        "GOV_PROPOSAL_FINALIZE",
    }:
        _apply(
            state,
            "GOV_VOTING_CLOSE",
            {"proposal_id": proposal_id, "_due_height": 11},
            system=True,
        )

    if tx_type == "GOV_VOTING_CLOSE":
        return "SYSTEM", payload

    if tx_type == "GOV_TALLY_PUBLISH":
        payload.update(
            {
                "tally": {"yes": 1, "no": 0, "abstain": 0},
                "total_votes": 1,
                "quorum_required": 0,
                "quorum_met": True,
                "passed": True,
                "_due_height": 11,
            }
        )
        return "SYSTEM", payload

    if tx_type in {"GOV_EXECUTE", "GOV_PROPOSAL_FINALIZE"}:
        _apply(
            state,
            "GOV_TALLY_PUBLISH",
            {
                "proposal_id": proposal_id,
                "tally": {"yes": 1, "no": 0, "abstain": 0},
                "total_votes": 1,
                "quorum_required": 0,
                "quorum_met": True,
                "passed": True,
                "_due_height": 11,
            },
            system=True,
        )

    if tx_type == "GOV_EXECUTE":
        payload["_due_height"] = 11
        return "SYSTEM", payload

    if tx_type == "GOV_PROPOSAL_FINALIZE":
        _apply(
            state,
            "GOV_EXECUTE",
            {"proposal_id": proposal_id, "_due_height": 11},
            system=True,
        )
        payload["_due_height"] = 11
        return "SYSTEM", payload

    return "@tester", payload


def _create_group(state: dict[str, Any], *, approval_required: bool = False) -> None:
    _apply(
        state,
        "GROUP_CREATE",
        {
            "group_id": "group-a16",
            "charter": "P2 lifecycle group",
            "membership_mode": "approval_required" if approval_required else "open",
            "read_visibility": "public",
        },
        signer="@tester",
    )


def _prepare_groups(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    if tx_type == "GROUP_CREATE":
        payload.setdefault("charter", "P2 lifecycle group")
        payload.setdefault("membership_mode", "open")
        payload["group_id"] = "group-a16"
        return "@tester", payload

    if tx_type == "GROUP_TREASURY_CREATE":
        return "SYSTEM", payload

    approval_required = tx_type == "GROUP_MEMBERSHIP_DECIDE"
    _create_group(state, approval_required=approval_required)
    payload.setdefault("group_id", "group-a16")

    if tx_type == "GROUP_MEMBERSHIP_REQUEST":
        return "@member", payload

    if tx_type == "GROUP_MEMBERSHIP_DECIDE":
        _apply(
            state,
            "GROUP_MEMBERSHIP_REQUEST",
            {"group_id": "group-a16", "note": "P2 request"},
            signer="@member",
        )
        payload["account"] = "@member"
        payload["decision"] = "accept"
        return "@tester", payload

    if tx_type == "GROUP_MEMBERSHIP_REMOVE":
        _apply(
            state,
            "GROUP_MEMBERSHIP_REQUEST",
            {"group_id": "group-a16"},
            signer="@member",
        )
        payload["account"] = "@member"
        return "@tester", payload

    if tx_type == "GROUP_ROLE_GRANT":
        payload["account"] = "@member"
        payload["role"] = "moderators"
        return "@tester", payload

    if tx_type == "GROUP_ROLE_REVOKE":
        _apply(
            state,
            "GROUP_ROLE_GRANT",
            {"group_id": "group-a16", "account": "@member", "role": "moderators"},
            signer="@tester",
        )
        payload["account"] = "@member"
        payload["role"] = "moderators"
        return "@tester", payload

    if tx_type == "GROUP_SIGNERS_SET":
        payload["signers"] = ["@tester"]
        return "@tester", payload

    if tx_type == "GROUP_MODERATORS_SET":
        payload["moderators"] = ["@tester", "@member"]
        return "@tester", payload

    if tx_type == "GROUP_EMISSARY_ELECTION_CREATE":
        payload.update(
            {
                "group_id": "group-a16",
                "election_id": "election-a16",
                "candidates": ["@tester"],
                "seats": 5,
                "start_height": 11,
                "end_height": 20,
            }
        )
        return "@tester", payload

    if tx_type in {"GROUP_EMISSARY_BALLOT_CAST", "GROUP_EMISSARY_ELECTION_FINALIZE"}:
        _apply(
            state,
            "GROUP_EMISSARY_ELECTION_CREATE",
            {
                "group_id": "group-a16",
                "election_id": "election-a16",
                "candidates": ["@tester"],
                "seats": 5,
                "start_height": 11,
                "end_height": 20,
            },
            signer="@tester",
        )
        payload["group_id"] = "group-a16"
        payload["election_id"] = "election-a16"
        if tx_type == "GROUP_EMISSARY_BALLOT_CAST":
            payload.pop("group_id", None)
            payload["ranking"] = ["@tester"]
            return "@tester", payload
        _apply(
            state,
            "GROUP_EMISSARY_BALLOT_CAST",
            {"election_id": "election-a16", "ranking": ["@tester"]},
            signer="@tester",
        )
        state["height"] = 20
        return "@tester", payload

    if tx_type == "GROUP_TREASURY_AUDIT_ANCHOR_SET":
        payload["anchor"] = {"root": "p2-audit-anchor"}
        return "SYSTEM", payload

    if tx_type == "GROUP_TREASURY_POLICY_SET":
        payload["policy"] = {"threshold": 1}
        return "SYSTEM", payload

    spend_family = {
        "GROUP_TREASURY_SPEND_PROPOSE",
        "GROUP_TREASURY_SPEND_SIGN",
        "GROUP_TREASURY_SPEND_CANCEL",
        "GROUP_TREASURY_SPEND_EXECUTE",
        "GROUP_TREASURY_SPEND_EXPIRE",
    }
    if tx_type in spend_family:
        _apply(
            state,
            "GROUP_SIGNERS_SET",
            {"group_id": "group-a16", "signers": ["@tester"]},
            signer="@tester",
        )
        if tx_type != "GROUP_TREASURY_SPEND_PROPOSE":
            _apply(
                state,
                "GROUP_TREASURY_SPEND_PROPOSE",
                {
                    "group_id": "group-a16",
                    "spend_id": "spend-a16",
                    "to": "@member",
                    "amount": 1,
                },
                signer="@tester",
            )

        payload["group_id"] = "group-a16"
        payload["spend_id"] = "spend-a16"

        if tx_type == "GROUP_TREASURY_SPEND_PROPOSE":
            payload.update({"to": "@member", "amount": 1})
            return "@tester", payload

        if tx_type == "GROUP_TREASURY_SPEND_SIGN":
            return "@tester", payload

        if tx_type == "GROUP_TREASURY_SPEND_CANCEL":
            return "@tester", payload

        if tx_type == "GROUP_TREASURY_SPEND_EXECUTE":
            _apply(
                state,
                "GROUP_TREASURY_SPEND_SIGN",
                {"group_id": "group-a16", "spend_id": "spend-a16"},
                signer="@tester",
            )
            state["height"] = 11
            state["treasury_wallets"]["TREASURY_GROUP::group-a16"]["balance"] = 100
            payload.clear()
            payload["spend_id"] = "spend-a16"
            return "SYSTEM", payload

        return "SYSTEM", payload

    return "@tester", payload


def _prepare_dispute(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    roles = state.setdefault("roles", {})
    roles["jurors"] = {"active_set": ["@juror1"], "by_id": {}}

    if tx_type == "DISPUTE_FINAL_RECEIPT":
        return "SYSTEM", payload

    if tx_type == "DISPUTE_OPEN":
        payload.update(
            {
                "dispute_id": "a",
                "target_type": "account",
                "target_id": "@target",
                "reason": "P2 lifecycle fixture",
            }
        )
        return "@tester", payload

    _apply(
        state,
        "DISPUTE_OPEN",
        {
            "dispute_id": "a",
            "target_type": "account",
            "target_id": "@target",
            "reason": "P2 lifecycle fixture",
        },
        signer="@tester",
    )
    payload["dispute_id"] = "a"

    if tx_type == "DISPUTE_STAGE_SET":
        payload["stage"] = "juror_review"
        return "SYSTEM", payload
    if tx_type == "DISPUTE_EVIDENCE_DECLARE":
        payload.update({"evidence_id": "evidence-a16", "kind": "text"})
        return "@tester", payload
    if tx_type == "DISPUTE_EVIDENCE_BIND":
        _apply(
            state,
            "DISPUTE_EVIDENCE_DECLARE",
            {"dispute_id": "a", "evidence_id": "evidence-a16", "kind": "text"},
            signer="@tester",
        )
        payload["evidence_id"] = "evidence-a16"
        return "@tester", payload
    if tx_type == "DISPUTE_JUROR_ASSIGN":
        payload["juror_id"] = "@juror1"
        return "SYSTEM", payload

    if tx_type == "DISPUTE_JUROR_ATTENDANCE":
        dispute = state["disputes_by_id"]["a"]
        dispute["jurors"] = {"SYSTEM": {"status": "assigned"}}
        dispute["assigned_jurors"] = ["SYSTEM"]
        payload["present"] = True
        return "SYSTEM", payload

    if tx_type in {
        "DISPUTE_JUROR_ACCEPT",
        "DISPUTE_JUROR_DECLINE",
        "DISPUTE_JUROR_TIMEOUT",
        "DISPUTE_JUROR_WITHDRAW",
        "DISPUTE_VOTE_SUBMIT",
    }:
        _apply(
            state,
            "DISPUTE_JUROR_ASSIGN",
            {"dispute_id": "a", "juror_id": "@juror1"},
            system=True,
        )

    if tx_type == "DISPUTE_JUROR_ACCEPT":
        return "@juror1", payload
    if tx_type == "DISPUTE_JUROR_DECLINE":
        return "@juror1", payload

    if tx_type in {"DISPUTE_JUROR_TIMEOUT", "DISPUTE_JUROR_WITHDRAW", "DISPUTE_VOTE_SUBMIT"}:
        _apply(
            state,
            "DISPUTE_JUROR_ACCEPT",
            {"dispute_id": "a"},
            signer="@juror1",
        )

    if tx_type == "DISPUTE_JUROR_TIMEOUT":
        state["height"] = 100_000
        payload["juror_id"] = "@juror1"
        return "SYSTEM", payload
    if tx_type == "DISPUTE_JUROR_WITHDRAW":
        return "@juror1", payload
    if tx_type == "DISPUTE_VOTE_SUBMIT":
        payload.pop("appeal_vote", None)
        payload["vote"] = "yes"
        payload["resolution"] = {"summary": "P2 lifecycle fixture"}
        return "@juror1", payload
    if tx_type == "DISPUTE_RESOLVE":
        payload["resolution"] = {"summary": "P2 lifecycle fixture"}
        return "SYSTEM", payload
    if tx_type == "DISPUTE_APPEAL":
        _apply(
            state,
            "DISPUTE_RESOLVE",
            {
                "dispute_id": "a",
                "resolution": {"summary": "P2 lifecycle fixture"},
                "_due_height": int(state.get("height") or 0),
            },
            system=True,
        )
        return "@target", payload

    return "@tester", payload


def _poh_reviewers(state: dict[str, Any]) -> None:
    roles = state.setdefault("roles", {})
    roles["jurors"] = {
        "active_set": ["@juror1", *[f"j{i}" for i in range(1, 11)]],
        "by_id": {},
    }
    params = state.setdefault("params", {}).setdefault("poh", {})
    params.update(
        {
            "async_n_jurors": 3,
            "async_min_reviews": 3,
            "async_approval_threshold": 2,
            "async_rejection_threshold": 2,
            "async_expiry_window_blocks": 100,
            "tier2_n_jurors": 3,
            "tier2_min_total_reviews": 3,
            "tier2_pass_threshold": 2,
            "tier2_fail_max": 1,
        }
    )


def _poh_case_id(state: dict[str, Any], family: str) -> str:
    cases = state.get("poh", {}).get(family, {})
    assert isinstance(cases, dict) and len(cases) == 1
    return str(next(iter(cases)))


def _open_async_poh(state: dict[str, Any]) -> str:
    _poh_reviewers(state)
    state["accounts"]["@tester"]["poh_tier"] = 0
    _apply(
        state,
        "POH_ASYNC_REQUEST_OPEN",
        {
            "account_id": "@tester",
            "case_id": "case-a16",
            "challenge_id": "prompt-a16",
            "challenge_commitment": "sha256:" + ("1" * 64),
        },
        signer="@tester",
    )
    return "case-a16"


def _declare_async_evidence(state: dict[str, Any], case_id: str) -> None:
    _apply(
        state,
        "POH_ASYNC_EVIDENCE_DECLARE",
        {
            "case_id": case_id,
            "evidence_id": "evidence-a16",
            "evidence_commitment": "sha256:" + ("2" * 64),
        },
        signer="@tester",
    )


def _bind_async_evidence(state: dict[str, Any], case_id: str) -> None:
    _apply(
        state,
        "POH_ASYNC_EVIDENCE_BIND",
        {
            "case_id": case_id,
            "evidence_id": "evidence-a16",
            "target_id": case_id,
            "evidence_root_commitment": "sha256:" + ("2" * 64),
        },
        signer="@tester",
    )


def _assign_async_jurors(state: dict[str, Any], case_id: str) -> None:
    _apply(
        state,
        "POH_ASYNC_JUROR_ASSIGN",
        {"case_id": case_id, "jurors": ["j1", "j2", "j3"]},
        system=True,
    )


def _accept_async_juror(state: dict[str, Any], case_id: str, juror: str) -> None:
    _apply(
        state,
        "POH_ASYNC_JUROR_ACCEPT",
        {"case_id": case_id},
        signer=juror,
    )


def _open_tier2_poh(state: dict[str, Any]) -> str:
    _poh_reviewers(state)
    state["accounts"]["@tester"]["poh_tier"] = 1
    _apply(
        state,
        "POH_TIER2_REQUEST_OPEN",
        {
            "account_id": "@tester",
            "target_tier": 2,
            "video_commitment": "p2-a02-tier2-video-commitment",
        },
        signer="@tester",
    )
    return _poh_case_id(state, "tier2_cases")


def _assign_tier2_jurors(state: dict[str, Any], case_id: str) -> None:
    _apply(
        state,
        "POH_TIER2_JUROR_ASSIGN",
        {
            "case_id": case_id,
            "jurors": ["j1", "j2", "j3"],
            "n_jurors": 3,
            "min_total_reviews": 3,
            "pass_threshold": 2,
            "fail_max": 1,
        },
        system=True,
    )


def _open_live_poh(state: dict[str, Any]) -> str:
    _poh_reviewers(state)
    state["accounts"]["@tester"]["poh_tier"] = 1
    _apply(
        state,
        "POH_LIVE_REQUEST_OPEN",
        {
            "account_id": "@tester",
            "session_commitment": "session:cmt:p2",
            "room_commitment": "room:cmt:p2",
            "prompt_commitment": "prompt:cmt:p2",
            "device_pairing_commitment": "device:cmt:p2",
        },
        signer="@tester",
    )
    return _poh_case_id(state, "live_cases")


def _init_live_poh(state: dict[str, Any], case_id: str) -> None:
    _apply(
        state,
        "POH_LIVE_SESSION_INIT",
        {
            "case_id": case_id,
            "account_id": "@tester",
            "session_commitment": "session:cmt:p2",
            "room_commitment": "room:cmt:p2",
            "prompt_commitment": "prompt:cmt:p2",
            "device_pairing_commitment": "device:cmt:p2",
        },
        system=True,
    )


def _assign_live_jurors(state: dict[str, Any], case_id: str) -> None:
    _apply(
        state,
        "POH_LIVE_JUROR_ASSIGN",
        {"case_id": case_id, "jurors": [f"j{i}" for i in range(1, 11)]},
        system=True,
    )


def _complete_live_review(state: dict[str, Any], case_id: str, juror: str) -> None:
    _apply(
        state,
        "POH_LIVE_JUROR_ACCEPT",
        {"case_id": case_id},
        signer=juror,
    )
    _apply(
        state,
        "POH_LIVE_ATTENDANCE_MARK",
        {
            "case_id": case_id,
            "juror_id": juror,
            "attended": True,
            "session_commitment": "session:cmt:p2",
        },
        signer=juror,
    )
    _apply(
        state,
        "POH_LIVE_VERDICT_SUBMIT",
        {
            "case_id": case_id,
            "verdict": "pass",
            "session_commitment": "session:cmt:p2",
        },
        signer=juror,
    )


def _prepare_poh(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    _poh_reviewers(state)

    if tx_type == "POH_BOOTSTRAP_TIER2_GRANT":
        state["accounts"]["@tester"]["poh_tier"] = 0
        state["params"].update(
            {
                "poh_bootstrap_mode": "open",
                "poh_bootstrap_max_height": 100_000,
            }
        )
        payload["account_id"] = "@tester"
        return "@tester", payload

    if tx_type == "POH_CHALLENGE_RESOLVE":
        _apply(
            state,
            "POH_CHALLENGE_OPEN",
            {"account_id": "@tester"},
            signer="@tester",
        )
        payload.update(
            {
                "challenge_id": "pohc:@tester:1",
                "resolution": "dismissed",
            }
        )
        return "SYSTEM", payload

    if tx_type == "POH_EVIDENCE_BIND":
        _apply(
            state,
            "POH_EVIDENCE_DECLARE",
            {"evidence_id": "evidence-a16"},
            signer="@tester",
        )
        payload.update({"evidence_id": "evidence-a16", "target_id": "a"})
        return "@tester", payload

    if tx_type.startswith("POH_ASYNC_"):
        if tx_type == "POH_ASYNC_REQUEST_OPEN":
            payload.update(
                {
                    "account_id": "@tester",
                    "case_id": "case-a16",
                    "challenge_id": "prompt-a16",
                    "challenge_commitment": "sha256:" + ("1" * 64),
                }
            )
            return "@tester", payload

        case_id = _open_async_poh(state)
        if tx_type == "POH_ASYNC_EVIDENCE_DECLARE":
            payload.update(
                {
                    "case_id": case_id,
                    "evidence_id": "evidence-a16",
                    "evidence_commitment": "sha256:" + ("2" * 64),
                }
            )
            return "@tester", payload

        _declare_async_evidence(state, case_id)
        if tx_type == "POH_ASYNC_EVIDENCE_BIND":
            payload.update(
                {
                    "case_id": case_id,
                    "evidence_id": "evidence-a16",
                    "target_id": case_id,
                    "evidence_root_commitment": "sha256:" + ("2" * 64),
                }
            )
            return "@tester", payload

        _bind_async_evidence(state, case_id)
        if tx_type == "POH_ASYNC_JUROR_ASSIGN":
            payload.update({"case_id": case_id, "jurors": ["j1", "j2", "j3"]})
            return "SYSTEM", payload

        _assign_async_jurors(state, case_id)
        if tx_type == "POH_ASYNC_JUROR_ACCEPT":
            payload["case_id"] = case_id
            return "j1", payload
        if tx_type == "POH_ASYNC_JUROR_DECLINE":
            payload["case_id"] = case_id
            return "j1", payload

        _accept_async_juror(state, case_id, "j1")
        if tx_type == "POH_ASYNC_REVIEW_SUBMIT":
            payload.update({"case_id": case_id, "verdict": "approve"})
            return "j1", payload

        for juror in ("j2", "j3"):
            _accept_async_juror(state, case_id, juror)
        _apply(
            state,
            "POH_ASYNC_REVIEW_SUBMIT",
            {"case_id": case_id, "verdict": "approve"},
            signer="j1",
        )
        _apply(
            state,
            "POH_ASYNC_REVIEW_SUBMIT",
            {"case_id": case_id, "verdict": "approve"},
            signer="j2",
        )
        _apply(
            state,
            "POH_ASYNC_REVIEW_SUBMIT",
            {"case_id": case_id, "verdict": "reject"},
            signer="j3",
        )
        if tx_type == "POH_ASYNC_FINALIZE":
            payload["case_id"] = case_id
            return "SYSTEM", payload

        _apply(
            state,
            "POH_ASYNC_FINALIZE",
            {"case_id": case_id},
            system=True,
        )
        payload["case_id"] = case_id
        return "SYSTEM", payload

    if tx_type.startswith("POH_TIER2_"):
        if tx_type == "POH_TIER2_REQUEST_OPEN":
            state["accounts"]["@tester"]["poh_tier"] = 1
            payload.update(
                {
                    "account_id": "@tester",
                    "target_tier": 2,
                    "video_commitment": "p2-a02-tier2-video-commitment",
                }
            )
            return "@tester", payload

        case_id = _open_tier2_poh(state)
        if tx_type == "POH_TIER2_JUROR_ASSIGN":
            payload.update(
                {
                    "case_id": case_id,
                    "jurors": ["j1", "j2", "j3"],
                    "n_jurors": 3,
                    "min_total_reviews": 3,
                    "pass_threshold": 2,
                    "fail_max": 1,
                }
            )
            return "SYSTEM", payload

        _assign_tier2_jurors(state, case_id)
        if tx_type == "POH_TIER2_JUROR_ACCEPT":
            payload["case_id"] = case_id
            return "j1", payload
        if tx_type == "POH_TIER2_JUROR_DECLINE":
            payload["case_id"] = case_id
            return "j1", payload
        if tx_type == "POH_TIER2_REVIEW_SUBMIT":
            payload.update({"case_id": case_id, "verdict": "pass"})
            return "j1", payload

        for juror, verdict in (("j1", "pass"), ("j2", "pass"), ("j3", "fail")):
            _apply(
                state,
                "POH_TIER2_REVIEW_SUBMIT",
                {"case_id": case_id, "verdict": verdict},
                signer=juror,
            )
        if tx_type == "POH_TIER2_FINALIZE":
            payload["case_id"] = case_id
            return "SYSTEM", payload

        _apply(
            state,
            "POH_TIER2_FINALIZE",
            {"case_id": case_id, "ts_ms": 2},
            system=True,
        )
        payload["case_id"] = case_id
        return "SYSTEM", payload

    if tx_type.startswith("POH_LIVE_"):
        if tx_type == "POH_LIVE_REQUEST_OPEN":
            state["accounts"]["@tester"]["poh_tier"] = 1
            payload.update(
                {
                    "account_id": "@tester",
                    "session_commitment": "session:cmt:p2",
                    "room_commitment": "room:cmt:p2",
                    "prompt_commitment": "prompt:cmt:p2",
                    "device_pairing_commitment": "device:cmt:p2",
                }
            )
            return "@tester", payload

        case_id = _open_live_poh(state)
        if tx_type == "POH_LIVE_SESSION_INIT":
            payload.update(
                {
                    "case_id": case_id,
                    "account_id": "@tester",
                    "session_commitment": "session:cmt:p2",
                    "room_commitment": "room:cmt:p2",
                    "prompt_commitment": "prompt:cmt:p2",
                    "device_pairing_commitment": "device:cmt:p2",
                }
            )
            return "SYSTEM", payload

        _init_live_poh(state, case_id)
        if tx_type == "POH_LIVE_JUROR_ASSIGN":
            payload.update({"case_id": case_id, "jurors": [f"j{i}" for i in range(1, 11)]})
            return "SYSTEM", payload

        _assign_live_jurors(state, case_id)
        if tx_type == "POH_LIVE_JUROR_ACCEPT":
            payload["case_id"] = case_id
            return "j1", payload
        if tx_type == "POH_LIVE_JUROR_DECLINE":
            payload["case_id"] = case_id
            return "j1", payload
        if tx_type == "POH_LIVE_JUROR_REPLACE":
            payload.update(
                {
                    "case_id": case_id,
                    "old_juror_id": "j10",
                    "new_juror_id": "@juror1",
                }
            )
            return "SYSTEM", payload

        _apply(
            state,
            "POH_LIVE_JUROR_ACCEPT",
            {"case_id": case_id},
            signer="j1",
        )
        if tx_type == "POH_LIVE_ATTENDANCE_MARK":
            payload.update(
                {
                    "case_id": case_id,
                    "juror_id": "j1",
                    "attended": True,
                    "session_commitment": "session:cmt:p2",
                }
            )
            return "j1", payload

        _apply(
            state,
            "POH_LIVE_ATTENDANCE_MARK",
            {
                "case_id": case_id,
                "juror_id": "j1",
                "attended": True,
                "session_commitment": "session:cmt:p2",
            },
            signer="j1",
        )
        if tx_type == "POH_LIVE_VERDICT_SUBMIT":
            payload.update(
                {
                    "case_id": case_id,
                    "verdict": "pass",
                    "session_commitment": "session:cmt:p2",
                }
            )
            return "j1", payload

        _apply(
            state,
            "POH_LIVE_VERDICT_SUBMIT",
            {
                "case_id": case_id,
                "verdict": "pass",
                "session_commitment": "session:cmt:p2",
            },
            signer="j1",
        )
        for juror in ("j2", "j3"):
            _complete_live_review(state, case_id, juror)

        if tx_type == "POH_LIVE_FINALIZE":
            payload["case_id"] = case_id
            return "SYSTEM", payload

        _apply(
            state,
            "POH_LIVE_FINALIZE",
            {"case_id": case_id, "ts_ms": 2},
            system=True,
        )
        payload["case_id"] = case_id
        return "SYSTEM", payload

    return "@tester", payload


_CONTENT_CID = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3pt5a3u4ct6shwrdfl5f5d4ii"


def _content_post(state: dict[str, Any]) -> None:
    _apply(
        state,
        "CONTENT_POST_CREATE",
        {"post_id": "post-a16", "body": "P2 lifecycle fixture"},
        signer="@tester",
    )


def _content_media(state: dict[str, Any]) -> None:
    _apply(
        state,
        "CONTENT_MEDIA_DECLARE",
        {"media_id": "media-a16", "cid": _CONTENT_CID, "kind": "image"},
        signer="@tester",
    )


def _prepare_content(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    if tx_type == "CONTENT_MEDIA_DECLARE":
        payload.update({"media_id": "media-a16", "cid": _CONTENT_CID, "kind": "image"})
        return "@tester", payload

    if tx_type in {"CONTENT_POST_EDIT", "CONTENT_POST_DELETE"}:
        _content_post(state)
        payload["post_id"] = "post-a16"
        if tx_type == "CONTENT_POST_EDIT":
            payload["body"] = "P2 edited post"
        return "@tester", payload

    if tx_type in {"CONTENT_COMMENT_CREATE", "CONTENT_COMMENT_DELETE"}:
        _content_post(state)
        if tx_type == "CONTENT_COMMENT_CREATE":
            payload.update(
                {
                    "post_id": "post-a16",
                    "comment_id": "comment-a16",
                    "body": "P2 lifecycle comment",
                }
            )
            return "@tester", payload
        _apply(
            state,
            "CONTENT_COMMENT_CREATE",
            {
                "post_id": "post-a16",
                "comment_id": "comment-a16",
                "body": "P2 lifecycle comment",
            },
            signer="@tester",
        )
        payload["comment_id"] = "comment-a16"
        return "@tester", payload

    if tx_type in {
        "CONTENT_MEDIA_BIND",
        "CONTENT_MEDIA_REPLACE",
        "CONTENT_MEDIA_UNBIND",
    }:
        _content_media(state)
        if tx_type == "CONTENT_MEDIA_REPLACE":
            payload.update({"media_id": "media-a16", "new_cid": _CONTENT_CID})
            return "@tester", payload

        _content_post(state)
        if tx_type == "CONTENT_MEDIA_BIND":
            payload.update({"media_id": "media-a16", "target_id": "post-a16"})
            return "@tester", payload

        _apply(
            state,
            "CONTENT_MEDIA_BIND",
            {
                "media_id": "media-a16",
                "target_id": "post-a16",
                "binding_id": "binding-a16",
            },
            signer="@tester",
        )
        payload["binding_id"] = "binding-a16"
        return "@tester", payload

    return "@tester", payload


def _snapshot_ready(state: dict[str, Any]) -> None:
    _apply(
        state,
        "STATE_SNAPSHOT_DECLARE",
        {"snapshot_id": "a"},
        system=True,
    )
    _apply(
        state,
        "STATE_SNAPSHOT_ACCEPT",
        {"snapshot_id": "a"},
        system=True,
    )


def _prepare_indexing(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    if tx_type == "STATE_SNAPSHOT_ACCEPT":
        _apply(
            state,
            "STATE_SNAPSHOT_DECLARE",
            {"snapshot_id": "a"},
            system=True,
        )
        payload["snapshot_id"] = "a"
        return "SYSTEM", payload

    if tx_type == "COLD_SYNC_REQUEST":
        _snapshot_ready(state)
        payload.update({"snapshot_id": "a", "request_id": "request-a16"})
        return "SYSTEM", payload

    if tx_type == "COLD_SYNC_COMPLETE":
        _snapshot_ready(state)
        _apply(
            state,
            "COLD_SYNC_REQUEST",
            {"snapshot_id": "a", "request_id": "request-a16"},
            system=True,
        )
        payload["request_id"] = "request-a16"
        return "SYSTEM", payload

    return "SYSTEM", payload


def _treasury_ready(state: dict[str, Any]) -> None:
    _apply(
        state,
        "TREASURY_CREATE",
        {"treasury_id": "treasury-a16"},
        signer="@tester",
    )
    _apply(
        state,
        "TREASURY_WALLET_CREATE",
        {"wallet_id": "treasury-a16", "balance": 100},
        system=True,
    )


def _treasury_signers_ready(state: dict[str, Any]) -> None:
    _treasury_ready(state)
    _apply(
        state,
        "TREASURY_SIGNERS_SET",
        {
            "treasury_id": "treasury-a16",
            "signers": ["@tester"],
            "threshold": 1,
        },
        signer="@tester",
    )


def _treasury_spend_ready(state: dict[str, Any]) -> None:
    _treasury_signers_ready(state)
    _apply(
        state,
        "TREASURY_SPEND_PROPOSE",
        {
            "treasury_id": "treasury-a16",
            "spend_id": "spend-a16",
            "to": "@member",
            "amount": 1,
        },
        signer="@tester",
    )


def _prepare_treasury(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    if tx_type == "TREASURY_CREATE":
        payload["treasury_id"] = "treasury-a16"
        return "@tester", payload

    if tx_type == "TREASURY_SIGNERS_SET":
        _apply(
            state,
            "TREASURY_CREATE",
            {"treasury_id": "treasury-a16"},
            signer="@tester",
        )
        payload.update(
            {
                "treasury_id": "treasury-a16",
                "signers": ["@tester"],
                "threshold": 1,
            }
        )
        return "@tester", payload

    if tx_type in {"TREASURY_SIGNER_ADD", "TREASURY_SIGNER_REMOVE"}:
        _treasury_ready(state)
        if tx_type == "TREASURY_SIGNER_REMOVE":
            _apply(
                state,
                "TREASURY_SIGNER_ADD",
                {"wallet_id": "treasury-a16", "signer": "@member"},
                system=True,
            )
        payload.update({"wallet_id": "treasury-a16", "signer": "@member"})
        return "SYSTEM", payload

    spend_family = {
        "TREASURY_SPEND_PROPOSE",
        "TREASURY_SPEND_SIGN",
        "TREASURY_SPEND_CANCEL",
        "TREASURY_SPEND_EXECUTE",
    }
    if tx_type in spend_family:
        if tx_type == "TREASURY_SPEND_PROPOSE":
            _treasury_signers_ready(state)
            payload.update(
                {
                    "treasury_id": "treasury-a16",
                    "spend_id": "spend-a16",
                    "to": "@member",
                    "amount": 1,
                }
            )
            return "@tester", payload

        _treasury_spend_ready(state)
        payload.update({"treasury_id": "treasury-a16", "spend_id": "spend-a16"})
        if tx_type == "TREASURY_SPEND_SIGN":
            return "@tester", payload
        if tx_type == "TREASURY_SPEND_CANCEL":
            return "@tester", payload

        _apply(
            state,
            "TREASURY_SPEND_SIGN",
            {"treasury_id": "treasury-a16", "spend_id": "spend-a16"},
            signer="@tester",
        )
        payload.clear()
        payload["spend_id"] = "spend-a16"
        return "SYSTEM", payload

    return "SYSTEM" if tx_type.startswith("TREASURY_") else "@tester", payload


def _identity_guardian_config(
    state: dict[str, Any],
    *,
    subject: str = "@tester",
    guardian: str = "a",
) -> None:
    state["params"]["guardian_recovery_new_admission"] = True
    _apply(
        state,
        "ACCOUNT_RECOVERY_CONFIG_SET",
        {"guardians": [guardian], "threshold": 1},
        signer=subject,
        nonce=1,
    )


def _identity_recovery_request(
    state: dict[str, Any],
    *,
    subject: str = "@tester",
    guardian: str = "a",
) -> None:
    _identity_guardian_config(state, subject=subject, guardian=guardian)
    _apply(
        state,
        "ACCOUNT_RECOVERY_REQUEST",
        {"request_id": "request-a16"},
        signer=subject,
        nonce=2,
    )


def _identity_approved_recovery(state: dict[str, Any]) -> None:
    _identity_recovery_request(state, subject="@target", guardian="@tester")
    _apply(
        state,
        "ACCOUNT_RECOVERY_APPROVE",
        {"request_id": "request-a16"},
        signer="@tester",
        nonce=1,
    )


def _prepare_identity(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    state["params"]["guardian_recovery_new_admission"] = True

    if tx_type == "ACCOUNT_REGISTER":
        state["accounts"].pop("@tester", None)
        state["params"].update(
            {
                "account_registration_work_required": True,
                "account_registration_work_difficulty_bits": 16,
            }
        )
        payload["pubkey"] = "k:p2-a02-account"
        payload["registration_work_version"] = ACCOUNT_REGISTRATION_WORK_VERSION
        probe = _tx("ACCOUNT_REGISTER", payload, signer="@tester", nonce=1)
        for work_nonce in range(1_000_000):
            if leading_zero_bits(account_registration_work_digest(probe, work_nonce)) >= 16:
                payload["registration_work_nonce"] = work_nonce
                break
        else:  # pragma: no cover - deterministic 16-bit search should never exhaust.
            raise AssertionError("unable to find ACCOUNT_REGISTER work nonce")
        return "@tester", payload

    if tx_type == "ACCOUNT_DEVICE_REGISTER":
        payload.update({"device_id": "device-a16", "pubkey": "k:p2-a02-device"})
        return "@tester", payload

    if tx_type == "ACCOUNT_DEVICE_REVOKE":
        _apply(
            state,
            "ACCOUNT_DEVICE_REGISTER",
            {"device_id": "device-a16", "pubkey": "k:p2-a02-device"},
            signer="@tester",
            nonce=1,
        )
        payload["device_id"] = "device-a16"
        return "@tester", payload

    if tx_type == "ACCOUNT_KEY_REVOKE":
        _apply(
            state,
            "ACCOUNT_KEY_ADD",
            {
                "pubkey": "k:p2-a02-secondary",
                "key_type": "secondary",
                "key_id": "key-p2-secondary",
            },
            signer="@tester",
            nonce=1,
        )
        by_id = state["accounts"]["@tester"]["keys"]["by_id"]
        payload.clear()
        payload["key_id"] = str(next(iter(by_id)))
        return "@tester", payload

    if tx_type == "ACCOUNT_SESSION_KEY_ISSUE":
        payload.update({"session_key": "p2-a02-session-key", "ttl_s": 3600})
        return "@tester", payload

    if tx_type == "ACCOUNT_SESSION_KEY_REVOKE":
        _apply(
            state,
            "ACCOUNT_SESSION_KEY_ISSUE",
            {"session_key": "p2-a02-session-key", "ttl_s": 3600},
            signer="@tester",
            nonce=1,
        )
        payload["session_key"] = "p2-a02-session-key"
        return "@tester", payload

    if tx_type == "ACCOUNT_GUARDIAN_ADD":
        payload["guardian_id"] = "a"
        return "@tester", payload

    if tx_type == "ACCOUNT_GUARDIAN_REMOVE":
        _apply(
            state,
            "ACCOUNT_GUARDIAN_ADD",
            {"guardian_id": "a"},
            signer="@tester",
            nonce=1,
        )
        payload["guardian_id"] = "a"
        return "@tester", payload

    if tx_type == "ACCOUNT_RECOVERY_CONFIG_SET":
        payload.update({"guardians": ["a"], "threshold": 1})
        return "@tester", payload

    if tx_type == "ACCOUNT_RECOVERY_REQUEST":
        _identity_guardian_config(state)
        payload["request_id"] = "request-a16"
        return "@tester", payload

    if tx_type == "ACCOUNT_RECOVERY_CANCEL":
        _identity_recovery_request(state)
        payload["request_id"] = "request-a16"
        return "@tester", payload

    if tx_type == "ACCOUNT_RECOVERY_APPROVE":
        _identity_recovery_request(state, subject="@target", guardian="@tester")
        payload["request_id"] = "request-a16"
        return "@tester", payload

    if tx_type == "ACCOUNT_RECOVERY_FINALIZE":
        _identity_approved_recovery(state)
        payload["request_id"] = "request-a16"
        return "SYSTEM", payload

    if tx_type == "ACCOUNT_RECOVERY_RECEIPT":
        _identity_approved_recovery(state)
        _apply(
            state,
            "ACCOUNT_RECOVERY_FINALIZE",
            {"request_id": "request-a16"},
            system=True,
        )
        payload.update({"request_id": "request-a16", "status": "finalized"})
        return "SYSTEM", payload

    if tx_type == "ACCOUNT_LOCK":
        payload["target"] = "@target"
        return "SYSTEM", payload

    if tx_type == "ACCOUNT_UNLOCK":
        state["accounts"]["@target"]["locked"] = True
        payload["target"] = "@target"
        return "SYSTEM", payload

    return "@tester", payload


def _register_node_device(state: dict[str, Any]) -> None:
    _apply(
        state,
        "ACCOUNT_DEVICE_REGISTER",
        {
            "device_id": "node:p2-a02",
            "device_type": "node",
            "pubkey": "node-pub-p2-a02",
        },
        signer="@tester",
        nonce=1,
    )


def _prepare_networking(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    if tx_type == "PEER_ADVERTISE":
        _register_node_device(state)
        payload.update(
            {
                "endpoint": "https://127.0.0.1:8443",
                "peer_id": "@tester",
                "device_id": "node:p2-a02",
                "node_pubkey": "node-pub-p2-a02",
            }
        )
        return "@tester", payload

    if tx_type == "PEER_REQUEST_CONNECT":
        _register_node_device(state)
        payload.clear()
        payload["endpoint"] = "https://127.0.0.1:8443"
        return "@tester", payload

    if tx_type == "PEER_RENDEZVOUS_TICKET_REVOKE":
        _apply(
            state,
            "PEER_RENDEZVOUS_TICKET_CREATE",
            {"ticket_id": "ticket-a16", "target_peer": "@target"},
            signer="@tester",
        )
        payload["ticket_id"] = "ticket-a16"
        return "@tester", payload

    return "@tester", payload


def _prepare_economics(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    if tx_type == "ECONOMICS_ACTIVATION":
        state["params"]["economics_enabled"] = False
        payload.clear()
        payload["enable"] = True
        return "SYSTEM", payload

    if tx_type == "RATE_LIMIT_POLICY_SET":
        payload.clear()
        payload.update({"scope": "global", "window_ms": 60_000, "limit": 100})
        return "SYSTEM", payload

    return "@tester", payload


def _prepare_rewards(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    if tx_type == "REWARD_POOL_OPT_IN_SET":
        payload["enabled"] = True
        return "@tester", payload
    if tx_type == "BLOCK_REWARD_MINT":
        payload.update({"block_id": "block-a16", "issuance_epoch": 0, "amount": 1})
    return "SYSTEM", payload


def _node_operator_active(state: dict[str, Any]) -> None:
    _apply(
        state,
        "ROLE_NODE_OPERATOR_ENROLL",
        {"account_id": "@tester"},
        signer="@tester",
    )
    _apply(
        state,
        "ROLE_NODE_OPERATOR_ACTIVATE",
        {"account_id": "@tester"},
        system=True,
    )


def _validator_responsibility_ready(state: dict[str, Any]) -> None:
    _register_node_device(state)
    _node_operator_active(state)
    _apply(
        state,
        "NODE_OPERATOR_VALIDATOR_OPT_IN",
        {"account_id": "@tester", "node_pubkey": "node-pub-p2-a02"},
        signer="@tester",
    )


def _verified_validator_responsibility(state: dict[str, Any]) -> None:
    _validator_responsibility_ready(state)
    receipt = build_validator_readiness_receipt(
        account_id="@tester",
        node_pubkey="node-pub-p2-a02",
        bft_pubkey="bft-pub-p2-a02",
        chain_id="weall-testnet-v1",
        schema_version="1",
        protocol_version="1.25.0",
        manifest_hash="sha256:p2-a02-manifest",
        tx_index_hash="sha256:p2-a02-tx-index",
        runtime_profile_hash="sha256:p2-a02-runtime",
        readiness_expires_height=100,
    )
    receipt["verification_status"] = "verified"
    _apply(
        state,
        "VALIDATOR_READINESS_VERIFY",
        receipt,
        system=True,
    )


def _prepare_roles(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    payload["account_id"] = "@tester"

    if tx_type == "ROLE_JUROR_ACTIVATE":
        _apply(
            state,
            "ROLE_JUROR_ENROLL",
            {"account_id": "@tester"},
            signer="@tester",
        )
        return "SYSTEM", payload

    if tx_type == "ROLE_JUROR_SUSPEND":
        _apply(
            state,
            "ROLE_JUROR_ENROLL",
            {"account_id": "@tester"},
            signer="@tester",
        )
        return "SYSTEM", payload

    if tx_type == "ROLE_JUROR_REINSTATE":
        _apply(
            state,
            "ROLE_JUROR_ENROLL",
            {"account_id": "@tester"},
            signer="@tester",
        )
        _apply(
            state,
            "ROLE_JUROR_SUSPEND",
            {"account_id": "@tester"},
            system=True,
        )
        return "SYSTEM", payload

    if tx_type == "REVIEWER_LANE_OPT_IN":
        payload["lane"] = "dispute_review"
        return "@tester", payload

    if tx_type == "REVIEWER_LANE_OPT_OUT":
        _apply(
            state,
            "REVIEWER_LANE_OPT_IN",
            {"account_id": "@tester", "lane": "dispute_review"},
            signer="@tester",
        )
        payload["lane"] = "dispute_review"
        return "@tester", payload

    if tx_type == "ROLE_EMISSARY_VOTE":
        _apply(
            state,
            "ROLE_EMISSARY_NOMINATE",
            {"account_id": "@tester"},
            signer="@target",
        )
        return "@tester", payload

    if tx_type == "ROLE_NODE_OPERATOR_ACTIVATE":
        _apply(
            state,
            "ROLE_NODE_OPERATOR_ENROLL",
            {"account_id": "@tester"},
            signer="@tester",
        )
        return "SYSTEM", payload

    if tx_type == "ROLE_NODE_OPERATOR_SUSPEND":
        _node_operator_active(state)
        return "SYSTEM", payload

    if tx_type in {
        "NODE_OPERATOR_STORAGE_OPT_IN",
        "NODE_OPERATOR_VALIDATOR_OPT_IN",
        "NODE_OPERATOR_HELPER_OPT_IN",
        "NODE_OPERATOR_RESPONSIBILITY_UPDATE",
    }:
        _node_operator_active(state)
        if tx_type == "NODE_OPERATOR_STORAGE_OPT_IN":
            payload["declared_capacity_bytes"] = 1024
        elif tx_type == "NODE_OPERATOR_VALIDATOR_OPT_IN":
            payload["validator_opt_in"] = True
        elif tx_type == "NODE_OPERATOR_HELPER_OPT_IN":
            payload.clear()
            payload["account_id"] = "@tester"
        else:
            payload.clear()
            payload.update(
                {
                    "account_id": "@tester",
                    "responsibilities": {"helper": {"opted_in": True}},
                }
            )
        return "@tester", payload

    if tx_type == "VALIDATOR_READINESS_VERIFY":
        _validator_responsibility_ready(state)
        payload["verification_status"] = "failed"
        return "SYSTEM", payload

    if tx_type == "ROLE_VALIDATOR_ACTIVATE":
        _verified_validator_responsibility(state)
        payload["node_pubkey"] = "node-pub-p2-a02"
        return "SYSTEM", payload

    return "@tester", payload


def _storage_operator_ready(state: dict[str, Any]) -> None:
    state["accounts"]["@tester"]["devices"] = {
        "by_id": {
            "node:p2-storage": {
                "device_type": "node",
                "pubkey": "node-pub-p2-storage",
                "revoked": False,
            }
        }
    }
    state["roles"]["node_operators"] = {
        "active_set": ["@tester"],
        "by_id": {
            "@tester": {
                "account_id": "@tester",
                "enrolled": True,
                "active": True,
                "status": "active",
                "responsibilities": {
                    "storage": {
                        "opted_in": True,
                        "active": True,
                        "declared_capacity_bytes": 1024,
                        "proven_capacity_bytes": 1024,
                        "allocated_capacity_bytes": 0,
                        "reserved_capacity_bytes": 0,
                        "probed_capacity_bytes": 1024,
                        "used_capacity_bytes": 0,
                        "proof_status": "verified",
                        "proof_expires_height": 100,
                        "node_pubkey": "node-pub-p2-storage",
                    }
                },
            }
        },
    }


def _storage_offer(state: dict[str, Any]) -> None:
    _storage_operator_ready(state)
    _apply(
        state,
        "STORAGE_OFFER_CREATE",
        {
            "offer_id": "offer-a16",
            "cid": _CONTENT_CID,
            "capacity_bytes": 1,
            "price": 1,
        },
        signer="@tester",
    )


def _storage_lease(state: dict[str, Any]) -> None:
    _storage_offer(state)
    _apply(
        state,
        "STORAGE_LEASE_CREATE",
        {
            "lease_id": "lease-a16",
            "offer_id": "offer-a16",
            "duration_blocks": 20,
            "size_bytes": 1,
        },
        signer="@tester",
    )


def _storage_lease_challenge(state: dict[str, Any]) -> None:
    _storage_lease(state)
    _apply(
        state,
        "STORAGE_CHALLENGE_ISSUE",
        {
            "challenge_id": "challenge-a16",
            "lease_id": "lease-a16",
            "operator_id": "@tester",
            "account_id": "@tester",
        },
        system=True,
    )


def _storage_capacity_challenge(state: dict[str, Any]) -> None:
    _storage_operator_ready(state)
    _apply(
        state,
        "STORAGE_CHALLENGE_ISSUE",
        {
            "challenge_id": "challenge-a16",
            "proof_scope": "capacity_probe",
            "account_id": "@tester",
            "operator_id": "@tester",
            "sample_count": 1,
            "sample_size_bytes": 1,
            "reserved_capacity_bytes": 1,
            "expires_height": 20,
            "challenge_seed": "p2-a02-storage",
        },
        system=True,
    )


def _prepare_storage(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    if tx_type == "STORAGE_OFFER_CREATE":
        _storage_operator_ready(state)
        payload.update(
            {
                "offer_id": "offer-a16",
                "cid": _CONTENT_CID,
                "capacity_bytes": 1,
                "price": 1,
            }
        )
        return "@tester", payload

    if tx_type == "STORAGE_OFFER_WITHDRAW":
        _storage_offer(state)
        payload["offer_id"] = "offer-a16"
        return "@tester", payload

    if tx_type == "STORAGE_LEASE_CREATE":
        _storage_offer(state)
        payload.update(
            {
                "lease_id": "lease-a16",
                "offer_id": "offer-a16",
                "duration_blocks": 20,
                "size_bytes": 1,
            }
        )
        return "@tester", payload

    if tx_type in {"STORAGE_LEASE_RENEW", "STORAGE_LEASE_REVOKE", "STORAGE_PROOF_SUBMIT"}:
        _storage_lease(state)
        payload["lease_id"] = "lease-a16"
        if tx_type == "STORAGE_LEASE_RENEW":
            payload["add_blocks"] = 5
        elif tx_type == "STORAGE_PROOF_SUBMIT":
            payload["proof_cid"] = _CONTENT_CID
        return "@tester", payload

    if tx_type == "STORAGE_CHALLENGE_ISSUE":
        _storage_lease(state)
        payload.clear()
        payload.update(
            {
                "challenge_id": "challenge-a16",
                "lease_id": "lease-a16",
                "operator_id": "@tester",
                "account_id": "@tester",
            }
        )
        return "SYSTEM", payload

    if tx_type == "STORAGE_CHALLENGE_RESPOND":
        _storage_lease_challenge(state)
        payload.update({"challenge_id": "challenge-a16", "response_cid": _CONTENT_CID})
        return "@tester", payload

    if tx_type == "STORAGE_CAPACITY_PROOF_VERIFY":
        _storage_capacity_challenge(state)
        payload.update(
            {
                "challenge_id": "challenge-a16",
                "verification_status": "failed",
            }
        )
        return "SYSTEM", payload

    if tx_type == "IPFS_PIN_CONFIRM":
        _storage_offer(state)
        _apply(
            state,
            "IPFS_PIN_REQUEST",
            {
                "pin_id": "pin-a16",
                "cid": _CONTENT_CID,
                "size_bytes": 1,
            },
            signer="@tester",
        )
        payload.update(
            {
                "pin_id": "pin-a16",
                "cid": _CONTENT_CID,
                "operator_id": "@tester",
                "ok": True,
            }
        )
        return "SYSTEM", payload

    return "@tester", payload


def _consensus_known_block(state: dict[str, Any]) -> None:
    state["blocks"] = {
        "a": {
            "block_id": "a",
            "height": 1,
            "parent": None,
        }
    }


def _register_consensus_validator(state: dict[str, Any], account: str) -> None:
    _apply(
        state,
        "VALIDATOR_REGISTER",
        {
            "account": account,
            "pubkey": f"validator-pub:{account}",
            "node_id": f"node:{account}",
            "endpoint": "https://127.0.0.1:9443",
        },
        system=True,
    )


def _prepare_consensus(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    if tx_type == "BLOCK_PROPOSE":
        payload.update({"block_id": "a", "height": 1})
        return "@validator1", payload

    if tx_type == "BLOCK_ATTEST":
        _consensus_known_block(state)
        payload.update({"block_id": "a", "height": 1, "round": 0})
        return "@validator1", payload

    if tx_type == "BLOCK_FINALIZE":
        _consensus_known_block(state)
        state["roles"]["validators"] = {"active_set": ["@validator1"], "by_id": {}}
        _apply(
            state,
            "BLOCK_ATTEST",
            {"block_id": "a", "height": 1, "round": 0, "attestation": "yes"},
            signer="@validator1",
        )
        payload.update({"block_id": "a", "height": 1})
        return "SYSTEM", payload

    if tx_type == "EPOCH_CLOSE":
        state["consensus"] = {
            "epochs": {"current": 1, "events": []},
            "validators": {"registry": {}},
        }
        payload["epoch"] = 1
        return "SYSTEM", payload

    if tx_type == "VALIDATOR_REGISTER":
        payload.update(
            {
                "account": "@validator1",
                "pubkey": "validator-pub:@validator1",
                "node_id": "node:@validator1",
                "endpoint": "https://127.0.0.1:9443",
            }
        )
        return "SYSTEM", payload

    if tx_type == "VALIDATOR_CANDIDATE_APPROVE":
        _register_consensus_validator(state, "@validator1")
        payload.update({"account": "@validator1", "activate_at_epoch": 1})
        return "SYSTEM", payload

    if tx_type == "VALIDATOR_DEREGISTER":
        _register_consensus_validator(state, "@tester")
        payload["account"] = "@tester"
        return "@tester", payload

    if tx_type == "VALIDATOR_HEARTBEAT":
        payload.update(
            {
                "account": "@validator1",
                "node_id": "node-heartbeat-a16",
                "ts_ms": 1,
            }
        )
        return "@validator1", payload

    if tx_type in {"VALIDATOR_REMOVE", "VALIDATOR_SUSPEND"}:
        _register_consensus_validator(state, "@validator1")
        payload.update({"account": "@validator1", "effective_epoch": 1})
        return "SYSTEM", payload

    return "SYSTEM" if str(tx_type).startswith("BLOCK_") else "@tester", payload


def _prepared_envelope(
    state: dict[str, Any],
    row: dict[str, Any],
) -> TxEnvelope:
    tx_type = str(row["tx_type"])
    payload = copy.deepcopy(row["baseline_payload"])
    system = str(row.get("origin") or "").upper() == "SYSTEM"
    signer = "SYSTEM" if system else "@tester"

    if str(row.get("domain") or "") == "Governance":
        signer, payload = _prepare_governance(state, tx_type, payload)
    elif str(row.get("domain") or "") == "Groups":
        signer, payload = _prepare_groups(state, tx_type, payload)
    elif str(row.get("domain") or "") == "Dispute":
        signer, payload = _prepare_dispute(state, tx_type, payload)
    elif str(row.get("domain") or "") == "PoH":
        signer, payload = _prepare_poh(state, tx_type, payload)
    elif str(row.get("domain") or "") == "Content":
        signer, payload = _prepare_content(state, tx_type, payload)
    elif str(row.get("domain") or "") == "Indexing":
        signer, payload = _prepare_indexing(state, tx_type, payload)
    elif str(row.get("domain") or "") == "Treasury":
        signer, payload = _prepare_treasury(state, tx_type, payload)
    elif str(row.get("domain") or "") == "Identity":
        signer, payload = _prepare_identity(state, tx_type, payload)
    elif str(row.get("domain") or "") == "Networking":
        signer, payload = _prepare_networking(state, tx_type, payload)
    elif str(row.get("domain") or "") == "Economics":
        signer, payload = _prepare_economics(state, tx_type, payload)
    elif str(row.get("domain") or "") == "Rewards":
        signer, payload = _prepare_rewards(state, tx_type, payload)
    elif str(row.get("domain") or "") == "Roles":
        signer, payload = _prepare_roles(state, tx_type, payload)
    elif str(row.get("domain") or "") == "Storage":
        signer, payload = _prepare_storage(state, tx_type, payload)
    elif str(row.get("domain") or "") == "Consensus":
        signer, payload = _prepare_consensus(state, tx_type, payload)

    system = str(row.get("origin") or "").upper() == "SYSTEM"
    if system and tx_type != "POH_BOOTSTRAP_TIER2_GRANT":
        signer = "SYSTEM"
    block_only = str(row.get("context") or "").lower() == "block"
    receipt_only = bool(row.get("receipt_only"))
    nonce = 1
    if not system:
        account = state.get("accounts", {}).get(signer)
        if isinstance(account, dict):
            nonce = int(account.get("nonce") or 0) + 1
    return _tx(
        tx_type,
        payload,
        signer=signer,
        system=system,
        nonce=nonce,
        parent="PARENT-A02" if block_only or receipt_only else None,
    )


def test_a02_f003_all_canon_baselines_have_successful_apply_fixture() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = manifest["rows"]
    assert len(rows) == 236

    failures: list[tuple[str, str, str]] = []
    successes: list[str] = []

    for row in rows:
        tx_type = str(row["tx_type"])
        state = _base_state()
        try:
            apply_tx_atomic_meta_bounded_rollback(state, _prepared_envelope(state, row))
        except Exception as exc:  # domain error families intentionally vary.
            failures.append(
                (
                    tx_type,
                    str(getattr(exc, "code", "") or type(exc).__name__),
                    str(getattr(exc, "reason", "") or str(exc)),
                )
            )
        else:
            successes.append(tx_type)

    if failures:
        detail = "\n".join(f"{tx_type}\t{code}\t{reason}" for tx_type, code, reason in failures)
        raise AssertionError(
            f"A02-F003 successful-baseline gap: "
            f"success_count={len(successes)} failure_count={len(failures)}\n{detail}"
        )


def _seed_a02_admission_authority(
    state: dict[str, Any],
    tx_type: str,
    signer: str,
    payload: dict[str, Any],
) -> None:
    roles = state.setdefault("roles", {})

    if tx_type in {
        "BLOCK_ATTEST",
        "BLOCK_PROPOSE",
        "SLASH_VOTE",
        "VALIDATOR_DEREGISTER",
        "VALIDATOR_HEARTBEAT",
        "VALIDATOR_PERFORMANCE_REPORT",
    }:
        roles["validators"] = {
            "active_set": [signer],
            "by_id": {signer: {"active": True}},
        }

    if tx_type == "NODE_OPERATOR_PERFORMANCE_REPORT":
        roles["node_operators"] = {
            "active_set": [signer],
            "by_id": {signer: {"active": True}},
        }

    if tx_type in {
        "GROUP_TREASURY_SPEND_PROPOSE",
        "GROUP_TREASURY_SPEND_CANCEL",
    }:
        group_id = str(payload.get("group_id") or "group-a16")
        group_roles = roles.setdefault("groups_by_id", {}).setdefault(group_id, {})
        group_roles["emissaries"] = [signer]
        roles["emissaries"] = {
            "seated": [signer],
            "by_id": {signer: {"active": True}},
        }

    if tx_type == "TREASURY_SPEND_PROPOSE":
        treasury_id = str(payload.get("treasury_id") or "treasury-a16")
        treasury_roles = roles.setdefault("treasuries_by_id", {}).setdefault(treasury_id, {})
        treasury_roles.update(
            {
                "signers": [signer],
                "require_emissary_signers": True,
            }
        )
        roles["emissaries"] = {
            "seated": [signer],
            "by_id": {signer: {"active": True}},
        }


def test_a02_f003_all_canon_prepared_vectors_pass_admission() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = manifest["rows"]
    assert len(rows) == 236

    canon = load_default_tx_index()
    failures: list[tuple[str, str, str, str]] = []

    for row in rows:
        tx_type = str(row["tx_type"])
        state = _base_state()
        env = _prepared_envelope(state, row)
        context = str(row.get("context") or "mempool").strip().lower() or "mempool"
        _seed_a02_admission_authority(state, tx_type, env.signer, env.payload)

        if context == "block" and not bool(env.system):
            ensure_account_has_test_key(state.setdefault("accounts", {}), account_id=env.signer)
            env = TxEnvelope.from_json(sign_tx_dict(env.to_json(), label=env.signer))

        verdict = admit_tx(env, state, canon=canon, context=context)
        if not verdict.ok:
            failures.append((tx_type, context, verdict.code, verdict.reason))

    if failures:
        detail = "\n".join(
            f"{tx_type}\t{context}\t{code}\t{reason}" for tx_type, context, code, reason in failures
        )
        raise AssertionError(f"A02-F003 admission gap: failure_count={len(failures)}\n{detail}")
