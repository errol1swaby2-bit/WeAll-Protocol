from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from weall.runtime.domain_apply import apply_tx_atomic_meta_bounded_rollback
from weall.runtime.tx_admission_types import TxEnvelope

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
            "group_treasury_timelock_blocks": 0,
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
    signer: str = "@tester",
    system: bool = False,
    parent: str | None = None,
    nonce: int = 1,
) -> TxEnvelope:
    if system and parent is None:
        parent = "PARENT-A02"
    return TxEnvelope(
        tx_type=tx_type,
        signer="SYSTEM" if system and signer == "@tester" else signer,
        nonce=nonce,
        payload=copy.deepcopy(payload or {}),
        parent=parent,
        system=system,
        chain_id="weall-testnet-v1",
    )


def _apply(
    state: dict[str, Any],
    tx_type: str,
    payload: dict[str, Any] | None = None,
    *,
    signer: str = "@tester",
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

    if tx_type in {
        "DISPUTE_JUROR_ACCEPT",
        "DISPUTE_JUROR_ATTENDANCE",
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
    if tx_type == "DISPUTE_JUROR_ATTENDANCE":
        payload["present"] = True
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
        case_id = _open_async_poh(state)
        if tx_type == "POH_ASYNC_REQUEST_OPEN":
            payload.update(
                {
                    "account_id": "@tester",
                    "case_id": case_id,
                    "challenge_id": "prompt-a16",
                    "challenge_commitment": "sha256:" + ("1" * 64),
                }
            )
            return "@tester", payload

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
        case_id = _open_tier2_poh(state)
        if tx_type == "POH_TIER2_REQUEST_OPEN":
            payload.update(
                {
                    "account_id": "@tester",
                    "target_tier": 2,
                    "video_commitment": "p2-a02-tier2-video-commitment",
                }
            )
            return "@tester", payload

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
        case_id = _open_live_poh(state)
        if tx_type == "POH_LIVE_REQUEST_OPEN":
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

    system = str(row.get("origin") or "").upper() == "SYSTEM"
    block_only = str(row.get("context") or "").lower() == "block"
    receipt_only = bool(row.get("receipt_only"))
    return _tx(
        tx_type,
        payload,
        signer=signer,
        system=system,
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
