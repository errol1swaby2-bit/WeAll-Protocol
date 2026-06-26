from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

from weall.runtime.apply.governance import apply_governance
from weall.runtime.apply.groups import apply_groups
from weall.runtime.apply.rewards import RewardsApplyError, apply_rewards
from weall.runtime.apply.roles import apply_roles
from weall.runtime.chain_config import production_chain_param_safety_issues
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict | None = None,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    return TxEnvelope.from_json(
        {
            "tx_type": tx_type,
            "signer": signer,
            "nonce": nonce,
            "payload": payload or {},
            "sig": "sig",
            "system": bool(system),
            "parent": parent if parent is not None else (f"p:{tx_type}:{nonce}" if system else None),
        }
    )


def _load_genesis_verifier():
    path = ROOT / "scripts" / "assert_production_genesis_artifacts.py"
    spec = importlib.util.spec_from_file_location("assert_production_genesis_artifacts", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_production_chain_params_reject_open_bootstrap_roleless_juror_and_demo_flags() -> None:
    issues = production_chain_param_safety_issues(
        {
            "params": {
                "poh_bootstrap_mode": "open",
                "allow_case_scoped_juror_without_role": True,
                "poh_allow_case_scoped_juror_without_role": "1",
                "bootstrap_allow_case_scoped_juror_without_role": "yes",
                "seeded_demo_review_fallback": "on",
            }
        }
    )

    joined = "\n".join(issues)
    assert "params.poh_bootstrap_mode=open" in joined
    assert "params.allow_case_scoped_juror_without_role=true" in joined
    assert "params.poh_allow_case_scoped_juror_without_role=true" in joined
    assert "params.bootstrap_allow_case_scoped_juror_without_role=true" in joined
    assert "params.seeded_demo_review_fallback=true" in joined


def test_production_genesis_verifier_rejects_open_bootstrap_and_roleless_juror_flags(tmp_path: Path) -> None:
    verifier = _load_genesis_verifier()
    manifest_path = ROOT / "configs" / "chains" / "weall-genesis.json"
    tx_index_path = ROOT / "generated" / "tx_index.json"
    genesis = json.loads((ROOT / "configs" / "genesis.ledger.prod.json").read_text(encoding="utf-8"))
    genesis.setdefault("params", {})["poh_bootstrap_mode"] = "open"
    genesis["params"]["allow_case_scoped_juror_without_role"] = True
    genesis["params"]["seeded_demo_review_fallback"] = True

    bad_genesis_path = tmp_path / "bad-genesis.json"
    bad_genesis_path.write_text(json.dumps(genesis, sort_keys=True), encoding="utf-8")

    report = verifier.verify(
        manifest_path=manifest_path,
        genesis_path=bad_genesis_path,
        tx_index_path=tx_index_path,
    )
    codes = {issue.get("code") for issue in report["issues"]}

    assert "genesis_poh_bootstrap_mode_not_allowlist" in codes
    assert "genesis_poh_bootstrap_open_forbidden_in_prod" in codes
    assert "genesis_forbidden_production_chain_param" in codes


def test_production_founder_bootstrap_grant_is_auditable_receipt_backed_and_transitional() -> None:
    genesis = json.loads((ROOT / "configs" / "genesis.ledger.prod.json").read_text(encoding="utf-8"))
    params = genesis["params"]
    founder = params["bootstrap_founder_account"]
    grants_root = genesis["poh"]["bootstrap_grants"]
    grants = grants_root["by_id"]
    grant_ids = grants_root["by_account"][founder]

    assert params["poh_bootstrap_mode"] == "allowlist"
    assert int(params["bootstrap_expires_height"]) > 0
    assert int(params["poh_bootstrap_max_height"]) == 0
    assert params["poh_bootstrap_auto_lock_rule"] == "active_validators>=BFT_MIN_VALIDATORS"
    assert grant_ids

    for grant_id in grant_ids:
        grant = grants[grant_id]
        assert grant["account_id"] == founder
        assert grant["grant_type"] == "poh_tier2_live_verified"
        assert grant["grant_height"] == 0
        assert grant["expires_height"] > grant["grant_height"]
        assert grant["reason_code"]
        assert grant["authority_path"]
        assert grant["review_condition"]
        assert grant["receipt_id"].startswith("poh_bootstrap_receipt:")
        assert genesis["accounts"][founder]["poh_bootstrap_receipt_id"] == grant["receipt_id"]


def _native_poh_state() -> dict:
    return {
        "height": 10,
        "chain_id": "weall-prod",
        "params": {
            "poh": {
                "async_n_jurors": 1,
                "async_min_reviews": 1,
                "async_approval_threshold": 1,
                "async_rejection_threshold": 1,
                "async_expiry_window_blocks": 100,
            }
        },
        "accounts": {
            "@founder": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "balance": 0, "reputation_milli": 10_000},
            "@alice": {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False, "balance": 0, "reputation_milli": 10_000},
            "SYSTEM": {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False, "balance": 0},
        },
        "roles": {
            "jurors": {
                "active_set": ["@founder"],
                "by_id": {"@founder": {"account_id": "@founder", "enrolled": True, "active": True}},
            }
        },
    }


def test_native_async_live_path_grows_juror_pool_from_founder_bootstrap() -> None:
    st = _native_poh_state()

    apply_tx(
        st,
        _env(
            "POH_ASYNC_REQUEST_OPEN",
            "@alice",
            1,
            {"account_id": "@alice", "case_id": "async-alice", "response_commitment": "sha256:response"},
        ),
    )
    apply_tx(
        st,
        _env(
            "POH_ASYNC_EVIDENCE_DECLARE",
            "@alice",
            2,
            {"case_id": "async-alice", "evidence_id": "ev1", "evidence_commitment": "sha256:evidence"},
        ),
    )
    apply_tx(
        st,
        _env("POH_ASYNC_JUROR_ASSIGN", "SYSTEM", 3, {"case_id": "async-alice", "jurors": ["@founder"]}, system=True),
    )
    apply_tx(st, _env("POH_ASYNC_JUROR_ACCEPT", "@founder", 4, {"case_id": "async-alice"}))
    apply_tx(st, _env("POH_ASYNC_REVIEW_SUBMIT", "@founder", 5, {"case_id": "async-alice", "verdict": "approve"}))
    apply_tx(st, _env("POH_ASYNC_FINALIZE", "SYSTEM", 6, {"case_id": "async-alice"}, system=True))
    assert st["accounts"]["@alice"]["poh_tier"] == 1

    session_commitment = "sha256:live-session"
    out = apply_tx(
        st,
        _env(
            "POH_LIVE_REQUEST_OPEN",
            "@alice",
            7,
            {
                "account_id": "@alice",
                "session_commitment": session_commitment,
                "room_commitment": "sha256:room",
                "prompt_commitment": "sha256:prompt",
            },
        ),
    )
    live_case_id = out["case_id"]
    apply_tx(st, _env("POH_LIVE_JUROR_ASSIGN", "SYSTEM", 8, {"case_id": live_case_id, "jurors": ["@founder"]}, system=True))
    apply_tx(st, _env("POH_LIVE_JUROR_ACCEPT", "@founder", 9, {"case_id": live_case_id, "session_commitment": session_commitment}))
    apply_tx(
        st,
        _env(
            "POH_LIVE_ATTENDANCE_MARK",
            "@founder",
            10,
            {"case_id": live_case_id, "juror_id": "@founder", "attended": True, "session_commitment": session_commitment},
        ),
    )
    apply_tx(
        st,
        _env(
            "POH_LIVE_VERDICT_SUBMIT",
            "@founder",
            11,
            {"case_id": live_case_id, "verdict": "pass", "session_commitment": session_commitment},
        ),
    )
    apply_tx(st, _env("POH_LIVE_FINALIZE", "SYSTEM", 12, {"case_id": live_case_id}, system=True))
    assert st["accounts"]["@alice"]["poh_tier"] == 2

    apply_tx(st, _env("ROLE_JUROR_ENROLL", "@alice", 13, {"account_id": "@alice"}))
    apply_tx(st, _env("ROLE_JUROR_ACTIVATE", "SYSTEM", 14, {"account_id": "@alice"}, system=True))
    assert "@alice" in st["roles"]["jurors"]["active_set"]


def _governance_state(*, unlocked: bool) -> dict:
    genesis_time = 1_700_000_000
    unlock_time = genesis_time + 90 * 24 * 60 * 60
    return {
        "height": 20,
        "chain_id": "weall-prod",
        "time": unlock_time if unlocked else genesis_time,
        "params": {
            "mode": "production",
            "genesis_time": genesis_time,
            "economic_unlock_time": unlock_time,
            "economics_enabled": bool(unlocked),
        },
        "accounts": {
            "@val1": {"poh_tier": 2, "banned": False, "locked": False},
            "SYSTEM": {"poh_tier": 0, "banned": False, "locked": False},
        },
        "roles": {"validators": {"active_set": ["@val1"]}},
        "gov_proposals_by_id": {},
    }


def test_governance_treasury_spend_actions_remain_blocked_by_genesis_econ_lock() -> None:
    st = _governance_state(unlocked=False)

    with pytest.raises(ApplyError) as exc:
        apply_governance(
            st,
            _env(
                "GOV_PROPOSAL_CREATE",
                "@val1",
                1,
                {
                    "proposal_id": "p-treasury-before-unlock",
                    "title": "execute treasury spend",
                    "rules": {"start_stage": "voting"},
                    "actions": [{"tx_type": "TREASURY_SPEND_EXECUTE", "payload": {"spend_id": "spend-1"}}],
                },
            ),
        )

    assert exc.value.reason == "economic_actions_locked"


def test_governance_allowlists_proposal_voted_treasury_spend_execute_after_unlock() -> None:
    st = _governance_state(unlocked=True)

    apply_governance(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@val1",
            1,
            {
                "proposal_id": "p-treasury-after-unlock",
                "title": "execute treasury spend",
                "rules": {"start_stage": "voting"},
                "actions": [{"tx_type": "TREASURY_SPEND_EXECUTE", "payload": {"spend_id": "spend-1"}}],
            },
        ),
    )

    proposal = st["gov_proposals_by_id"]["p-treasury-after-unlock"]
    assert proposal["actions"] == [{"tx_type": "TREASURY_SPEND_EXECUTE", "payload": {"spend_id": "spend-1"}}]
    assert proposal["eligible_validator_ids"] == ["@val1"]

    proposal["stage"] = "tallied"
    proposal["tallies"] = [{"height": 21, "payload": {"proposal_id": "p-treasury-after-unlock", "passed": True}}]
    apply_governance(
        st,
        _env("GOV_EXECUTE", "SYSTEM", 2, {"proposal_id": "p-treasury-after-unlock"}, system=True, parent="gov:p-treasury-after-unlock"),
    )

    queued = st.get("system_queue", [])
    assert any(item.get("tx_type") == "TREASURY_SPEND_EXECUTE" and item.get("payload", {}).get("spend_id") == "spend-1" for item in queued)


def test_rewards_remain_disabled_before_economics_activation() -> None:
    st = {
        "height": 5,
        "time": 1,
        "params": {"economic_unlock_time": 999, "economics_enabled": False},
        "accounts": {"SYSTEM": {"poh_tier": 0}},
    }

    with pytest.raises(ValueError) as exc:
        apply_rewards(
            st,
            _env("BLOCK_REWARD_MINT", "SYSTEM", 1, {"to": "@val1", "amount": 1}, system=True),
        )

    assert "economics" in str(exc.value)


def test_global_emissary_nominate_vote_seat_remove_syncs_protocol_treasury_signers() -> None:
    st = {
        "height": 10,
        "accounts": {
            "@e1": {"poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 10_000},
            "@e2": {"poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 10_000},
            "SYSTEM": {"poh_tier": 0, "banned": False, "locked": False},
        },
        "roles": {
            "emissaries": {"by_id": {}, "nominations": {}, "seated": []},
            "treasuries_by_id": {
                "TREASURY_PROTOCOL": {
                    "treasury_id": "TREASURY_PROTOCOL",
                    "label": "protocol",
                    "require_emissary_signers": True,
                    "auto_sync_emissaries": True,
                    "signers": [],
                    "threshold": 2,
                }
            },
        },
    }

    apply_roles(st, _env("ROLE_EMISSARY_NOMINATE", "@e1", 1, {"account_id": "@e1"}))
    apply_roles(st, _env("ROLE_EMISSARY_VOTE", "@e2", 2, {"account_id": "@e1"}))
    assert st["roles"]["emissaries"]["nominations"]["@e1"]["votes"] == ["@e1", "@e2"]

    apply_roles(st, _env("ROLE_EMISSARY_SEAT", "SYSTEM", 3, {"account_id": "@e1"}, system=True))
    assert st["roles"]["treasuries_by_id"]["TREASURY_PROTOCOL"]["signers"] == []

    apply_roles(st, _env("ROLE_EMISSARY_NOMINATE", "@e2", 4, {"account_id": "@e2"}))
    apply_roles(st, _env("ROLE_EMISSARY_SEAT", "SYSTEM", 5, {"account_id": "@e2"}, system=True))
    treasury_policy = st["roles"]["treasuries_by_id"]["TREASURY_PROTOCOL"]
    assert treasury_policy["signers"] == ["@e1", "@e2"]
    assert treasury_policy["threshold"] == 2

    apply_roles(st, _env("ROLE_EMISSARY_REMOVE", "SYSTEM", 6, {"account_id": "@e1", "reason": "term_end"}, system=True))
    treasury_policy = st["roles"]["treasuries_by_id"]["TREASURY_PROTOCOL"]
    assert treasury_policy["signers"] == []
    assert treasury_policy["threshold"] == 2
    assert treasury_policy["synced_from_emissaries_reason"] == "emissary_removed:inert_until_two_emissaries"


def test_group_emissary_election_finalize_syncs_group_and_treasury_signers() -> None:
    candidates = ["@a", "@b", "@c", "@d", "@e"]
    st = {
        "height": 10,
        "accounts": {account: {"poh_tier": 2, "banned": False, "locked": False} for account in ["@owner", *candidates]},
        "roles": {
            "groups_by_id": {
                "g1": {
                    "group_id": "g1",
                    "created_by": "@owner",
                    "treasury_id": "TREASURY_GROUP::g1",
                    "signers": ["@owner"],
                    "threshold": 1,
                    "members": {account: {"account": account} for account in ["@owner", *candidates]},
                }
            },
            "treasuries_by_id": {
                "TREASURY_GROUP::g1": {
                    "treasury_id": "TREASURY_GROUP::g1",
                    "label": "group",
                    "group_id": "g1",
                    "signers": ["@owner"],
                    "threshold": 1,
                }
            }
        },
    }

    out = apply_groups(
        st,
        _env(
            "GROUP_EMISSARY_ELECTION_CREATE",
            "@owner",
            1,
            {"group_id": "g1", "election_id": "ge1", "seats": 5, "candidates": candidates, "start_height": 11, "end_height": 12},
        ),
    )
    assert out["n_candidates"] == 5

    st["height"] = 12
    final = apply_groups(st, _env("GROUP_EMISSARY_ELECTION_FINALIZE", "@owner", 2, {"election_id": "ge1"}))
    winners = final["winners"]
    assert winners == sorted(candidates)
    assert st["groups_by_id"]["g1"]["emissaries"] == winners
    assert st["groups_by_id"]["g1"]["signers"] == winners
    assert st["groups_by_id"]["g1"]["threshold"] == 3
    treasury_policy = st["roles"]["treasuries_by_id"]["TREASURY_GROUP::g1"]
    assert treasury_policy["require_emissary_signers"] is True
    assert treasury_policy["signers"] == winners
    assert treasury_policy["threshold"] == 3
