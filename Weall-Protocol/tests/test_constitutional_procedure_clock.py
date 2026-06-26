from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.constitutional_clock import (
    expected_block_time_ms,
    is_too_early,
    policy_from_manifest,
    policy_from_state,
    procedure_height,
    slot_time_ms,
)
from weall.runtime.dispute_engine import tick_dispute_lifecycle
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.chain_manifest import load_chain_manifest, chain_manifest_status
from weall.tx.canon import load_tx_index_json


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_index():
    return load_tx_index_json(_repo_root() / "generated" / "tx_index.json")


def _clock_meta() -> dict:
    return {
        "enabled": True,
        "target_block_interval_ms": 20_000,
        "empty_blocks_enabled": True,
        "procedure_time_source": "finalized_block_height",
        "block_time_derivation": "genesis_time_plus_height_times_interval",
        "no_fast_forward": True,
        "no_height_skip": True,
        "allowed_clock_skew_ms": 2_000,
        "genesis_time_ms": 0,
    }


def _state() -> dict:
    return {
        "height": 0,
        "finalized_height": 0,
        "meta": {"constitutional_clock": _clock_meta()},
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation": 10},
            "SYSTEM": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation": 10},
        },
        "roles": {},
        "system_queue": [],
        "params": {
            "gov_action_allowlist": ["ECONOMICS_ACTIVATION", "GOV_RULES_SET", "GOV_QUORUM_SET"],
        },
    }


def _env(tx_type: str, signer: str = "alice", nonce: int = 1, payload: dict | None = None, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload or {}, sig="", system=system)


def test_manifest_pins_twenty_second_constitutional_clock() -> None:
    manifest_path = _repo_root() / "configs" / "chains" / "weall-genesis.json"
    manifest = load_chain_manifest(str(manifest_path), required=True)
    policy = policy_from_manifest(manifest)

    assert policy.enabled is True
    assert policy.target_block_interval_ms == 20_000
    assert policy.empty_blocks_enabled is True
    assert policy.procedure_time_source == "finalized_block_height"
    assert slot_time_ms(genesis_time_ms=0, height=1, target_block_interval_ms=20_000) == 20_000
    assert expected_block_time_ms(policy, height=3) == 60_000

    status = chain_manifest_status(
        manifest=manifest,
        chain_id=str(manifest.chain_id),
        mode="prod",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
        strict=True,
    )
    assert status["ok"] is True
    assert status.get("constitutional_clock", {}).get("target_block_interval_ms") == 20_000


def test_clock_policy_rejects_non_twenty_second_strict_manifest(tmp_path: Path) -> None:
    source = json.loads((_repo_root() / "configs" / "chains" / "weall-genesis.json").read_text())
    source["constitutional_clock"]["target_block_interval_ms"] = 10_000
    manifest_path = tmp_path / "bad-clock.json"
    manifest_path.write_text(json.dumps(source))
    manifest = load_chain_manifest(str(manifest_path), required=True)

    status = chain_manifest_status(
        manifest=manifest,
        chain_id=str(manifest.chain_id),
        mode="prod",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
        strict=True,
    )
    assert status["ok"] is False
    assert any("constitutional_clock" in issue for issue in status["issues"])


def test_executable_proposal_must_deliberate_and_can_collect_comments_and_versions() -> None:
    idx = _load_index()
    st = _state()

    with pytest.raises(ApplyError) as exc:
        apply_tx(
            st,
            _env(
                "GOV_PROPOSAL_CREATE",
                payload={
                    "proposal_id": "p-fast",
                    "title": "Fast",
                    "body": "skip",
                    "rules": {"start_stage": "voting"},
                    "actions": [{"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_bps": 5000}}],
                },
            ),
        )
    assert "constitutional_proposal_must_deliberate_before_voting" in str(exc.value)

    apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            payload={"proposal_id": "p1", "title": "Original", "body": "Deliberate this"},
        ),
    )
    apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_COMMENT",
            nonce=2,
            payload={"proposal_id": "p1", "body": "Please make this clearer"},
        ),
    )
    apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_EDIT",
            nonce=3,
            payload={"proposal_id": "p1", "title": "Revised", "body": "Adjusted after comments", "revision_reason": "popular feedback"},
        ),
    )

    proposal = st["gov_proposals_by_id"]["p1"]
    assert len(proposal["comments"]) == 1
    assert proposal["comments"][0]["body"] == "Please make this clearer"
    assert proposal["current_version"] == 2
    assert len(proposal["versions"]) == 2
    assert proposal["versions"][0]["title"] == "Original"
    assert proposal["versions"][1]["title"] == "Revised"

    apply_tx(
        st,
        _env("GOV_STAGE_SET", signer="SYSTEM", nonce=1, payload={"proposal_id": "p1", "stage": "validation", "_due_height": 1}, system=True),
    )
    proposal = st["gov_proposals_by_id"]["p1"]
    assert proposal["stage"] == "validation"
    assert proposal["frozen_version"] == 2


def test_dispute_verdict_opens_appeal_window_and_engine_finalizes_after_deadline() -> None:
    st = _state()
    st["height"] = 10
    st["finalized_height"] = 10
    st["disputes_by_id"] = {"d1": {"dispute_id": "d1", "stage": "review", "appeal_window_blocks": 3}}

    apply_dispute(
        st,
        _env(
            "DISPUTE_RESOLVE",
            signer="SYSTEM",
            nonce=1,
            payload={"dispute_id": "d1", "resolution": {"summary": "warning"}, "_due_height": 11},
            system=True,
        ),
    )
    d = st["disputes_by_id"]["d1"]
    assert d["stage"] == "appeal_window"
    assert d["appeal_deadline_height"] == 14
    assert not any(item.get("tx_type") == "DISPUTE_FINAL_RECEIPT" for item in st.get("system_queue", []))

    st["height"] = 12
    apply_dispute(
        st,
        _env("DISPUTE_APPEAL", nonce=2, payload={"dispute_id": "d1", "reason": "new evidence"}),
    )
    assert st["disputes_by_id"]["d1"]["stage"] == "appealed"

    queued = tick_dispute_lifecycle(st, next_height=15)
    assert queued == 0
    assert not any(item.get("tx_type") == "DISPUTE_FINAL_RECEIPT" for item in st.get("system_queue", []))

    st["disputes_by_id"]["d1"]["stage"] = "appeal_window"
    queued = tick_dispute_lifecycle(st, next_height=15)
    assert queued == 1
    assert any(item.get("tx_type") == "DISPUTE_FINAL_RECEIPT" and item.get("due_height") == 15 for item in st.get("system_queue", []))


def test_dispute_final_receipt_moves_to_finalized() -> None:
    st = _state()
    st["disputes_by_id"] = {"d1": {"dispute_id": "d1", "stage": "appeal_window"}}
    apply_dispute(
        st,
        _env("DISPUTE_FINAL_RECEIPT", signer="SYSTEM", nonce=1, payload={"dispute_id": "d1"}, system=True),
    )
    assert st["disputes_by_id"]["d1"]["stage"] == "finalized"


def test_procedure_height_prefers_finalized_height() -> None:
    assert procedure_height({"height": 10, "finalized_height": 7}) == 7
    assert procedure_height({"height": 10, "finalized": {"height": 8}}) == 8
    assert procedure_height({"height": 10}) == 10


def test_not_before_gate_uses_real_genesis_time_only() -> None:
    legacy_policy = policy_from_manifest({"constitutional_clock": {**_clock_meta(), "genesis_time_ms": 0}})
    assert is_too_early(legacy_policy, height=1, now_ms=0) is False

    launch_policy = policy_from_manifest({"constitutional_clock": {**_clock_meta(), "genesis_time_ms": 1_000_000}})
    assert is_too_early(launch_policy, height=1, now_ms=1_010_000) is True
    assert is_too_early(launch_policy, height=1, now_ms=1_018_000) is False

def test_constitutional_clock_default_draft_proposals_auto_progress_unless_disabled() -> None:
    st = _state()

    apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            payload={"proposal_id": "p-default", "title": "Default", "body": "Default draft should advance by clock"},
        ),
    )
    assert st["gov_proposals_by_id"]["p-default"]["stage"] == "draft"
    assert st["gov_proposals_by_id"]["p-default"]["auto_progress_enabled"] is True

    apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            nonce=2,
            payload={
                "proposal_id": "p-manual",
                "title": "Manual",
                "body": "Manual fixture can opt out",
                "rules": {"auto_progress_enabled": False},
            },
        ),
    )
    assert st["gov_proposals_by_id"]["p-manual"]["auto_progress_enabled"] is False

