from __future__ import annotations

from pathlib import Path

from weall.runtime.poh.eligibility import get_required_poh_tier, require_poh_tier
from weall.runtime.poh.state import effective_poh_tier, poh_tier_label, set_account_poh_status


def test_legacy_live_state_is_user_facing_tier2_during_migration() -> None:
    state = {"height": 7, "accounts": {"@alice": {"poh_tier": 2}}, "poh": {}}
    set_account_poh_status(state, account_id="@alice", poh_tier=2, verified_at_height=7, last_updated_height=7)

    assert effective_poh_tier(state, "@alice") == 2
    assert poh_tier_label(3) == "Live Verified Human"


def test_former_live_user_actions_are_v2_tier2_gated() -> None:
    state = {"height": 9, "accounts": {"@alice": {"poh_tier": 2}}, "poh": {}}
    set_account_poh_status(state, account_id="@alice", poh_tier=2, verified_at_height=9, last_updated_height=9)

    for tx_type in (
        "CONTENT_POST_CREATE",
        "CONTENT_MEDIA_DECLARE",
        "GOV_PROPOSAL_CREATE",
        "GOV_VOTE_CAST",
        "GROUP_CREATE",
        "ROLE_JUROR_ENROLL",
        "VALIDATOR_REGISTER",
        "TREASURY_CREATE",
    ):
        assert get_required_poh_tier(tx_type) == 2
        require_poh_tier(state, "@alice", tx_type)


def test_tx_canon_has_no_user_origin_live_gate_after_v2_remap() -> None:
    spec = Path(__file__).resolve().parents[1] / "specs" / "tx_canon" / "tx_canon.yaml"
    text = spec.read_text(encoding="utf-8")
    legacy_live_gate = "gate: " + "Live" + "+"
    assert legacy_live_gate not in text
    assert "V2.1 PoH migration" in text


def test_content_apply_post_create_accepts_v2_tier2_gate() -> None:
    from weall.runtime.apply.content import apply_content
    from weall.runtime.tx_admission_types import TxEnvelope

    state = {"height": 10, "accounts": {"@alice": {"poh_tier": 2, "nonce": 0}}, "content": {}}
    env = TxEnvelope(
        tx_type="CONTENT_POST_CREATE",
        signer="@alice",
        nonce=1,
        payload={"post_id": "post:alice:1", "body": "hello v2.1"},
    )

    result = apply_content(state, env)

    assert result == {"applied": "CONTENT_POST_CREATE", "post_id": "post:alice:1"}
    assert state["content"]["posts"]["post:alice:1"]["author"] == "@alice"


def test_content_apply_post_create_rejects_tier1_after_v2_gate() -> None:
    import pytest
    from weall.runtime.apply.content import ContentApplyError, apply_content
    from weall.runtime.tx_admission_types import TxEnvelope

    state = {"height": 10, "accounts": {"@alice": {"poh_tier": 1, "nonce": 0}}, "content": {}}
    env = TxEnvelope(
        tx_type="CONTENT_POST_CREATE",
        signer="@alice",
        nonce=1,
        payload={"post_id": "post:alice:1", "body": "hello v2.1"},
    )

    with pytest.raises(ContentApplyError) as exc:
        apply_content(state, env)

    assert exc.value.reason == "insufficient_poh_tier"
    assert exc.value.details["required"] == 2
