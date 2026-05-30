from __future__ import annotations

from pathlib import Path

from weall.runtime.gate_expr import eval_gate


ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent


def _state() -> dict:
    return {
        "accounts": {
            "@alice": {"poh_tier": 2, "banned": False, "locked": False},
            "@bob": {"poh_tier": 2, "banned": False, "locked": False},
        },
        "roles": {
            "groups_by_id": {
                "g:test": {
                    "group_id": "g:test",
                    "members": {"@alice": {"joined_at_nonce": 1}},
                    "moderators": [],
                }
            }
        },
    }


def test_group_membership_remove_allows_self_leave_without_moderator_batch496() -> None:
    ok, meta = eval_gate(
        "GroupModerator",
        signer="@alice",
        state=_state(),
        payload={"group_id": "g:test", "account": "@alice"},
        tx_type="GROUP_MEMBERSHIP_REMOVE",
    )
    assert ok is True, meta


def test_group_membership_remove_does_not_allow_removing_someone_else_batch496() -> None:
    ok, meta = eval_gate(
        "GroupModerator",
        signer="@alice",
        state=_state(),
        payload={"group_id": "g:test", "account": "@bob"},
        tx_type="GROUP_MEMBERSHIP_REMOVE",
    )
    assert ok is False
    assert meta.get("expr") == "GroupModerator"


def test_frontend_nonce_reservation_never_lowers_from_stale_observer_snapshot_batch496() -> None:
    src = (OUTER / "web" / "src" / "auth" / "session.ts").read_text(encoding="utf-8")
    assert "Never lower the" in src
    assert "const synced = Math.max(getReservedNonce(acct), Math.floor(onChain));" in src
    assert "nonceConflictNonceFromError" in src
    assert "waitForLocalAccountNonceAtLeast({" in src
    assert "timeoutMs: 5_000" in src
