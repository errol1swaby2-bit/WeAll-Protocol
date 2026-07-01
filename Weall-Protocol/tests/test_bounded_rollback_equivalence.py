from __future__ import annotations

import copy
from typing import Any, Callable

import pytest

from weall.runtime.domain_apply import (
    ApplyError,
    apply_tx_atomic_meta,
    apply_tx_atomic_meta_bounded_rollback,
    apply_tx_atomic_meta_deepcopy,
)
from weall.runtime.state_hash import compute_state_root

Json = dict[str, Any]
ApplyFn = Callable[..., Json | None]


def _account(nonce: int = 0, *, tier: int = 2) -> Json:
    return {
        "nonce": int(nonce),
        "poh_tier": int(tier),
        "banned": False,
        "locked": False,
        "reputation": "0",
        "keys": {"by_id": {"k:test": {"pubkey": "k:test", "revoked": False}}},
    }


def _base_state() -> Json:
    return {
        "chain_id": "rollback-audit",
        "height": 0,
        "tip": "",
        "tip_hash": "",
        "accounts": {
            "@alice": _account(),
            "@bob": _account(),
            "@carol": _account(),
            "@validator": _account(),
        },
        "params": {"system_signer": "SYSTEM", "poh_bootstrap_open": True},
        "roles": {
            "validators": {"active_set": ["@validator"]},
            "node_operators": {"by_id": {}},
        },
        "consensus": {"validator_set": {"active_set": ["@validator"]}},
        "poh": {},
        "content": {"posts": {}, "comments": {}, "reactions": {}, "flags": {}},
    }


def _tx(tx_type: str, signer: str, nonce: int, payload: Json | None = None) -> Json:
    return {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": int(nonce),
        "payload": payload or {},
        "sig": "test",
    }


def _run_sequence(state: Json, apply_fn: ApplyFn, txs: list[Json]) -> tuple[Json, list[Json]]:
    receipts: list[Json] = []
    for env in txs:
        try:
            meta = apply_fn(state, copy.deepcopy(env), consume_nonce_on_fail=False)
            receipts.append(
                {
                    "tx_type": env["tx_type"],
                    "signer": env["signer"],
                    "nonce": env["nonce"],
                    "ok": meta is not None,
                    "meta": meta,
                }
            )
        except ApplyError as exc:
            receipts.append(
                {
                    "tx_type": env["tx_type"],
                    "signer": env["signer"],
                    "nonce": env["nonce"],
                    "ok": False,
                    "code": exc.code,
                    "reason": exc.reason,
                    "details": exc.details,
                }
            )
    return state, receipts


def test_bounded_rollback_matches_full_deepcopy_for_mixed_success_and_failure_load() -> None:
    txs = [
        _tx("PROFILE_UPDATE", "@alice", 1, {"display_name": "Alice", "bio": "Builder"}),
        _tx("GROUP_CREATE", "@alice", 2, {"group_id": "g:builders", "charter": "Build in public"}),
        _tx("CONTENT_POST_CREATE", "@alice", 3, {"post_id": "post:1", "body": "hello", "tags": ["group:g:builders"]}),
        _tx("CONTENT_COMMENT_CREATE", "@bob", 1, {"comment_id": "comment:1", "post_id": "post:1", "body": "reply"}),
        _tx("CONTENT_REACTION_SET", "@carol", 1, {"target_id": "post:1", "reaction": "like"}),
        _tx("FOLLOW_SET", "@bob", 2, {"target": "@alice", "active": True}),
        _tx("GOV_PROPOSAL_CREATE", "@alice", 4, {"proposal_id": "prop:1", "title": "Tune", "body": "proposal"}),
        _tx("GOV_PROPOSAL_COMMENT", "@bob", 3, {"proposal_id": "prop:1", "comment_id": "gov-comment:1", "body": "comment"}),
        _tx("VALIDATOR_CANDIDATE_REGISTER", "@validator", 1, {"account": "@validator", "pubkey": "vpub", "node_id": "node-v", "endpoint": "https://node.invalid"}),
        _tx("CONTENT_REACTION_SET", "@carol", 2, {"target_id": "", "reaction": "like"}),
        _tx("PROFILE_UPDATE", "@carol", 2, {"display_name": "Carol"}),
    ]

    deepcopy_state, deepcopy_receipts = _run_sequence(
        copy.deepcopy(_base_state()), apply_tx_atomic_meta_deepcopy, txs
    )
    bounded_state, bounded_receipts = _run_sequence(
        copy.deepcopy(_base_state()), apply_tx_atomic_meta_bounded_rollback, txs
    )

    assert bounded_receipts == deepcopy_receipts
    assert bounded_state == deepcopy_state
    assert compute_state_root(bounded_state) == compute_state_root(deepcopy_state)
    assert bounded_state["content"]["reactions"]["@carol:post:1"]["reaction"] == "like"
    assert "@carol:" not in bounded_state["content"]["reactions"]
    assert "@carol::" not in bounded_state["content"]["reactions"]
    assert bounded_state["accounts"]["@carol"]["nonce"] == 2


def test_bounded_rollback_restores_partial_writes_after_apply_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.runtime import domain_apply as da

    original = da._apply_tx_internal

    def mutates_then_rejects(state: Json, env: Any) -> Json | None:
        state.setdefault("audit_probe", {})["partial"] = {"tx_type": env.tx_type}
        raise ApplyError("probe", "forced_reject_after_touch", {"tx_type": env.tx_type})

    env = _tx("PROFILE_UPDATE", "@alice", 1, {"display_name": "Alice"})

    for apply_fn in (apply_tx_atomic_meta_deepcopy, apply_tx_atomic_meta_bounded_rollback, apply_tx_atomic_meta):
        state = copy.deepcopy(_base_state())
        monkeypatch.setattr(da, "_apply_tx_internal", mutates_then_rejects)
        with pytest.raises(ApplyError, match="forced_reject_after_touch"):
            apply_fn(state, copy.deepcopy(env), consume_nonce_on_fail=False)
        assert "audit_probe" not in state
        assert state == _base_state()

    monkeypatch.setattr(da, "_apply_tx_internal", original)


def test_default_atomic_meta_uses_bounded_rollback_entrypoint(monkeypatch: pytest.MonkeyPatch) -> None:
    from weall.runtime import domain_apply as da

    original = da.run_with_bounded_rollback
    calls = {"count": 0}

    def counted_run_with_bounded_rollback(state: Json, fn: Callable[[Json], Any]) -> tuple[Any, int]:
        calls["count"] += 1
        return original(state, fn)

    monkeypatch.setattr(da, "run_with_bounded_rollback", counted_run_with_bounded_rollback)

    state = copy.deepcopy(_base_state())
    meta = da.apply_tx_atomic_meta(
        state,
        _tx("PROFILE_UPDATE", "@alice", 1, {"display_name": "Alice"}),
        consume_nonce_on_fail=False,
    )

    assert calls["count"] == 1
    assert meta is not None
    assert state["accounts"]["@alice"]["nonce"] == 1


def test_legacy_deepcopy_oracle_remains_equivalent_to_new_default() -> None:
    txs = [
        _tx("PROFILE_UPDATE", "@alice", 1, {"display_name": "Alice"}),
        _tx("CONTENT_POST_CREATE", "@alice", 2, {"post_id": "post:equiv", "body": "hello"}),
        _tx("CONTENT_COMMENT_CREATE", "@bob", 1, {"comment_id": "comment:equiv", "post_id": "post:equiv", "body": "reply"}),
        _tx("CONTENT_REACTION_SET", "@carol", 1, {"target_id": "post:equiv", "reaction": "like"}),
    ]

    default_state, default_receipts = _run_sequence(copy.deepcopy(_base_state()), apply_tx_atomic_meta, txs)
    deepcopy_state, deepcopy_receipts = _run_sequence(copy.deepcopy(_base_state()), apply_tx_atomic_meta_deepcopy, txs)

    assert default_receipts == deepcopy_receipts
    assert default_state == deepcopy_state
    assert compute_state_root(default_state) == compute_state_root(deepcopy_state)
