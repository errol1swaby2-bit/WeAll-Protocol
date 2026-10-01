from __future__ import annotations

import copy

import pytest
from fastapi import FastAPI, Request

from weall.api.errors import ApiError
from weall.api.poh_route_auth import enforce_poh_read_authorization
from weall.runtime.ballot_policy import ballot_profile_status
from weall.runtime.block_commit import commit_block_candidate
from weall.runtime.block_hash import compute_block_hash, compute_receipts_root
from weall.runtime.block_id import compute_block_id
from weall.runtime.group_treasury_scheduler import maybe_enqueue_group_spend_execute
from weall.runtime.poh.async_scheduler import schedule_poh_async_system_txs
from weall.runtime.poh.live_scheduler import schedule_poh_live_system_txs
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs
from weall.runtime.runtime_context import RuntimeContext
from weall.runtime.state_hash import compute_state_root


def test_block_inclusion_context_forces_nonce_consumption_on_apply_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A02-F001: canonical inclusion must make a failed user tx one-shot."""

    from weall.runtime import executor as executor_mod

    seen: list[bool] = []

    def fake_apply(state, env, *, consume_nonce_on_fail: bool = False):
        del state, env
        seen.append(bool(consume_nonce_on_fail))
        return None

    monkeypatch.setattr(executor_mod, "apply_tx_atomic_meta", fake_apply)
    apply_fn = RuntimeContext.from_executor(object()).tx_execution_set.apply_tx_atomic_meta

    apply_fn({}, object(), consume_nonce_on_fail=False)

    assert seen == [True]


def _tier2_receipt_state(order: tuple[str, str]) -> dict:
    cases = {
        case_id: {
            "case_id": case_id,
            "account_id": f"@{case_id}",
            "status": "awarded",
            "tier2_receipt_emitted": False,
        }
        for case_id in order
    }
    return {
        "height": 10,
        "tip": "b10",
        "poh": {"tier2_cases": cases},
        "system_queue": [],
    }


def _async_receipt_state(order: tuple[str, str]) -> dict:
    cases = {
        case_id: {
            "case_id": case_id,
            "account_id": f"@{case_id}",
            "status": "approved",
            "outcome": "approved",
        }
        for case_id in order
    }
    return {
        "height": 10,
        "tip": "b10",
        "poh": {"async_cases": cases},
        "system_queue": [],
    }


def _live_receipt_state(order: tuple[str, str]) -> dict:
    cases = {
        case_id: {
            "case_id": case_id,
            "account_id": f"@{case_id}",
            "status": "awarded",
            "live_receipt_emitted": False,
        }
        for case_id in order
    }
    return {
        "height": 10,
        "tip": "b10",
        "poh": {"live_cases": cases},
        "system_queue": [],
    }


@pytest.mark.parametrize(
    ("factory", "scheduler"),
    [
        (_tier2_receipt_state, schedule_poh_tier2_system_txs),
        (_async_receipt_state, schedule_poh_async_system_txs),
        (_live_receipt_state, schedule_poh_live_system_txs),
    ],
)
def test_equal_root_poh_case_permutations_schedule_identical_system_work(
    factory,
    scheduler,
) -> None:
    """A04-F001/A16-F003: mapping insertion order cannot affect consensus work."""

    state_a = factory(("case-a", "case-b"))
    state_b = factory(("case-b", "case-a"))

    assert compute_state_root(state_a) == compute_state_root(state_b)

    scheduler(state_a, next_height=11)
    scheduler(state_b, next_height=11)

    assert state_a["system_queue"] == state_b["system_queue"]
    assert compute_state_root(state_a) == compute_state_root(state_b)

    payload_case_ids = [
        str(item.get("payload", {}).get("case_id") or "")
        for item in state_a["system_queue"]
        if isinstance(item, dict)
    ]
    assert payload_case_ids == sorted(payload_case_ids)


def _complete_empty_block(*, chain_id: str = "weall-p0-test") -> dict:
    receipts: list[dict] = []
    receipts_root = compute_receipts_root(receipts=receipts)
    header = {
        "chain_id": chain_id,
        "height": 1,
        "block_ts_ms": 1_000,
        "prev_block_hash": "0" * 64,
        "tx_ids": [],
        "receipts_root": receipts_root,
    }
    block_id = compute_block_id(
        chain_id=chain_id,
        height=1,
        prev_block_id="genesis",
        prev_block_hash=header["prev_block_hash"],
        ts_ms=header["block_ts_ms"],
        node_id="@validator",
        tx_ids=[],
        receipts_root=receipts_root,
    )
    return {
        "chain_id": chain_id,
        "height": 1,
        "block_ts_ms": header["block_ts_ms"],
        "prev_block_id": "genesis",
        "prev_block_hash": header["prev_block_hash"],
        "proposer": "@validator",
        "txs": [],
        "receipts": receipts,
        "header": header,
        "block_id": block_id,
        "block_hash": compute_block_hash(header=header),
    }


def test_durable_commit_rejects_unbound_received_receipt_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A06-F001: durable commit must not persist receipt metadata replay did not bind."""

    from weall.runtime import block_commit as block_commit_mod

    class DummyExecutor:
        chain_id = "weall-p0-test"

    monkeypatch.setattr(
        block_commit_mod,
        "prune_emitted_system_queue",
        lambda state: None,
    )

    block = _complete_empty_block()
    malformed = copy.deepcopy(block)
    malformed["receipts"] = [
        {
            "tx_id": "tx:attacker-controlled-alias",
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@victim",
            "nonce": 999,
            "ok": False,
        }
    ]

    meta = commit_block_candidate(
        DummyExecutor(),
        block=malformed,
        new_state={"height": 1, "tip": block["block_id"], "system_queue": []},
        applied_ids=[],
        invalid_ids=[],
    )

    assert meta.ok is False


def test_production_chain_identity_activates_strict_launch_gated_ballot_posture() -> None:
    """A09-F001: weall-prod may not silently inherit legacy/local ballot semantics."""

    status = ballot_profile_status({"chain_id": "weall-prod", "params": {}})

    assert status["strict"] is True
    assert status["active"] is False
    assert status["reason"] == "launch_gated_profile_unassigned"
    assert status["mode"] == "production"


def test_group_treasury_execute_is_not_enqueued_while_economics_is_disabled() -> None:
    """A10-F001: mandatory SYSTEM work must not be scheduled to fail on the econ lock."""

    state = {
        "height": 100,
        "time": 10_000,
        "params": {
            "economic_unlock_time": 1,
            "economics_enabled": False,
        },
        "system_queue": [],
    }
    spend = {
        "spend_id": "spend-1",
        "status": "proposed",
        "threshold": 1,
        "allowed_signers": ["@alice"],
        "signatures": {"@alice": {"signature": "test"}},
        "earliest_execute_height": 1,
    }

    queue_id = maybe_enqueue_group_spend_execute(state, spend=spend)

    assert queue_id is None
    assert state["system_queue"] == []


class _ReadStateExecutor:
    def __init__(self, state: dict) -> None:
        self._state = state

    def read_state(self) -> dict:
        return copy.deepcopy(self._state)


def _poh_request(
    *,
    path: str,
    state: dict,
    query_string: bytes = b"",
    path_params: dict | None = None,
) -> Request:
    app = FastAPI()
    app.state.executor = _ReadStateExecutor(state)
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("utf-8"),
            "query_string": query_string,
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "app": app,
            "path_params": dict(path_params or {}),
        }
    )


def test_poh_scoped_queue_requires_session_and_exact_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A12-F001: query selectors cannot substitute for the authenticated principal."""

    from weall.api import poh_route_auth

    request = _poh_request(
        path="/v1/poh/tier2/my-cases",
        state={},
        query_string=b"account=%40alice",
    )

    def missing_session(_request, _state):
        raise PermissionError("session_missing")

    monkeypatch.setattr(poh_route_auth, "require_account_session", missing_session)
    with pytest.raises(ApiError) as missing_exc:
        enforce_poh_read_authorization(request)
    assert missing_exc.value.status_code == 403

    monkeypatch.setattr(
        poh_route_auth,
        "require_account_session",
        lambda _r, _s: "@mallory",
    )
    with pytest.raises(ApiError) as mismatch_exc:
        enforce_poh_read_authorization(request)
    assert mismatch_exc.value.status_code == 403
    assert mismatch_exc.value.code == "poh_session_identity_mismatch"

    monkeypatch.setattr(
        poh_route_auth,
        "require_account_session",
        lambda _r, _s: "@alice",
    )
    assert enforce_poh_read_authorization(request) is None


def test_poh_full_tier2_case_is_participant_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A12-F001: Tier-2 juror/evidence maps may not be enumerated by unrelated viewers."""

    from weall.api import poh_route_auth

    state = {
        "poh": {
            "tier2_cases": {
                "case-1": {
                    "case_id": "case-1",
                    "account_id": "@alice",
                    "jurors": {"@juror": {"verdict": "pass"}},
                    "evidence": {"commitment": "secret-metadata"},
                }
            }
        }
    }
    request = _poh_request(
        path="/v1/poh/tier2/case/case-1",
        state=state,
        path_params={"case_id": "case-1"},
    )

    monkeypatch.setattr(
        poh_route_auth,
        "require_account_session",
        lambda _r, _s: "@mallory",
    )
    with pytest.raises(ApiError) as forbidden_exc:
        enforce_poh_read_authorization(request)
    assert forbidden_exc.value.status_code == 403
    assert forbidden_exc.value.code == "poh_case_viewer_forbidden"

    monkeypatch.setattr(
        poh_route_auth,
        "require_account_session",
        lambda _r, _s: "@juror",
    )
    assert enforce_poh_read_authorization(request) is None
