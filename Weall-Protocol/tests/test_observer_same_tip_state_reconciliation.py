"""Observer-only reconciliation: no false proof on mismatched committed state.

All test identities are deterministic mocks. This does not prove a real
multi-machine validator network or authorize public PoH onboarding.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from weall.api.routes_public_parts import status as status_routes
from weall.api.routes_public_parts import tx as tx_routes

TX_ID = "tx:historical-confirmed-in-both-nodes"
UPSTREAM = "http://127.0.0.1:8001"
BLOCK_ID = "canonical-block-3"
IDENTITY = {
    "chain_id": "weall-controlled-devnet",
    "height": 114,
    "tip_hash": "canonical-tip-114",
    "state_root": "canonical-state-root-114",
    "schema_version": "1",
    "tx_index_hash": "matching-tx-index-hash",
    "protocol_profile_hash": "matching-profile-hash",
}


def _setup(monkeypatch, tmp_path: Path, *, proof: bool = False) -> Path:
    now = int(time.time() * 1000)
    queue = tmp_path / "observer_tx_queue.json"
    queue.write_text(
        json.dumps(
            {
                "version": 2,
                "records": [
                    {
                        "tx_id": TX_ID,
                        "chain_id": IDENTITY["chain_id"],
                        "created_ms": now,
                        "updated_ms": now,
                        "upstream_status": "confirmed",
                        "confirmed_height": 3,
                        "confirmed_block_id": BLOCK_ID,
                        "local_state_synced": proof,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("WEALL_TX_QUEUE_PATH", str(queue))
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setattr(
        tx_routes,
        "_safe_executor",
        lambda _request: SimpleNamespace(chain_id=IDENTITY["chain_id"]),
    )
    monkeypatch.setattr(tx_routes, "_local_height_for_request", lambda _request: 114)
    monkeypatch.setattr(
        tx_routes,
        "_verify_upstream_identity",
        lambda *_args, **_kwargs: {"ok": True},
    )
    monkeypatch.setattr(
        tx_routes,
        "_tx_index_lookup",
        lambda *_args: {
            "tx_id": TX_ID,
            "height": 3,
            "block_id": BLOCK_ID,
            "apply_ok": True,
        },
    )
    monkeypatch.setattr(
        tx_routes,
        "_status_from_upstream",
        lambda *_args, **_kwargs: {
            "ok": True,
            "tx_id": TX_ID,
            "status": "confirmed",
            "height": 3,
            "block_id": BLOCK_ID,
            "apply_ok": True,
        },
    )
    monkeypatch.setattr(
        tx_routes,
        "_upstream_get_json",
        lambda *_args, **_kwargs: dict(IDENTITY),
    )
    monkeypatch.setattr(
        status_routes,
        "_chain_identity_payload",
        lambda _request: dict(IDENTITY),
    )
    return queue


def _reconcile() -> dict:
    return tx_routes._request_and_apply_state_sync_from_upstream(
        object(),
        UPSTREAM,
        tx_id=TX_ID,
        target_height=3,
        timeout_s=5,
    )


def _queue_row(path: Path) -> dict:
    rows = json.loads(path.read_text(encoding="utf-8"))["records"]
    return next(row for row in rows if row["tx_id"] == TX_ID)


def test_already_applied_tx_marks_synced_only_after_full_tip_match(
    monkeypatch, tmp_path: Path
) -> None:
    path = _setup(monkeypatch, tmp_path)
    result = _reconcile()
    row = _queue_row(path)
    assert result["ok"] is True
    assert result["local_state_synced"] is True
    assert result["source"] == "matching_committed_tip_and_tx"
    assert row["local_state_synced"] is True
    assert row["local_sync_proof"]["height"] == 114
    assert row["local_sync_proof"]["state_root"] == IDENTITY["state_root"]
    assert row["local_sync_proof"]["tx_block_id"] == BLOCK_ID


@pytest.mark.parametrize(
    ("field", "mismatch"),
    [
        ("chain_id", "other-chain"),
        ("height", 115),
        ("tip_hash", "other-tip"),
        ("state_root", "other-root"),
        ("schema_version", "other-schema"),
        ("tx_index_hash", "other-index"),
        ("protocol_profile_hash", "other-profile"),
    ],
)
def test_tip_commitment_mismatch_never_claims_synced(
    monkeypatch, tmp_path: Path, field: str, mismatch: str | int
) -> None:
    path = _setup(monkeypatch, tmp_path)
    bad = dict(IDENTITY)
    bad[field] = mismatch
    monkeypatch.setattr(
        tx_routes, "_upstream_get_json", lambda *_args, **_kwargs: bad
    )
    result = _reconcile()
    assert result["ok"] is False
    assert result["error"] == "existing_tip_commitment_mismatch"
    assert result["field"] == field
    assert _queue_row(path)["local_state_synced"] is False


def test_upstream_tx_receipt_rejection_cannot_serve_as_sync_proof(
    monkeypatch, tmp_path: Path
) -> None:
    path = _setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        tx_routes,
        "_status_from_upstream",
        lambda *_args, **_kwargs: {
            "ok": True,
            "tx_id": TX_ID,
            "status": "rejected",
            "height": 3,
            "block_id": BLOCK_ID,
            "apply_ok": False,
        },
    )
    result = _reconcile()
    assert result["ok"] is False
    assert result["error"] == "existing_tx_confirmation_not_proven"
    assert _queue_row(path)["local_state_synced"] is False


def test_local_tx_index_rejection_cannot_serve_as_sync_proof(
    monkeypatch, tmp_path: Path
) -> None:
    path = _setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        tx_routes,
        "_tx_index_lookup",
        lambda *_args: {
            "tx_id": TX_ID,
            "height": 3,
            "block_id": BLOCK_ID,
            "apply_ok": False,
        },
    )
    result = _reconcile()
    assert result["ok"] is False
    assert _queue_row(path)["local_state_synced"] is False


def test_committed_tx_block_disagreement_must_fail_closed(
    monkeypatch, tmp_path: Path
) -> None:
    path = _setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        tx_routes,
        "_status_from_upstream",
        lambda *_args, **_kwargs: {
            "ok": True,
            "tx_id": TX_ID,
            "status": "confirmed",
            "height": 3,
            "block_id": "different-block",
            "apply_ok": True,
        },
    )
    result = _reconcile()
    assert result["error"] == "existing_tx_committed_block_mismatch"
    assert _queue_row(path)["local_state_synced"] is False


def test_observer_state_change_during_identity_sample_fails_closed(
    monkeypatch, tmp_path: Path
) -> None:
    path = _setup(monkeypatch, tmp_path)
    samples = iter([dict(IDENTITY), {**IDENTITY, "state_root": "changed"}])
    monkeypatch.setattr(
        status_routes,
        "_chain_identity_payload",
        lambda _request: next(samples),
    )
    result = _reconcile()
    assert result["error"] == "existing_tip_commitment_mismatch"
    assert _queue_row(path)["local_state_synced"] is False


def test_no_local_index_at_or_above_target_does_not_claim_sync(
    monkeypatch, tmp_path: Path
) -> None:
    path = _setup(monkeypatch, tmp_path)
    monkeypatch.setattr(tx_routes, "_tx_index_lookup", lambda *_args: None)
    result = _reconcile()
    assert result["error"] == "local_height_at_or_above_target_without_tx"
    assert _queue_row(path)["local_state_synced"] is False


def test_repeated_confirmed_poll_preserves_prior_matching_sync_proof(
    monkeypatch, tmp_path: Path
) -> None:
    path = _setup(monkeypatch, tmp_path, proof=True)
    monkeypatch.setattr(
        tx_routes, "_normalized_tx_upstream_urls", lambda *_args: [UPSTREAM]
    )
    result = tx_routes._reconcile_tx_queue_confirmation(TX_ID)
    assert result["upstream_status"] == "confirmed"
    assert result["local_state_synced"] is True
    assert _queue_row(path)["local_state_synced"] is True


def test_changed_upstream_committed_block_revokes_prior_sync_proof(
    monkeypatch, tmp_path: Path
) -> None:
    path = _setup(monkeypatch, tmp_path, proof=True)
    monkeypatch.setattr(
        tx_routes, "_normalized_tx_upstream_urls", lambda *_args: [UPSTREAM]
    )
    monkeypatch.setattr(
        tx_routes,
        "_status_from_upstream",
        lambda *_args, **_kwargs: {
            "ok": True,
            "tx_id": TX_ID,
            "status": "confirmed",
            "height": 3,
            "block_id": "changed-block",
            "apply_ok": True,
        },
    )
    result = tx_routes._reconcile_tx_queue_confirmation(TX_ID)
    assert result["upstream_status"] == "confirmed"
    assert result["local_state_synced"] is False
    assert _queue_row(path)["confirmed_block_id"] == "changed-block"


@pytest.mark.parametrize(
    ("local_status", "local_block"),
    [
        (False, BLOCK_ID),
        (True, "different-local-block"),
    ],
)
def test_stored_sync_flag_requires_matching_successful_local_receipt(
    monkeypatch, tmp_path: Path, local_status: bool, local_block: str
) -> None:
    path = _setup(monkeypatch, tmp_path, proof=True)
    monkeypatch.setattr(
        tx_routes,
        "_locally_confirmed_tx",
        lambda *_args: {
            "tx_id": TX_ID,
            "height": 3,
            "block_id": local_block,
            "apply_ok": local_status,
        },
    )
    monkeypatch.setattr(
        tx_routes,
        "_reconcile_tx_queue_confirmation",
        lambda _txid: {
            "upstream_status": "confirmed",
            "confirmed_height": 3,
            "confirmed_block_id": BLOCK_ID,
            "local_state_synced": True,
        },
    )
    monkeypatch.setattr(
        tx_routes, "_normalized_tx_upstream_urls", lambda *_args: [UPSTREAM]
    )
    monkeypatch.setattr(
        tx_routes,
        "_request_and_apply_state_sync_from_upstream",
        lambda *_args, **_kwargs: {
            "ok": False,
            "error": "existing_tx_confirmation_not_proven",
        },
    )
    result = tx_routes._reconcile_and_sync_local_state(object(), TX_ID)
    assert result["ok"] is False
    assert result["local_state_synced"] is False
    assert result["error"] == "local_state_sync_failed"
    assert _queue_row(path)["tx_id"] == TX_ID


def test_valid_stored_sync_flag_can_short_circuit_redundant_sync(
    monkeypatch, tmp_path: Path
) -> None:
    path = _setup(monkeypatch, tmp_path, proof=True)
    monkeypatch.setattr(
        tx_routes,
        "_locally_confirmed_tx",
        lambda *_args: {
            "tx_id": TX_ID,
            "height": 3,
            "block_id": BLOCK_ID,
            "apply_ok": True,
        },
    )
    monkeypatch.setattr(
        tx_routes,
        "_reconcile_tx_queue_confirmation",
        lambda _txid: {
            "upstream_status": "confirmed",
            "confirmed_height": 3,
            "confirmed_block_id": BLOCK_ID,
            "local_state_synced": True,
        },
    )
    result = tx_routes._reconcile_and_sync_local_state(object(), TX_ID)
    assert result["ok"] is True
    assert result["local_state_synced"] is True
    assert result["source"] == "already_synced"
    assert _queue_row(path)["local_state_synced"] is True


def test_reconcile_route_and_status_converge_after_verified_existing_tip(
    monkeypatch, tmp_path: Path
) -> None:
    path = _setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        tx_routes, "_normalized_tx_upstream_urls", lambda *_args: [UPSTREAM]
    )
    monkeypatch.setattr(
        tx_routes,
        "_locally_confirmed_tx",
        lambda *_args: {
            "tx_id": TX_ID,
            "height": 3,
            "block_id": BLOCK_ID,
            "apply_ok": True,
        },
    )

    reconcile = tx_routes._reconcile_and_sync_local_state(object(), TX_ID)
    assert reconcile["ok"] is True
    assert reconcile["local_state_synced"] is True
    assert reconcile["source"] == "state_sync"

    # Public status will poll upstream again. That poll must not regress the
    # newly proved observer state back to "not synced".
    status = tx_routes.tx_status(object(), TX_ID)
    assert status["status"] == "confirmed"
    assert status["source"] == "upstream_synced"
    assert status["local_state_synced"] is True
    assert status["outbound_propagation"]["local_state_synced"] is True
    assert _queue_row(path)["local_state_synced"] is True


def test_existing_tip_can_be_proven_without_delta_apply_method(
    monkeypatch, tmp_path: Path
) -> None:
    # The synthetic executor intentionally lacks apply_state_sync_response.
    # Matching, already-applied tips require read-only proof, not another delta.
    path = _setup(monkeypatch, tmp_path)
    result = _reconcile()
    assert result["ok"] is True
    assert _queue_row(path)["local_state_synced"] is True


def test_missing_state_requires_executor_delta_apply_capability(
    monkeypatch, tmp_path: Path
) -> None:
    path = _setup(monkeypatch, tmp_path)
    monkeypatch.setattr(tx_routes, "_local_height_for_request", lambda _req: 1)
    result = _reconcile()
    assert result["ok"] is False
    assert result["error"] == "state_sync_apply_unavailable"
    assert _queue_row(path)["local_state_synced"] is False


def test_no_executor_fails_closed_even_when_height_matches(
    monkeypatch, tmp_path: Path
) -> None:
    path = _setup(monkeypatch, tmp_path)
    monkeypatch.setattr(tx_routes, "_safe_executor", lambda _req: None)
    result = _reconcile()
    assert result["ok"] is False
    assert result["error"] == "state_sync_apply_unavailable"
    assert _queue_row(path)["local_state_synced"] is False
