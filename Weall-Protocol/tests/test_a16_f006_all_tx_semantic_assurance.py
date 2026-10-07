from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from weall.runtime.domain_apply import (
    apply_tx_atomic_meta_bounded_rollback,
    apply_tx_atomic_meta_deepcopy,
)
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_contracts import load_default_tx_index
from weall.runtime.tx_schema import model_for_tx_type

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "generated" / "tx_semantic_assurance_v1_5.json"


def _state() -> dict[str, Any]:
    return {
        "height": 10,
        "time": 1_000_000,
        "chain_id": "weall-testnet-v1",
        "network_id": "weall-testnet-v1",
        "params": {
            "chain_id": "weall-testnet-v1",
            "economics_enabled": False,
            "genesis_time": 0,
            "economic_unlock_time": 9_999_999_999,
        },
        "accounts": {
            "@tester": {
                "nonce": 0,
                "balance": 1_000_000,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
            },
            "@target": {
                "nonce": 0,
                "balance": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
            },
            "@juror1": {
                "nonce": 0,
                "balance": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
            },
            "@validator1": {
                "nonce": 0,
                "balance": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
            },
        },
        "roles": {},
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
    }


def _env(row: dict[str, Any], payload: dict[str, Any]) -> TxEnvelope:
    system = str(row.get("origin") or "").upper() == "SYSTEM"
    block_only = str(row.get("context") or "").lower() == "block"
    receipt_only = bool(row.get("receipt_only"))
    return TxEnvelope(
        tx_type=str(row["tx_type"]),
        signer="SYSTEM" if system else "@tester",
        nonce=1,
        payload=copy.deepcopy(payload),
        parent="PARENT-A16" if block_only or receipt_only else None,
        system=system,
        chain_id="weall-testnet-v1",
    )


def _exception_identity(exc: Exception) -> tuple[str, str, str]:
    code = str(getattr(exc, "code", "") or "")
    reason = str(getattr(exc, "reason", "") or "")
    if not code and not reason:
        raise AssertionError(
            f"unexpected non-domain exception: {type(exc).__name__}: {exc}"
        ) from exc
    return ("reject", code, reason)


def _run(fn, row: dict[str, Any], payload: dict[str, Any]) -> tuple[tuple, dict]:
    state = _state()
    before = copy.deepcopy(state)
    env = _env(row, payload)
    try:
        meta = fn(state, env)
    except Exception as exc:  # domain error classes do not share one exported base.
        ident = _exception_identity(exc)
        assert state == before, (row["tx_type"], ident, "rejection_mutated_state")
        return ident, state

    canonical_meta = json.loads(json.dumps(meta, sort_keys=True, default=str))
    return ("success", canonical_meta), state


def _assert_execution_parity(row: dict[str, Any], payload: dict[str, Any]) -> None:
    deep_outcome, deep_state = _run(apply_tx_atomic_meta_deepcopy, row, payload)
    bounded_outcome, bounded_state = _run(apply_tx_atomic_meta_bounded_rollback, row, payload)

    assert bounded_outcome == deep_outcome, (
        row["tx_type"],
        "bounded_vs_deepcopy_outcome",
        bounded_outcome,
        deep_outcome,
    )
    assert bounded_state == deep_state, (
        row["tx_type"],
        "bounded_vs_deepcopy_state",
    )


def _load_manifest() -> dict[str, Any]:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert payload["schema"] == "weall.v1_5.tx_semantic_assurance_manifest"
    assert payload["finding"] == "A16-F006"
    return payload


def test_a16_f006_manifest_covers_every_canonical_transaction() -> None:
    payload = _load_manifest()
    canon = load_default_tx_index()
    rows = payload["rows"]

    assert payload["tx_count"] == 236
    assert payload["all_canon_types_have_executable_vectors"] is True
    assert len(rows) == 236
    assert {row["tx_type"] for row in rows} == set(canon.list_types())
    assert len({row["tx_type"] for row in rows}) == 236


@pytest.mark.parametrize(
    "row",
    _load_manifest()["rows"],
    ids=lambda row: str(row["tx_type"]),
)
def test_a16_f006_all_tx_semantic_matrix(row: dict[str, Any]) -> None:
    tx_type = str(row["tx_type"])
    model = model_for_tx_type(tx_type)
    assert model is not None, tx_type

    baseline = copy.deepcopy(row["baseline_payload"])
    parsed = model.model_validate(baseline)
    normalized = parsed.model_dump(exclude_none=True)
    assert isinstance(normalized, dict)

    mutation = row["required_mutation"]
    assert mutation["expected"] == "schema_reject"
    with pytest.raises((ValueError, TypeError)):
        model.model_validate(copy.deepcopy(mutation["payload"]))

    _assert_execution_parity(row, baseline)
    _assert_execution_parity(row, normalized)

    raw_outcome, raw_state = _run(apply_tx_atomic_meta_bounded_rollback, row, baseline)
    normalized_outcome, normalized_state = _run(
        apply_tx_atomic_meta_bounded_rollback,
        row,
        normalized,
    )
    assert raw_outcome == normalized_outcome, (
        tx_type,
        "raw_vs_normalized_outcome",
        raw_outcome,
        normalized_outcome,
    )
    assert raw_state == normalized_state, (tx_type, "raw_vs_normalized_state")

    probe = row["coercion_probe"]
    if probe["schema_outcome"] == "accept":
        raw_probe = copy.deepcopy(probe["payload"])
        normalized_probe = copy.deepcopy(probe["normalized_payload"])
        _assert_execution_parity(row, raw_probe)
        _assert_execution_parity(row, normalized_probe)

        raw_probe_outcome, raw_probe_state = _run(
            apply_tx_atomic_meta_bounded_rollback,
            row,
            raw_probe,
        )
        norm_probe_outcome, norm_probe_state = _run(
            apply_tx_atomic_meta_bounded_rollback,
            row,
            normalized_probe,
        )
        assert raw_probe_outcome == norm_probe_outcome, (
            tx_type,
            "accepted_coercion_raw_vs_normalized_outcome",
            raw_probe_outcome,
            norm_probe_outcome,
        )
        assert raw_probe_state == norm_probe_state, (
            tx_type,
            "accepted_coercion_raw_vs_normalized_state",
        )
