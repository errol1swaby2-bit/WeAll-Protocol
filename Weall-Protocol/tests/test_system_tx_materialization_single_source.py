"""Producer/follower SYSTEM envelope materialization must stay byte-identical."""

from __future__ import annotations

import json

import pytest

from weall.runtime.system_tx_engine import (
    SystemQueueItem,
    _expected_emitted_system_env_fields,
    _materialize_system_queue_item,
    enqueue_system_tx,
    system_tx_emitter,
    validate_system_tx_queue_binding,
)


def _canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


@pytest.mark.parametrize(
    ("signer", "system_signer", "parent", "payload"),
    [
        ("SYSTEM", "", "", {"test": 1}),
        ("SYSTEM", "@override", "governance:parent", {"_parent_ref": "fallback"}),
        ("@fixed", "@ignored", "", {"_parent_ref": "payload:parent"}),
        ("SYSTEM", "", "", {"_parent_ref": None, "_due_height": 1}),
    ],
)
def test_system_queue_single_materializer_has_producer_follower_byte_parity(
    signer: str,
    system_signer: str,
    parent: str,
    payload: dict,
) -> None:
    state = {
        "height": 0,
        "system_queue": [],
        "params": {"system_signer": system_signer},
    }
    queue_id = enqueue_system_tx(
        state,
        tx_type="EXAMPLE_SYSTEM_RECEIPT",
        payload=payload,
        due_height=1,
        signer=signer,
        parent=parent,
        once=True,
        phase="post",
    )
    queued = SystemQueueItem.from_ledger_obj(state["system_queue"][0])
    canon = {"by_name": {"EXAMPLE_SYSTEM_RECEIPT": {"context": "block"}}}

    prepared = _materialize_system_queue_item(state, queued)
    expected_payload, expected_signer, expected_parent = _expected_emitted_system_env_fields(
        state, canon, queued
    )
    assert prepared.payload == expected_payload
    assert prepared.signer == expected_signer
    assert (prepared.parent or "") == expected_parent
    assert prepared.payload["_system_queue_id"] == queue_id
    assert prepared.payload["_due_height"] == 1

    emitted = system_tx_emitter(state, canon, next_height=1, phase="post")
    assert len(emitted) == 1
    assert _canonical_bytes(prepared.to_json()) == _canonical_bytes(emitted[0].to_json())
    assert state["system_queue"][0]["queue_id"] == queue_id

    ok, reason = validate_system_tx_queue_binding(
        state, canon, emitted[0], next_height=1, phase="post"
    )
    assert (ok, reason) == (True, "")


def test_system_signer_override_never_rewrites_explicit_non_system_signer() -> None:
    state = {
        "system_queue": [],
        "params": {"system_signer": "@override"},
    }
    enqueue_system_tx(
        state,
        tx_type="EXAMPLE_SYSTEM_RECEIPT",
        payload={},
        due_height=1,
        signer="@fixed",
    )
    item = SystemQueueItem.from_ledger_obj(state["system_queue"][0])

    env = _materialize_system_queue_item(state, item)

    assert env.signer == "@fixed"


def test_materialization_preserves_golden_queue_id_and_envelope_bytes() -> None:
    state = {
        "height": 16,
        "system_queue": [],
        "params": {"system_signer": "@override"},
    }
    queue_id = enqueue_system_tx(
        state,
        tx_type="EXAMPLE_SYSTEM_RECEIPT",
        payload={"receipt": "example"},
        due_height=17,
        signer="SYSTEM",
        parent="actual-parent",
        once=True,
        phase="post",
    )
    assert queue_id == "629a91dbd410e0e482cc6cf6620512ff47f02850d6e8bfde84b5a47d7f4a3359"
    queued = SystemQueueItem.from_ledger_obj(state["system_queue"][0])
    materialized = _materialize_system_queue_item(state, queued)
    expected = {
        "tx_type": "EXAMPLE_SYSTEM_RECEIPT",
        "signer": "@override",
        "nonce": 0,
        "payload": {
            "receipt": "example",
            "_due_height": 17,
            "_system_queue_id": queue_id,
            "_parent_ref": "actual-parent",
        },
        "sig": "",
        "parent": "actual-parent",
        "system": True,
    }

    assert _canonical_bytes(materialized.to_json()) == _canonical_bytes(expected)
