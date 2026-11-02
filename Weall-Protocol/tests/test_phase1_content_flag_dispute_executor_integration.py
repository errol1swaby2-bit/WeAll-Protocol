"""Phase-1 signed account -> content -> flag -> dispute -> replay wiring test.

Uses an explicit controlled local-genesis and *local-dev-only* PoH bootstrap.
This does not prove global humanity, S4 authority, independent BFT, or testnet
readiness. Every transaction passes the actual executor admission/block path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.executor import WeAllExecutor
from weall.runtime.replay_consistency import (
    _deterministic_replay_fixture_keypair,
    build_replay_manifest,
    compare_replay_manifests,
)
from weall.runtime.tx_id import compute_tx_id_from_dict

CHAIN = "weall-controlled-devnet"
POST_ID = "post:@alice:1"
FLAG_ID = "flag:@bob:3"


def _signed(
    *,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
) -> dict:
    _, secret = _deterministic_replay_fixture_keypair(label=signer)
    return sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN,
            "tx_type": tx_type,
            "signer": signer,
            "nonce": nonce,
            "payload": payload,
        },
        privkey=secret,
        encoding="hex",
    )


def _commit_signed(
    executor: WeAllExecutor,
    *,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
) -> tuple[int, str]:
    tx = _signed(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload)
    tx_id = compute_tx_id_from_dict(CHAIN, tx)
    result = executor.submit_tx(tx)
    assert result["ok"] is True, (tx_type, result)
    height = int(executor.read_state()["height"]) + 1
    produced = executor.produce_block(max_txs=1)
    assert produced.ok is True, (tx_type, produced.error)
    block = executor.get_block_by_height(height)
    assert isinstance(block, dict)
    assert tx_id in block["header"]["tx_ids"]
    receipts = [r for r in block["receipts"] if r.get("tx_id") == tx_id]
    assert len(receipts) == 1 and receipts[0]["ok"] is True, (tx_type, receipts)
    return height, tx_id


def test_signed_flag_creates_canonical_dispute_and_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alice_pub, _ = _deterministic_replay_fixture_keypair(label="@alice")
    bob_pub, _ = _deterministic_replay_fixture_keypair(label="@bob")
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", "@alice")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", alice_pub)
    monkeypatch.setenv("WEALL_POH_BOOTSTRAP_OPEN", "1")
    monkeypatch.setenv("WEALL_POH_BOOTSTRAP_MAX_HEIGHT", "50")
    monkeypatch.delenv("WEALL_GENESIS_MODE", raising=False)
    monkeypatch.delenv("WEALL_NODE_ID", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)

    tx_index = Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"
    source = WeAllExecutor(
        db_path=str(tmp_path / "flag-source.sqlite"),
        node_id="phase1-source",
        chain_id=CHAIN,
        tx_index_path=str(tx_index),
    )
    genesis = source.read_state()
    assert genesis["height"] == 0
    assert genesis["accounts"]["@alice"]["poh_tier"] == 2
    assert genesis["params"]["poh_bootstrap_open"] is True
    assert genesis["params"]["block_tx_signature_policy"] == "required"

    _commit_signed(
        source,
        tx_type="ACCOUNT_REGISTER",
        signer="@bob",
        nonce=1,
        payload={"pubkey": bob_pub},
    )
    _commit_signed(
        source,
        tx_type="POH_BOOTSTRAP_TIER2_GRANT",
        signer="@bob",
        nonce=2,
        payload={"account_id": "@bob"},
    )
    assert source.read_state()["accounts"]["@bob"]["poh_tier"] == 2

    _commit_signed(
        source,
        tx_type="CONTENT_POST_CREATE",
        signer="@alice",
        nonce=1,
        payload={"body": "A public synthetic integration post", "visibility": "public"},
    )
    assert source.read_state()["content"]["posts"][POST_ID]["author"] == "@alice"

    _commit_signed(
        source,
        tx_type="CONTENT_FLAG",
        signer="@bob",
        nonce=3,
        payload={"target_id": POST_ID, "reason": "Synthetic report"},
    )
    flagged = source.read_state()
    assert flagged["content"]["flags"][FLAG_ID]["by"] == "@bob"

    # Real system-queue transactions may execute in the proposal following
    # the flag or later, depending on phase/height scheduling. Never simulate
    # escalation by calling an applier directly.
    for _ in range(4):
        state = source.read_state()
        cases = state.get("disputes_by_id") or {}
        if any(d.get("target_id") == POST_ID for d in cases.values()):
            break
        next_block = source.produce_block(max_txs=2)
        assert next_block.ok is True, next_block.error

    state = source.read_state()
    matched = [
        case
        for case in (state.get("disputes_by_id") or {}).values()
        if case.get("target_id") == POST_ID
    ]
    assert len(matched) == 1, state.get("disputes_by_id")
    case = matched[0]
    assert case["target_type"] == "content"
    assert case["opened_by"] == "SYSTEM"
    assert case["flagged_by"] == "@bob"
    assert case["target_owner"] == "@alice"
    assert "@alice" not in case.get("assigned_jurors", [])
    assert "@bob" not in case.get("assigned_jurors", [])
    assert case["id"] == state["content"]["moderation"]["targets"][POST_ID]["dispute_id"]
    assert not state["accounts"]["@alice"].get("banned", False)
    assert not state["accounts"]["@bob"].get("banned", False)

    # The system escalation itself must be present as a successful canonical
    # block receipt, not merely a state mutation made by a test helper.
    blocks = [source.get_block_by_height(h) for h in range(1, int(state["height"]) + 1)]
    assert all(isinstance(block, dict) for block in blocks)
    matching_receipts = [
        receipt
        for block in blocks
        for receipt in block["receipts"]
        if receipt.get("tx_type") == "CONTENT_ESCALATE_TO_DISPUTE"
    ]
    assert len(matching_receipts) == 1
    assert matching_receipts[0]["ok"] is True
    assert matching_receipts[0]["signer"] == "SYSTEM"

    replay = WeAllExecutor(
        db_path=str(tmp_path / "flag-replay.sqlite"),
        node_id="phase1-fresh-replay",
        chain_id=CHAIN,
        tx_index_path=str(tx_index),
    )
    assert replay.read_state()["height"] == 0
    for block in blocks:
        applied = replay.apply_block(dict(block))
        assert applied.ok is True, applied.error
    expected = build_replay_manifest(source)
    observed = build_replay_manifest(replay)
    assert compare_replay_manifests(expected, observed) == []
    assert replay.read_state()["disputes_by_id"] == state["disputes_by_id"]
