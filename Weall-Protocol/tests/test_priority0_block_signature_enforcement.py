from __future__ import annotations

import copy
from pathlib import Path

import pytest

from weall.ledger.state import LedgerView
from weall.runtime.block_hash import compute_receipts_root, ensure_block_hash, make_block_header
from weall.runtime.block_id import compute_block_id
from weall.runtime.domain_apply import apply_tx_atomic_meta
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_id import compute_tx_id
from weall.runtime.tx_admission import TxEnvelope, admit_tx
from weall.crypto.sig import canonical_tx_message
from weall.testing.sigtools import deterministic_ed25519_keypair
from weall.tx.canon import load_tx_index_json


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> Path:
    return _repo_root() / "generated" / "tx_index.json"


def _load_index():
    return load_tx_index_json(_tx_index_path())


def _executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=name,
        chain_id="sig-enforce",
        tx_index_path=str(_tx_index_path()),
    )


def test_block_admission_rejects_unsigned_non_system_tx() -> None:
    ledger = LedgerView(
        accounts={},
        roles={},
        chain_id="sig-enforce",
        params={"require_signatures": True},
    )
    idx = _load_index()
    pub, _priv = deterministic_ed25519_keypair(label="@alice")

    env = TxEnvelope(
        tx_type="ACCOUNT_REGISTER",
        signer="@alice",
        nonce=1,
        payload={"pubkey": pub},
        sig="",
        parent=None,
    )

    verdict = admit_tx(env, ledger, idx, context="block")
    assert verdict.ok is False
    assert verdict.code == "missing_sig"
    assert verdict.reason == "sig_required_in_block"


def test_apply_block_rejects_forged_block_with_signature_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    follower = _executor(tmp_path, "follower")

    pub, priv = deterministic_ed25519_keypair(label="@alice")
    msg = canonical_tx_message(
        chain_id="sig-enforce",
        tx_type="ACCOUNT_REGISTER",
        signer="@alice",
        nonce=1,
        payload={"pubkey": pub},
        parent=None,
    )
    signed = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"pubkey": pub},
        "chain_id": "sig-enforce",
        "sig": priv.sign(msg).hex(),
    }
    tx_id = compute_tx_id(chain_id="sig-enforce", tx_type="ACCOUNT_REGISTER", signer="@alice", nonce=1, payload={"pubkey": pub})
    signed["tx_id"] = tx_id

    working = copy.deepcopy(follower.read_state())
    apply_tx_atomic_meta(working, signed, consume_nonce_on_fail=True)
    receipts = [{
        "tx_id": tx_id,
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@alice",
        "nonce": 1,
        "ok": True,
    }]
    receipts_root = compute_receipts_root(receipts=receipts)
    block_id = compute_block_id(
        chain_id="sig-enforce",
        height=1,
        prev_block_id="",
        prev_block_hash="",
        ts_ms=1,
        node_id="leader",
        tx_ids=[tx_id],
        receipts_root=receipts_root,
    )
    working["blocks"] = {block_id: {"height": 1, "prev_block_id": "", "block_ts_ms": 1}}
    working["height"] = 1
    working["tip"] = block_id
    working["time"] = 0
    state_root = compute_state_root(working)
    header = make_block_header(
        chain_id="sig-enforce",
        height=1,
        prev_block_hash="",
        block_ts_ms=1,
        tx_ids=[tx_id],
        receipts_root=receipts_root,
        state_root=state_root,
    )
    forged = {
        "block_id": block_id,
        "prev_block_id": "",
        "proposer": "leader",
        "header": header,
        "txs": [dict(signed, sig="")],
    }
    forged, _ = ensure_block_hash(forged)

    meta = follower.apply_block(forged)
    assert meta.ok is False
    assert meta.error == "bad_block:tx_reject:missing_sig"

    follower_state = follower.read_state()
    assert "@alice" not in (follower_state.get("accounts") or {})



def test_apply_block_rejects_non_system_tx_missing_chain_id_in_prod(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    follower = _executor(tmp_path, "follower-missing-chain-id")

    pub, priv = deterministic_ed25519_keypair(label="@alice-chain")
    msg = canonical_tx_message(
        chain_id="sig-enforce",
        tx_type="ACCOUNT_REGISTER",
        signer="@alice",
        nonce=1,
        payload={"pubkey": pub},
        parent=None,
    )
    signed = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"pubkey": pub},
        "sig": priv.sign(msg).hex(),
    }
    tx_id = compute_tx_id(chain_id="sig-enforce", tx_type="ACCOUNT_REGISTER", signer="@alice", nonce=1, payload={"pubkey": pub})
    signed["tx_id"] = tx_id

    header = make_block_header(
        chain_id="sig-enforce",
        height=1,
        prev_block_hash="",
        block_ts_ms=1,
        tx_ids=[tx_id],
        receipts_root="",
        state_root="",
    )
    block_id = compute_block_id(
        chain_id="sig-enforce",
        height=1,
        prev_block_id="",
        prev_block_hash="",
        ts_ms=1,
        node_id="leader",
        tx_ids=[tx_id],
        receipts_root="",
    )
    forged = {
        "block_id": block_id,
        "prev_block_id": "",
        "proposer": "leader",
        "header": header,
        "txs": [signed],
    }
    forged, _ = ensure_block_hash(forged)

    meta = follower.apply_block(forged)
    assert meta.ok is False
    assert meta.error == "bad_block:tx_reject:missing_chain_id"
