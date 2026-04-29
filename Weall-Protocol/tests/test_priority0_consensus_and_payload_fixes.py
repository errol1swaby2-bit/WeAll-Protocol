from __future__ import annotations

from pathlib import Path

from weall.ledger.state import LedgerView
from weall.runtime.block_admission import admit_bft_commit_block
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import load_tx_index_json

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_index():
    return load_tx_index_json(REPO_ROOT / "generated" / "tx_index.json")


def test_bft_commit_block_accepts_descendant_of_finalized_path(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")

    state = {
        "chain_id": "weall-test",
        "roles": {"validators": {"active_set": ["@v1"]}},
        "consensus": {
            "validator_set": {"epoch": 1, "set_hash": "validator-set-hash-1"},
            "validators": {"registry": {"@v1": {"pubkey": "ed25519:v1"}}},
        },
        "bft": {
            "finalized_block_id": "B2",
            "view": 4,
            "high_qc": {"block_id": "B2", "view": 4},
        },
    }
    blocks_map = {
        "B1": {"block_id": "B1", "prev_block_id": "GENESIS"},
        "B2": {"block_id": "B2", "prev_block_id": "B1"},
        "B3": {"block_id": "B3", "prev_block_id": "B2"},
    }
    block = {
        "block_id": "B3",
        "prev_block_id": "B2",
        "height": 3,
        "view": 5,
        "proposer": "@v1",
        "validator_epoch": 1,
        "validator_set_hash": "validator-set-hash-1",
        "txs": [],
    }

    ok, rej = admit_bft_commit_block(block=block, state=state, blocks_map=blocks_map)
    assert ok is True
    assert rej is None


def test_bft_commit_block_rejects_ancestor_before_finalized(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")

    state = {
        "chain_id": "weall-test",
        "roles": {"validators": {"active_set": ["@v1"]}},
        "consensus": {
            "validator_set": {"epoch": 1, "set_hash": "validator-set-hash-1"},
            "validators": {"registry": {"@v1": {"pubkey": "ed25519:v1"}}},
        },
        "bft": {
            "finalized_block_id": "B2",
            "view": 4,
            "high_qc": {"block_id": "B2", "view": 4},
        },
    }
    blocks_map = {
        "B1": {"block_id": "B1", "prev_block_id": "GENESIS"},
        "B2": {"block_id": "B2", "prev_block_id": "B1"},
    }
    block = {
        "block_id": "B1",
        "prev_block_id": "GENESIS",
        "height": 1,
        "view": 1,
        "proposer": "@v1",
        "validator_epoch": 1,
        "validator_set_hash": "validator-set-hash-1",
        "txs": [],
    }

    ok, rej = admit_bft_commit_block(block=block, state=state, blocks_map=blocks_map)
    assert ok is False
    assert rej is not None
    assert rej.code == "bft_not_finalized"
    assert rej.reason == "block_not_on_finalized_path"


def test_tx_admission_rejects_float_payload_values(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    idx = _load_index()
    ledger = LedgerView(
        accounts={
            "@alice": {
                "nonce": 0,
                "poh_tier": 3,
                "banned": False,
                "locked": False,
                "reputation": 10,
            }
        },
        roles={},
    )
    env = TxEnvelope(
        tx_type="ACCOUNT_DEVICE_REGISTER",
        signer="@alice",
        nonce=1,
        payload={"device_id": "dev1", "pubkey": "k:dev1", "weight": 1.25},
        sig="",
    )

    ok, rej = admit_tx(env.to_json(), ledger, idx, context="mempool")
    assert ok is False
    assert rej is not None
    assert rej.code == "invalid_payload"
    assert rej.reason == "payload_float_not_allowed"


def test_tx_admission_rejects_nested_float_payload_values(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    idx = _load_index()
    ledger = LedgerView(
        accounts={
            "@alice": {
                "nonce": 0,
                "poh_tier": 3,
                "banned": False,
                "locked": False,
                "reputation": 10,
            }
        },
        roles={},
    )
    env = TxEnvelope(
        tx_type="ACCOUNT_DEVICE_REGISTER",
        signer="@alice",
        nonce=1,
        payload={"device_id": "dev1", "pubkey": "k:dev1", "meta": {"scores": [1, 2.5]}},
        sig="",
    )

    ok, rej = admit_tx(env.to_json(), ledger, idx, context="mempool")
    assert ok is False
    assert rej is not None
    assert rej.code == "invalid_payload"
    assert rej.reason == "payload_float_not_allowed"
