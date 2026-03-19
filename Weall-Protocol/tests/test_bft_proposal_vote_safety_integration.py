from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.bft_hotstuff import QuorumCert
from weall.runtime.executor import WeAllExecutor


def _canon_path() -> str:
    repo_root = Path(__file__).resolve().parents[1]
    return str(repo_root / "generated" / "tx_index.json")


def test_bft_on_proposal_refuses_same_view_conflicting_vote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "11" * 32)
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@val1")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "db.sqlite"),
        node_id="n1",
        chain_id="test-chain",
        tx_index_path=_canon_path(),
    )
    ex.state.setdefault("roles", {}).setdefault("validators", {})["active_set"] = ["@val1"]
    ex.state.setdefault("consensus", {}).setdefault("validators", {}).setdefault("registry", {})[
        "@val1"
    ] = {"pubkey": "pub"}
    ex._bft.locked_qc = QuorumCert(
        chain_id="test-chain",
        view=1,
        block_id="lock",
        block_hash="lock-h",
        parent_id="genesis",
        votes=tuple(),
    )
    ex._validate_remote_proposal_for_vote = lambda block: True
    ex.state["blocks"] = {
        "genesis": {"prev_block_id": ""},
        "lock": {"prev_block_id": "genesis"},
        "good": {"prev_block_id": "lock"},
        "bad": {"prev_block_id": "genesis"},
    }

    good = {
        "view": 2,
        "block": {
            "block_id": "good",
            "header": {
                "chain_id": "test-chain",
                "height": 1,
                "prev_block_hash": "00" * 32,
                "block_ts_ms": 1000,
                "tx_ids": [],
                "receipts_root": "",
            },
            "prev_block_id": "lock",
        },
    }
    bad = {
        "view": 2,
        "block": {
            "block_id": "bad",
            "header": {
                "chain_id": "test-chain",
                "height": 1,
                "prev_block_hash": "00" * 32,
                "block_ts_ms": 1001,
                "tx_ids": [],
                "receipts_root": "",
            },
            "prev_block_id": "genesis",
        },
    }

    vote1 = ex.bft_on_proposal(good)
    vote2 = ex.bft_on_proposal(bad)

    assert isinstance(vote1, dict)
    assert vote1.get("block_id") == "good"
    assert vote2 is None
    assert ex.state.get("bft", {}).get("last_voted_view") == 2
    assert ex.state.get("bft", {}).get("last_voted_block_id") == "good"


def test_bft_on_proposal_refuses_vote_when_replay_validation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "11" * 32)
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@val1")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "db.sqlite"),
        node_id="n1",
        chain_id="test-chain",
        tx_index_path=_canon_path(),
    )
    ex.state.setdefault("roles", {}).setdefault("validators", {})["active_set"] = ["@val1"]
    ex.state.setdefault("consensus", {}).setdefault("validators", {}).setdefault("registry", {})[
        "@val1"
    ] = {"pubkey": "pub"}

    proposal = {
        "view": 2,
        "block": {
            "block_id": "bad",
            "header": {
                "chain_id": "test-chain",
                "height": 1,
                "prev_block_hash": "00" * 32,
                "block_ts_ms": 1000,
                "tx_ids": [],
                "receipts_root": "",
            },
            "prev_block_id": "genesis",
        },
    }

    ex._validate_remote_proposal_for_vote = lambda block: False
    assert ex.bft_on_proposal(proposal) is None
