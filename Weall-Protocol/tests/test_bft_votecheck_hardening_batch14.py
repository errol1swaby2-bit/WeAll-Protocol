from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor



def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]



def _make_executor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, bft_enabled: bool = False) -> WeAllExecutor:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1" if bft_enabled else "0")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    return WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@v1",
        chain_id="votecheck-chain",
        tx_index_path=tx_index_path,
    )



def test_votecheck_caches_success_by_block_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ex = _make_executor(tmp_path, monkeypatch, bft_enabled=False)
    sub = ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "@u1", "nonce": 1, "payload": {"pubkey": "k:1"}})
    assert sub["ok"] is True
    proposal, _st, _applied, _invalid, err = ex.build_block_candidate(max_txs=1)
    assert err == ""
    assert isinstance(proposal, dict)

    calls = {"n": 0}
    real_apply_block = WeAllExecutor.apply_block

    def counting_apply_block(self: WeAllExecutor, block):
        calls["n"] += 1
        return real_apply_block(self, block)

    monkeypatch.setattr(WeAllExecutor, "apply_block", counting_apply_block)

    assert ex._validate_remote_proposal_for_vote(proposal) is True
    assert calls["n"] == 1
    assert ex._validate_remote_proposal_for_vote(proposal) is True
    assert calls["n"] == 1



def test_votecheck_rejects_oversized_proposal_before_clone_replay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_MAX_BLOCK_BYTES", "256")
    ex = _make_executor(tmp_path, monkeypatch, bft_enabled=False)
    sub = ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "@u1", "nonce": 1, "payload": {"pubkey": "k:1"}})
    assert sub["ok"] is True
    proposal, _st, _applied, _invalid, err = ex.build_block_candidate(max_txs=1)
    assert err == ""
    assert isinstance(proposal, dict)
    proposal = dict(proposal)
    proposal["padding"] = "x" * 5000

    def fail_apply_block(self: WeAllExecutor, block):
        raise AssertionError("expensive replay path should not run for oversized proposals")

    monkeypatch.setattr(WeAllExecutor, "apply_block", fail_apply_block)

    assert ex._validate_remote_proposal_for_vote(proposal) is False
