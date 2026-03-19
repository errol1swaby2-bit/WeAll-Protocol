from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair


def _seed_validator_set(ex: WeAllExecutor, validators: list[str], pubs: dict[str, str], *, epoch: int = 7) -> None:
    st = ex.state
    st.setdefault("roles", {}).setdefault("validators", {})["active_set"] = list(validators)
    c = st.setdefault("consensus", {})
    c.setdefault("validators", {}).setdefault("registry", {})
    for v in validators:
        c["validators"]["registry"].setdefault(v, {})["pubkey"] = pubs[v]
    c.setdefault("validator_set", {})["active_set"] = list(validators)
    c["validator_set"]["epoch"] = int(epoch)
    c["validator_set"]["set_hash"] = ex._current_validator_set_hash() or ""
    ex._ledger_store.write(st)
    ex.state = ex._ledger_store.read()


def _mk_executor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[WeAllExecutor, dict[str, str], dict[str, str]]:
    ex = WeAllExecutor(db_path=str(tmp_path / "node.db"), node_id="v1", chain_id="bft-prod", tx_index_path=str(Path("generated/tx_index.json")))
    pubs: dict[str, str] = {}
    privs: dict[str, str] = {}
    for vid in ("v1", "v2", "v3", "v4"):
        pub, sk = deterministic_ed25519_keypair(label=vid)
        pubs[vid] = pub
        privs[vid] = sk.private_bytes_raw().hex()
    _seed_validator_set(ex, ["v1", "v2", "v3", "v4"], pubs)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs["v1"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs["v1"])
    return ex, pubs, privs


def test_prod_rejects_proposal_missing_epoch_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ex, _pubs, _privs = _mk_executor(tmp_path, monkeypatch)
    ex.bft_set_view(0)
    proposal = ex.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)

    missing_epoch = dict(proposal)
    missing_epoch.pop("validator_epoch", None)
    assert ex.bft_on_proposal(missing_epoch) is None

    missing_set_hash = dict(proposal)
    missing_set_hash.pop("validator_set_hash", None)
    assert ex.bft_on_proposal(missing_set_hash) is None


def test_prod_rejects_vote_missing_epoch_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ex, _pubs, _privs = _mk_executor(tmp_path, monkeypatch)
    vote = ex.bft_make_vote_for_block(view=3, block_id="b3", block_hash="bh3", parent_id="b2")
    assert isinstance(vote, dict)
    bad = dict(vote)
    bad.pop("validator_epoch", None)
    assert ex.bft_handle_vote(bad) is None
    bad2 = dict(vote)
    bad2.pop("validator_set_hash", None)
    assert ex.bft_handle_vote(bad2) is None


def test_prod_rejects_timeout_missing_epoch_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ex, _pubs, _privs = _mk_executor(tmp_path, monkeypatch)
    tmo = ex.bft_make_timeout(view=4)
    assert isinstance(tmo, dict)
    bad = dict(tmo)
    bad.pop("validator_epoch", None)
    assert ex.bft_handle_timeout(bad) is None
    bad2 = dict(tmo)
    bad2.pop("validator_set_hash", None)
    assert ex.bft_handle_timeout(bad2) is None


def test_prod_rejects_qc_missing_epoch_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ex, pubs, privs = _mk_executor(tmp_path, monkeypatch)

    proposal = {
        "chain_id": ex.chain_id,
        "height": 1,
        "prev_block_id": "",
        "prev_block_hash": "",
        "block_ts_ms": 1,
        "txs": [],
        "validator_epoch": ex._current_validator_epoch(),
        "validator_set_hash": ex._current_validator_set_hash(),
        "view": 0,
        "proposer": "v1",
    }
    proposal, _ = ex.bft_leader_propose(max_txs=0), None
    assert isinstance(proposal, dict)
    bid = str(proposal["block_id"])
    parent_id = str(proposal.get("prev_block_id") or "")

    votes = []
    for signer in ("v1", "v2", "v3"):
        monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", signer)
        monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs[signer])
        monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs[signer])
        vx = ex.bft_make_vote_for_block(view=0, block_id=bid, block_hash=str(proposal.get("block_hash") or ""), parent_id=parent_id)
        assert isinstance(vx, dict)
        votes.append(vx)

    qc = None
    for vx in votes:
        qc = ex.bft_handle_vote(vx) or qc
    assert qc is not None
    qcj = qc.to_json()

    bad = dict(qcj)
    bad.pop("validator_epoch", None)
    assert ex.bft_verify_qc_json(bad) is None

    bad2 = dict(qcj)
    bad2.pop("validator_set_hash", None)
    assert ex.bft_verify_qc_json(bad2) is None
