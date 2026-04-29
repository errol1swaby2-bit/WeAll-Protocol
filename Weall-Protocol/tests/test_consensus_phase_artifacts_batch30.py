from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.bft_hotstuff import (
    CONSENSUS_PHASE_BFT_ACTIVE,
    CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP,
)
from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair


def _seed_validator_state(
    ex: WeAllExecutor,
    validators: list[str],
    pubs: dict[str, str],
    *,
    epoch: int = 7,
    phase: str = CONSENSUS_PHASE_BFT_ACTIVE,
) -> None:
    st = ex.state
    st.setdefault("roles", {}).setdefault("validators", {})["active_set"] = list(validators)
    c = st.setdefault("consensus", {})
    c.setdefault("validators", {}).setdefault("registry", {})
    for v in validators:
        c["validators"]["registry"].setdefault(v, {})["pubkey"] = pubs[v]
    c.setdefault("validator_set", {})["active_set"] = list(validators)
    c["validator_set"]["epoch"] = int(epoch)
    c["validator_set"]["set_hash"] = ex._current_validator_set_hash() or ""
    c.setdefault("phase", {})["current"] = str(phase)
    ex._ledger_store.write(st)
    ex.state = ex._ledger_store.read()


def _mk_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    phase: str = CONSENSUS_PHASE_BFT_ACTIVE,
) -> tuple[WeAllExecutor, dict[str, str], dict[str, str]]:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="v1",
        chain_id="bft-phase",
        tx_index_path=str(Path("generated/tx_index.json")),
    )
    pubs: dict[str, str] = {}
    privs: dict[str, str] = {}
    for vid in ("v1", "v2", "v3", "v4"):
        pub, sk = deterministic_ed25519_keypair(label=vid)
        pubs[vid] = pub
        privs[vid] = sk.private_bytes_raw().hex()
    _seed_validator_state(ex, ["v1", "v2", "v3", "v4"], pubs, phase=phase)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs["v1"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs["v1"])
    return ex, pubs, privs


def _mk_qc_from_votes(
    ex: WeAllExecutor, monkeypatch: pytest.MonkeyPatch, pubs: dict[str, str], privs: dict[str, str]
):
    proposal = ex.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)
    bid = str(proposal["block_id"])
    parent_id = str(proposal.get("prev_block_id") or "")
    block_hash = str(proposal.get("block_hash") or "")

    qc = None
    for signer in ("v1", "v2", "v3"):
        monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", signer)
        monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs[signer])
        monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs[signer])
        vote = ex.bft_make_vote_for_block(
            view=0, block_id=bid, block_hash=block_hash, parent_id=parent_id
        )
        assert isinstance(vote, dict)
        qc = ex.bft_handle_vote(vote) or qc
    assert qc is not None
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs["v1"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs["v1"])
    return qc


def test_bootstrap_phase_suppresses_vote_timeout_and_qc_processing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ex, pubs, privs = _mk_executor(
        tmp_path, monkeypatch, phase=CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP
    )

    # Bootstrap may still build a proposal candidate, but BFT artifacts must not be emitted.
    proposal = ex.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)
    bid = str(proposal["block_id"])
    parent_id = str(proposal.get("prev_block_id") or "")
    block_hash = str(proposal.get("block_hash") or "")

    assert (
        ex.bft_make_vote_for_block(view=0, block_id=bid, block_hash=block_hash, parent_id=parent_id)
        is None
    )
    assert ex.bft_make_timeout(view=0) is None

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs["v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs["v2"])
    foreign_vote = ex.bft_make_vote_for_block(
        view=0, block_id=bid, block_hash=block_hash, parent_id=parent_id
    )
    assert foreign_vote is None

    qc_payload = {
        "chain_id": ex.chain_id,
        "view": 0,
        "block_id": bid,
        "block_hash": block_hash,
        "parent_id": parent_id,
        "votes": [],
        "validator_epoch": ex._current_validator_epoch(),
        "validator_set_hash": ex._current_validator_set_hash(),
    }
    assert ex.bft_verify_qc_json(qc_payload) is None
    assert (
        ex.bft_handle_timeout(
            {
                "t": "TIMEOUT",
                "chain_id": ex.chain_id,
                "view": 0,
                "high_qc_id": "genesis",
                "signer": "v1",
                "pubkey": pubs["v1"],
                "sig": "00",
                "validator_epoch": ex._current_validator_epoch(),
                "validator_set_hash": ex._current_validator_set_hash(),
            }
        )
        is None
    )


def test_bft_active_phase_allows_signed_votes_timeouts_and_qcs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ex, pubs, privs = _mk_executor(tmp_path, monkeypatch, phase=CONSENSUS_PHASE_BFT_ACTIVE)

    proposal = ex.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)
    vote = ex.bft_make_vote_for_block(
        view=0,
        block_id=str(proposal["block_id"]),
        block_hash=str(proposal.get("block_hash") or ""),
        parent_id=str(proposal.get("prev_block_id") or ""),
    )
    assert isinstance(vote, dict)
    timeout = ex.bft_make_timeout(view=1)
    assert isinstance(timeout, dict)

    qc = _mk_qc_from_votes(ex, monkeypatch, pubs, privs)
    assert ex.bft_verify_qc_json(qc.to_json()) is not None
