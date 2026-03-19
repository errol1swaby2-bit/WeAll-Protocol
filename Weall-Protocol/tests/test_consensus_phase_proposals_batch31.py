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
    node_id: str,
    phase: str,
) -> tuple[WeAllExecutor, dict[str, str], dict[str, str]]:
    ex = WeAllExecutor(
        db_path=str(tmp_path / f"{node_id}.db"),
        node_id=node_id,
        chain_id="bft-phase-proposals",
        tx_index_path=str(Path("generated/tx_index.json")),
    )
    pubs: dict[str, str] = {}
    privs: dict[str, str] = {}
    for vid in ("v1", "v2", "v3", "v4"):
        pub, sk = deterministic_ed25519_keypair(label=f"batch31-{vid}")
        pubs[vid] = pub
        privs[vid] = sk.private_bytes_raw().hex()
    _seed_validator_state(ex, ["v1", "v2", "v3", "v4"], pubs, phase=phase)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", node_id)
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs[node_id])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs[node_id])
    return ex, pubs, privs


def test_bootstrap_phase_rejects_remote_proposal_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    leader, pubs, privs = _mk_executor(tmp_path, monkeypatch, node_id="v1", phase=CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP)
    follower, _, _ = _mk_executor(tmp_path, monkeypatch, node_id="v2", phase=CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP)

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs["v1"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs["v1"])
    proposal = leader.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)
    assert proposal["consensus_phase"] == CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs["v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs["v2"])
    assert follower.bft_on_proposal(dict(proposal)) is None
    assert list(follower._pending_remote_blocks.keys()) == []
    assert list(follower._pending_missing_qc_entries().keys()) == []


def test_bft_active_rejects_stale_bootstrap_phase_proposal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    leader, pubs, privs = _mk_executor(tmp_path, monkeypatch, node_id="v1", phase=CONSENSUS_PHASE_BFT_ACTIVE)
    follower, _, _ = _mk_executor(tmp_path, monkeypatch, node_id="v2", phase=CONSENSUS_PHASE_BFT_ACTIVE)

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs["v1"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs["v1"])
    proposal = leader.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)

    stale = dict(proposal)
    stale["consensus_phase"] = CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs["v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs["v2"])
    assert follower.bft_on_proposal(stale) is None
    assert list(follower._pending_remote_blocks.keys()) == []


def test_phase_prune_drops_bootstrap_artifacts_after_activation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ex, pubs, privs = _mk_executor(tmp_path, monkeypatch, node_id="v1", phase=CONSENSUS_PHASE_BFT_ACTIVE)

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs["v1"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs["v1"])
    proposal = ex.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)
    proposal["consensus_phase"] = CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP

    bid = str(proposal["block_id"])
    ex._pending_remote_blocks[bid] = dict(proposal)
    changed = ex._prune_pending_bft_artifacts()
    assert changed is True
    assert bid not in ex._pending_remote_blocks
