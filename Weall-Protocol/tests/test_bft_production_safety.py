from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair


def _seed_validator_set(ex: WeAllExecutor, validators: list[str], pubs: dict[str, str]) -> None:
    st = ex.state
    st.setdefault("roles", {}).setdefault("validators", {})["active_set"] = list(validators)
    c = st.setdefault("consensus", {})
    c.setdefault("validators", {}).setdefault("registry", {})
    for v in validators:
        c["validators"]["registry"].setdefault(v, {})["pubkey"] = pubs[v]
    c.setdefault("validator_set", {})["active_set"] = list(validators)
    c["validator_set"]["epoch"] = 7
    c["validator_set"]["set_hash"] = ex._validator_epoch()[1] or ""
    ex._ledger_store.write(st)
    ex.state = ex._ledger_store.read()


def test_non_leader_cannot_propose(tmp_path: Path, monkeypatch) -> None:
    tx_index_path = str(Path("generated/tx_index.json"))
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="v2",
        chain_id="bft-prod",
        tx_index_path=tx_index_path,
    )

    pubs = {}
    privs = {}
    for vid in ("v1", "v2", "v3", "v4"):
        pub, sk = deterministic_ed25519_keypair(label=vid)
        pubs[vid] = pub
        privs[vid] = sk.private_bytes_raw().hex()
    _seed_validator_set(ex, ["v1", "v2", "v3", "v4"], pubs)

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs["v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs["v2"])
    ex.bft_set_view(0)
    assert ex.bft_leader_propose(max_txs=0) is None


def test_proposal_requires_valid_signature_and_epoch(tmp_path: Path, monkeypatch) -> None:
    tx_index_path = str(Path("generated/tx_index.json"))
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node2.db"),
        node_id="v1",
        chain_id="bft-prod",
        tx_index_path=tx_index_path,
    )

    pubs = {}
    privs = {}
    for vid in ("v1", "v2", "v3", "v4"):
        pub, sk = deterministic_ed25519_keypair(label=vid)
        pubs[vid] = pub
        privs[vid] = sk.private_bytes_raw().hex()
    _seed_validator_set(ex, ["v1", "v2", "v3", "v4"], pubs)

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs["v1"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs["v1"])
    ex.bft_set_view(0)
    proposal = ex.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)

    bad = dict(proposal)
    bad["proposer_sig"] = "00"
    assert ex.bft_on_proposal(bad) is None

    bad_epoch = dict(proposal)
    bad_epoch["validator_epoch"] = int(proposal["validator_epoch"]) + 1
    assert ex.bft_on_proposal(bad_epoch) is None
