from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _mk_keypair_hex() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pk_b.hex(), sk_b.hex()


def _seed_validator_set(ex: WeAllExecutor, *, validators: list[str], pub: dict[str, str], epoch: int = 1) -> None:
    st = ex.read_state()
    st.setdefault("roles", {})
    st["roles"].setdefault("validators", {})
    st["roles"]["validators"]["active_set"] = list(validators)
    st.setdefault("validators", {})
    st["validators"].setdefault("registry", {})
    st.setdefault("consensus", {})
    st["consensus"].setdefault("validators", {})
    st["consensus"]["validators"].setdefault("registry", {})
    st["consensus"].setdefault("epochs", {})
    st["consensus"]["epochs"]["current"] = int(epoch)
    st["consensus"].setdefault("validator_set", {})
    st["consensus"]["validator_set"]["active_set"] = list(validators)
    st["consensus"]["validator_set"]["epoch"] = int(epoch)
    for v in validators:
        st["consensus"]["validators"]["registry"].setdefault(v, {})
        st["consensus"]["validators"]["registry"][v]["pubkey"] = pub[v]
        st["validators"]["registry"].setdefault(v, {})
        st["validators"]["registry"][v]["pubkey"] = pub[v]
    ex.state = st
    ex._ledger_store.write(ex.state)
    st = ex.read_state()
    st["consensus"]["validator_set"]["set_hash"] = ex._current_validator_set_hash()
    ex.state = st
    ex._ledger_store.write(ex.state)


def test_vote_persisted_before_returned_vote_can_be_replayed_after_restart(tmp_path: Path, monkeypatch) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["@v1", "@v2", "@v3", "@v4"]
    pub: dict[str, str] = {}
    priv: dict[str, str] = {}
    for v in validators:
        pub[v], priv[v] = _mk_keypair_hex()

    monkeypatch.setenv("WEALL_AUTOVOTE", "1")
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pub["@v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", priv["@v2"])

    db_path = str(tmp_path / "node.db")
    ex = WeAllExecutor(db_path=db_path, node_id="@v2", chain_id="chain-A", tx_index_path=tx_index_path)
    _seed_validator_set(ex, validators=validators, pub=pub)

    ex.bft_set_view(1)
    proposal = ex.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)

    vote = ex.bft_on_proposal(proposal)
    assert isinstance(vote, dict)
    assert ex.state.get("bft", {}).get("last_voted_view") == 1
    assert ex.state.get("bft", {}).get("last_voted_block_id") == str(proposal.get("block_id") or "")

    ex2 = WeAllExecutor(db_path=db_path, node_id="@v2", chain_id="chain-A", tx_index_path=tx_index_path)
    _seed_validator_set(ex2, validators=validators, pub=pub)
    assert ex2.state.get("bft", {}).get("last_voted_view") == 1
    assert ex2.state.get("bft", {}).get("last_voted_block_id") == str(proposal.get("block_id") or "")
    replayed = ex2.bft_on_proposal(proposal)
    assert isinstance(replayed, dict)
    assert str(replayed.get("block_id") or "") == str(proposal.get("block_id") or "")
