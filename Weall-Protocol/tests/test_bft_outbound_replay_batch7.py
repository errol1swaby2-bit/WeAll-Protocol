from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from weall.net.messages import BftTimeoutMsg, BftVoteMsg
from weall.net.net_loop import NetMeshLoop, net_loop_config_from_env
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


class _FakeNode:
    def __init__(self) -> None:
        self.calls: list[tuple[object, str]] = []
        self.cfg = SimpleNamespace(peer_id="local-peer", chain_id="chain-A", schema_version="1", tx_index_hash="deadbeef")

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> int:
        self.calls.append((msg, exclude_peer_id))
        return 1


class _FakeMempool:
    def read_all(self):
        return []


def test_vote_replayed_after_restart_when_persisted_but_unsent(tmp_path: Path, monkeypatch) -> None:
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
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v2")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pub["@v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", priv["@v2"])
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")

    db_path = str(tmp_path / "node.db")
    ex = WeAllExecutor(db_path=db_path, node_id="@v2", chain_id="chain-A", tx_index_path=tx_index_path)
    _seed_validator_set(ex, validators=validators, pub=pub)

    ex.bft_set_view(1)
    proposal = ex.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)
    vote = ex.bft_on_proposal({"view": 1, "proposer": "@v2", "block": proposal})
    assert isinstance(vote, dict)

    ex2 = WeAllExecutor(db_path=db_path, node_id="@v2", chain_id="chain-A", tx_index_path=tx_index_path)
    _seed_validator_set(ex2, validators=validators, pub=pub)
    cfg = net_loop_config_from_env()
    loop = NetMeshLoop(executor=ex2, mempool=_FakeMempool(), cfg=cfg)
    loop.node = _FakeNode()
    loop._bft_enabled = True
    loop._bft_propose_interval_ms = 999999999
    loop._bft_vote_interval_ms = 999999999
    loop._bft_timeout_interval_ms = 999999999
    loop._last_bft_propose_ms = 10**18
    loop._last_bft_vote_ms = 10**18
    loop._last_bft_timeout_ms = 10**18
    loop._outbound_bft_tick()

    assert len(loop.node.calls) == 1
    msg, excluded = loop.node.calls[0]
    assert excluded == ""
    assert isinstance(msg, BftVoteMsg)
    assert msg.vote["block_id"] == str(proposal.get("block_id") or "")
    assert ex2.bft_pending_outbound_messages() == []


def test_timeout_replayed_after_restart_until_sent(tmp_path: Path, monkeypatch) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["@v1", "@v2", "@v3", "@v4"]
    pub: dict[str, str] = {}
    priv: dict[str, str] = {}
    for v in validators:
        pub[v], priv[v] = _mk_keypair_hex()

    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pub["@v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", priv["@v2"])
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")

    db_path = str(tmp_path / "node.db")
    ex = WeAllExecutor(db_path=db_path, node_id="@v2", chain_id="chain-A", tx_index_path=tx_index_path)
    _seed_validator_set(ex, validators=validators, pub=pub)
    timeoutj = ex.bft_make_timeout(view=2)
    assert isinstance(timeoutj, dict)

    ex2 = WeAllExecutor(db_path=db_path, node_id="@v2", chain_id="chain-A", tx_index_path=tx_index_path)
    _seed_validator_set(ex2, validators=validators, pub=pub)
    cfg = net_loop_config_from_env()
    loop = NetMeshLoop(executor=ex2, mempool=_FakeMempool(), cfg=cfg)
    loop.node = _FakeNode()
    loop._bft_enabled = True
    loop._bft_propose_interval_ms = 999999999
    loop._bft_vote_interval_ms = 999999999
    loop._bft_timeout_interval_ms = 999999999
    loop._last_bft_propose_ms = 10**18
    loop._last_bft_vote_ms = 10**18
    loop._last_bft_timeout_ms = 10**18
    loop._outbound_bft_tick()

    assert len(loop.node.calls) == 1
    msg, _excluded = loop.node.calls[0]
    assert isinstance(msg, BftTimeoutMsg)
    assert msg.timeout["view"] == 2
    assert ex2.bft_pending_outbound_messages() == []
