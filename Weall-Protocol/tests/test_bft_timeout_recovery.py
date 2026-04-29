from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from weall.runtime.bft_hotstuff import BftTimeout
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _mk_keypair_hex() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pk_b.hex(), sk_b.hex()


def _seed_validator_set(ex: WeAllExecutor, *, validators: list[str], pub: dict[str, str]) -> None:
    st = ex.read_state()
    st.setdefault("roles", {})
    st["roles"].setdefault("validators", {})
    st["roles"]["validators"]["active_set"] = list(validators)
    st.setdefault("consensus", {})
    st["consensus"].setdefault("validators", {})
    st["consensus"]["validators"].setdefault("registry", {})
    for v in validators:
        st["consensus"]["validators"]["registry"].setdefault(v, {})
        st["consensus"]["validators"]["registry"][v]["pubkey"] = pub[v]
    ex.state = st
    ex._ledger_store.write(ex.state)


def test_bft_timeout_check_emits_valid_genesis_timeout_for_non_leader(
    tmp_path: Path, monkeypatch
) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@v2",
        chain_id="bft-live",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(ex, validators=validators, pub=vpub)
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", vpub["v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", vpriv["v2"])
    ex._bft.last_progress_ms = 0

    tmo = ex.bft_timeout_check()
    assert isinstance(tmo, dict)
    assert tmo["view"] == 0
    assert tmo["high_qc_id"] == "genesis"
    assert (
        BftTimeout(
            chain_id=str(tmo["chain_id"]),
            view=int(tmo["view"]),
            high_qc_id=str(tmo["high_qc_id"]),
            signer=str(tmo["signer"]),
            pubkey=str(tmo["pubkey"]),
            sig=str(tmo["sig"]),
        ).verify()
        is True
    )


def test_bft_timeout_check_skips_current_leader(tmp_path: Path, monkeypatch) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    ex = WeAllExecutor(
        db_path=str(tmp_path / "leader.db"),
        node_id="@v1",
        chain_id="bft-live",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(ex, validators=validators, pub=vpub)
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", vpub["v1"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", vpriv["v1"])
    ex._bft.last_progress_ms = 0

    assert ex.bft_timeout_check() is None


def test_bft_timeout_recovery_persists_view_and_ignores_stale_messages(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    db_path = str(tmp_path / "recover.db")
    ex = WeAllExecutor(
        db_path=db_path, node_id="@v4", chain_id="bft-live", tx_index_path=tx_index_path
    )
    _seed_validator_set(ex, validators=validators, pub=vpub)

    def timeout_from(signer: str, view: int) -> dict:
        ex2 = WeAllExecutor(
            db_path=str(tmp_path / f"sign-{signer}-{view}.db"),
            node_id=f"@{signer}",
            chain_id="bft-live",
            tx_index_path=tx_index_path,
        )
        _seed_validator_set(ex2, validators=validators, pub=vpub)
        # build directly via executor signing path to match prod behavior
        import os

        old = {
            k: os.environ.get(k)
            for k in ("WEALL_VALIDATOR_ACCOUNT", "WEALL_NODE_PUBKEY", "WEALL_NODE_PRIVKEY")
        }
        os.environ["WEALL_VALIDATOR_ACCOUNT"] = signer
        os.environ["WEALL_NODE_PUBKEY"] = vpub[signer]
        os.environ["WEALL_NODE_PRIVKEY"] = vpriv[signer]
        try:
            out = ex2.bft_make_timeout(view=view)
            assert isinstance(out, dict)
            return out
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    for signer in ["v1", "v2", "v3"]:
        assert ex.bft_handle_timeout(timeout_from(signer, 0)) in {None, 1}
    assert ex.bft_current_view() == 1

    ex_restarted = WeAllExecutor(
        db_path=db_path, node_id="@v4", chain_id="bft-live", tx_index_path=tx_index_path
    )
    _seed_validator_set(ex_restarted, validators=validators, pub=vpub)
    assert ex_restarted.bft_current_view() == 1

    for signer in ["v1", "v2", "v3"]:
        assert ex_restarted.bft_handle_timeout(timeout_from(signer, 0)) is None
    assert ex_restarted.bft_current_view() == 1

    for signer in ["v2", "v3", "v4"]:
        ex_restarted.bft_handle_timeout(timeout_from(signer, 1))
    assert ex_restarted.bft_current_view() == 2
