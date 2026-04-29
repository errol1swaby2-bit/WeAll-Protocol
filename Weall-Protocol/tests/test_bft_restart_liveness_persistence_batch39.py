from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _mk_keypair_hex() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pk_b.hex(), sk_b.hex()


def _seed_validator_set(
    ex: WeAllExecutor, *, validators: list[str], pub: dict[str, str], epoch: int = 1
) -> None:
    st = ex.read_state()
    st.setdefault("roles", {})
    st["roles"].setdefault("validators", {})
    st["roles"]["validators"]["active_set"] = list(validators)
    st.setdefault("consensus", {})
    st["consensus"].setdefault("validators", {})
    st["consensus"]["validators"].setdefault("registry", {})
    st["consensus"].setdefault("epochs", {})
    st["consensus"]["epochs"]["current"] = int(epoch)
    st["consensus"].setdefault("validator_set", {})
    st["consensus"]["validator_set"]["epoch"] = int(epoch)
    for v in validators:
        st["consensus"]["validators"]["registry"].setdefault(v, {})
        st["consensus"]["validators"]["registry"][v]["pubkey"] = pub[v]
    ex.state = st
    ex._ledger_store.write(ex.state)


def test_partial_timeout_bucket_survives_restart_and_forms_new_view(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    db_path = str(tmp_path / "timeout-restart.db")
    ex = WeAllExecutor(
        db_path=db_path, node_id="@v4", chain_id="bft-live", tx_index_path=tx_index_path
    )
    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=3)

    def timeout_from(signer: str, view: int) -> dict:
        import os

        ex2 = WeAllExecutor(
            db_path=str(tmp_path / f"timeout-sign-{signer}-{view}.db"),
            node_id=f"@{signer}",
            chain_id="bft-live",
            tx_index_path=tx_index_path,
        )
        _seed_validator_set(ex2, validators=validators, pub=vpub, epoch=3)
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

    assert ex.bft_handle_timeout(timeout_from("v1", 0)) is None
    assert ex.bft_handle_timeout(timeout_from("v2", 0)) is None

    restarted = WeAllExecutor(
        db_path=db_path, node_id="@v4", chain_id="bft-live", tx_index_path=tx_index_path
    )
    _seed_validator_set(restarted, validators=validators, pub=vpub, epoch=3)

    assert restarted._bft.export_state().get("pending_timeouts")
    assert restarted.bft_handle_timeout(timeout_from("v3", 0)) == 1
    assert restarted.bft_current_view() == 1


def test_partial_vote_bucket_survives_restart_and_forms_qc(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    db_path = str(tmp_path / "vote-restart.db")
    ex = WeAllExecutor(
        db_path=db_path, node_id="@v1", chain_id="bft-live", tx_index_path=tx_index_path
    )
    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=5)

    block_id = "blk-partition-a"
    block_hash = "deadbeef" * 8
    parent_id = "genesis"

    def vote_from(signer: str) -> dict:
        import os

        ex2 = WeAllExecutor(
            db_path=str(tmp_path / f"vote-sign-{signer}.db"),
            node_id=f"@{signer}",
            chain_id="bft-live",
            tx_index_path=tx_index_path,
        )
        _seed_validator_set(ex2, validators=validators, pub=vpub, epoch=5)
        old = {
            k: os.environ.get(k)
            for k in ("WEALL_VALIDATOR_ACCOUNT", "WEALL_NODE_PUBKEY", "WEALL_NODE_PRIVKEY")
        }
        os.environ["WEALL_VALIDATOR_ACCOUNT"] = signer
        os.environ["WEALL_NODE_PUBKEY"] = vpub[signer]
        os.environ["WEALL_NODE_PRIVKEY"] = vpriv[signer]
        try:
            out = ex2.bft_make_vote_for_block(
                view=7, block_id=block_id, block_hash=block_hash, parent_id=parent_id
            )
            assert isinstance(out, dict)
            return out
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    assert ex.bft_handle_vote(vote_from("v1")) is None
    assert ex.bft_handle_vote(vote_from("v2")) is None

    restarted = WeAllExecutor(
        db_path=db_path, node_id="@v1", chain_id="bft-live", tx_index_path=tx_index_path
    )
    _seed_validator_set(restarted, validators=validators, pub=vpub, epoch=5)

    pending_votes = restarted._bft.export_state().get("pending_votes")
    assert isinstance(pending_votes, list) and pending_votes

    qc = restarted.bft_handle_vote(vote_from("v3"))
    assert qc is not None
    assert qc.block_id == block_id
    assert qc.block_hash == block_hash
    assert qc.view == 7


def test_restart_drops_old_epoch_liveness_buckets_after_transition(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    db_path = str(tmp_path / "epoch-restart.db")
    ex = WeAllExecutor(
        db_path=db_path, node_id="@v4", chain_id="bft-live", tx_index_path=tx_index_path
    )
    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=3)

    def timeout_from(signer: str, view: int, epoch: int) -> dict:
        import os

        ex2 = WeAllExecutor(
            db_path=str(tmp_path / f"epoch-timeout-{signer}-{view}-{epoch}.db"),
            node_id=f"@{signer}",
            chain_id="bft-live",
            tx_index_path=tx_index_path,
        )
        _seed_validator_set(ex2, validators=validators, pub=vpub, epoch=epoch)
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

    assert ex.bft_handle_timeout(timeout_from("v1", 0, 3)) is None
    state_before = ex._bft.export_state()
    assert state_before.get("pending_timeouts")

    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=4)
    ex._persist_bft_state()

    restarted = WeAllExecutor(
        db_path=db_path, node_id="@v4", chain_id="bft-live", tx_index_path=tx_index_path
    )
    _seed_validator_set(restarted, validators=validators, pub=vpub, epoch=4)

    pending_timeouts = restarted._bft.export_state().get("pending_timeouts") or []
    assert pending_timeouts == []
