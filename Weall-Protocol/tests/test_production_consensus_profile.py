from __future__ import annotations

from pathlib import Path

import pytest

from weall.api.routes_public_parts.tx import _http_requires_sig_by_default
from weall.ledger.state import LedgerView
from weall.net.net_loop import _peer_requires_sigverify
from weall.runtime.block_admission import admit_bft_block
from weall.runtime.block_loop import block_loop_config_from_env
from weall.runtime.chain_config import ChainConfig, validate_chain_config
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import load_tx_index_json


def _canon_path() -> Path:
    return Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"


def _load_index():
    return load_tx_index_json(_canon_path())


def test_http_sigverify_cannot_be_disabled_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    assert _http_requires_sig_by_default() is True


def test_peer_sigverify_cannot_be_disabled_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    assert _peer_requires_sigverify() is True


def test_tx_admission_requires_sig_on_peer_ingress_in_prod_even_with_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    idx = _load_index()
    ledger = LedgerView(
        accounts={
            "@alice": {
                "nonce": 0,
                "poh_tier": 3,
                "banned": False,
                "locked": False,
                "reputation": 10,
            },
        },
        roles={},
    )
    env = TxEnvelope(
        tx_type="ACCOUNT_DEVICE_REGISTER",
        signer="@alice",
        nonce=1,
        payload={"device_id": "dev1", "pubkey": "k:dev1"},
        sig="",
        parent=None,
    )

    ok, rej = admit_tx(env.to_json(), ledger, idx, context="peer")
    assert not ok
    assert rej is not None
    assert rej.code == "missing_sig"


def test_qc_less_blocks_remain_forbidden_in_prod_even_with_rollout_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")

    state = {
        "chain_id": "test-chain",
        "roles": {"validators": {"active_set": ["@v1", "@v2", "@v3", "@v4"]}},
        "consensus": {
            "validators": {
                "registry": {
                    "@v1": {"pubkey": "pk1"},
                    "@v2": {"pubkey": "pk2"},
                    "@v3": {"pubkey": "pk3"},
                    "@v4": {"pubkey": "pk4"},
                }
            }
        },
        "blocks": {"genesis": {"prev_block_id": ""}},
    }
    block = {
        "block_id": "b1",
        "prev_block_id": "genesis",
        "header": {
            "chain_id": "test-chain",
            "height": 1,
            "prev_block_hash": "00" * 32,
            "block_ts_ms": 1000,
            "tx_ids": [],
            "receipts_root": "r",
            "state_root": "s",
        },
    }

    ok, rej = admit_bft_block(block=block, state=state)
    assert ok is False
    assert rej is not None
    assert rej.code == "bft_missing_qc"


def test_prod_rejects_bft_unsafe_autocommit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_UNSAFE_AUTOCOMMIT", "1")

    with pytest.raises(ValueError, match="UNSAFE_AUTOCOMMIT"):
        block_loop_config_from_env()


def test_prod_chain_config_rejects_unsigned_txs(tmp_path: Path) -> None:
    tx_index = tmp_path / "tx_index.json"
    tx_index.write_text("{}", encoding="utf-8")

    cfg = ChainConfig(
        chain_id="weall-prod",
        node_id="node-1",
        mode="prod",
        db_path=str(tmp_path / "weall.db"),
        tx_index_path=str(tx_index),
        block_interval_ms=600_000,
        max_txs_per_block=1000,
        block_reward=0,
        api_host="127.0.0.1",
        api_port=8000,
        allow_unsigned_txs=True,
        log_level="INFO",
    )

    with pytest.raises(ValueError, match="allow_unsigned_txs"):
        validate_chain_config(cfg)
