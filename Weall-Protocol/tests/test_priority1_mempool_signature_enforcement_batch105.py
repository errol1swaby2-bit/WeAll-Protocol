from __future__ import annotations

from pathlib import Path

import pytest

from weall.crypto.sig import canonical_tx_message
from weall.runtime.executor import WeAllExecutor
from weall.runtime.tx_admission import admit_tx
from weall.testing.sigtools import deterministic_ed25519_keypair


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, name: str, *, chain_id: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=name,
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def test_prod_http_admission_rejects_bad_signature_batch105(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _executor(tmp_path, "prod-node", chain_id="mempool-prod-badsig")

    pub, _priv = deterministic_ed25519_keypair(label="@alice")
    bad = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"pubkey": pub},
        "chain_id": "mempool-prod-badsig",
        "sig": "00" * 64,
    }
    verdict = admit_tx(bad, ex.read_state(), ex.tx_index, context="http")
    assert verdict.ok is False
    assert verdict.code == "bad_sig"
    assert verdict.reason == "signature_verification_failed"


def test_prod_http_admission_accepts_valid_signature_batch105(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _executor(tmp_path, "prod-node", chain_id="mempool-prod-goodsig")

    pub, priv = deterministic_ed25519_keypair(label="@alice")
    payload = {"pubkey": pub}
    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@alice",
        "nonce": 1,
        "payload": payload,
        "chain_id": "mempool-prod-goodsig",
        "sig": priv.sign(
            canonical_tx_message(
                chain_id="mempool-prod-goodsig",
                tx_type="ACCOUNT_REGISTER",
                signer="@alice",
                nonce=1,
                payload=payload,
                parent=None,
            )
        ).hex(),
    }
    verdict = admit_tx(tx, ex.read_state(), ex.tx_index, context="http")
    assert verdict.ok is True
