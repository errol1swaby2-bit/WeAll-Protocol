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


def _signed_account_register(*, chain_id: str, signer: str, nonce: int) -> dict[str, object]:
    pub, priv = deterministic_ed25519_keypair(label=signer)
    payload = {"pubkey": pub}
    msg = canonical_tx_message(
        chain_id=chain_id,
        tx_type="ACCOUNT_REGISTER",
        signer=signer,
        nonce=nonce,
        payload=payload,
        parent=None,
    )
    return {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": signer,
        "nonce": nonce,
        "payload": payload,
        "chain_id": chain_id,
        "sig": priv.sign(msg).hex(),
    }


def test_prod_http_admission_rejects_unsigned_tx_and_executor_keeps_local_fixture_behavior(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _executor(tmp_path, "prod-node", chain_id="candidate-prod")

    unsigned = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@unsigned",
        "nonce": 1,
        "payload": {"pubkey": "ed25519:unsigned"},
        "chain_id": "candidate-prod",
        "sig": "",
    }
    verdict = admit_tx(unsigned, ex.read_state(), ex.tx_index, context="http")
    assert verdict.ok is False
    assert verdict.code == "missing_sig"

    # executor.submit_tx remains intentionally permissive for local fixture paths;
    # public HTTP routes enforce signature verification before calling it.
    local_fixture = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@fixturelocal",
            "nonce": 1,
            "payload": {"pubkey": "ed25519:fixture-local"},
        }
    )
    assert local_fixture["ok"] is True

    # A valid signed tx remains admissible through the same executor-local path.
    good = ex.submit_tx(
        _signed_account_register(chain_id="candidate-prod", signer="@signed", nonce=1)
    )
    assert good["ok"] is True

    meta = ex.produce_block(max_txs=4)
    assert meta.ok is True
    assert int(meta.applied_count) >= 1

    state = ex.read_state()
    accounts = state.get("accounts") or {}
    assert "@fixturelocal" in accounts or "@signed" in accounts
    assert "@unsigned" not in accounts


def test_nonprod_candidate_builder_preserves_unsigned_fixture_behavior(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    ex = _executor(tmp_path, "testnet-node", chain_id="candidate-testnet")

    res = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@fixture",
            "nonce": 1,
            "payload": {"pubkey": "ed25519:fixture"},
        }
    )
    assert res["ok"] is True

    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True
    assert int(meta.applied_count) == 1

    state = ex.read_state()
    assert "@fixture" in (state.get("accounts") or {})
