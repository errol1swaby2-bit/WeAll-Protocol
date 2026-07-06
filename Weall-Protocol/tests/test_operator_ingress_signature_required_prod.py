from __future__ import annotations

from pathlib import Path

import pytest

from weall.crypto.sig import canonical_tx_message
from weall.runtime.executor import WeAllExecutor
from weall.runtime.tx_admission import admit_tx
from weall.testing.sigtools import deterministic_mldsa_keypair

ROOT = Path(__file__).resolve().parents[1]
API_ROOT = ROOT / "src" / "weall" / "api"


def _executor(tmp_path: Path, *, chain_id: str = "operator-ingress-prod") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="operator-ingress-node",
        chain_id=chain_id,
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )


def _signed_account_register(*, chain_id: str, signer: str = "@operatoruser", nonce: int = 1) -> dict[str, object]:
    pub, priv = deterministic_mldsa_keypair(label=signer)
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


def test_prod_operator_ingress_rejects_unsigned_user_tx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _executor(tmp_path)

    unsigned = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@unsignedoperator",
        "nonce": 1,
        "payload": {"pubkey": "not-a-real-key"},
        "chain_id": ex.chain_id,
        "sig": "",
    }

    admitted = admit_tx(unsigned, ex.read_state(), ex.tx_index, context="operator")
    assert admitted.ok is False
    assert admitted.code == "missing_sig"

    submitted = ex.submit_tx(unsigned, ingress="operator")
    assert submitted["ok"] is False
    assert submitted["error"] == "missing_sig"


@pytest.mark.parametrize("context", ["http", "operator"])
def test_explicit_public_ingress_rejects_malformed_modeled_payload_before_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, context: str
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    ex = _executor(tmp_path, chain_id="explicit-ingress-schema")
    state = ex.read_state()
    state.setdefault("accounts", {})["@alice"] = {
        "nonce": 0,
        "poh_tier": 2,
        "reputation_milli": 1_000_000,
        "pubkey": "test-pubkey",
    }

    malformed_comment = {
        "tx_type": "CONTENT_COMMENT_CREATE",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"post_id": "post-1"},
        "chain_id": ex.chain_id,
    }

    verdict = admit_tx(malformed_comment, state, ex.tx_index, context=context)

    assert verdict.ok is False
    assert verdict.code == "invalid_payload"
    assert verdict.reason == "schema_validation_failed"



def test_prod_operator_ingress_rejects_bad_signature_and_accepts_valid_signed_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _executor(tmp_path)

    bad = _signed_account_register(chain_id=ex.chain_id, signer="@badoperator")
    bad["sig"] = "00" * 64
    rejected = ex.submit_tx(bad, ingress="operator")
    assert rejected["ok"] is False
    assert rejected["error"] == "bad_sig"

    good = _signed_account_register(chain_id=ex.chain_id, signer="@goodoperator")
    accepted = ex.submit_tx(good, ingress="operator")
    assert accepted["ok"] is True
    assert accepted["tx_id"]



def test_prod_operator_ingress_rejects_system_tx_injection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _executor(tmp_path)

    forged_system = {
        "tx_type": "ECONOMICS_ACTIVATION",
        "signer": "SYSTEM",
        "nonce": 0,
        "payload": {"enabled": True},
        "system": True,
        "chain_id": ex.chain_id,
    }

    verdict = admit_tx(forged_system, ex.read_state(), ex.tx_index, context="operator")
    assert verdict.ok is False
    assert verdict.code == "system_tx_forbidden"



def test_api_routes_call_submit_tx_with_explicit_public_ingress() -> None:
    offenders: list[str] = []
    for path in API_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "submit_tx(" not in text:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            if "submit_tx(" in line and "def submit_tx" not in line:
                if "ingress=\"http\"" not in line and "ingress='http'" not in line:
                    offenders.append(f"{path.relative_to(ROOT)}:{line_no}:{line.strip()}")
    assert offenders == []
