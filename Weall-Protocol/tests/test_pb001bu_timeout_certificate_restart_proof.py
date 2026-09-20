from __future__ import annotations

from typing import Any

import weall.runtime.bft_hotstuff as hs
from weall.runtime.bft_hotstuff import HotStuffBFT, TimeoutCertificate, validator_set_hash


def _tc_json(*, with_proofs: bool = False) -> dict[str, Any]:
    signers = ["v1", "v2", "v3"]
    tc: dict[str, Any] = {
        "t": "TC",
        "chain_id": "c",
        "view": 7,
        "high_qc_id": "qc-a",
        "signer_count": 3,
        "signers": list(signers),
        "validator_epoch": 4,
        "validator_set_hash": validator_set_hash(["v1", "v2", "v3", "v4"]),
    }
    if with_proofs:
        tc["timeouts"] = [
            {
                "t": "TIMEOUT",
                "chain_id": "c",
                "view": 7,
                "high_qc_id": "qc-a",
                "signer": signer,
                "pubkey": f"pk-{signer}",
                "sig": f"sig-{signer}",
                "sig_profile": "pq-mldsa-v1",
                "validator_epoch": 4,
                "validator_set_hash": tc["validator_set_hash"],
            }
            for signer in signers
        ]
    return tc


def test_restored_proofless_timeout_certificate_is_not_authoritative() -> None:
    bft = HotStuffBFT(chain_id="c")
    bft.load_from_state({"bft": {"last_timeout_certificate": _tc_json()}})

    assert bft.last_timeout_certificate is not None
    assert bft.best_timeout_certificate() is None


def test_restored_timeout_certificate_requires_cryptographic_revalidation(monkeypatch) -> None:
    bft = HotStuffBFT(chain_id="c")
    bft.load_from_state({"bft": {"last_timeout_certificate": _tc_json(with_proofs=True)}})

    monkeypatch.setattr(hs, "_verify_bft_signature", lambda **_: True)
    assert bft.revalidate_liveness_proof(
        validators=["v1", "v2", "v3", "v4"],
        vpub={f"v{i}": f"pk-v{i}" for i in range(1, 5)},
        validator_epoch=4,
        validator_set_hash_expected=validator_set_hash(["v1", "v2", "v3", "v4"]),
    )
    assert bft.best_timeout_certificate() is not None


def test_tampered_restored_timeout_proof_is_dropped(monkeypatch) -> None:
    tcj = _tc_json(with_proofs=True)
    tcj["timeouts"][0]["sig"] = "tampered"
    bft = HotStuffBFT(chain_id="c")
    bft.load_from_state({"bft": {"last_timeout_certificate": tcj}})

    monkeypatch.setattr(
        hs,
        "_verify_bft_signature",
        lambda *, sig, **_: str(sig) != "tampered",
    )
    assert not bft.revalidate_liveness_proof(
        validators=["v1", "v2", "v3", "v4"],
        vpub={f"v{i}": f"pk-v{i}" for i in range(1, 5)},
        validator_epoch=4,
        validator_set_hash_expected=validator_set_hash(["v1", "v2", "v3", "v4"]),
    )
    assert bft.last_timeout_certificate is None
    assert bft.best_timeout_certificate() is None


def test_formed_timeout_certificate_exports_only_after_verified() -> None:
    bft = HotStuffBFT(chain_id="c")
    bft.last_timeout_certificate = TimeoutCertificate(
        chain_id="c",
        view=1,
        high_qc_id="qc-a",
        signer_count=3,
        signers=("v1", "v2", "v3"),
    )
    assert "last_timeout_certificate" not in bft.export_state()
