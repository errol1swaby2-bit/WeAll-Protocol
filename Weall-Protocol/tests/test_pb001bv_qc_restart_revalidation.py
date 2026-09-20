from __future__ import annotations

from types import SimpleNamespace

import weall.runtime.bft_hotstuff as hs
import weall.runtime.runtime_posture as posture
from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert, validator_set_hash


def _qc(*, view: int, block_id: str, epoch: int = 4, set_hash: str = "set-hash") -> QuorumCert:
    return QuorumCert(
        chain_id="c",
        view=view,
        block_id=block_id,
        block_hash=f"{block_id}-hash",
        parent_id="parent",
        votes=tuple(
            {
                "t": "VOTE",
                "chain_id": "c",
                "view": view,
                "block_id": block_id,
                "block_hash": f"{block_id}-hash",
                "parent_id": "parent",
                "signer": signer,
                "pubkey": f"pk-{signer}",
                "sig": f"sig-{signer}",
                "sig_profile": "pq-mldsa-v1",
                "validator_epoch": epoch,
                "validator_set_hash": set_hash,
            }
            for signer in ("v1", "v2", "v3")
        ),
        validator_epoch=epoch,
        validator_set_hash=set_hash,
    )


def _restore(*qcs: QuorumCert) -> HotStuffBFT:
    bft = HotStuffBFT(chain_id="c")
    payload: dict[str, object] = {}
    if qcs:
        payload["high_qc"] = qcs[0].to_json()
    if len(qcs) > 1:
        payload["locked_qc"] = qcs[1].to_json()
    bft.load_from_state({"bft": payload})
    return bft


def _revalidate(bft: HotStuffBFT, *, epoch: int, set_hash: str, strict: bool = True) -> bool:
    fn = getattr(bft, "revalidate_safety_proofs", None)
    assert callable(fn), "persisted QC safety proofs have no restart revalidation API"
    return bool(
        fn(
            validators=["v1", "v2", "v3", "v4"],
            vpub={f"v{i}": f"pk-v{i}" for i in range(1, 5)},
            validator_epoch=epoch,
            validator_set_hash_expected=set_hash,
            strict_epoch_binding=strict,
        )
    )


def test_structurally_restored_forged_qcs_fail_restart_revalidation(monkeypatch) -> None:
    set_hash = validator_set_hash(["v1", "v2", "v3", "v4"])
    bft = _restore(
        _qc(view=9, block_id="H", set_hash=set_hash), _qc(view=8, block_id="L", set_hash=set_hash)
    )
    monkeypatch.setattr(hs, "verify_qc", lambda **_: False)
    assert not _revalidate(bft, epoch=4, set_hash=set_hash)


def test_restored_qc_wrong_epoch_fails_even_if_signature_verifier_accepts(monkeypatch) -> None:
    set_hash = validator_set_hash(["v1", "v2", "v3", "v4"])
    bft = _restore(_qc(view=9, block_id="H", epoch=3, set_hash=set_hash))
    monkeypatch.setattr(hs, "verify_qc", lambda **_: True)
    assert not _revalidate(bft, epoch=4, set_hash=set_hash, strict=True)


def test_restored_qc_wrong_set_hash_fails_even_if_signature_verifier_accepts(monkeypatch) -> None:
    current_hash = validator_set_hash(["v1", "v2", "v3", "v4"])
    bft = _restore(_qc(view=9, block_id="H", epoch=4, set_hash="stale-set"))
    monkeypatch.setattr(hs, "verify_qc", lambda **_: True)
    assert not _revalidate(bft, epoch=4, set_hash=current_hash, strict=True)


def test_current_epoch_restored_high_and_locked_qcs_can_be_revalidated(monkeypatch) -> None:
    set_hash = validator_set_hash(["v1", "v2", "v3", "v4"])
    high = _qc(view=9, block_id="H", set_hash=set_hash)
    lock = _qc(view=8, block_id="L", set_hash=set_hash)
    bft = _restore(high, lock)
    seen: list[str] = []

    def _ok(*, qc: QuorumCert, **_: object) -> bool:
        seen.append(qc.block_id)
        return True

    monkeypatch.setattr(hs, "verify_qc", _ok)
    assert _revalidate(bft, epoch=4, set_hash=set_hash)
    assert seen == ["H", "L"]


def test_invalid_restart_qc_proof_cannot_be_bypassed_by_nonprod_signing_override(
    monkeypatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    dummy = SimpleNamespace(
        _validator_signing_enabled=True,
        _signing_block_reason="",
        _bft_restart_safety_ok=False,
    )
    assert posture._effective_validator_signing_state(dummy) == (
        False,
        "bft_restart_qc_revalidation_failed",
    )
