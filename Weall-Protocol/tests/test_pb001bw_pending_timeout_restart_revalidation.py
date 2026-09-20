from __future__ import annotations

import pytest

from weall.runtime.bft_hotstuff import BftTimeout, HotStuffBFT

VALIDATORS = ["v1", "v2", "v3", "v4"]
VPUB = {v: f"pk-{v}" for v in VALIDATORS}


def _timeout(
    signer: str,
    *,
    view: int = 5,
    epoch: int = 4,
    set_hash: str = "set-4",
    sig: str = "good",
) -> dict:
    return {
        "t": "TIMEOUT",
        "chain_id": "pbw",
        "view": int(view),
        "high_qc_id": "hq",
        "signer": signer,
        "pubkey": VPUB[signer],
        "sig": sig,
        "sig_profile": "pq-mldsa-v1",
        "validator_epoch": int(epoch),
        "validator_set_hash": set_hash,
    }


def _restore(*timeouts: dict, view: int = 5) -> HotStuffBFT:
    bft = HotStuffBFT(chain_id="pbw")
    bft.load_from_state(
        {
            "bft": {
                "view": int(view),
                "pending_timeouts": [{"view": int(view), "timeouts": list(timeouts)}],
            }
        }
    )
    return bft


def _accept_current(bft: HotStuffBFT, signer: str = "v3") -> int | None:
    return bft.accept_timeout(
        timeout_json=_timeout(signer),
        validators=VALIDATORS,
        vpub=VPUB,
    )


def test_restored_old_epoch_timeouts_cannot_be_laundered_into_current_tc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(BftTimeout, "verify", lambda self: True)
    bft = _restore(
        _timeout("v1", epoch=3, set_hash="set-3"), _timeout("v2", epoch=3, set_hash="set-3")
    )

    assert _accept_current(bft) is None
    assert bft.view == 5
    assert bft.last_timeout_certificate is None
    assert set(bft._timeouts[5]) == {"v3"}


def test_restored_wrong_set_hash_timeouts_cannot_count_toward_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(BftTimeout, "verify", lambda self: True)
    bft = _restore(
        _timeout("v1", epoch=4, set_hash="stale-set"),
        _timeout("v2", epoch=4, set_hash="stale-set"),
    )

    assert _accept_current(bft) is None
    assert bft.view == 5
    assert bft.last_timeout_certificate is None
    assert set(bft._timeouts[5]) == {"v3"}


def test_restored_bad_signatures_are_dropped_and_do_not_squat_signer_slots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(BftTimeout, "verify", lambda self: self.sig == "good")
    bft = _restore(_timeout("v1", sig="bad"), _timeout("v2", sig="bad"))

    assert _accept_current(bft) is None
    assert bft.view == 5
    assert bft.last_timeout_certificate is None
    assert set(bft._timeouts[5]) == {"v3"}

    # A genuine retry from a signer whose restored slot was forged must be able
    # to replace the rejected durable entry rather than being suppressed.
    assert _accept_current(bft, "v1") is None
    assert set(bft._timeouts[5]) == {"v1", "v3"}


def test_valid_current_epoch_restored_timeouts_still_complete_quorum_after_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(BftTimeout, "verify", lambda self: self.sig == "good")
    bft = _restore(_timeout("v1"), _timeout("v2"))

    assert _accept_current(bft) == 6
    assert bft.view == 6
    assert bft.last_timeout_certificate is not None
    assert bft.last_timeout_certificate.signers == ("v1", "v2", "v3")
    assert bft._last_timeout_certificate_verified is True


def test_loading_state_without_pending_timeouts_clears_prior_in_memory_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(BftTimeout, "verify", lambda self: True)
    bft = _restore(_timeout("v1"), _timeout("v2"))
    assert bft._timeouts

    bft.load_from_state({"bft": {"view": 5}})

    assert bft._timeouts == {}
    assert bft._restored_liveness_views_pending_revalidation == set()
