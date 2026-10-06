from __future__ import annotations

from weall.crypto.sig import sign_signature_for_profile
from weall.crypto.signature_profiles import PQ_MLDSA_V1
from weall.runtime import bft_runtime_adapter
from weall.runtime.bft_hotstuff import (
    BftTimeout,
    HotStuffBFT,
    QuorumCert,
    TimeoutCertificate,
    canonical_timeout_message,
    canonical_vote_message,
    qc_from_json,
    quorum_threshold,
    validator_set_hash,
    verify_qc,
)
from weall.testing.sigtools import deterministic_mldsa_keypair

CHAIN_ID = "a05-timeout-rank"
VALIDATORS = ["v1", "v2", "v3", "v4"]
EPOCH = 9
SET_HASH = validator_set_hash(VALIDATORS)


def _keys() -> tuple[dict[str, str], dict[str, str]]:
    public: dict[str, str] = {}
    private: dict[str, str] = {}
    for signer in VALIDATORS:
        pubkey, privkey = deterministic_mldsa_keypair(label=f"a05-f003:{signer}")
        public[signer] = pubkey
        private[signer] = privkey.private_bytes_raw().hex()
    return public, private


def _qc(
    *,
    view: int,
    block_id: str,
    public: dict[str, str],
    private: dict[str, str],
) -> dict:
    parent_id = f"parent-{view}"
    block_hash = f"hash-{block_id}"
    votes: list[dict] = []
    for signer in VALIDATORS[: quorum_threshold(len(VALIDATORS))]:
        message = canonical_vote_message(
            chain_id=CHAIN_ID,
            view=view,
            block_id=block_id,
            block_hash=block_hash,
            parent_id=parent_id,
            signer=signer,
            validator_epoch=EPOCH,
            validator_set_hash=SET_HASH,
            sig_profile=PQ_MLDSA_V1,
        )
        signature = sign_signature_for_profile(
            sig_profile=PQ_MLDSA_V1,
            message=message,
            privkey=private[signer],
            encoding="hex",
        )
        votes.append(
            {
                "t": "VOTE",
                "chain_id": CHAIN_ID,
                "view": view,
                "block_id": block_id,
                "block_hash": block_hash,
                "parent_id": parent_id,
                "signer": signer,
                "pubkey": public[signer],
                "sig": signature,
                "sig_profile": PQ_MLDSA_V1,
                "validator_epoch": EPOCH,
                "validator_set_hash": SET_HASH,
            }
        )
    qc = QuorumCert(
        chain_id=CHAIN_ID,
        view=view,
        block_id=block_id,
        block_hash=block_hash,
        parent_id=parent_id,
        votes=tuple(votes),
        validator_epoch=EPOCH,
        validator_set_hash=SET_HASH,
    )
    assert verify_qc(qc=qc, validators=VALIDATORS, vpub=public, require_threshold=True)
    return qc.to_json()


def _timeout(
    *,
    signer: str,
    timeout_view: int,
    public: dict[str, str],
    private: dict[str, str],
    qc: dict | None,
    claimed_qc_view: int | None = None,
) -> dict:
    if qc is None:
        high_qc_id = "genesis"
        high_qc_view = -1
    else:
        high_qc_id = str(qc["block_id"])
        high_qc_view = int(qc["view"])
    if claimed_qc_view is not None:
        high_qc_view = int(claimed_qc_view)

    message = canonical_timeout_message(
        chain_id=CHAIN_ID,
        view=timeout_view,
        high_qc_id=high_qc_id,
        high_qc_view=high_qc_view,
        high_qc=qc,
        signer=signer,
        validator_epoch=EPOCH,
        validator_set_hash=SET_HASH,
        sig_profile=PQ_MLDSA_V1,
    )
    signature = sign_signature_for_profile(
        sig_profile=PQ_MLDSA_V1,
        message=message,
        privkey=private[signer],
        encoding="hex",
    )
    return BftTimeout(
        chain_id=CHAIN_ID,
        view=timeout_view,
        high_qc_id=high_qc_id,
        high_qc_view=high_qc_view,
        high_qc=dict(qc) if isinstance(qc, dict) else None,
        signer=signer,
        pubkey=public[signer],
        sig=signature,
        sig_profile=PQ_MLDSA_V1,
        validator_epoch=EPOCH,
        validator_set_hash=SET_HASH,
    ).to_json()


def _form_tc(timeouts: list[dict], public: dict[str, str]) -> HotStuffBFT:
    bft = HotStuffBFT(chain_id=CHAIN_ID)
    result = None
    for timeout in timeouts:
        result = bft.accept_timeout(
            timeout_json=timeout,
            validators=VALIDATORS,
            vpub=public,
        )
    assert result == 1
    assert bft.best_timeout_certificate() is not None
    return bft


def test_a05_f003_stale_plurality_loses_to_higher_verified_qc() -> None:
    public, private = _keys()
    stale = _qc(view=2, block_id="a-stale", public=public, private=private)
    high = _qc(view=7, block_id="z-high", public=public, private=private)

    bft = _form_tc(
        [
            _timeout(
                signer="v1",
                timeout_view=0,
                public=public,
                private=private,
                qc=stale,
            ),
            _timeout(
                signer="v2",
                timeout_view=0,
                public=public,
                private=private,
                qc=stale,
            ),
            _timeout(
                signer="v3",
                timeout_view=0,
                public=public,
                private=private,
                qc=high,
            ),
        ],
        public,
    )

    tc = bft.best_timeout_certificate()
    assert tc is not None
    assert tc.high_qc_id == "z-high"
    assert tc.high_qc_view == 7
    assert tc.high_qc == high


def test_a05_f003_same_view_conflict_uses_deterministic_qc_id_tie_break() -> None:
    public, private = _keys()
    qc_z = _qc(view=5, block_id="z-qc", public=public, private=private)
    qc_a = _qc(view=5, block_id="a-qc", public=public, private=private)

    bft = _form_tc(
        [
            _timeout(
                signer="v1",
                timeout_view=0,
                public=public,
                private=private,
                qc=qc_z,
            ),
            _timeout(
                signer="v2",
                timeout_view=0,
                public=public,
                private=private,
                qc=qc_z,
            ),
            _timeout(
                signer="v3",
                timeout_view=0,
                public=public,
                private=private,
                qc=qc_a,
            ),
        ],
        public,
    )

    tc = bft.best_timeout_certificate()
    assert tc is not None
    assert tc.high_qc_view == 5
    assert tc.high_qc_id == "a-qc"
    assert tc.high_qc == qc_a


def test_a05_f003_forged_high_qc_rank_is_rejected() -> None:
    public, private = _keys()
    qc = _qc(view=4, block_id="qc-4", public=public, private=private)
    forged = _timeout(
        signer="v1",
        timeout_view=0,
        public=public,
        private=private,
        qc=qc,
        claimed_qc_view=400,
    )

    bft = HotStuffBFT(chain_id=CHAIN_ID)
    assert (
        bft.accept_timeout(
            timeout_json=forged,
            validators=VALIDATORS,
            vpub=public,
        )
        is None
    )
    assert bft._timeouts == {}
    assert bft.best_timeout_certificate() is None


def test_a05_f003_restart_revalidates_same_highest_verified_qc() -> None:
    public, private = _keys()
    low = _qc(view=1, block_id="qc-low", public=public, private=private)
    mid = _qc(view=4, block_id="qc-mid", public=public, private=private)
    high = _qc(view=8, block_id="qc-high", public=public, private=private)

    bft = _form_tc(
        [
            _timeout(
                signer="v1",
                timeout_view=0,
                public=public,
                private=private,
                qc=low,
            ),
            _timeout(
                signer="v2",
                timeout_view=0,
                public=public,
                private=private,
                qc=high,
            ),
            _timeout(
                signer="v3",
                timeout_view=0,
                public=public,
                private=private,
                qc=mid,
            ),
        ],
        public,
    )

    state: dict = {}
    bft.dump_to_state(state)

    restored = HotStuffBFT(chain_id=CHAIN_ID)
    restored.load_from_state(state)
    assert restored.best_timeout_certificate() is None
    assert restored.revalidate_liveness_proof(
        validators=VALIDATORS,
        vpub=public,
        validator_epoch=EPOCH,
        validator_set_hash_expected=SET_HASH,
    )

    tc = restored.best_timeout_certificate()
    assert tc is not None
    assert (tc.high_qc_id, tc.high_qc_view, tc.high_qc) == ("qc-high", 8, high)


def test_a05_f003_partition_recovery_converges_under_reordered_delivery() -> None:
    public, private = _keys()
    low = _qc(view=2, block_id="qc-low", public=public, private=private)
    high = _qc(view=9, block_id="qc-high", public=public, private=private)
    proofs = [
        _timeout(
            signer="v1",
            timeout_view=0,
            public=public,
            private=private,
            qc=low,
        ),
        _timeout(
            signer="v2",
            timeout_view=0,
            public=public,
            private=private,
            qc=low,
        ),
        _timeout(
            signer="v3",
            timeout_view=0,
            public=public,
            private=private,
            qc=high,
        ),
    ]

    orders = ([0, 1, 2], [2, 0, 1], [1, 2, 0], [2, 1, 0])
    recovered: list[tuple[str, int]] = []
    for order in orders:
        bft = _form_tc([proofs[index] for index in order], public)
        tc = bft.best_timeout_certificate()
        assert tc is not None
        recovered.append((tc.high_qc_id, tc.high_qc_view))

    assert recovered == [("qc-high", 9)] * 4


def test_a05_f003_embedded_verified_qc_removes_local_cache_rank_dependency() -> None:
    public, private = _keys()
    high = _qc(view=6, block_id="qc-embedded", public=public, private=private)
    tc = TimeoutCertificate(
        chain_id=CHAIN_ID,
        view=0,
        high_qc_id="qc-embedded",
        high_qc_view=6,
        high_qc=high,
        signer_count=3,
        signers=("v1", "v2", "v3"),
        validator_epoch=EPOCH,
        validator_set_hash=SET_HASH,
    )
    bft = HotStuffBFT(chain_id=CHAIN_ID)
    bft.last_timeout_certificate = tc
    bft._last_timeout_certificate_verified = True

    class _Runtime:
        def __init__(self) -> None:
            self._bft = bft

        def bft_verify_qc_json(self, raw: dict):
            qc = qc_from_json(raw)
            if qc is None:
                return None
            if not verify_qc(
                qc=qc,
                validators=VALIDATORS,
                vpub=public,
                require_threshold=True,
            ):
                return None
            return qc

        def _pending_missing_qc_json(self, *, block_id: str):
            raise AssertionError(f"local QC cache must not be trusted for {block_id}")

    recovered = bft_runtime_adapter._bft_best_justify_qc_json(_Runtime())
    assert recovered == high
