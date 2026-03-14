from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope


def test_dispute_vote_rejected_when_no_juror_assignment_strict() -> None:
    st = {
        "height": 0,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10},
        },
    }

    # Open dispute (alice is opener)
    apply_tx(
        st,
        TxEnvelope(
            tx_type="DISPUTE_OPEN",
            signer="alice",
            nonce=1,
            payload={"dispute_id": "d1", "target_type": "content", "target_id": "c1"},
            sig="",
            system=False,
        ),
    )

    # Without explicit juror assignment, alice may NOT vote in strict mode.
    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st,
            TxEnvelope(
                tx_type="DISPUTE_VOTE_SUBMIT",
                signer="alice",
                nonce=2,
                payload={"dispute_id": "d1", "vote": "yes"},
                sig="",
                system=False,
            ),
        )

    err = ei.value
    assert err.code == "forbidden"
    assert err.reason == "juror_not_assigned"
