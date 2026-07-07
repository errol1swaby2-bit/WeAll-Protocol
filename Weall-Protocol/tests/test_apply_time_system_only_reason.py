from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope


def test_apply_time_canon_system_only_uses_stable_domain_reason() -> None:
    """Direct apply/replay paths should keep the domain error contract.

    Admission may reject public ingress with edge-specific reasons such as
    ``system_flag_required`` or ``system_only_tx_not_allowed_in_public_ingress``.
    Once a transaction reaches apply/replay, non-system attempts at SYSTEM or
    system_only transaction types should surface the canonical domain reason
    ``system_only`` so older PoH/system tests and block-replay diagnostics stay
    stable.
    """

    state = {"chain_id": "test", "height": 1, "accounts": {"alice": {"nonce": 0}}}
    env = TxEnvelope(
        tx_type="POH_LIVE_JUROR_REPLACE",
        signer="alice",
        nonce=1,
        payload={"case_id": "case-1", "old_juror_id": "j1", "new_juror_id": "j2"},
        system=False,
        sig="sig",
    )

    with pytest.raises(ApplyError) as ei:
        apply_tx(state, env)

    assert ei.value.code == "forbidden"
    assert ei.value.reason == "system_only"
