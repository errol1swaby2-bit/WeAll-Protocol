"""GOV_VOTING_CLOSE strict model matches canonical queued governance execution.

This is payload-schema consistency only, NOT governance approval or production
validator authorization. Origin and queue bindings remain independently enforced.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from weall.runtime.tx_schema import GovVotingClosePayload, validate_tx_envelope


@pytest.mark.parametrize("reason", ["quorum_reached", "poll_threshold_reached"])
def test_canonical_governance_close_reason_is_schema_valid(reason: str) -> None:
    raw = {
        "tx_type": "GOV_VOTING_CLOSE",
        "signer": "SYSTEM",
        "nonce": 0,
        "system": True,
        "payload": {"proposal_id": "signed-tier2-proposal", "close_reason": reason},
    }
    envelope, payload = validate_tx_envelope(raw)
    assert envelope.system is True
    assert isinstance(payload, GovVotingClosePayload)
    assert payload.proposal_id == "signed-tier2-proposal"
    assert payload.close_reason == reason


def test_governance_close_payload_remains_strict() -> None:
    with pytest.raises(ValidationError):
        GovVotingClosePayload.model_validate(
            {"proposal_id": "signed-tier2-proposal", "close_reason": "quorum_reached", "unreviewed_override": True}
        )
    with pytest.raises(ValidationError):
        GovVotingClosePayload.model_validate({"proposal_id": "signed-tier2-proposal", "close_reason": ""})
