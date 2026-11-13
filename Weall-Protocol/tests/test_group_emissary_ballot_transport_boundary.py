"""Risk-characterization tests: the current ballot envelope is NOT secret.

These tests document an unsafe disclosure property so no frontend or reviewer
can confuse strict aggregate apply-state storage with secret-ballot transport.
They are not cryptographic assurance or release/activation authorization.
"""

from __future__ import annotations

import json

from weall.api.routes_public_parts.groups import _public_election_row
from weall.runtime.ballot_policy import ballot_profile_status
from weall.runtime.tx_schema import validate_tx_envelope


def _current_plaintext_group_ballot() -> dict:
    return {
        "tx_type": "GROUP_EMISSARY_BALLOT_CAST",
        "signer": "@alice",
        "nonce": 7,
        "sig": "fixture_signature_not_real_crypto",
        "payload": {
            "election_id": "e:test",
            "ranking": ["@bob", "@carl"],
        },
    }


def test_current_signed_ballot_schema_exposes_voter_with_ranked_choices() -> None:
    envelope, parsed = validate_tx_envelope(_current_plaintext_group_ballot())
    assert parsed is not None
    assert envelope.signer == "@alice"
    assert envelope.tx_type == "GROUP_EMISSARY_BALLOT_CAST"
    assert envelope.payload == {
        "election_id": "e:test",
        "ranking": ["@bob", "@carl"],
    }
    # The JSON serialization of the whole envelope is sufficient to correlate
    # the identifying signer and plaintext choices. This is an exposure test,
    # not proof that any particular real voter's data was published.
    signed_envelope_json = json.dumps(envelope.model_dump(mode="json"), sort_keys=True)
    assert '"signer": "@alice"' in signed_envelope_json
    assert '"ranking": ["@bob", "@carl"]' in signed_envelope_json


def test_strict_aggregate_storage_does_not_change_plaintext_envelope() -> None:
    state = {
        "params": {
            "mode": "controlled-testnet",
            "m3_civic_governance_strict": True,
            "ballot_profile_id": "controlled-testnet-aggregate-v1",
            "ballot_profile_active": True,
        }
    }
    profile = ballot_profile_status(state)
    assert profile["strict"] is True
    assert profile["active"] is True
    envelope, _ = validate_tx_envelope(_current_plaintext_group_ballot())
    assert envelope.signer == "@alice"
    assert envelope.payload["ranking"] == ["@bob", "@carl"]


def test_public_group_election_flags_block_secret_ballot_claim_even_in_strict_profile() -> None:
    item = _public_election_row(
        {
            "group_id": "g:test",
            "status": "open",
            "candidates": ["@bob", "@carl"],
            "start_height": 2,
            "end_height": 20,
            "voter_snapshot": ["@alice"],
        },
        election_id="e:test",
        group_id="g:test",
        observed_height=5,
        viewer="@alice",
    )
    assert item["viewer_in_voter_snapshot"] is True
    assert item["ballot_submission_authorized"] is False
    assert item["ballot_transport_privacy_verified"] is False
    assert item["secret_ballot_supported"] is False
    assert (
        item["ballot_transport_disclosure"]
        == "signed_envelope_contains_signer_and_plaintext_ranking"
    )
    for field in ("ranking", "voter_snapshot", "ballots", "ballot_boxes"):
        assert field not in item
