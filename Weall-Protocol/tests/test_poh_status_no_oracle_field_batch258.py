from __future__ import annotations

from weall.runtime.poh.state import canonical_account_poh_status, revoke_account_poh_status, set_account_poh_status


def test_set_account_poh_status_writes_provider_neutral_issuer_authority_id() -> None:
    state = {"height": 12, "accounts": {"@alice": {"poh_tier": 0}}, "poh": {}}

    rec = set_account_poh_status(
        state,
        account_id="@alice",
        poh_tier=1,
        verified_at_height=12,
        issuer_authority_id="async-case-authority",
    )

    assert rec["issuer_authority_id"] == "async-case-authority"
    assert "issuer_oracle_id" not in rec
    stored = state["poh"]["account_status"]["@alice"]
    assert stored["issuer_authority_id"] == "async-case-authority"
    assert "issuer_oracle_id" not in stored


def test_legacy_issuer_oracle_id_is_read_as_authority_id_without_reemitting() -> None:
    state = {
        "height": 7,
        "poh": {
            "account_status": {
                "@bob": {
                    "account_id": "@bob",
                    "poh_tier": 1,
                    "status": "active",
                    "verified_at_height": 5,
                    "expires_at_height": None,
                    "proof_commitment": "commitment",
                    "issuer_oracle_id": "legacy-issuer",
                    "last_updated_height": 5,
                }
            }
        },
    }

    status = canonical_account_poh_status(state, "@bob")

    assert status["issuer_authority_id"] == "legacy-issuer"
    assert "issuer_oracle_id" not in status


def test_legacy_issuer_oracle_id_kwarg_is_compatibility_alias_only() -> None:
    state = {"height": 2, "accounts": {"@carol": {"poh_tier": 0}}, "poh": {}}

    rec = set_account_poh_status(
        state,
        account_id="@carol",
        poh_tier=1,
        issuer_oracle_id="legacy-call-site",
    )

    assert rec["issuer_authority_id"] == "legacy-call-site"
    assert "issuer_oracle_id" not in rec


def test_revoke_preserves_issuer_authority_id_without_legacy_key() -> None:
    state = {"height": 2, "accounts": {"@dave": {"poh_tier": 0}}, "poh": {}}
    set_account_poh_status(
        state,
        account_id="@dave",
        poh_tier=2,
        issuer_authority_id="live-case-authority",
    )

    rec = revoke_account_poh_status(state, account_id="@dave", reason="test")

    assert rec["issuer_authority_id"] == "live-case-authority"
    assert "issuer_oracle_id" not in rec
