from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from weall.runtime.lineage_witness import (
    LineageWitnessError,
    LineageWitnessKind,
    canonicalize_lineage_witness,
    lineage_certificate_commitment,
    lineage_tx_set_commitment,
    lineage_witness_commitment,
    lineage_witness_from_json,
    make_certificate_witness,
    make_scoped_state_witness,
    make_single_tx_witness,
    make_tx_set_witness,
    validate_lineage_witness,
)


def _tx(ch: str) -> str:
    return "tx:" + ch * 64


def test_lineage_witness_kind_values_are_explicit_and_stable() -> None:
    assert [kind.value for kind in LineageWitnessKind] == [
        "SINGLE_TX",
        "TX_SET",
        "CERTIFICATE",
        "SCOPED_STATE",
    ]


def test_single_tx_witness_round_trip_is_canonical_and_frozen() -> None:
    witness = make_single_tx_witness(
        parent_tx_type="block_finalize",
        parent_tx_id=_tx("a"),
        scope="block:7",
        same_block_position=2,
    )
    assert witness.to_json() == {
        "version": 1,
        "kind": "SINGLE_TX",
        "parent_tx_type": "BLOCK_FINALIZE",
        "parent_tx_id": _tx("a"),
        "scope": "block:7",
        "same_block_position": 2,
    }
    assert lineage_witness_from_json(witness.to_json()) == witness
    with pytest.raises(FrozenInstanceError):
        witness.scope = "other"  # type: ignore[misc]


def test_single_tx_rejects_noncanonical_tx_id() -> None:
    with pytest.raises(LineageWitnessError, match="parent_tx_id_not_canonical_tx_id"):
        make_single_tx_witness(parent_tx_type="EPOCH_OPEN", parent_tx_id="tx:not-a-hash")


def test_single_tx_rejects_negative_same_block_position() -> None:
    with pytest.raises(LineageWitnessError, match="same_block_position_must_be_nonnegative"):
        make_single_tx_witness(
            parent_tx_type="BLOCK_FINALIZE",
            parent_tx_id=_tx("a"),
            same_block_position=-1,
        )


def test_tx_set_canonicalizes_order_and_binds_scope_and_policy() -> None:
    left = make_tx_set_witness(
        parent_tx_type="GOV_VOTE_CAST",
        parent_tx_ids=[_tx("b"), _tx("a")],
        scope="proposal:p1",
        policy_id="gov-majority-v1",
        required_count=2,
    )
    right = make_tx_set_witness(
        parent_tx_type="gov_vote_cast",
        parent_tx_ids=[_tx("a"), _tx("b")],
        scope="proposal:p1",
        policy_id="gov-majority-v1",
        required_count=2,
    )
    assert left == right
    assert left.parent_tx_ids == (_tx("a"), _tx("b"))
    assert left.set_commitment == lineage_tx_set_commitment(
        parent_tx_type="GOV_VOTE_CAST",
        parent_tx_ids=[_tx("b"), _tx("a")],
        scope="proposal:p1",
        policy_id="gov-majority-v1",
    )


def test_tx_set_rejects_duplicate_parent_transaction_ids() -> None:
    with pytest.raises(LineageWitnessError, match="parent_tx_ids_duplicate"):
        make_tx_set_witness(
            parent_tx_type="GOV_VOTE_CAST",
            parent_tx_ids=[_tx("a"), _tx("a")],
            scope="proposal:p1",
            policy_id="gov-majority-v1",
        )


def test_tx_set_rejects_impossible_required_count() -> None:
    with pytest.raises(LineageWitnessError, match="required_count_exceeds_parent_tx_ids"):
        make_tx_set_witness(
            parent_tx_type="DISPUTE_VOTE_SUBMIT",
            parent_tx_ids=[_tx("a"), _tx("b")],
            scope="dispute:d1",
            policy_id="dispute-quorum-v1",
            required_count=3,
        )


def test_tx_set_rejects_tampered_set_commitment() -> None:
    witness = make_tx_set_witness(
        parent_tx_type="TREASURY_SPEND_SIGN",
        parent_tx_ids=[_tx("a"), _tx("b")],
        scope="spend:s1",
        policy_id="treasury-threshold-v1",
    ).to_json()
    witness["set_commitment"] = "sha256:" + "0" * 64
    verdict = validate_lineage_witness(witness)
    assert verdict.ok is False
    assert verdict.reason == "set_commitment_mismatch"


def test_strict_validator_rejects_noncanonical_tx_set_order() -> None:
    witness = make_tx_set_witness(
        parent_tx_type="GOV_VOTE_CAST",
        parent_tx_ids=[_tx("a"), _tx("b")],
        scope="proposal:p1",
        policy_id="gov-majority-v1",
    ).to_json()
    witness["parent_tx_ids"] = [_tx("b"), _tx("a")]
    strict = validate_lineage_witness(witness)
    relaxed = validate_lineage_witness(witness, require_canonical=False)
    assert strict.ok is False
    assert strict.reason == "noncanonical_lineage_witness"
    assert relaxed.ok is True


def test_certificate_witness_requires_canonical_commitment_and_subject() -> None:
    commitment = lineage_certificate_commitment({"block_id": "B7", "qc": ["a", "b", "c"]})
    witness = make_certificate_witness(
        parent_tx_type="BLOCK_ATTEST",
        certificate_type="BFT_QC_V1",
        certificate_commitment=commitment,
        subject_id="block:B7",
        policy_id="two-thirds-plus-one",
    )
    assert witness.kind is LineageWitnessKind.CERTIFICATE
    assert witness.certificate_commitment == commitment
    assert validate_lineage_witness(witness).ok is True


def test_certificate_witness_rejects_non_sha256_commitment() -> None:
    with pytest.raises(LineageWitnessError, match="certificate_commitment_not_sha256_commitment"):
        make_certificate_witness(
            parent_tx_type="BLOCK_ATTEST",
            certificate_type="BFT_QC_V1",
            certificate_commitment="qc:opaque",
            subject_id="block:B7",
            policy_id="two-thirds-plus-one",
        )


def test_scoped_state_wraps_exact_source_witness() -> None:
    source = make_single_tx_witness(
        parent_tx_type="ACCOUNT_RECOVERY_APPROVE",
        parent_tx_id=_tx("c"),
        scope="recovery:r1",
    )
    witness = make_scoped_state_witness(
        parent_tx_type="ACCOUNT_RECOVERY_APPROVE",
        scope="recovery:r1",
        created_height=10,
        updated_height=12,
        source=source,
    )
    parsed = lineage_witness_from_json(witness.to_json())
    assert parsed == witness
    assert parsed.source == source
    assert validate_lineage_witness(witness).ok is True


def test_scoped_state_rejects_source_parent_type_mismatch() -> None:
    source = make_single_tx_witness(
        parent_tx_type="GOV_STAGE_SET",
        parent_tx_id=_tx("a"),
    )
    with pytest.raises(LineageWitnessError, match="scoped_state_source_parent_tx_type_mismatch"):
        make_scoped_state_witness(
            parent_tx_type="GOV_PROPOSAL_CREATE",
            scope="proposal:p1",
            created_height=5,
            updated_height=6,
            source=source,
        )


def test_scoped_state_rejects_nested_scoped_state() -> None:
    source = make_single_tx_witness(parent_tx_type="GOV_STAGE_SET", parent_tx_id=_tx("a"))
    nested = make_scoped_state_witness(
        parent_tx_type="GOV_STAGE_SET",
        scope="proposal:p1",
        created_height=5,
        updated_height=6,
        source=source,
    )
    with pytest.raises(LineageWitnessError, match="nested_scoped_state_not_allowed"):
        make_scoped_state_witness(
            parent_tx_type="GOV_STAGE_SET",
            scope="proposal:p1",
            created_height=6,
            updated_height=7,
            source=nested,
        )


def test_scoped_state_rejects_height_reversal() -> None:
    source = make_single_tx_witness(parent_tx_type="GOV_STAGE_SET", parent_tx_id=_tx("a"))
    with pytest.raises(LineageWitnessError, match="updated_height_before_created_height"):
        make_scoped_state_witness(
            parent_tx_type="GOV_STAGE_SET",
            scope="proposal:p1",
            created_height=7,
            updated_height=6,
            source=source,
        )


def test_validator_checks_expected_parent_tx_type() -> None:
    witness = make_single_tx_witness(
        parent_tx_type="BLOCK_FINALIZE",
        parent_tx_id=_tx("a"),
    )
    verdict = validate_lineage_witness(witness, expected_parent_tx_type="GOV_EXECUTE")
    assert verdict.ok is False
    assert verdict.reason == "parent_tx_type_mismatch"


def test_validator_rejects_unknown_fields_fail_closed() -> None:
    raw = make_single_tx_witness(
        parent_tx_type="BLOCK_FINALIZE",
        parent_tx_id=_tx("a"),
    ).to_json()
    raw["context"] = "silently-ignored-field"
    verdict = validate_lineage_witness(raw)
    assert verdict.ok is False
    assert verdict.reason == "unknown_fields:context"


def test_canonicalizer_can_normalize_kind_and_parent_type_but_strict_validator_rejects_raw_form() -> (
    None
):
    raw = {
        "version": 1,
        "kind": " single_tx ",
        "parent_tx_type": " block_finalize ",
        "parent_tx_id": _tx("a"),
    }
    assert canonicalize_lineage_witness(raw)["kind"] == "SINGLE_TX"
    verdict = validate_lineage_witness(raw)
    assert verdict.ok is False
    assert verdict.reason == "noncanonical_lineage_witness"


def test_lineage_witness_commitment_is_deterministic_and_scope_sensitive() -> None:
    a = make_single_tx_witness(
        parent_tx_type="BLOCK_FINALIZE",
        parent_tx_id=_tx("a"),
        scope="block:7",
    )
    b = make_single_tx_witness(
        parent_tx_type="BLOCK_FINALIZE",
        parent_tx_id=_tx("a"),
        scope="block:8",
    )
    assert lineage_witness_commitment(a) == lineage_witness_commitment(a.to_json())
    assert lineage_witness_commitment(a) != lineage_witness_commitment(b)
