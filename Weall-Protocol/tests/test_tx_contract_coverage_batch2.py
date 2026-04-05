from __future__ import annotations

from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_contracts import (
    build_tx_contract_map,
    duplicate_handler_claims,
    handler_name_for_tx_type,
    load_default_tx_index,
    noncanon_registry_tx_types,
    resolve_applier_for_tx_type,
    unclaimed_canon_tx_types,
)


def _canon_txdef(tx_type: str) -> dict:
    idx = load_default_tx_index()
    rec = idx.get(tx_type, {})
    return rec if isinstance(rec, dict) else {}



def _minimal_env_for_tx(tx_type: str) -> TxEnvelope:
    txdef = _canon_txdef(tx_type)
    origin = str(txdef.get("origin") or "").strip().upper()
    receipt_only = bool(txdef.get("receipt_only", False))
    context = str(txdef.get("context") or "").strip().lower()
    is_system = origin == "SYSTEM"

    parent = None
    if receipt_only or context == "block":
        parent = "PARENT-TEST"

    return TxEnvelope(
        tx_type=tx_type,
        signer="SYSTEM" if is_system else "@tester",
        nonce=1,
        payload={},
        sig="",
        parent=parent,
        system=is_system,
        chain_id="batch2-test",
    )



def test_every_canon_tx_is_claimed_exactly_once() -> None:
    idx = load_default_tx_index()
    assert unclaimed_canon_tx_types(idx) == []
    assert duplicate_handler_claims(idx) == {}



def test_canon_handler_routes_are_stable() -> None:
    rows = build_tx_contract_map()
    assert rows
    assert len(rows) == len(load_default_tx_index().list_types())

    for row in rows:
        assert row["claim_count"] == 1, row
        assert isinstance(row["handler"], str) and row["handler"], row



def test_registry_exposes_only_known_legacy_extras() -> None:
    assert noncanon_registry_tx_types(load_default_tx_index()) == [
        "ACCOUNT_RECOVERY_EXECUTE",
        "ACCOUNT_RECOVERY_PROPOSE",
        "ACCOUNT_RECOVERY_VOTE",
        "ACCOUNT_UNBAN",
        "POH_EMAIL_RECEIPT_SUBMIT",
        "POH_TIER3_JUROR_REPLACE",
        "POST_CREATE",
        "POST_DELETE",
        "POST_EDIT",
        "SLASH",
        "TREASURY_PARAMS_SET",
        "TREASURY_PROGRAM_RECEIPT",
    ]



def test_every_canon_handler_claims_when_invoked() -> None:
    idx = load_default_tx_index()

    for tx_type in idx.list_types():
        fn = resolve_applier_for_tx_type(tx_type)
        assert fn is not None, tx_type
        env = _minimal_env_for_tx(tx_type)
        try:
            out = fn({}, env)
        except Exception as e:  # noqa: BLE001 - domain modules do not share one base error yet.
            reason = str(getattr(e, "reason", "") or "")
            assert reason not in {"unknown_tx_type", "unclaimed_tx_type"}, (
                tx_type,
                getattr(e, "code", None),
                reason,
                getattr(e, "details", None),
            )
            continue

        assert out is not None, tx_type



def test_dispatch_prefers_canonical_reputation_route_for_account_ban() -> None:
    assert handler_name_for_tx_type("ACCOUNT_BAN") == "reputation"
    env = TxEnvelope(
        tx_type="ACCOUNT_BAN",
        signer="SYSTEM",
        nonce=1,
        payload={},
        sig="",
        parent="DISPUTE_RESOLVE:test",
        system=True,
        chain_id="batch2-test",
    )
    fn = resolve_applier_for_tx_type("ACCOUNT_BAN")
    assert fn is not None
    try:
        fn({}, env)
    except Exception as e:  # noqa: BLE001 - see note above.
        assert str(getattr(e, "reason", "")) == "missing_account_id"
        assert str(getattr(e, "code", "")) == "invalid_payload"
    else:
        raise AssertionError("ACCOUNT_BAN without payload should fail in reputation handler")
