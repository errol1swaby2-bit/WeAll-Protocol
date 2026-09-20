from __future__ import annotations

import math
from pathlib import Path

import pytest

from weall.net.codec import WireDecodeError, WireEncodeError, decode_message, encode_message
from weall.net.messages import MsgType, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import StateSyncService, StateSyncVerifyError
from weall.runtime.json_tools import canonical_json_str, strict_json_loads
from weall.runtime.sqlite_db import SqliteDB, SqliteLedgerStore
from weall.runtime.state_hash import compute_state_root


def _response_header() -> WireHeader:
    return WireHeader(
        type=MsgType.STATE_SYNC_RESPONSE,
        chain_id="strict-json-test",
        schema_version="1",
        tx_index_hash="deadbeef",
        corr_id="strict-json",
    )


def _service() -> StateSyncService:
    return StateSyncService(
        chain_id="strict-json-test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: {"height": 1},
    )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_and_state_root_reject_nonfinite_numbers(value: float) -> None:
    state = {"height": 1, "accounts": {"alice": {"reputation": value}}}

    with pytest.raises(ValueError):
        canonical_json_str(state)
    with pytest.raises(ValueError):
        compute_state_root(state)


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_strict_json_loads_rejects_nonstandard_number_tokens(token: str) -> None:
    with pytest.raises(ValueError, match="non_finite_json_number"):
        strict_json_loads(f'{{"value":{token}}}')


def test_state_sync_wire_rejects_nonfinite_snapshot_on_encode_and_decode() -> None:
    msg = StateSyncResponseMsg(
        header=_response_header(),
        ok=True,
        reason=None,
        height=1,
        snapshot={"height": 1, "accounts": {"alice": {"reputation": float("nan")}}},
        snapshot_hash="unused",
        snapshot_anchor={"height": 1},
        blocks=(),
    )

    with pytest.raises(WireEncodeError, match="encode failed"):
        encode_message(msg)

    raw = (
        b'{"header":{"type":"STATE_SYNC_RESPONSE","chain_id":"strict-json-test",'
        b'"schema_version":"1","tx_index_hash":"deadbeef"},"ok":true,'
        b'"reason":null,"height":1,"snapshot":{"height":1,"accounts":'
        b'{"alice":{"reputation":NaN}}},"snapshot_hash":"unused",'
        b'"snapshot_anchor":{"height":1},"blocks":[]}'
    )
    with pytest.raises(WireDecodeError, match="non_finite_json_number"):
        decode_message(raw)

    with pytest.raises(WireDecodeError) as excinfo:
        decode_message(b"\xff")
    assert excinfo.value.code == "invalid_utf8"


def test_finite_canonical_json_bytes_remain_unchanged() -> None:
    value = {"z": [0.0, 1, True, None], "a": {"text": "caf\u00e9"}}
    assert canonical_json_str(value) == '{"a":{"text":"caf\u00e9"},"z":[0.0,1,true,null]}'


def test_state_sync_verifier_rejects_in_memory_nonfinite_snapshot_before_hash_acceptance() -> None:
    poisoned = {"height": 1, "accounts": {"alice": {"reputation": float("nan")}}}
    resp = StateSyncResponseMsg(
        header=_response_header(),
        ok=True,
        reason=None,
        height=1,
        snapshot=poisoned,
        snapshot_hash="attacker-controlled",
        snapshot_anchor={"height": 1},
        blocks=(),
    )

    with pytest.raises(StateSyncVerifyError, match="snapshot_not_strict_json"):
        _service().verify_response(resp)


def test_sqlite_ledger_rejects_nonfinite_write_and_poisoned_restart_read(tmp_path: Path) -> None:
    db = SqliteDB(path=str(tmp_path / "strict-json.sqlite"))
    db.init_schema()
    store = SqliteLedgerStore(db=db)

    poisoned = {"height": 0, "tip": "", "accounts": {"alice": {"reputation": float("nan")}}}
    with pytest.raises(ValueError):
        store.write(poisoned)

    store.write({"height": 0, "tip": "", "accounts": {"alice": {"reputation": 0}}})
    with db.write_tx() as con:
        con.execute(
            "UPDATE ledger_state SET state_json=? WHERE id=1;",
            ('{"height":0,"tip":"","accounts":{"alice":{"reputation":NaN}}}',),
        )

    with pytest.raises(ValueError, match="non_finite_json_number"):
        store.read()

    # Ordinary finite floats remain valid JSON and retain their value.
    finite = strict_json_loads('{"value":0.0}')
    assert isinstance(finite["value"], float)
    assert math.isfinite(finite["value"])
