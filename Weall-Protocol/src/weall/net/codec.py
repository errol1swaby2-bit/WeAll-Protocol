# src/weall/net/codec.py
from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, Type, TypeVar, Union

from weall.net.messages import (
    MsgType,
    WireHeader,
    WireMessage,
    PeerHello,
    PeerHelloAck,
    TxEnvelopeMsg,
    BlockProposalMsg,
    BlockVoteMsg,
    BftProposalMsg,
    BftVoteMsg,
    BftQcMsg,
    BftTimeoutMsg,
    StateSyncRequestMsg,
    StateSyncResponseMsg,
    PingMsg,
    PongMsg,
)

Json = Dict[str, Any]

T = TypeVar("T")


class WireDecodeError(RuntimeError):
    def __init__(self, code: str, msg: str) -> None:
        super().__init__(msg)
        self.code = code


class WireEncodeError(RuntimeError):
    def __init__(self, code: str, msg: str) -> None:
        super().__init__(msg)
        self.code = code


AnyWireMsg = Union[
    PeerHello,
    PeerHelloAck,
    TxEnvelopeMsg,
    BlockProposalMsg,
    BlockVoteMsg,
    BftProposalMsg,
    BftVoteMsg,
    BftQcMsg,
    BftTimeoutMsg,
    StateSyncRequestMsg,
    StateSyncResponseMsg,
    PingMsg,
    PongMsg,
]


def dumps_json(obj: Any) -> bytes:
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except Exception as e:
        raise WireEncodeError("encode_failed", f"encode failed: {e}") from e


def loads_json(data: bytes | str) -> Any:
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return json.loads(data)
    except json.JSONDecodeError as e:
        raise WireDecodeError("invalid_json", f"invalid json: {e}") from e
    except UnicodeDecodeError as e:
        raise WireDecodeError("invalid_utf8", f"invalid utf-8: {e}") from e


_MSG_REGISTRY: Dict[MsgType, Type[AnyWireMsg]] = {
    MsgType.PEER_HELLO: PeerHello,
    MsgType.PEER_HELLO_ACK: PeerHelloAck,
    MsgType.TX_ENVELOPE: TxEnvelopeMsg,
    MsgType.BLOCK_PROPOSAL: BlockProposalMsg,
    MsgType.BLOCK_VOTE: BlockVoteMsg,
    MsgType.BFT_PROPOSAL: BftProposalMsg,
    MsgType.BFT_VOTE: BftVoteMsg,
    MsgType.BFT_QC: BftQcMsg,
    MsgType.BFT_TIMEOUT: BftTimeoutMsg,
    MsgType.STATE_SYNC_REQUEST: StateSyncRequestMsg,
    MsgType.STATE_SYNC_RESPONSE: StateSyncResponseMsg,
    MsgType.PING: PingMsg,
    MsgType.PONG: PongMsg,
}


def _coerce_msg_type(v: Any) -> MsgType:
    if isinstance(v, MsgType):
        return v
    if isinstance(v, str):
        try:
            return MsgType(v)
        except Exception as e:
            raise WireDecodeError("unknown_message_type", f"Unknown message type: {v}") from e
    raise WireDecodeError("invalid_message_type", f"Invalid message type field: {type(v).__name__}")


def _coerce_int(v: Any, field: str) -> int:
    if isinstance(v, bool):
        raise WireDecodeError("invalid_int_field", f"Invalid int field '{field}': bool not allowed")
    if isinstance(v, int):
        return v
    raise WireDecodeError("invalid_int_field", f"Invalid int field '{field}': expected int, got {type(v).__name__}")


def _coerce_opt_int(v: Any, field: str) -> int | None:
    if v is None:
        return None
    return _coerce_int(v, field)


def _coerce_opt_str(v: Any, field: str) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    raise WireDecodeError("invalid_str_field", f"Invalid str field '{field}': expected str, got {type(v).__name__}")


def _tupleize(v: Any) -> tuple:
    if v is None:
        return tuple()
    if isinstance(v, tuple):
        return v
    if isinstance(v, list):
        return tuple(v)
    if isinstance(v, dict):
        raise WireDecodeError("invalid_tuple_field", "Expected list/tuple for tuple field, got dict")
    if isinstance(v, (str, bytes)):
        raise WireDecodeError("invalid_tuple_field", "Expected list/tuple for tuple field, got scalar")
    if isinstance(v, Iterable):
        return tuple(v)
    raise WireDecodeError("invalid_tuple_field", f"Expected list/tuple for tuple field, got {type(v).__name__}")


def _coerce_header(header_raw: Any) -> WireHeader:
    if not isinstance(header_raw, dict):
        raise WireDecodeError("missing_header", "Wire message missing 'header' object")

    h = dict(header_raw)
    mtype = _coerce_msg_type(h.get("type"))
    chain_id = h.get("chain_id")
    schema_version = h.get("schema_version")
    tx_index_hash = h.get("tx_index_hash")
    if not isinstance(chain_id, str) or not isinstance(schema_version, str) or not isinstance(tx_index_hash, str):
        raise WireDecodeError("invalid_header", "Invalid header fields")

    sent_ts_ms = _coerce_opt_int(h.get("sent_ts_ms"), "sent_ts_ms")
    corr_id = _coerce_opt_str(h.get("corr_id"), "corr_id")
    return WireHeader(
        type=mtype,
        chain_id=chain_id,
        schema_version=schema_version,
        tx_index_hash=tx_index_hash,
        sent_ts_ms=sent_ts_ms,
        corr_id=corr_id,
    )


def _normalize_tuple_fields_for_message(msg_type: MsgType, body: Dict[str, Any]) -> Dict[str, Any]:
    b = dict(body)
    if msg_type in (MsgType.PEER_HELLO, MsgType.PEER_HELLO_ACK):
        b["caps"] = _tupleize(b.get("caps"))
        return b
    if msg_type == MsgType.BLOCK_PROPOSAL:
        b["txs"] = _tupleize(b.get("txs"))
        return b
    if msg_type == MsgType.STATE_SYNC_RESPONSE:
        b["blocks"] = _tupleize(b.get("blocks"))
        return b
    return b


def encode_message(msg: AnyWireMsg) -> bytes:
    if not is_dataclass(msg):
        raise WireEncodeError("not_dataclass", "msg must be dataclass")
    d = asdict(msg)
    return dumps_json(d)


def decode_message(payload: bytes) -> AnyWireMsg:
    raw = loads_json(payload)
    if not isinstance(raw, dict):
        raise WireDecodeError("invalid_message", "wire message must be an object")

    header = _coerce_header(raw.get("header"))
    body = {k: v for (k, v) in raw.items() if k != "header"}

    body = _normalize_tuple_fields_for_message(header.type, body)

    cls = _MSG_REGISTRY.get(header.type)
    if cls is None:
        raise WireDecodeError("unknown_message_type", f"Unknown message type: {header.type}")

    try:
        return cls(header=header, **body)  # type: ignore[arg-type]
    except TypeError as e:
        raise WireDecodeError("invalid_message_shape", f"Invalid message shape: {e}") from e
