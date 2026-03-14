from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

JsonScalar = Union[str, int, float, bool, None]
JsonValue = Union[JsonScalar, Dict[str, Any], List[Any]]
JsonObject = Dict[str, JsonValue]

ChainId = str
SchemaVersion = str
HexDigest = str
PeerId = str


class MsgType(str, Enum):
    PEER_HELLO = "PEER_HELLO"
    PEER_HELLO_ACK = "PEER_HELLO_ACK"

    TX_ENVELOPE = "TX_ENVELOPE"

    BLOCK_PROPOSAL = "BLOCK_PROPOSAL"
    BLOCK_VOTE = "BLOCK_VOTE"

    # HotStuff BFT (finality path)
    BFT_PROPOSAL = "BFT_PROPOSAL"
    BFT_VOTE = "BFT_VOTE"
    BFT_QC = "BFT_QC"
    BFT_TIMEOUT = "BFT_TIMEOUT"

    STATE_SYNC_REQUEST = "STATE_SYNC_REQUEST"
    STATE_SYNC_RESPONSE = "STATE_SYNC_RESPONSE"

    # Keepalive / liveness
    PING = "PING"
    PONG = "PONG"


@dataclass(frozen=True, slots=True)
class WireHeader:
    type: MsgType
    chain_id: ChainId
    schema_version: SchemaVersion
    tx_index_hash: HexDigest
    sent_ts_ms: Optional[int] = None
    corr_id: Optional[str] = None


@dataclass(frozen=True, slots=True)
class WireMessage:
    header: WireHeader


@dataclass(frozen=True, slots=True)
class PeerHello(WireMessage):
    peer_id: PeerId
    agent: Optional[str] = None
    nonce: Optional[str] = None
    caps: Tuple[str, ...] = field(default_factory=tuple)
    identity: Optional[JsonObject] = None


@dataclass(frozen=True, slots=True)
class PeerHelloAck(WireMessage):
    peer_id: PeerId
    ok: bool
    reason: Optional[str] = None
    caps: Tuple[str, ...] = field(default_factory=tuple)
    server_ts_ms: Optional[int] = None


@dataclass(frozen=True, slots=True)
class TxEnvelopeMsg(WireMessage):
    nonce: int
    client_tx_id: Optional[str] = None
    tx: JsonObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BlockProposalMsg(WireMessage):
    height: int
    prev_block_hash: HexDigest
    block_ts_ms: int
    block_hash: Optional[HexDigest] = None
    txs: Tuple[JsonObject, ...] = field(default_factory=tuple)
    proposer: Optional[str] = None


@dataclass(frozen=True, slots=True)
class BlockVoteMsg(WireMessage):
    height: int
    block_hash: HexDigest
    vote: Literal["yes", "no"]
    reason: Optional[str] = None
    voter: Optional[str] = None


# ----------------------------
# HotStuff BFT messages
# ----------------------------

@dataclass(frozen=True, slots=True)
class BftProposalMsg(WireMessage):
    view: int
    proposer: str
    block: JsonObject = field(default_factory=dict)
    justify_qc: Optional[JsonObject] = None


@dataclass(frozen=True, slots=True)
class BftVoteMsg(WireMessage):
    view: int
    vote: JsonObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BftQcMsg(WireMessage):
    qc: JsonObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BftTimeoutMsg(WireMessage):
    view: int
    timeout: JsonObject = field(default_factory=dict)


# ----------------------------
# State sync (BACK-COMPAT SHAPE)
# ----------------------------

@dataclass(frozen=True, slots=True)
class StateSyncRequestMsg(WireMessage):
    mode: Literal["snapshot", "delta"]
    from_height: int = 0
    to_height: Optional[int] = None
    selector: Optional[JsonObject] = None


@dataclass(frozen=True, slots=True)
class StateSyncResponseMsg(WireMessage):
    ok: bool
    reason: Optional[str]
    height: int

    # snapshot mode
    snapshot: Optional[JsonObject] = None
    snapshot_hash: Optional[str] = None

    # delta mode
    blocks: Tuple[JsonObject, ...] = field(default_factory=tuple)


# ----------------------------
# Keepalive / liveness
# ----------------------------

@dataclass(frozen=True, slots=True)
class PingMsg(WireMessage):
    ping_id: Optional[str] = None


@dataclass(frozen=True, slots=True)
class PongMsg(WireMessage):
    ping_id: Optional[str] = None
