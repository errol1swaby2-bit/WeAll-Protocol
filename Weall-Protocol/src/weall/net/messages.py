from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | dict[str, Any] | list[Any]
JsonObject = dict[str, JsonValue]

ChainId = str
SchemaVersion = str
HexDigest = str
PeerId = str


class MsgType(Enum):
    PEER_HELLO = "PEER_HELLO"
    PEER_HELLO_ACK = "PEER_HELLO_ACK"

    TX_ENVELOPE = "TX_ENVELOPE"

    BLOCK_PROPOSAL = "BLOCK_PROPOSAL"
    BLOCK_VOTE = "BLOCK_VOTE"

    BFT_PROPOSAL = "BFT_PROPOSAL"
    BFT_VOTE = "BFT_VOTE"
    BFT_QC = "BFT_QC"
    BFT_TIMEOUT = "BFT_TIMEOUT"

    STATE_SYNC_REQUEST = "STATE_SYNC_REQUEST"
    STATE_SYNC_RESPONSE = "STATE_SYNC_RESPONSE"

    PING = "PING"
    PONG = "PONG"


@dataclass(frozen=True, slots=True)
class WireHeader:
    type: MsgType
    chain_id: ChainId
    schema_version: SchemaVersion
    tx_index_hash: HexDigest
    sent_ts_ms: int | None = None
    corr_id: str | None = None


@dataclass(frozen=True, slots=True)
class WireMessage:
    header: WireHeader


@dataclass(frozen=True, slots=True)
class PeerHello(WireMessage):
    peer_id: PeerId
    agent: str | None = None
    nonce: str | None = None
    caps: tuple[str, ...] = field(default_factory=tuple)
    identity: JsonObject | None = None
    protocol_version: str | None = None
    protocol_profile_hash: str | None = None
    validator_epoch: int | None = None
    validator_set_hash: str | None = None
    bft_enabled: bool | None = None
    genesis_bootstrap_profile_hash: str | None = None
    genesis_bootstrap_enabled: bool | None = None
    genesis_bootstrap_mode: str | None = None


@dataclass(frozen=True, slots=True)
class PeerHelloAck(WireMessage):
    peer_id: PeerId
    ok: bool
    reason: str | None = None
    caps: tuple[str, ...] = field(default_factory=tuple)
    server_ts_ms: int | None = None
    protocol_version: str | None = None
    protocol_profile_hash: str | None = None
    validator_epoch: int | None = None
    validator_set_hash: str | None = None
    bft_enabled: bool | None = None
    genesis_bootstrap_profile_hash: str | None = None
    genesis_bootstrap_enabled: bool | None = None
    genesis_bootstrap_mode: str | None = None


@dataclass(frozen=True, slots=True)
class TxEnvelopeMsg(WireMessage):
    nonce: int
    client_tx_id: str | None = None
    tx: JsonObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BlockProposalMsg(WireMessage):
    height: int
    prev_block_hash: HexDigest
    block_ts_ms: int
    block_hash: HexDigest | None = None
    txs: tuple[JsonObject, ...] = field(default_factory=tuple)
    proposer: str | None = None


@dataclass(frozen=True, slots=True)
class BlockVoteMsg(WireMessage):
    height: int
    block_hash: HexDigest
    vote: Literal["yes", "no"]
    reason: str | None = None
    voter: str | None = None


@dataclass(frozen=True, slots=True)
class BftProposalMsg(WireMessage):
    view: int
    proposer: str
    block: JsonObject = field(default_factory=dict)
    justify_qc: JsonObject | None = None


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


@dataclass(frozen=True, slots=True)
class StateSyncRequestMsg(WireMessage):
    mode: Literal["snapshot", "delta"]
    from_height: int = 0
    to_height: int | None = None
    selector: JsonObject | None = None


@dataclass(frozen=True, slots=True)
class StateSyncResponseMsg(WireMessage):
    ok: bool
    reason: str | None
    height: int
    snapshot: JsonObject | None = None
    snapshot_hash: str | None = None
    snapshot_anchor: JsonObject | None = None
    blocks: tuple[JsonObject, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class PingMsg(WireMessage):
    ping_id: str | None = None


@dataclass(frozen=True, slots=True)
class PongMsg(WireMessage):
    ping_id: str | None = None
