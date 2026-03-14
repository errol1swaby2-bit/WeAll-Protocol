from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from weall.net.messages import (
    MsgType,
    WireMessage,
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
from weall.net.handshake import (
    HandshakeState,
    HandshakeRejected,
    begin_outbound_handshake,
    process_inbound_hello,
    process_inbound_ack,
    require_established,
)


class RouterError(RuntimeError):
    pass


class UnknownMessageType(RouterError):
    pass


class SessionRequired(RouterError):
    pass


class SessionRequiredInternal(RuntimeError):
    pass


TxHandler = Callable[[TxEnvelopeMsg], None]
BlockHandler = Callable[[BlockProposalMsg], None]
VoteHandler = Callable[[BlockVoteMsg], None]
SyncRequestHandler = Callable[[StateSyncRequestMsg], Optional[StateSyncResponseMsg]]

PingHandler = Callable[[PingMsg], Optional[PongMsg]]

BftProposalHandler = Callable[[BftProposalMsg], None]
BftVoteHandler = Callable[[BftVoteMsg], None]
BftQcHandler = Callable[[BftQcMsg], None]
BftTimeoutHandler = Callable[[BftTimeoutMsg], None]


@dataclass
class Router:
    handshake: HandshakeState

    on_tx: Optional[TxHandler] = None
    on_block: Optional[BlockHandler] = None
    on_vote: Optional[VoteHandler] = None
    on_sync_request: Optional[SyncRequestHandler] = None
    on_ping: Optional[PingHandler] = None

    # BFT
    on_bft_proposal: Optional[BftProposalHandler] = None
    on_bft_vote: Optional[BftVoteHandler] = None
    on_bft_qc: Optional[BftQcHandler] = None
    on_bft_timeout: Optional[BftTimeoutHandler] = None

    last_error: Optional[str] = None

    def handle_message(self, msg: WireMessage) -> Optional[WireMessage]:
        try:
            mtype = msg.header.type
        except Exception:
            raise RouterError("Message missing header/type")

        # Handshake path (pre-session)
        if mtype == MsgType.PEER_HELLO:
            try:
                return process_inbound_hello(self.handshake, msg)  # type: ignore[arg-type]
            except HandshakeRejected as e:
                self.last_error = e.reason
                raise

        if mtype == MsgType.PEER_HELLO_ACK:
            try:
                process_inbound_ack(self.handshake, msg)  # type: ignore[arg-type]
                return None
            except HandshakeRejected as e:
                self.last_error = e.reason
                raise

        # Post-handshake requires session
        try:
            require_established(self.handshake)
        except Exception as e:
            raise SessionRequired(str(e)) from e

        # TX gossip
        if mtype == MsgType.TX_ENVELOPE:
            if self.on_tx:
                self.on_tx(msg)  # type: ignore[arg-type]
            return None

        # Legacy block messages (kept)
        if mtype == MsgType.BLOCK_PROPOSAL:
            if self.on_block:
                self.on_block(msg)  # type: ignore[arg-type]
            return None

        if mtype == MsgType.BLOCK_VOTE:
            if self.on_vote:
                self.on_vote(msg)  # type: ignore[arg-type]
            return None

        # BFT messages
        if mtype == MsgType.BFT_PROPOSAL:
            if self.on_bft_proposal:
                self.on_bft_proposal(msg)  # type: ignore[arg-type]
            return None

        if mtype == MsgType.BFT_VOTE:
            if self.on_bft_vote:
                self.on_bft_vote(msg)  # type: ignore[arg-type]
            return None

        if mtype == MsgType.BFT_QC:
            if self.on_bft_qc:
                self.on_bft_qc(msg)  # type: ignore[arg-type]
            return None

        if mtype == MsgType.BFT_TIMEOUT:
            if self.on_bft_timeout:
                self.on_bft_timeout(msg)  # type: ignore[arg-type]
            return None

        # State sync
        if mtype == MsgType.STATE_SYNC_REQUEST:
            if not self.on_sync_request:
                return None
            return self.on_sync_request(msg)  # type: ignore[arg-type]

        if mtype == MsgType.STATE_SYNC_RESPONSE:
            return None

        # Keepalive
        if mtype == MsgType.PING:
            if self.on_ping:
                return self.on_ping(msg)  # type: ignore[arg-type]
            return None

        if mtype == MsgType.PONG:
            return None

        raise UnknownMessageType(f"Unhandled message type: {mtype}")


def initiate_handshake(router: Router) -> WireMessage:
    return begin_outbound_handshake(router.handshake)
