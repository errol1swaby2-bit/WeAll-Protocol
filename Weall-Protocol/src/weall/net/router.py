from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from weall.net.handshake import (
    HandshakeRejected,
    HandshakeState,
    begin_outbound_handshake,
    process_inbound_ack,
    process_inbound_hello,
    require_established,
)
from weall.net.messages import (
    BftProposalMsg,
    BftQcMsg,
    BftTimeoutMsg,
    BftVoteMsg,
    BlockProposalMsg,
    BlockVoteMsg,
    MsgType,
    PingMsg,
    PongMsg,
    StateSyncRequestMsg,
    StateSyncResponseMsg,
    TxEnvelopeMsg,
    WireMessage,
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
SyncRequestHandler = Callable[[StateSyncRequestMsg], StateSyncResponseMsg | None]
SyncResponseHandler = Callable[[StateSyncResponseMsg], None]

PingHandler = Callable[[PingMsg], PongMsg | None]

BftProposalHandler = Callable[[BftProposalMsg], None]
BftVoteHandler = Callable[[BftVoteMsg], None]
BftQcHandler = Callable[[BftQcMsg], None]
BftTimeoutHandler = Callable[[BftTimeoutMsg], None]


@dataclass
class Router:
    handshake: HandshakeState

    on_tx: TxHandler | None = None
    on_block: BlockHandler | None = None
    on_vote: VoteHandler | None = None
    on_sync_request: SyncRequestHandler | None = None
    on_sync_response: SyncResponseHandler | None = None
    on_ping: PingHandler | None = None

    # BFT
    on_bft_proposal: BftProposalHandler | None = None
    on_bft_vote: BftVoteHandler | None = None
    on_bft_qc: BftQcHandler | None = None
    on_bft_timeout: BftTimeoutHandler | None = None

    last_error: str | None = None

    def handle_message(self, msg: WireMessage) -> WireMessage | None:
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
            if self.on_sync_response:
                self.on_sync_response(msg)  # type: ignore[arg-type]
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
