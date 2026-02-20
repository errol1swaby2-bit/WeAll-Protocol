# src/weall/net/transport_tcp.py
"""
WeAll Protocol — TCP Transport (Length-Prefixed Frames)

Frame format:
  [4-byte big-endian length][message bytes]

Where message bytes are canonical JSON from weall.net.codec.encode_message().

This backend is intentionally minimal, but safe:
  - non-blocking sockets + selectors
  - bounded read buffers
  - fail-closed on oversized frames
"""

from __future__ import annotations

import selectors
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from weall.net.transport import Connection, PeerAddr, WirePacket


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def tcp_addr(host: str, port: int) -> PeerAddr:
    return PeerAddr(f"tcp://{host}:{int(port)}")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _peer_id_for(addr: PeerAddr) -> str:
    # Transport-level peer_id. This is NOT the handshake peer_id; it’s the connection id.
    return addr.uri


def _parse_tcp_uri(uri: str) -> tuple[str, int]:
    if not uri.startswith("tcp://"):
        raise ValueError(f"invalid tcp uri: {uri}")
    rest = uri[len("tcp://") :]
    if ":" not in rest:
        raise ValueError(f"invalid tcp uri: {uri}")
    host, port_s = rest.rsplit(":", 1)
    return host, int(port_s)


# ---------------------------------------------------------------------
# Connection implementation
# ---------------------------------------------------------------------

@dataclass(slots=True)
class _TcpConn(Connection):
    sock: socket.socket
    _peer_id: str
    _peer_addr: PeerAddr

    # inbound buffer
    rbuf: bytearray = field(default_factory=bytearray)

    # outbound buffer
    wbuf: bytearray = field(default_factory=bytearray)

    closed: bool = False

    @property
    def peer_id(self) -> str:
        return self._peer_id

    @property
    def peer_addr(self) -> PeerAddr:
        return self._peer_addr

    def queue_send(self, payload: bytes) -> None:
        if self.closed:
            return
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        frame = struct.pack(">I", len(payload)) + payload
        self.wbuf.extend(frame)

    def send(self, payload: bytes) -> None:
        # immediate queue; actual flush happens during poll()
        self.queue_send(payload)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------

class TcpTransport:
    def __init__(
        self,
        *,
        max_frame_bytes: int = 2_000_000,
        max_buffer_bytes: int = 8_000_000,
    ) -> None:
        self.max_frame_bytes = int(max_frame_bytes)
        self.max_buffer_bytes = int(max_buffer_bytes)

        self._sel = selectors.DefaultSelector()
        self._listener: Optional[socket.socket] = None
        self._conns: Dict[str, _TcpConn] = {}

    # -------------------------
    # lifecycle
    # -------------------------

    def bind(self, addr: PeerAddr) -> None:
        host, port = _parse_tcp_uri(addr.uri)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setblocking(False)
        s.bind((host, port))
        s.listen(128)

        self._listener = s
        self._sel.register(s, selectors.EVENT_READ, data=("listener", None))

    def connect(self, addr: PeerAddr) -> _TcpConn:
        host, port = _parse_tcp_uri(addr.uri)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)

        try:
            s.connect((host, port))
        except BlockingIOError:
            pass

        pid = _peer_id_for(addr)
        conn = _TcpConn(sock=s, _peer_id=pid, _peer_addr=addr)
        self._conns[pid] = conn

        self._sel.register(s, selectors.EVENT_READ | selectors.EVENT_WRITE, data=("conn", pid))
        return conn

    def close(self) -> None:
        try:
            if self._listener is not None:
                try:
                    self._sel.unregister(self._listener)
                except Exception:
                    pass
                try:
                    self._listener.close()
                except Exception:
                    pass
                self._listener = None
        finally:
            for pid in list(self._conns.keys()):
                self._drop_conn(pid)
            try:
                self._sel.close()
            except Exception:
                pass

    # -------------------------
    # enumerations
    # -------------------------

    def connections(self) -> Iterable[_TcpConn]:
        return list(self._conns.values())

    def disconnect(self, peer_id: str) -> None:
        """Best-effort drop a connection by its transport peer_id."""
        if not isinstance(peer_id, str) or not peer_id.strip():
            return
        self._drop_conn(peer_id)

    # -------------------------
    # polling
    # -------------------------

    def poll(self, *, max_packets: int = 250) -> Iterable[WirePacket]:
        out: List[WirePacket] = []
        if max_packets <= 0:
            return out

        events = self._sel.select(timeout=0)
        for key, mask in events:
            kind, pid = key.data

            if kind == "listener":
                self._accept_loop(max_accepts=16)
                continue

            if kind == "conn" and pid is not None:
                conn = self._conns.get(pid)
                if conn is None or conn.closed:
                    continue

                # Read first (collect inbound)
                if mask & selectors.EVENT_READ:
                    if not self._read_into(conn):
                        self._drop_conn(pid)
                        continue

                    pkts = self._drain_frames(conn, max_packets=max_packets - len(out))
                    out.extend(pkts)
                    if len(out) >= max_packets:
                        break

                # Write next (flush outbound)
                if mask & selectors.EVENT_WRITE:
                    if not self._flush_out(conn):
                        self._drop_conn(pid)
                        continue

        return out

    # -------------------------
    # internals
    # -------------------------

    def _accept_loop(self, *, max_accepts: int) -> None:
        if self._listener is None:
            return

        for _ in range(max_accepts):
            try:
                client, (ip, port) = self._listener.accept()
            except BlockingIOError:
                return
            except Exception:
                return

            client.setblocking(False)
            addr = PeerAddr(f"tcp://{ip}:{port}")
            pid = _peer_id_for(addr)

            conn = _TcpConn(sock=client, _peer_id=pid, _peer_addr=addr)
            self._conns[pid] = conn
            self._sel.register(client, selectors.EVENT_READ | selectors.EVENT_WRITE, data=("conn", pid))

    def _drop_conn(self, pid: str) -> None:
        conn = self._conns.pop(pid, None)
        if conn is None:
            return
        try:
            self._sel.unregister(conn.sock)
        except Exception:
            pass
        conn.close()

    def _read_into(self, conn: _TcpConn) -> bool:
        try:
            chunk = conn.sock.recv(65536)
        except BlockingIOError:
            return True
        except Exception:
            return False

        if not chunk:
            return False

        conn.rbuf.extend(chunk)
        if len(conn.rbuf) > self.max_buffer_bytes:
            return False
        return True

    def _drain_frames(self, conn: _TcpConn, *, max_packets: int) -> List[WirePacket]:
        out: List[WirePacket] = []
        buf = conn.rbuf

        while max_packets > 0:
            if len(buf) < 4:
                break

            (n,) = struct.unpack(">I", buf[:4])
            if n <= 0 or n > self.max_frame_bytes:
                # Invalid/oversized frame.
                #
                # IMPORTANT: emit a synthetic packet carrying the failure class so
                # higher layers can apply strike escalation + ban cooldowns.
                try:
                    out.append(
                        WirePacket(
                            peer_id=conn.peer_id,
                            payload=b"",
                            received_at_ms=_now_ms(),
                            meta={
                                "transport": "tcp",
                                "addr": conn.peer_addr.uri,
                                "frame_error": "oversize" if n > self.max_frame_bytes else "invalid_length",
                                "declared_len": int(n),
                                "max_frame_bytes": int(self.max_frame_bytes),
                            },
                        )
                    )
                except Exception:
                    pass

                # Then drop.
                conn.rbuf.clear()
                conn.closed = True
                break

            if len(buf) < 4 + n:
                break

            payload = bytes(buf[4 : 4 + n])
            del buf[: 4 + n]

            out.append(
                WirePacket(
                    peer_id=conn.peer_id,
                    payload=payload,
                    received_at_ms=_now_ms(),
                    meta={"transport": "tcp", "addr": conn.peer_addr.uri},
                )
            )
            max_packets -= 1

        return out

    def _flush_out(self, conn: _TcpConn) -> bool:
        if not conn.wbuf:
            return True
        try:
            sent = conn.sock.send(conn.wbuf)
            if sent > 0:
                del conn.wbuf[:sent]
            return True
        except BlockingIOError:
            return True
        except Exception:
            return False
