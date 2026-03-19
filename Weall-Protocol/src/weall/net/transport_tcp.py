# src/weall/net/transport_tcp.py
"""WeAll Protocol — TCP Transport (Length-Prefixed Frames)

Frame format:
  [4-byte big-endian length][message bytes]

Where message bytes are canonical JSON from weall.net.codec.encode_message().

This backend is intentionally minimal, but safe:
  - non-blocking sockets + selectors
  - bounded read buffers
  - fail-closed on oversized frames

Production hardening notes
--------------------------
This transport is a low-level subsystem that will see adversarial inputs.
We keep it fail-closed, but we must not *silently* swallow errors in prod.
Accordingly, this file emits lightweight JSONL events (net_logging.log_event)
plus integer counters (runtime.metrics.inc_counter) on the key failure paths.

All observability is best-effort and will never raise.
"""

from __future__ import annotations

import logging
import os
import selectors
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from weall.net.net_logging import log_event
from weall.net.transport import Connection, PeerAddr, WirePacket
from weall.runtime.metrics import inc_counter


_LOG = logging.getLogger("weall.net.transport.tcp")


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def tcp_addr(host: str, port: int) -> PeerAddr:
    return PeerAddr(f"tcp://{host}:{int(port)}")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        return int(str(raw).strip() or str(default))
    except Exception as exc:
        if _mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}") from exc
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    raw = str(os.environ.get(name, "")).strip().lower()
    if not raw:
        return bool(default)
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


def _mode() -> str:
    # Mirror node.py: tests default to a non-prod posture unless explicitly set.
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return (str(os.environ.get("WEALL_MODE", "prod")).strip().lower() or "prod")


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


def _safe_count(name: str, value: int = 1) -> None:
    try:
        inc_counter(name, value)
    except Exception:
        pass


def _safe_event(event: str, **fields) -> None:
    try:
        log_event(_LOG, event, **fields)
    except Exception:
        pass


# ---------------------------------------------------------------------
# Connection implementation
# ---------------------------------------------------------------------


@dataclass(slots=True)
class _TcpConn(Connection):
    sock: socket.socket
    _peer_id: str
    _peer_addr: PeerAddr

    # connection metadata
    inbound: bool = False
    remote_ip: str = ""
    remote_port: int = 0

    # inbound buffer
    rbuf: bytearray = field(default_factory=bytearray)

    # outbound buffer
    wbuf: bytearray = field(default_factory=bytearray)

    # outbound backpressure
    max_wbuf_bytes: int = 0
    close_on_overflow: bool = True

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

        # Backpressure: bound outbound queue growth to avoid memory DoS.
        if self.max_wbuf_bytes and (len(self.wbuf) + len(frame)) > int(self.max_wbuf_bytes):
            _safe_count("net_tcp_outbound_overflow_total", 1)
            if self.close_on_overflow:
                self.close()
            return

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

        # Connection caps (abuse hardening). Defaults are conservative in prod,
        # and effectively unlimited in test mode so unit tests don't break.
        #
        # Set WEALL_NET_MAX_CONNECTIONS=0 to disable the cap.
        md = _mode()
        default_total = 0 if md == "test" else 200
        default_inbound = 0 if md == "test" else 128
        default_per_ip = 0 if md == "test" else 16

        self.max_connections_total = max(0, _env_int("WEALL_NET_MAX_CONNECTIONS", default_total))
        self.max_inbound_connections = max(0, _env_int("WEALL_NET_MAX_INBOUND", default_inbound))
        self.max_connections_per_ip = max(0, _env_int("WEALL_NET_MAX_PER_IP", default_per_ip))

        # Allow opting out of caps entirely (useful for controlled lab networks)
        self._caps_enabled = _env_bool("WEALL_NET_ENABLE_CONN_CAPS", True if md == "prod" else False)

        # Outbound backpressure (bound per-connection send queue)
        default_out_q = 0 if md == "test" else 8_000_000
        self.max_outbound_buffer_bytes = max(0, _env_int("WEALL_NET_MAX_OUTBOUND_BUFFER_BYTES", default_out_q))
        self.close_on_outbound_overflow = _env_bool("WEALL_NET_CLOSE_ON_OUTBOUND_OVERFLOW", True)

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
        _safe_event("net_tcp_bound", addr=str(addr.uri))

    def connect(self, addr: PeerAddr) -> _TcpConn:
        if self._caps_enabled and self.max_connections_total and len(self._conns) >= self.max_connections_total:
            raise RuntimeError("max_connections_exceeded")

        host, port = _parse_tcp_uri(addr.uri)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)

        try:
            s.connect((host, port))
        except BlockingIOError:
            pass

        pid = _peer_id_for(addr)
        conn = _TcpConn(
            sock=s,
            _peer_id=pid,
            _peer_addr=addr,
            inbound=False,
            remote_ip=str(host),
            remote_port=int(port),
            max_wbuf_bytes=int(self.max_outbound_buffer_bytes),
            close_on_overflow=bool(self.close_on_outbound_overflow),
        )
        self._conns[pid] = conn

        self._sel.register(s, selectors.EVENT_READ | selectors.EVENT_WRITE, data=("conn", pid))
        _safe_count("net_tcp_connect_attempt_total", 1)
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

        try:
            events = self._sel.select(timeout=0)
        except Exception as e:
            _safe_count("net_tcp_select_error_total", 1)
            _safe_event("net_tcp_select_error", err=repr(e))
            return out

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
                        _safe_count("net_tcp_read_fail_total", 1)
                        self._drop_conn(pid)
                        continue

                    pkts = self._drain_frames(conn, max_packets=max_packets - len(out))
                    out.extend(pkts)
                    if len(out) >= max_packets:
                        break

                # Write next (flush outbound)
                if mask & selectors.EVENT_WRITE:
                    if not self._flush_out(conn):
                        _safe_count("net_tcp_write_fail_total", 1)
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
            except Exception as e:
                _safe_count("net_tcp_accept_error_total", 1)
                _safe_event("net_tcp_accept_error", err=repr(e))
                return

            client.setblocking(False)
            addr = PeerAddr(f"tcp://{ip}:{port}")
            pid = _peer_id_for(addr)

            # Connection caps: refuse abusive fan-in before allocating buffers.
            if self._caps_enabled:
                if self.max_connections_total and len(self._conns) >= self.max_connections_total:
                    _safe_count("net_tcp_conn_refused_total", 1)
                    try:
                        client.close()
                    except Exception:
                        pass
                    continue

                if self.max_inbound_connections:
                    inbound_count = sum(1 for c in self._conns.values() if getattr(c, "inbound", False))
                    if inbound_count >= self.max_inbound_connections:
                        _safe_count("net_tcp_conn_refused_total", 1)
                        try:
                            client.close()
                        except Exception:
                            pass
                        continue

                if self.max_connections_per_ip:
                    ip_count = sum(1 for c in self._conns.values() if getattr(c, "remote_ip", "") == str(ip))
                    if ip_count >= self.max_connections_per_ip:
                        _safe_count("net_tcp_conn_refused_total", 1)
                        try:
                            client.close()
                        except Exception:
                            pass
                        continue

            conn = _TcpConn(
                sock=client,
                _peer_id=pid,
                _peer_addr=addr,
                inbound=True,
                remote_ip=str(ip),
                remote_port=int(port),
                max_wbuf_bytes=int(self.max_outbound_buffer_bytes),
                close_on_overflow=bool(self.close_on_outbound_overflow),
            )
            self._conns[pid] = conn

            try:
                self._sel.register(client, selectors.EVENT_READ | selectors.EVENT_WRITE, data=("conn", pid))
            except Exception as e:
                _safe_count("net_tcp_register_error_total", 1)
                _safe_event("net_tcp_register_error", peer=str(pid), err=repr(e))
                self._drop_conn(pid)
                continue

            _safe_count("net_tcp_accept_ok_total", 1)

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
        except Exception as e:
            _safe_event("net_tcp_recv_error", peer=str(conn.peer_id), err=repr(e))
            return False

        if not chunk:
            return False

        conn.rbuf.extend(chunk)
        if len(conn.rbuf) > self.max_buffer_bytes:
            _safe_count("net_tcp_inbound_overflow_total", 1)
            _safe_event(
                "net_tcp_inbound_overflow",
                peer=str(conn.peer_id),
                size=int(len(conn.rbuf)),
                max_buffer_bytes=int(self.max_buffer_bytes),
            )
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
                # Emit a synthetic packet carrying the failure class for upper-layer strikes.
                _safe_count("net_tcp_frame_error_total", 1)
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
                                "declared_len": str(int(n)),
                                "max_frame_bytes": str(int(self.max_frame_bytes)),
                            },
                        )
                    )
                except Exception:
                    pass

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
        except Exception as e:
            _safe_event("net_tcp_send_error", peer=str(conn.peer_id), err=repr(e))
            return False
