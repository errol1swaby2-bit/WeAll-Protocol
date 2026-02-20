# src/weall/net/transport_tls.py
"""WeAll Protocol — TLS over TCP Transport (Length-Prefixed Frames)

This is a drop-in alternative to TcpTransport providing hop encryption.

Threat model notes
------------------
TLS protects against *passive* network observers.

Peer identity is enforced at the WeAll handshake layer (account_id + Ed25519
proof). However, *active* MITM resistance at the transport layer requires the
client to authenticate the server certificate.

Production defaults
-------------------
If WEALL_MODE=prod and WEALL_NET_TRANSPORT=tls, we require certificate
verification unless you explicitly opt out via:

  WEALL_NET_TLS_INSECURE_OK=1

This opt-out is intended only for private testbeds.

Environment
-----------
Server side requires a certificate and private key:
  WEALL_NET_TLS_CERT=/path/to/cert.pem
  WEALL_NET_TLS_KEY=/path/to/key.pem

Client verification options:
  WEALL_NET_TLS_CA=/path/to/ca.pem
  WEALL_NET_TLS_SERVER_NAME=example.com   (optional SNI/hostname verification name)

Frame format is identical to TcpTransport:
  [4-byte big-endian length][message bytes]
"""

from __future__ import annotations

import os
import selectors
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from weall.net.transport import Connection, PeerAddr, WirePacket


def tls_addr(host: str, port: int) -> PeerAddr:
    return PeerAddr(f"tls://{host}:{int(port)}")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _peer_id_for(addr: PeerAddr) -> str:
    # Transport-level peer_id. This is NOT the handshake peer_id; it’s the connection id.
    return addr.uri


def _parse_tls_uri(uri: str) -> tuple[str, int]:
    if not uri.startswith("tls://"):
        raise ValueError(f"invalid tls uri: {uri}")
    rest = uri[len("tls://") :]
    if ":" not in rest:
        raise ValueError(f"invalid tls uri: {uri}")
    host, port_s = rest.rsplit(":", 1)
    return host, int(port_s)


def _env_path(name: str) -> str:
    return str(os.getenv(name, "")).strip()


def _env_str(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    return str(default if v is None else v).strip()


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
    return _env_str("WEALL_MODE", "prod").lower() or "prod"


@dataclass(slots=True)
class _TlsConn(Connection):
    sock: socket.socket
    ssl_sock: ssl.SSLSocket
    _peer_id: str
    _peer_addr: PeerAddr

    rbuf: bytearray = field(default_factory=bytearray)
    wbuf: bytearray = field(default_factory=bytearray)

    closed: bool = False
    handshake_done: bool = False

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
        self.queue_send(payload)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.ssl_sock.close()
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


class TlsTransport:
    def __init__(
        self,
        *,
        server_cert: str,
        server_key: str,
        ca_file: str = "",
        server_name: str = "",
        max_frame_bytes: int = 2_000_000,
        max_buffer_bytes: int = 8_000_000,
    ) -> None:
        self.server_cert = str(server_cert).strip()
        self.server_key = str(server_key).strip()
        self.ca_file = str(ca_file).strip()
        self.server_name = str(server_name).strip()

        self.max_frame_bytes = int(max_frame_bytes)
        self.max_buffer_bytes = int(max_buffer_bytes)

        self._sel = selectors.DefaultSelector()
        self._listener: Optional[socket.socket] = None
        self._conns: Dict[str, _TlsConn] = {}

        self._server_ctx = self._make_server_ctx()
        self._client_ctx = self._make_client_ctx()

    @classmethod
    def from_env(cls) -> "TlsTransport":
        cert = _env_path("WEALL_NET_TLS_CERT")
        key = _env_path("WEALL_NET_TLS_KEY")
        ca = _env_path("WEALL_NET_TLS_CA")
        sni = _env_path("WEALL_NET_TLS_SERVER_NAME")

        if not cert or not key:
            raise RuntimeError(
                "TLS transport selected but WEALL_NET_TLS_CERT/WEALL_NET_TLS_KEY are not set"
            )

        # Production guardrail: require server certificate verification.
        insecure_ok = _env_bool("WEALL_NET_TLS_INSECURE_OK", False)
        if _mode() == "prod" and not ca and not insecure_ok:
            raise RuntimeError(
                "WEALL_MODE=prod with TLS transport requires WEALL_NET_TLS_CA for certificate verification. "
                "If you *really* need encryption-only for a private testbed, set WEALL_NET_TLS_INSECURE_OK=1."
            )

        return cls(server_cert=cert, server_key=key, ca_file=ca, server_name=sni)

    def bind(self, addr: PeerAddr) -> None:
        host, port = _parse_tls_uri(addr.uri)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setblocking(False)
        s.bind((host, port))
        s.listen(128)

        self._listener = s
        self._sel.register(s, selectors.EVENT_READ, data=("listener", None))

    def connect(self, addr: PeerAddr) -> _TlsConn:
        host, port = _parse_tls_uri(addr.uri)
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setblocking(False)

        try:
            raw.connect((host, port))
        except BlockingIOError:
            pass

        # Hostname verification:
        # - If CA verification is enabled, pass server_hostname so Python can verify.
        # - Prefer WEALL_NET_TLS_SERVER_NAME if set (useful for IP connects).
        server_hostname: Optional[str] = None
        if self.ca_file:
            server_hostname = self.server_name or host

        ssl_sock = self._client_ctx.wrap_socket(
            raw,
            server_side=False,
            do_handshake_on_connect=False,
            server_hostname=server_hostname,
        )
        ssl_sock.setblocking(False)

        pid = _peer_id_for(addr)
        conn = _TlsConn(sock=raw, ssl_sock=ssl_sock, _peer_id=pid, _peer_addr=addr)
        self._conns[pid] = conn

        self._sel.register(ssl_sock, selectors.EVENT_READ | selectors.EVENT_WRITE, data=("conn", pid))
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

    def connections(self) -> Iterable[_TlsConn]:
        return list(self._conns.values())

    def disconnect(self, peer_id: str) -> None:
        if not isinstance(peer_id, str) or not peer_id.strip():
            return
        self._drop_conn(peer_id)

    def poll(self, *, max_packets: int = 250) -> Iterable[WirePacket]:
        out: List[WirePacket] = []
        if max_packets <= 0:
            return out

        events = self._sel.select(timeout=0.01)
        for key, mask in events:
            kind, pid = key.data
            if kind == "listener":
                self._accept_new()
                continue

            if kind != "conn" or pid is None:
                continue

            conn = self._conns.get(pid)
            if conn is None or conn.closed:
                continue

            # Complete TLS handshake if needed.
            if not conn.handshake_done:
                if not self._try_handshake(conn):
                    continue

            # Read
            if mask & selectors.EVENT_READ:
                pkts = self._try_read(conn, max_packets=max_packets - len(out))
                out.extend(pkts)
                if len(out) >= max_packets:
                    break

            # Write
            if mask & selectors.EVENT_WRITE:
                self._try_write(conn)

        return out

    # -----------------------
    # Internals
    # -----------------------

    def _make_server_ctx(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=self.server_cert, keyfile=self.server_key)

        # We are not doing mTLS yet. (Peer identity is handled by the WeAll handshake.)
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _make_client_ctx(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        if self.ca_file:
            ctx.load_verify_locations(cafile=self.ca_file)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
        else:
            # Encryption-only mode. Allowed in non-prod (or when WEALL_NET_TLS_INSECURE_OK=1).
            ctx.verify_mode = ssl.CERT_NONE
            ctx.check_hostname = False

        return ctx

    def _accept_new(self) -> None:
        if self._listener is None:
            return

        while True:
            try:
                client, addr = self._listener.accept()
            except BlockingIOError:
                return
            except Exception:
                return

            client.setblocking(False)
            try:
                ssl_sock = self._server_ctx.wrap_socket(client, server_side=True, do_handshake_on_connect=False)
                ssl_sock.setblocking(False)
            except Exception:
                try:
                    client.close()
                except Exception:
                    pass
                continue

            pid = f"tls://{addr[0]}:{int(addr[1])}"
            conn = _TlsConn(sock=client, ssl_sock=ssl_sock, _peer_id=pid, _peer_addr=PeerAddr(pid))
            self._conns[pid] = conn
            self._sel.register(ssl_sock, selectors.EVENT_READ | selectors.EVENT_WRITE, data=("conn", pid))

    def _drop_conn(self, pid: str) -> None:
        conn = self._conns.pop(pid, None)
        if conn is None:
            return
        try:
            self._sel.unregister(conn.ssl_sock)
        except Exception:
            pass
        conn.close()

    def _try_handshake(self, conn: _TlsConn) -> bool:
        try:
            conn.ssl_sock.do_handshake()
            conn.handshake_done = True
            return True
        except ssl.SSLWantReadError:
            return False
        except ssl.SSLWantWriteError:
            return False
        except Exception:
            self._drop_conn(conn.peer_id)
            return False

    def _try_read(self, conn: _TlsConn, *, max_packets: int) -> List[WirePacket]:
        if max_packets <= 0:
            return []

        try:
            chunk = conn.ssl_sock.recv(65536)
        except ssl.SSLWantReadError:
            return []
        except ssl.SSLWantWriteError:
            return []
        except Exception:
            self._drop_conn(conn.peer_id)
            return []

        if not chunk:
            self._drop_conn(conn.peer_id)
            return []

        conn.rbuf.extend(chunk)
        if len(conn.rbuf) > self.max_buffer_bytes:
            self._drop_conn(conn.peer_id)
            return []

        out: List[WirePacket] = []
        while len(conn.rbuf) >= 4 and len(out) < max_packets:
            n = struct.unpack(">I", conn.rbuf[:4])[0]
            if n <= 0 or n > self.max_frame_bytes:
                self._drop_conn(conn.peer_id)
                return []
            if len(conn.rbuf) < 4 + n:
                break
            payload = bytes(conn.rbuf[4 : 4 + n])
            del conn.rbuf[: 4 + n]
            out.append(WirePacket(peer_id=conn.peer_id, payload=payload, received_ms=_now_ms()))

        return out

    def _try_write(self, conn: _TlsConn) -> None:
        if conn.closed or not conn.wbuf:
            return
        try:
            sent = conn.ssl_sock.send(conn.wbuf)
            if sent > 0:
                del conn.wbuf[:sent]
        except ssl.SSLWantReadError:
            return
        except ssl.SSLWantWriteError:
            return
        except Exception:
            self._drop_conn(conn.peer_id)
            return
