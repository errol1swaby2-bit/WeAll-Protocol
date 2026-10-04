from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    s = read(rel)
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{rel}: expected one anchor, found {n}: {old[:100]!r}")
    write(rel, s.replace(old, new, 1))


wire_limits = '''from __future__ import annotations

import os

# A07-F002 canonical protocol wire budget.
#
# This is the single production authority for peer-message sizing. The 4-byte
# TCP/TLS frame prefix is transport framing and is not counted inside this
# payload budget.
MAX_WIRE_MESSAGE_BYTES = 1_000_000
MAX_TRANSPORT_FRAME_BYTES = MAX_WIRE_MESSAGE_BYTES
WIRE_FRAME_PREFIX_BYTES = 4

# Reserve enough room for the BFT_PROPOSAL envelope, proposer/view metadata,
# and a justification QC. The final encoded proposal is still checked against
# MAX_WIRE_MESSAGE_BYTES immediately before peer or relay emission.
BFT_PROPOSAL_WRAPPER_RESERVE_BYTES = 128 * 1024
MAX_BFT_BLOCK_BYTES = MAX_WIRE_MESSAGE_BYTES - BFT_PROPOSAL_WRAPPER_RESERVE_BYTES

# State-sync chunk payload sizing is derived from the same wire budget. Base64
# expands raw bytes by ~4/3; this reserve leaves room for the response header
# and chunk-integrity metadata.
STATE_SYNC_CHUNK_WRAPPER_RESERVE_BYTES = 96 * 1024
MAX_STATE_SYNC_CHUNK_RAW_BYTES = (
    (MAX_WIRE_MESSAGE_BYTES - STATE_SYNC_CHUNK_WRAPPER_RESERVE_BYTES) * 3 // 4
)
MAX_STATE_SYNC_CHUNKS = 4096
MAX_STATE_SYNC_TRANSFER_BYTES = MAX_STATE_SYNC_CHUNK_RAW_BYTES * MAX_STATE_SYNC_CHUNKS


class WireSizeError(ValueError):
    pass


def _mode() -> str:
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def ensure_wire_payload_size(payload: bytes | bytearray, *, limit: int = MAX_WIRE_MESSAGE_BYTES) -> int:
    size = len(payload)
    cap = int(limit)
    if cap <= 0 or size > cap:
        raise WireSizeError(f"wire_message_too_large:{size}>{cap}")
    return size


def bft_block_limit_from_env() -> int:
    """Resolve the votecheck block budget without permitting prod drift.

    Non-production tests may lower/disable the legacy limit to exercise fast
    rejection paths. Production may not override the protocol-pinned value.
    """
    raw = os.environ.get("WEALL_BFT_VOTECHECK_MAX_BLOCK_BYTES")
    if raw is None or not str(raw).strip():
        return int(MAX_BFT_BLOCK_BYTES)
    try:
        value = int(str(raw).strip())
    except Exception as exc:
        raise WireSizeError("invalid_bft_wire_limit") from exc
    if _mode() == "prod" and value != int(MAX_BFT_BLOCK_BYTES):
        raise WireSizeError(
            f"production_bft_wire_limit_mismatch:{value}!={MAX_BFT_BLOCK_BYTES}"
        )
    if _mode() == "prod":
        return int(MAX_BFT_BLOCK_BYTES)
    if value <= 0:
        return 0
    return min(int(value), int(MAX_BFT_BLOCK_BYTES))
'''
write("src/weall/net/wire_limits.py", wire_limits)

# NetNode: canonical ingress/sender authority and transport construction.
replace_once(
    "src/weall/net/node.py",
    "from weall.net.codec import decode_message, encode_message\n",
    "from weall.net.codec import decode_message, encode_message\n"
    "from weall.net.wire_limits import (\n"
    "    MAX_TRANSPORT_FRAME_BYTES,\n"
    "    MAX_WIRE_MESSAGE_BYTES,\n"
    "    ensure_wire_payload_size,\n"
    ")\n",
)
replace_once(
    "src/weall/net/node.py",
    "    max_packet_bytes: int = 256 * 1024\n",
    "    max_packet_bytes: int = MAX_WIRE_MESSAGE_BYTES\n",
)
replace_once(
    "src/weall/net/node.py",
    "    if kind in {\"tcp\", \"plain\"}:\n        return TcpTransport()\n",
    "    if kind in {\"tcp\", \"plain\"}:\n"
    "        return TcpTransport(max_frame_bytes=MAX_TRANSPORT_FRAME_BYTES)\n",
)
replace_once(
    "src/weall/net/node.py",
    "        return TlsTransport(\n            server_cert=cert, server_key=key, ca_file=ca_file, server_name=server_name\n        )\n",
    "        return TlsTransport(\n"
    "            server_cert=cert,\n"
    "            server_key=key,\n"
    "            ca_file=ca_file,\n"
    "            server_name=server_name,\n"
    "            max_frame_bytes=MAX_TRANSPORT_FRAME_BYTES,\n"
    "        )\n",
)
replace_once(
    "src/weall/net/node.py",
    "        self.cfg = cfg\n        self.peer_policy = peer_policy or PeerPolicy()\n\n        self.on_tx = on_tx\n",
    "        self.cfg = cfg\n"
    "        self.peer_policy = peer_policy or PeerPolicy()\n"
    "        mode = str(os.environ.get(\"WEALL_MODE\", \"prod\") or \"prod\").strip().lower() or \"prod\"\n"
    "        if mode == \"prod\" and int(self.peer_policy.max_packet_bytes) != int(MAX_WIRE_MESSAGE_BYTES):\n"
    "            raise ValueError(\n"
    "                f\"production_peer_wire_limit_mismatch:{self.peer_policy.max_packet_bytes}!={MAX_WIRE_MESSAGE_BYTES}\"\n"
    "            )\n\n"
    "        self.on_tx = on_tx\n",
)
replace_once(
    "src/weall/net/node.py",
    "    def send_bytes(self, peer_id: str, payload: bytes) -> None:\n        pid = str(peer_id or \"\").strip()\n",
    "    def send_bytes(self, peer_id: str, payload: bytes) -> None:\n"
    "        raw = bytes(payload)\n"
    "        ensure_wire_payload_size(raw)\n"
    "        pid = str(peer_id or \"\").strip()\n",
)
replace_once(
    "src/weall/net/node.py",
    "        c.send(bytes(payload))\n\n    def send_message(self, peer_id: str, msg: WireMessage) -> None:\n        self.send_bytes(peer_id, encode_message(msg))\n\n    def broadcast_message(self, msg: WireMessage, *, exclude_peer_id: str = \"\") -> None:\n        ex = str(exclude_peer_id or \"\").strip()\n        payload = encode_message(msg)\n",
    "        c.send(raw)\n\n"
    "    def assert_message_fits(self, msg: WireMessage) -> bytes:\n"
    "        payload = encode_message(msg)\n"
    "        ensure_wire_payload_size(payload)\n"
    "        return payload\n\n"
    "    def send_message(self, peer_id: str, msg: WireMessage) -> None:\n"
    "        self.send_bytes(peer_id, self.assert_message_fits(msg))\n\n"
    "    def broadcast_message(self, msg: WireMessage, *, exclude_peer_id: str = \"\") -> None:\n"
    "        ex = str(exclude_peer_id or \"\").strip()\n"
    "        payload = self.assert_message_fits(msg)\n",
)

# TCP: same frame authority on both receive and direct-send paths.
replace_once(
    "src/weall/net/transport_tcp.py",
    "from weall.net.transport import Connection, PeerAddr, WirePacket\n",
    "from weall.net.transport import Connection, PeerAddr, WirePacket\n"
    "from weall.net.wire_limits import MAX_TRANSPORT_FRAME_BYTES, MAX_WIRE_MESSAGE_BYTES\n",
)
replace_once(
    "src/weall/net/transport_tcp.py",
    "    # outbound backpressure\n    max_wbuf_bytes: int = 0\n",
    "    # canonical frame bound + outbound backpressure\n"
    "    max_frame_bytes: int = MAX_TRANSPORT_FRAME_BYTES\n"
    "    max_wbuf_bytes: int = 0\n",
)
replace_once(
    "src/weall/net/transport_tcp.py",
    "        frame = struct.pack(\">I\", len(payload)) + payload\n\n        # Backpressure: bound outbound queue growth to avoid memory DoS.\n",
    "        if len(payload) > int(self.max_frame_bytes):\n"
    "            _safe_count(\"net_tcp_outbound_frame_oversize_total\", 1)\n"
    "            if self.close_on_overflow:\n"
    "                self.close()\n"
    "            raise ValueError(\"wire_frame_too_large\")\n"
    "        frame = struct.pack(\">I\", len(payload)) + payload\n\n"
    "        # Backpressure: bound outbound queue growth to avoid memory DoS.\n",
)
replace_once(
    "src/weall/net/transport_tcp.py",
    "        max_frame_bytes: int = 2_000_000,\n",
    "        max_frame_bytes: int = MAX_TRANSPORT_FRAME_BYTES,\n",
)
replace_once(
    "src/weall/net/transport_tcp.py",
    "        self.max_frame_bytes = int(max_frame_bytes)\n        self.max_buffer_bytes = int(max_buffer_bytes)\n\n        # Connection caps",
    "        self.max_frame_bytes = int(max_frame_bytes)\n"
    "        self.max_buffer_bytes = int(max_buffer_bytes)\n"
    "        if _mode() == \"prod\" and self.max_frame_bytes != int(MAX_WIRE_MESSAGE_BYTES):\n"
    "            raise ValueError(\n"
    "                f\"production_tcp_frame_limit_mismatch:{self.max_frame_bytes}!={MAX_WIRE_MESSAGE_BYTES}\"\n"
    "            )\n\n"
    "        # Connection caps",
)
s = read("src/weall/net/transport_tcp.py")
needle = "            max_wbuf_bytes=int(self.max_outbound_buffer_bytes),\n"
count = s.count(needle)
if count < 2:
    raise SystemExit(f"transport_tcp expected >=2 connection anchors, found {count}")
s = s.replace(
    needle,
    "            max_frame_bytes=int(self.max_frame_bytes),\n" + needle,
)
write("src/weall/net/transport_tcp.py", s)

# TLS: mirror TCP exactly.
replace_once(
    "src/weall/net/transport_tls.py",
    "from weall.net.transport import Connection, PeerAddr, WirePacket\n",
    "from weall.net.transport import Connection, PeerAddr, WirePacket\n"
    "from weall.net.wire_limits import MAX_TRANSPORT_FRAME_BYTES, MAX_WIRE_MESSAGE_BYTES\n",
)
replace_once(
    "src/weall/net/transport_tls.py",
    "    # outbound backpressure\n    max_wbuf_bytes: int = 0\n",
    "    # canonical frame bound + outbound backpressure\n"
    "    max_frame_bytes: int = MAX_TRANSPORT_FRAME_BYTES\n"
    "    max_wbuf_bytes: int = 0\n",
)
replace_once(
    "src/weall/net/transport_tls.py",
    "        frame = struct.pack(\">I\", len(payload)) + payload\n\n        # Backpressure: bound outbound queue growth to avoid memory DoS.\n",
    "        if len(payload) > int(self.max_frame_bytes):\n"
    "            _safe_count(\"net_tls_outbound_frame_oversize_total\", 1)\n"
    "            if self.close_on_overflow:\n"
    "                self.close()\n"
    "            raise ValueError(\"wire_frame_too_large\")\n"
    "        frame = struct.pack(\">I\", len(payload)) + payload\n\n"
    "        # Backpressure: bound outbound queue growth to avoid memory DoS.\n",
)
replace_once(
    "src/weall/net/transport_tls.py",
    "        max_frame_bytes: int = 2_000_000,\n",
    "        max_frame_bytes: int = MAX_TRANSPORT_FRAME_BYTES,\n",
)
replace_once(
    "src/weall/net/transport_tls.py",
    "        self.max_frame_bytes = int(max_frame_bytes)\n        self.max_buffer_bytes = int(max_buffer_bytes)\n\n        md = _mode()\n",
    "        self.max_frame_bytes = int(max_frame_bytes)\n"
    "        self.max_buffer_bytes = int(max_buffer_bytes)\n\n"
    "        md = _mode()\n"
    "        if md == \"prod\" and self.max_frame_bytes != int(MAX_WIRE_MESSAGE_BYTES):\n"
    "            raise ValueError(\n"
    "                f\"production_tls_frame_limit_mismatch:{self.max_frame_bytes}!={MAX_WIRE_MESSAGE_BYTES}\"\n"
    "            )\n",
)
s = read("src/weall/net/transport_tls.py")
count = s.count(needle)
if count < 2:
    raise SystemExit(f"transport_tls expected >=2 connection anchors, found {count}")
s = s.replace(
    needle,
    "            max_frame_bytes=int(self.max_frame_bytes),\n" + needle,
)
write("src/weall/net/transport_tls.py", s)

# BFT votecheck gets the exact same protocol-derived block budget.
replace_once(
    "src/weall/runtime/executor.py",
    "from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader\n",
    "from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader\n"
    "from weall.net.wire_limits import bft_block_limit_from_env\n",
)
replace_once(
    "src/weall/runtime/executor.py",
    "        self._max_votecheck_block_bytes: int = max(\n            0, _safe_int(os.environ.get(\"WEALL_BFT_VOTECHECK_MAX_BLOCK_BYTES\"), 1_000_000)\n        )\n",
    "        self._max_votecheck_block_bytes: int = bft_block_limit_from_env()\n",
)

# Block builder refuses/trim-retries candidates that cannot fit the reserved BFT wire budget.
replace_once(
    "src/weall/runtime/block_builder.py",
    "from weall.runtime.bft_finality_bridge import schedule_bft_finality_receipt\n",
    "from weall.net.wire_limits import MAX_BFT_BLOCK_BYTES\n"
    "from weall.runtime.bft_finality_bridge import schedule_bft_finality_receipt\n",
)
replace_once(
    "src/weall/runtime/block_builder.py",
    "    _consensus_fail_closed,\n",
    "    _canon_json,\n    _consensus_fail_closed,\n",
)
replace_once(
    "src/weall/runtime/block_builder.py",
    "    except Exception as exc:\n        return None, None, [], invalid_ids, f\"block_hash_commitment_failed:{type(exc).__name__}\"\n\n    return block, working, applied_ids, invalid_ids, \"\"\n",
    "    except Exception as exc:\n"
    "        return None, None, [], invalid_ids, f\"block_hash_commitment_failed:{type(exc).__name__}\"\n\n"
    "    try:\n"
    "        encoded_block_bytes = len(_canon_json(block).encode(\"utf-8\"))\n"
    "    except Exception as exc:\n"
    "        return None, None, [], invalid_ids, f\"block_wire_size_failed:{type(exc).__name__}\"\n"
    "    if encoded_block_bytes > int(MAX_BFT_BLOCK_BYTES):\n"
    "        if mempool_applied_count <= 0:\n"
    "            return (\n"
    "                None,\n"
    "                None,\n"
    "                [],\n"
    "                invalid_ids,\n"
    "                \"block_reject:wire_too_large:mandatory_protocol_data_exceed_wire_budget\",\n"
    "            )\n"
    "        scaled = (int(mempool_applied_count) * int(MAX_BFT_BLOCK_BYTES)) // max(1, encoded_block_bytes)\n"
    "        reduced_mempool_limit = max(0, min(int(mempool_applied_count) - 1, int(scaled) - 1))\n"
    "        retry = build_block_candidate(\n"
    "            self,\n"
    "            max_txs=int(reduced_mempool_limit),\n"
    "            allow_empty=True,\n"
    "            force_ts_ms=force_ts_ms,\n"
    "            helper_certificates=helper_certificates,\n"
    "            helper_receipts_by_lane=helper_receipts_by_lane,\n"
    "            bft_justify_qc=bft_justify_qc,\n"
    "            proposer=proposer,\n"
    "            base_state=source_state,\n"
    "        )\n"
    "        retry_block = retry[0]\n"
    "        if (\n"
    "            not bool(allow_empty)\n"
    "            and isinstance(retry_block, dict)\n"
    "            and not list(retry_block.get(\"txs\") or [])\n"
    "        ):\n"
    "            return None, None, [], list(retry[3]), \"no_applicable\"\n"
    "        return retry\n\n"
    "    return block, working, applied_ids, invalid_ids, \"\"\n",
)

# Relay emission must observe the same local wire gate before HTTP wrapping.
replace_once(
    "src/weall/net/net_loop.py",
    "        if not self._relay_client_enabled or self.node is None or not self._relay_urls:\n            return\n        cfg = self._relay_cfg()\n",
    "        if not self._relay_client_enabled or self.node is None or not self._relay_urls:\n"
    "            return\n"
    "        self.node.assert_message_fits(msg)\n"
    "        cfg = self._relay_cfg()\n",
)

# Focused F002a regressions.
test_text = '''from __future__ import annotations

import inspect

import pytest

from weall.net.codec import encode_message
from weall.net.messages import BftProposalMsg, MsgType, WireHeader
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.transport_memory import InMemoryTransport
from weall.net.transport_tcp import TcpTransport
from weall.net.transport_tls import TlsTransport
from weall.net.wire_limits import (
    MAX_BFT_BLOCK_BYTES,
    MAX_TRANSPORT_FRAME_BYTES,
    MAX_WIRE_MESSAGE_BYTES,
    WireSizeError,
    bft_block_limit_from_env,
)


def _cfg() -> NetConfig:
    return NetConfig(chain_id="wire-test", schema_version="1", tx_index_hash="0" * 64)


class _CaptureConn:
    peer_id = "peer"

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def send(self, payload: bytes) -> None:
        self.sent.append(bytes(payload))

    def close(self) -> None:
        return None


def _proposal_with_encoded_size_at_most(limit: int) -> BftProposalMsg:
    header = WireHeader(
        type=MsgType.BFT_PROPOSAL,
        chain_id="wire-test",
        schema_version="1",
        tx_index_hash="0" * 64,
    )
    base = BftProposalMsg(header=header, view=1, proposer="@v1", block={"pad": ""})
    base_size = len(encode_message(base))
    pad = max(0, int(limit) - base_size)
    return BftProposalMsg(header=header, view=1, proposer="@v1", block={"pad": "x" * pad})


def test_one_canonical_default_drives_node_tcp_tls_and_bft(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEALL_BFT_VOTECHECK_MAX_BLOCK_BYTES", raising=False)
    assert PeerPolicy().max_packet_bytes == MAX_WIRE_MESSAGE_BYTES
    assert inspect.signature(TcpTransport).parameters["max_frame_bytes"].default == MAX_TRANSPORT_FRAME_BYTES
    assert inspect.signature(TlsTransport).parameters["max_frame_bytes"].default == MAX_TRANSPORT_FRAME_BYTES
    assert bft_block_limit_from_env() == MAX_BFT_BLOCK_BYTES
    assert 0 < MAX_BFT_BLOCK_BYTES < MAX_WIRE_MESSAGE_BYTES


def test_sender_accepts_max_and_rejects_one_byte_over_before_connection_send() -> None:
    node = NetNode(cfg=_cfg(), transport=InMemoryTransport())
    conn = _CaptureConn()
    node._conns["peer"] = conn  # focused sender boundary fixture
    node.send_bytes("peer", b"x" * MAX_WIRE_MESSAGE_BYTES)
    assert len(conn.sent) == 1
    with pytest.raises(WireSizeError):
        node.send_bytes("peer", b"x" * (MAX_WIRE_MESSAGE_BYTES + 1))
    assert len(conn.sent) == 1


def test_bft_wrapper_boundary_fails_locally_at_max_plus_one() -> None:
    node = NetNode(cfg=_cfg(), transport=InMemoryTransport())
    msg = _proposal_with_encoded_size_at_most(MAX_WIRE_MESSAGE_BYTES)
    raw = node.assert_message_fits(msg)
    assert len(raw) == MAX_WIRE_MESSAGE_BYTES
    too_large = BftProposalMsg(
        header=msg.header,
        view=msg.view,
        proposer=msg.proposer,
        block={"pad": str(msg.block["pad"]) + "x"},
    )
    with pytest.raises(WireSizeError):
        node.assert_message_fits(too_large)


def test_prod_rejects_local_limit_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    with pytest.raises(ValueError, match="production_peer_wire_limit_mismatch"):
        NetNode(cfg=_cfg(), peer_policy=PeerPolicy(max_packet_bytes=1024), transport=InMemoryTransport())
    with pytest.raises(ValueError, match="production_tcp_frame_limit_mismatch"):
        TcpTransport(max_frame_bytes=1024)
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_MAX_BLOCK_BYTES", "1024")
    with pytest.raises(WireSizeError, match="production_bft_wire_limit_mismatch"):
        bft_block_limit_from_env()


def test_nonprod_can_lower_legacy_votecheck_limit_for_boundary_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_MAX_BLOCK_BYTES", "256")
    assert bft_block_limit_from_env() == 256
'''
write("tests/test_p0_05_f002a_wire_budget.py", test_text)

print("P0-05 F002a canonical wire-budget patch applied")
