from __future__ import annotations

import re
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def sub_once(text: str, pattern: str, replacement: str, label: str) -> str:
    new_text, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one regex match, found {count}")
    return new_text


def patch_state_sync() -> None:
    path = Path("src/weall/net/state_sync.py")
    text = path.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader\n",
        "from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader\n"
        "from weall.net.wire_limits import (\n"
        "    MAX_WIRE_MESSAGE_BYTES,\n"
        "    STATE_SYNC_CHUNK_WRAPPER_RESERVE_BYTES,\n"
        ")\n",
        "state-sync wire-limit import",
    )

    text = replace_once(
        text,
        "Json = dict[str, Any]\n",
        "Json = dict[str, Any]\n\n"
        "DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES = max(\n"
        "    1, int(MAX_WIRE_MESSAGE_BYTES) - int(STATE_SYNC_CHUNK_WRAPPER_RESERVE_BYTES)\n"
        ")\n"
        "_TRUSTED_ANCHOR_PIN_KEYS = (\n"
        "    \"height\",\n"
        "    \"tip_hash\",\n"
        "    \"state_root\",\n"
        "    \"finalized_height\",\n"
        "    \"finalized_block_id\",\n"
        "    \"snapshot_hash\",\n"
        ")\n",
        "state-sync hardening constants",
    )

    text = sub_once(
        text,
        r"def _trusted_anchor_env\(default: bool\) -> bool:\n.*?\n\ndef _finalized_anchor_env",
        '''def _trusted_anchor_env(default: bool) -> bool:
    """Read either trusted-anchor env alias and fail closed on invalid/conflicting input."""

    names = ("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR")
    seen: dict[str, bool] = {}
    for name in names:
        raw = os.environ.get(name)
        if raw is None:
            continue
        parsed = str(raw).strip().lower()
        if parsed in {"1", "true", "yes", "y", "on"}:
            seen[name] = True
        elif parsed in {"0", "false", "no", "n", "off"}:
            seen[name] = False
        elif not parsed:
            seen[name] = bool(default)
        elif _mode() == "prod":
            raise StateSyncVerifyError(f"invalid_boolean_env:{name}")
        else:
            seen[name] = bool(default)
    if not seen:
        return bool(default)
    vals = set(seen.values())
    if len(vals) > 1:
        raise StateSyncVerifyError("trusted_anchor_env_conflict")
    return bool(next(iter(vals)))


def _finalized_anchor_env''',
        "trusted-anchor env parser",
    )

    text = replace_once(
        text,
        "    max_snapshot_bytes: int = 0  # 0 = unlimited\n"
        "    max_delta_bytes: int = 0  # 0 = unlimited\n",
        "    max_snapshot_bytes: int = DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES\n"
        "    max_delta_bytes: int = DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES\n",
        "state-sync finite defaults",
    )

    text = replace_once(
        text,
        '''        self.max_snapshot_bytes = max(
            0, _env_int("WEALL_SYNC_MAX_SNAPSHOT_BYTES", int(self.max_snapshot_bytes or 0))
        )
        self.max_delta_bytes = max(
            0, _env_int("WEALL_SYNC_MAX_DELTA_BYTES", int(self.max_delta_bytes or 0))
        )
''',
        '''        self.max_snapshot_bytes = max(
            0, _env_int("WEALL_SYNC_MAX_SNAPSHOT_BYTES", int(self.max_snapshot_bytes))
        )
        self.max_delta_bytes = max(
            0, _env_int("WEALL_SYNC_MAX_DELTA_BYTES", int(self.max_delta_bytes))
        )
        mode = _mode()
        if mode == "prod":
            if self.max_snapshot_bytes <= 0:
                raise StateSyncVerifyError("unsafe_sync_snapshot_cap_unbounded")
            if self.max_delta_bytes <= 0:
                raise StateSyncVerifyError("unsafe_sync_delta_cap_unbounded")
            if self.max_snapshot_bytes > int(DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES):
                raise StateSyncVerifyError("unsafe_sync_snapshot_cap_exceeds_wire_budget")
            if self.max_delta_bytes > int(DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES):
                raise StateSyncVerifyError("unsafe_sync_delta_cap_exceeds_wire_budget")
''',
        "state-sync production cap validation",
    )

    text = replace_once(
        text,
        "        self.require_trusted_anchor = _trusted_anchor_env(bool(self.require_trusted_anchor))\n",
        "        trusted_anchor_default = bool(self.require_trusted_anchor)\n"
        "        self.require_trusted_anchor = _trusted_anchor_env(trusted_anchor_default)\n"
        "        if mode == \"prod\" and trusted_anchor_default and not self.require_trusted_anchor:\n"
        "            raise StateSyncVerifyError(\"unsafe_sync_trusted_anchor_disabled\")\n",
        "state-sync trusted-anchor production posture",
    )

    preflight = '''    def _response_header(self, req: StateSyncRequestMsg) -> WireHeader:
        try:
            corr_id = str(getattr(req.header, "corr_id", "") or "").strip() or None
        except Exception:
            corr_id = None
        return WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id=self.chain_id,
            schema_version=self.schema_version,
            tx_index_hash=self.tx_index_hash,
            sent_ts_ms=_now_ms(),
            corr_id=corr_id,
        )

    def reject_request(
        self, req: StateSyncRequestMsg, reason: str, *, height: int = 0
    ) -> StateSyncResponseMsg:
        return StateSyncResponseMsg(
            header=self._response_header(req),
            ok=False,
            reason=str(reason or "state_sync_rejected"),
            height=max(0, int(height or 0)),
        )

    def _preflight_trusted_anchor(self, selector: Any) -> str | None:
        if selector is None:
            return "trusted_anchor_required" if self.require_trusted_anchor else None
        if not isinstance(selector, dict):
            return "trusted_anchor_invalid"
        if "trusted_anchor" not in selector:
            return "trusted_anchor_required" if self.require_trusted_anchor else None
        anchor = selector.get("trusted_anchor")
        if not isinstance(anchor, dict):
            return "trusted_anchor_invalid"
        if not any(anchor.get(key) not in (None, "") for key in _TRUSTED_ANCHOR_PIN_KEYS):
            return "trusted_anchor_invalid"
        for key in ("height", "finalized_height"):
            if key not in anchor or anchor.get(key) in (None, ""):
                continue
            value = anchor.get(key)
            if isinstance(value, bool):
                return "trusted_anchor_invalid"
            try:
                parsed = int(value)
            except Exception:
                return "trusted_anchor_invalid"
            if parsed < 0:
                return "trusted_anchor_invalid"
        for key in ("tip_hash", "state_root", "finalized_block_id", "snapshot_hash"):
            if key in anchor and anchor.get(key) not in (None, ""):
                if not isinstance(anchor.get(key), str):
                    return "trusted_anchor_invalid"
        return None

    def preflight_request(self, req: StateSyncRequestMsg) -> StateSyncResponseMsg | None:
        reason = self._header_ok(req)
        if reason:
            return self.reject_request(req, reason)

        mode = str(getattr(req, "mode", "") or "").strip().lower()
        if mode not in {"snapshot", "delta"}:
            return self.reject_request(req, "bad_mode")

        anchor_reason = self._preflight_trusted_anchor(req.selector)
        if anchor_reason:
            return self.reject_request(req, anchor_reason)

        if mode == "delta":
            if not self.enable_delta:
                return self.reject_request(req, "delta_disabled")
            if self.block_provider is None:
                return self.reject_request(req, "delta_unavailable")
            raw_start = getattr(req, "from_height", 0)
            if isinstance(raw_start, bool):
                return self.reject_request(req, "bad_from_height")
            try:
                start = int(raw_start or 0)
            except Exception:
                return self.reject_request(req, "bad_from_height")
            if start < 0:
                return self.reject_request(req, "bad_from_height")
            raw_end = getattr(req, "to_height", None)
            if raw_end is not None:
                if isinstance(raw_end, bool):
                    return self.reject_request(req, "bad_to_height")
                try:
                    end = int(raw_end)
                except Exception:
                    return self.reject_request(req, "bad_to_height")
                if end < 0:
                    return self.reject_request(req, "bad_to_height")
                if end < start:
                    return self.reject_request(req, "bad_height_range")
        return None

'''
    text = replace_once(
        text,
        "    def handle_request(self, req: StateSyncRequestMsg) -> StateSyncResponseMsg:\n",
        preflight + "    def handle_request(self, req: StateSyncRequestMsg) -> StateSyncResponseMsg:\n",
        "state-sync preflight insertion",
    )

    text = replace_once(
        text,
        "    def handle_request(self, req: StateSyncRequestMsg) -> StateSyncResponseMsg:\n"
        "        corr_id = req.header.corr_id\n",
        "    def handle_request(self, req: StateSyncRequestMsg) -> StateSyncResponseMsg:\n"
        "        early = self.preflight_request(req)\n"
        "        if early is not None:\n"
        "            return early\n\n"
        "        corr_id = req.header.corr_id\n",
        "state-sync early preflight call",
    )

    text = replace_once(
        text,
        '''            checkpoint_blocks = _snapshot_checkpoint_blocks()
            if checkpoint_blocks is None:
                return StateSyncResponseMsg(
                    header=hdr,
                    ok=False,
                    reason="snapshot_checkpoint_unavailable",
                    height=tip_h,
                )
            snap_hash = sha256_hex_of(snap)
''',
        '''            checkpoint_blocks = _snapshot_checkpoint_blocks()
            if checkpoint_blocks is None:
                return StateSyncResponseMsg(
                    header=hdr,
                    ok=False,
                    reason="snapshot_checkpoint_unavailable",
                    height=tip_h,
                )
            bounded_payload = {
                "snapshot": snap,
                "snapshot_anchor": local_anchor,
                "blocks": list(checkpoint_blocks),
            }
            if not self._size_ok(bounded_payload, self.max_snapshot_bytes):
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="snapshot_too_large", height=tip_h
                )
            snap_hash = sha256_hex_of(snap)
''',
        "state-sync bounded snapshot envelope",
    )

    text = replace_once(
        text,
        "            if self.max_delta_bytes > 0 and not self._size_ok(blocks, self.max_delta_bytes):\n",
        "            bounded_delta = {\"blocks\": blocks, \"snapshot_anchor\": local_anchor}\n"
        "            if self.max_delta_bytes > 0 and not self._size_ok(\n"
        "                bounded_delta, self.max_delta_bytes\n"
        "            ):\n",
        "state-sync bounded delta envelope",
    )

    path.write_text(text, encoding="utf-8")


def patch_node() -> None:
    path = Path("src/weall/net/node.py")
    text = path.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "import hashlib\nimport os\nimport time\n",
        "import hashlib\nimport os\nimport queue\nimport threading\nimport time\n",
        "net-node worker imports",
    )

    text = replace_once(
        text,
        "        self._sync_completed: OrderedDict[tuple[str, str], int] = OrderedDict()\n",
        "        self._sync_completed: OrderedDict[tuple[str, str], int] = OrderedDict()\n"
        "        self._sync_work_cap = max(1, _env_int(\"WEALL_NET_SYNC_WORK_MAX\", 4))\n"
        "        self._sync_work_per_peer_cap = max(\n"
        "            1, _env_int(\"WEALL_NET_SYNC_WORK_PER_PEER_MAX\", 1)\n"
        "        )\n"
        "        self._sync_results_per_tick = max(\n"
        "            1, _env_int(\"WEALL_NET_SYNC_RESULTS_PER_TICK\", 1)\n"
        "        )\n"
        "        self._sync_work_queue: queue.Queue[tuple[str, StateSyncRequestMsg] | None] = (\n"
        "            queue.Queue(maxsize=int(self._sync_work_cap))\n"
        "        )\n"
        "        self._sync_result_queue: queue.Queue[tuple[str, StateSyncResponseMsg]] = (\n"
        "            queue.Queue(maxsize=int(self._sync_work_cap))\n"
        "        )\n"
        "        self._sync_work_slots = threading.BoundedSemaphore(int(self._sync_work_cap))\n"
        "        self._sync_work_lock = threading.Lock()\n"
        "        self._sync_work_per_peer: dict[str, int] = {}\n"
        "        self._sync_worker_stop = threading.Event()\n"
        "        self._sync_worker: threading.Thread | None = None\n",
        "net-node bounded sync worker state",
    )

    worker_methods = '''    def _acquire_sync_work_slot(self, peer_id: str) -> bool:
        pid = str(peer_id or "").strip()
        if not pid:
            return False
        with self._sync_work_lock:
            peer_count = int(self._sync_work_per_peer.get(pid, 0) or 0)
            if peer_count >= int(self._sync_work_per_peer_cap):
                return False
            if not self._sync_work_slots.acquire(blocking=False):
                return False
            self._sync_work_per_peer[pid] = peer_count + 1
        return True

    def _release_sync_work_slot(self, peer_id: str) -> None:
        pid = str(peer_id or "").strip()
        with self._sync_work_lock:
            count = int(self._sync_work_per_peer.get(pid, 0) or 0)
            if count <= 1:
                self._sync_work_per_peer.pop(pid, None)
            else:
                self._sync_work_per_peer[pid] = count - 1
            try:
                self._sync_work_slots.release()
            except ValueError:
                pass

    def _ensure_sync_worker(self) -> None:
        if self.sync_service is None:
            return
        with self._sync_work_lock:
            worker = self._sync_worker
            if worker is not None and worker.is_alive():
                return
            self._sync_worker_stop.clear()
            worker = threading.Thread(
                target=self._sync_worker_main,
                name=f"weall-state-sync-{self.cfg.peer_id}",
                daemon=True,
            )
            self._sync_worker = worker
            worker.start()

    def _sync_worker_main(self) -> None:
        while not self._sync_worker_stop.is_set():
            try:
                item = self._sync_work_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if item is None:
                self._sync_work_queue.task_done()
                break
            peer_id, req = item
            response: StateSyncResponseMsg | None = None
            try:
                service = self.sync_service
                if service is not None:
                    response = service.handle_request(req)
            except Exception:
                service = self.sync_service
                if service is not None:
                    response = service.reject_request(req, "sync_internal_error")
            finally:
                self._sync_work_queue.task_done()

            if response is None:
                self._release_sync_work_slot(peer_id)
                continue
            try:
                self._sync_result_queue.put_nowait((peer_id, response))
            except queue.Full:
                self._release_sync_work_slot(peer_id)

    def _enqueue_sync_request(
        self, peer_id: str, req: StateSyncRequestMsg
    ) -> StateSyncResponseMsg | None:
        service = self.sync_service
        if service is None:
            return None
        early = service.preflight_request(req)
        if early is not None:
            return early

        pid = str(peer_id or "").strip()
        if not self._acquire_sync_work_slot(pid):
            return service.reject_request(req, "sync_busy")
        try:
            self._ensure_sync_worker()
            self._sync_work_queue.put_nowait((pid, req))
        except Exception:
            self._release_sync_work_slot(pid)
            return service.reject_request(req, "sync_busy")
        return None

    def _drain_sync_work(self, *, max_results: int | None = None) -> None:
        limit = max(
            1,
            int(self._sync_results_per_tick if max_results is None else max_results),
        )
        for _ in range(limit):
            try:
                peer_id, response = self._sync_result_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self.send_message(peer_id, response)
            except Exception:
                pass
            finally:
                self._sync_result_queue.task_done()
                self._release_sync_work_slot(peer_id)

    def sync_work_debug(self) -> Json:
        with self._sync_work_lock:
            per_peer = dict(self._sync_work_per_peer)
        worker = self._sync_worker
        return {
            "capacity": int(self._sync_work_cap),
            "per_peer_capacity": int(self._sync_work_per_peer_cap),
            "results_per_tick": int(self._sync_results_per_tick),
            "outstanding": int(sum(max(0, int(v)) for v in per_peer.values())),
            "queued": int(self._sync_work_queue.qsize()),
            "completed_waiting": int(self._sync_result_queue.qsize()),
            "worker_alive": bool(worker is not None and worker.is_alive()),
            "per_peer": per_peer,
        }

'''
    text = replace_once(
        text,
        "    # ----------------------------\n    # Peer address gossip helpers\n    # ----------------------------\n",
        worker_methods
        + "    # ----------------------------\n    # Peer address gossip helpers\n    # ----------------------------\n",
        "net-node sync worker methods",
    )

    text = replace_once(
        text,
        '''        def _on_sync_request(msg: WireMessage) -> WireMessage | None:
            if not self.sync_service:
                return None
            return self.sync_service.handle_request(msg)  # type: ignore[arg-type]
''',
        '''        def _on_sync_request(msg: WireMessage) -> WireMessage | None:
            if not self.sync_service or not isinstance(msg, StateSyncRequestMsg):
                return None
            return self._enqueue_sync_request(peer_id, msg)
''',
        "net-node state-sync router isolation",
    )

    text = replace_once(
        text,
        '''    def close(self) -> None:
        try:
            self.transport.close()
        except Exception:
            pass
        self._conns.clear()
        self._peers.clear()
''',
        '''    def close(self) -> None:
        self._sync_worker_stop.set()
        try:
            self._sync_work_queue.put_nowait(None)
        except queue.Full:
            pass
        worker = self._sync_worker
        if worker is not None and worker.is_alive():
            worker.join(timeout=0.25)
        try:
            self.transport.close()
        except Exception:
            pass
        self._conns.clear()
        self._peers.clear()
''',
        "net-node worker shutdown",
    )

    text = replace_once(
        text,
        '''    def tick(self, *, max_packets: int = 250) -> None:
        self._refresh_conns()
        try:
            for pkt in self.transport.poll(max_packets=int(max_packets)):
                try:
                    self._handle_packet(pkt)
                except Exception:
                    continue
        except Exception:
            return
''',
        '''    def tick(self, *, max_packets: int = 250) -> None:
        self._refresh_conns()
        try:
            for pkt in self.transport.poll(max_packets=int(max_packets)):
                try:
                    self._handle_packet(pkt)
                except Exception:
                    continue
        except Exception:
            self._drain_sync_work()
            return
        self._drain_sync_work()
''',
        "net-node bounded sync completion drain",
    )

    path.write_text(text, encoding="utf-8")


def patch_net_loop() -> None:
    path = Path("src/weall/net/net_loop.py")
    text = path.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "from weall.runtime.protocol_profile import validate_runtime_consensus_profile\n",
        "from weall.runtime.protocol_profile import (\n"
        "    active_consensus_profile,\n"
        "    validate_runtime_consensus_profile,\n"
        ")\n",
        "net-loop consensus-profile import",
    )

    text = replace_once(
        text,
        "            block_provider=block_provider,\n            bft_enabled=bool(self._bft_enabled),\n",
        "            block_provider=block_provider,\n"
        "            require_trusted_anchor=bool(active_consensus_profile().trusted_anchor_required),\n"
        "            bft_enabled=bool(self._bft_enabled),\n",
        "net-loop trusted-anchor production authority",
    )

    path.write_text(text, encoding="utf-8")


def write_tests() -> None:
    path = Path("tests/test_p0_10_a15_f002_state_sync_resource_bounds.py")
    path.write_text(
        '''from __future__ import annotations

import threading
import time

import pytest

from weall.net.messages import BftVoteMsg, MsgType, StateSyncRequestMsg, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.net.node import NetConfig, NetNode
from weall.net.state_sync import (
    DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES,
    StateSyncService,
    StateSyncVerifyError,
)
from weall.net.transport_memory import InMemoryTransport


def _header(mtype: str, corr_id: str = "corr-1") -> WireHeader:
    return WireHeader(
        type=mtype,
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        corr_id=corr_id,
    )


def _request(
    corr_id: str,
    *,
    mode: str = "snapshot",
    selector: dict | None = None,
    from_height: int = 0,
    to_height: int | None = None,
) -> StateSyncRequestMsg:
    return StateSyncRequestMsg(
        header=_header(MsgType.STATE_SYNC_REQUEST, corr_id),
        mode=mode,  # type: ignore[arg-type]
        selector=selector,
        from_height=from_height,
        to_height=to_height,
    )


def _cfg(peer_id: str = "server") -> NetConfig:
    return NetConfig(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        peer_id=peer_id,
    )


def _established(node: NetNode, peer_id: str):
    rec = node._ensure_peer(peer_id)
    rec.router.handshake.status = "ESTABLISHED"
    rec.router.handshake.session_id = f"session-{peer_id}"
    return rec


def test_missing_trusted_anchor_rejects_before_state_materialization() -> None:
    calls = 0

    def _state_provider():
        nonlocal calls
        calls += 1
        raise AssertionError("state provider must not run")

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=_state_provider,
        require_trusted_anchor=True,
    )
    response = service.handle_request(_request("missing-anchor"))

    assert response.ok is False
    assert response.reason == "trusted_anchor_required"
    assert calls == 0


def test_malformed_trusted_anchor_rejects_before_state_materialization() -> None:
    calls = 0

    def _state_provider():
        nonlocal calls
        calls += 1
        raise AssertionError("state provider must not run")

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=_state_provider,
        require_trusted_anchor=True,
    )
    response = service.handle_request(
        _request("bad-anchor", selector={"trusted_anchor": {"height": -1}})
    )

    assert response.ok is False
    assert response.reason == "trusted_anchor_invalid"
    assert calls == 0


def test_bad_delta_range_rejects_before_state_materialization() -> None:
    calls = 0

    def _state_provider():
        nonlocal calls
        calls += 1
        raise AssertionError("state provider must not run")

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=_state_provider,
        block_provider=lambda _height: None,
    )
    response = service.handle_request(
        _request("bad-range", mode="delta", from_height=10, to_height=9)
    )

    assert response.ok is False
    assert response.reason == "bad_height_range"
    assert calls == 0


def test_production_response_caps_are_finite(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: {},
    )
    assert 0 < service.max_snapshot_bytes <= DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES
    assert 0 < service.max_delta_bytes <= DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES

    monkeypatch.setenv("WEALL_SYNC_MAX_SNAPSHOT_BYTES", "0")
    with pytest.raises(StateSyncVerifyError, match="unsafe_sync_snapshot_cap_unbounded"):
        StateSyncService(
            chain_id="test",
            schema_version="1",
            tx_index_hash="deadbeef",
            state_provider=lambda: {},
        )


def test_production_network_profile_cannot_disable_trusted_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "0")
    with pytest.raises(StateSyncVerifyError, match="unsafe_sync_trusted_anchor_disabled"):
        StateSyncService(
            chain_id="test",
            schema_version="1",
            tx_index_hash="deadbeef",
            state_provider=lambda: {},
            require_trusted_anchor=True,
        )


def test_snapshot_response_has_finite_service_cap() -> None:
    state = {"height": 0, "accounts": {"alice": {"blob": "x" * 8_192}}}
    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: state,
        max_snapshot_bytes=512,
    )
    response = service.handle_request(_request("oversize"))
    assert response.ok is False
    assert response.reason == "snapshot_too_large"
    assert response.snapshot is None


def test_valid_state_sync_work_does_not_block_bft_router_progress() -> None:
    started = threading.Event()
    release = threading.Event()
    vote_seen = threading.Event()

    def _slow_state_provider():
        started.set()
        assert release.wait(2.0)
        return {"height": 0, "accounts": {}}

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=_slow_state_provider,
    )
    node = NetNode(
        cfg=_cfg(),
        sync_service=service,
        transport=InMemoryTransport(),
        on_bft_vote=lambda _peer_id, _msg: vote_seen.set(),
    )
    rec = _established(node, "peer-a")

    begin = time.monotonic()
    response = rec.router.handle_message(_request("slow-sync"))
    assert response is None
    assert time.monotonic() - begin < 0.5
    assert started.wait(1.0)

    vote = BftVoteMsg(
        header=_header(MsgType.BFT_VOTE, "vote-1"),
        view=1,
        vote={"block_id": "b1"},
    )
    begin = time.monotonic()
    rec.router.handle_message(vote)
    assert vote_seen.is_set()
    assert time.monotonic() - begin < 0.5

    release.set()
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and node.sync_work_debug()["outstanding"]:
        node.tick(max_packets=0)
        time.sleep(0.01)
    assert node.sync_work_debug()["outstanding"] == 0
    node.close()


def test_state_sync_worker_has_global_and_per_peer_work_budgets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_NET_SYNC_WORK_MAX", "2")
    monkeypatch.setenv("WEALL_NET_SYNC_WORK_PER_PEER_MAX", "1")
    started = threading.Event()
    release = threading.Event()

    def _slow_state_provider():
        started.set()
        assert release.wait(2.0)
        return {"height": 0, "accounts": {}}

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=_slow_state_provider,
    )
    node = NetNode(cfg=_cfg(), sync_service=service, transport=InMemoryTransport())
    peer_a = _established(node, "peer-a")
    peer_b = _established(node, "peer-b")
    peer_c = _established(node, "peer-c")

    assert peer_a.router.handle_message(_request("a-1")) is None
    assert started.wait(1.0)

    same_peer = peer_a.router.handle_message(_request("a-2"))
    assert same_peer is not None
    assert same_peer.reason == "sync_busy"

    assert peer_b.router.handle_message(_request("b-1")) is None
    global_busy = peer_c.router.handle_message(_request("c-1"))
    assert global_busy is not None
    assert global_busy.reason == "sync_busy"
    assert node.sync_work_debug()["outstanding"] == 2

    release.set()
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and node.sync_work_debug()["outstanding"]:
        node.tick(max_packets=0)
        time.sleep(0.01)
    assert node.sync_work_debug()["outstanding"] == 0
    node.close()


def test_net_loop_builds_state_sync_with_profile_trusted_anchor() -> None:
    class _Executor:
        chain_id = "test"
        tx_index = None

        def tx_index_hash(self):
            return "deadbeef"

        def _schema_version(self):
            return "1"

        def read_state(self):
            return {"height": 0}

        def get_block_by_height(self, _height):
            return None

    class _Mempool:
        pass

    loop = NetMeshLoop(
        executor=_Executor(),
        mempool=_Mempool(),
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=0,
            tick_ms=25,
            schema_version="1",
        ),
    )
    node = loop._build_node()
    assert node.sync_service is not None
    assert node.sync_service.require_trusted_anchor is True
    node.close()
''',
        encoding="utf-8",
    )


def main() -> None:
    patch_state_sync()
    patch_node()
    patch_net_loop()
    write_tests()


if __name__ == "__main__":
    main()
