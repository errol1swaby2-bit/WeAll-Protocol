from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader

Json = Dict[str, Any]


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex_of(obj: Any) -> str:
    h = hashlib.sha256()
    h.update(_canon_json(obj).encode("utf-8"))
    return h.hexdigest()


class StateSyncVerifyError(RuntimeError):
    pass


@dataclass
class StateSyncService:
    chain_id: str
    schema_version: str
    tx_index_hash: str
    state_provider: Callable[[], Json]
    # Optional provider to fetch blocks by height for delta sync.
    # Signature: (height:int) -> block dict | None
    block_provider: Optional[Callable[[int], Optional[Json]]] = None
    enable_delta: bool = True

    # Hardening caps (tunable by env). Defaults keep prior behavior while adding safe guards.
    max_delta_blocks: int = 250
    max_snapshot_bytes: int = 0  # 0 = unlimited
    max_delta_bytes: int = 0  # 0 = unlimited
    require_header_match: bool = True
    # If a delta cannot be served (e.g., history pruned), optionally fall back to a snapshot.
    # This is a safety valve for operators who enable DB pruning.
    fallback_to_snapshot: bool = True

    def __post_init__(self) -> None:
        # Allow operators to tune limits without code changes.
        self.max_delta_blocks = max(1, _env_int("WEALL_SYNC_MAX_DELTA_BLOCKS", int(self.max_delta_blocks or 250)))
        self.max_snapshot_bytes = max(0, _env_int("WEALL_SYNC_MAX_SNAPSHOT_BYTES", int(self.max_snapshot_bytes or 0)))
        self.max_delta_bytes = max(0, _env_int("WEALL_SYNC_MAX_DELTA_BYTES", int(self.max_delta_bytes or 0)))
        self.require_header_match = _env_bool("WEALL_SYNC_REQUIRE_HEADER_MATCH", bool(self.require_header_match))
        self.fallback_to_snapshot = _env_bool("WEALL_SYNC_FALLBACK_TO_SNAPSHOT", bool(self.fallback_to_snapshot))

    def _header_ok(self, req: StateSyncRequestMsg) -> Optional[str]:
        """Return None if ok, else a rejection reason."""
        if not self.require_header_match:
            return None
        try:
            h = req.header
        except Exception:
            return "bad_header"
        if str(getattr(h, "chain_id", "")) != str(self.chain_id):
            return "chain_mismatch"
        if str(getattr(h, "schema_version", "")) != str(self.schema_version):
            return "schema_mismatch"
        if str(getattr(h, "tx_index_hash", "")) != str(self.tx_index_hash):
            return "tx_index_mismatch"
        return None

    def _size_ok(self, obj: Any, limit_bytes: int) -> bool:
        if limit_bytes <= 0:
            return True
        try:
            s = _canon_json(obj).encode("utf-8")
            return len(s) <= int(limit_bytes)
        except Exception:
            # If we can't size it, fail closed when a limit is set.
            return False

    def handle_request(self, req: StateSyncRequestMsg) -> StateSyncResponseMsg:
        corr_id = req.header.corr_id
        hdr = WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id=self.chain_id,
            schema_version=self.schema_version,
            tx_index_hash=self.tx_index_hash,
            sent_ts_ms=_now_ms(),
            corr_id=corr_id,
        )

        # Basic header/domain matching to prevent cross-chain poisoning.
        reason = self._header_ok(req)
        if reason:
            return StateSyncResponseMsg(header=hdr, ok=False, reason=reason, height=0)

        st = self.state_provider()
        if not isinstance(st, dict):
            return StateSyncResponseMsg(header=hdr, ok=False, reason="bad_state", height=0)

        tip_h = int(st.get("height", 0) or 0)

        if req.mode == "snapshot":
            snap: Json = st
            if not self._size_ok(snap, self.max_snapshot_bytes):
                return StateSyncResponseMsg(header=hdr, ok=False, reason="snapshot_too_large", height=tip_h)
            snap_hash = sha256_hex_of(snap)
            return StateSyncResponseMsg(
                header=hdr,
                ok=True,
                reason=None,
                height=tip_h,
                snapshot=snap,
                blocks=(),
                snapshot_hash=snap_hash,
            )

        def _reply_snapshot(reason: str) -> StateSyncResponseMsg:
            snap: Json = st
            if not self._size_ok(snap, self.max_snapshot_bytes):
                return StateSyncResponseMsg(header=hdr, ok=False, reason="snapshot_too_large", height=tip_h)
            snap_hash = sha256_hex_of(snap)
            return StateSyncResponseMsg(
                header=hdr,
                ok=True,
                reason=reason,
                height=tip_h,
                snapshot=snap,
                blocks=(),
                snapshot_hash=snap_hash,
            )

        if req.mode == "delta":
            if not self.enable_delta:
                return StateSyncResponseMsg(header=hdr, ok=False, reason="delta_disabled", height=tip_h)

            if self.block_provider is None:
                return StateSyncResponseMsg(header=hdr, ok=False, reason="delta_unavailable", height=tip_h)

            start = int(req.from_height or 0)
            if start < 0:
                return StateSyncResponseMsg(header=hdr, ok=False, reason="bad_from_height", height=tip_h)
            # Delta returns blocks in (start, end] inclusive.
            end = int(req.to_height) if req.to_height is not None else tip_h
            if end < 0:
                return StateSyncResponseMsg(header=hdr, ok=False, reason="bad_to_height", height=tip_h)
            end = max(start, min(end, tip_h))

            # Prevent unbounded responses.
            if end - start > int(self.max_delta_blocks):
                end = start + int(self.max_delta_blocks)

            blocks: list[Json] = []
            for h in range(start + 1, end + 1):
                blk = self.block_provider(h)
                if not isinstance(blk, dict):
                    # Missing blocks commonly means local history was pruned.
                    # Prefer a deterministic snapshot fallback when enabled.
                    if self.fallback_to_snapshot:
                        return _reply_snapshot("fallback_snapshot")
                    # Otherwise fail closed; caller can retry snapshot explicitly.
                    return StateSyncResponseMsg(header=hdr, ok=False, reason="delta_missing_block", height=tip_h)
                blocks.append(blk)

            if self.max_delta_bytes > 0:
                # Size check is on the returned payload to prevent large response amplification.
                if not self._size_ok(blocks, self.max_delta_bytes):
                    return StateSyncResponseMsg(header=hdr, ok=False, reason="delta_too_large", height=tip_h)

            return StateSyncResponseMsg(
                header=hdr,
                ok=True,
                reason=None,
                height=tip_h,
                snapshot=None,
                blocks=tuple(blocks),
                snapshot_hash=None,
            )

        return StateSyncResponseMsg(header=hdr, ok=False, reason="bad_mode", height=tip_h)

    def verify_response(self, resp: StateSyncResponseMsg) -> None:
        """
        Verify the integrity of a response (tests expect this method to exist and not raise).
        """
        if not isinstance(resp, StateSyncResponseMsg):
            raise StateSyncVerifyError("bad_response_type")
        if not resp.ok:
            # If remote says not ok, treat as non-verifiable but not corrupted.
            return

        # Snapshot verify
        if resp.snapshot is not None:
            if not isinstance(resp.snapshot, dict):
                raise StateSyncVerifyError("snapshot_not_object")
            expect = sha256_hex_of(resp.snapshot)
            have = resp.snapshot_hash or ""
            if not isinstance(have, str) or not have:
                raise StateSyncVerifyError("missing_snapshot_hash")
            if have != expect:
                raise StateSyncVerifyError("snapshot_hash_mismatch")

        # Delta sanity checks (best-effort; does not require hashes).
        if resp.blocks:
            if not isinstance(resp.blocks, (tuple, list)):
                raise StateSyncVerifyError("blocks_not_sequence")
            last_h: Optional[int] = None
            for blk in resp.blocks:
                if not isinstance(blk, dict):
                    raise StateSyncVerifyError("block_not_object")
                bh = blk.get("height")
                if bh is None:
                    # Some back-compat blocks may omit height; skip ordering checks.
                    continue
                try:
                    bh_i = int(bh)
                except Exception as e:
                    raise StateSyncVerifyError("block_height_bad") from e
                if last_h is not None and bh_i <= last_h:
                    raise StateSyncVerifyError("block_height_not_increasing")
                last_h = bh_i
