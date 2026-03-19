from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.runtime.state_hash import compute_state_root

Json = dict[str, Any]


def _mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        return int(str(raw).strip() or str(default))
    except Exception as exc:
        if _mode() == "prod":
            raise StateSyncVerifyError(f"invalid_integer_env:{name}") from exc
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    raw = str(v).strip().lower()
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    if not raw:
        return bool(default)
    if _mode() == "prod":
        raise StateSyncVerifyError(f"invalid_boolean_env:{name}")
    return bool(default)


def _trusted_anchor_env(default: bool) -> bool:
    """Read either trusted-anchor env alias and fail closed on conflict."""

    names = ("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR")
    seen: dict[str, bool] = {}
    for name in names:
        raw = os.environ.get(name)
        if raw is None:
            continue
        seen[name] = str(raw).strip().lower() in {"1", "true", "yes", "y", "on"}
    if not seen:
        return bool(default)
    vals = set(seen.values())
    if len(vals) > 1:
        raise StateSyncVerifyError("trusted_anchor_env_conflict")
    return bool(next(iter(vals)))


def _finalized_anchor_env(default: bool) -> bool:
    raw = os.environ.get("WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR")
    if raw is None:
        return bool(default)
    parsed = str(raw).strip().lower()
    if parsed in {"1", "true", "yes", "y", "on"}:
        return True
    if parsed in {"0", "false", "no", "n", "off"}:
        return False
    if not parsed:
        return bool(default)
    if _mode() == "prod":
        raise StateSyncVerifyError("invalid_boolean_env:WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR")
    return bool(default)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex_of(obj: Any) -> str:
    h = hashlib.sha256()
    h.update(_canon_json(obj).encode("utf-8"))
    return h.hexdigest()


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any) -> str:
    return str(v or "").strip()


def build_snapshot_anchor(snapshot: Json) -> Json:
    if not isinstance(snapshot, dict):
        raise StateSyncVerifyError("snapshot_not_object")
    finalized = snapshot.get("finalized") if isinstance(snapshot.get("finalized"), dict) else {}
    return {
        "height": _as_int(snapshot.get("height"), 0),
        "tip_hash": _as_str(
            snapshot.get("tip_hash") or snapshot.get("tip") or snapshot.get("block_hash") or ""
        ),
        "state_root": compute_state_root(snapshot),
        "finalized_height": _as_int(finalized.get("height"), 0),
        "finalized_block_id": _as_str(
            finalized.get("block_id") or snapshot.get("finalized_block_id") or ""
        ),
        "snapshot_hash": sha256_hex_of(snapshot),
    }


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
    block_provider: Callable[[int], Json | None] | None = None
    enable_delta: bool = True

    # Hardening caps (tunable by env).
    max_delta_blocks: int = 250
    max_snapshot_bytes: int = 0  # 0 = unlimited
    max_delta_bytes: int = 0  # 0 = unlimited
    require_header_match: bool = True
    fallback_to_snapshot: bool = True
    require_trusted_anchor: bool = False
    enforce_finalized_anchor: bool = False

    def __post_init__(self) -> None:
        self.max_delta_blocks = max(
            1, _env_int("WEALL_SYNC_MAX_DELTA_BLOCKS", int(self.max_delta_blocks or 250))
        )
        self.max_snapshot_bytes = max(
            0, _env_int("WEALL_SYNC_MAX_SNAPSHOT_BYTES", int(self.max_snapshot_bytes or 0))
        )
        self.max_delta_bytes = max(
            0, _env_int("WEALL_SYNC_MAX_DELTA_BYTES", int(self.max_delta_bytes or 0))
        )
        self.require_header_match = _env_bool(
            "WEALL_SYNC_REQUIRE_HEADER_MATCH", bool(self.require_header_match)
        )
        self.fallback_to_snapshot = _env_bool(
            "WEALL_SYNC_FALLBACK_TO_SNAPSHOT", bool(self.fallback_to_snapshot)
        )
        self.require_trusted_anchor = _trusted_anchor_env(bool(self.require_trusted_anchor))
        default_finalized = bool(self.enforce_finalized_anchor)
        if not default_finalized:
            mode = str(os.environ.get("WEALL_MODE") or "").strip().lower()
            bft_enabled = _env_bool("WEALL_BFT_ENABLED", False)
            default_finalized = bool(mode == "prod" and bft_enabled)
        self.enforce_finalized_anchor = _finalized_anchor_env(default_finalized)

    def _header_ok(self, req: StateSyncRequestMsg) -> str | None:
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
            return False

    def _trusted_anchor_from_selector(self, selector: Any) -> Json | None:
        if not isinstance(selector, dict):
            return None
        anchor = selector.get("trusted_anchor")
        if isinstance(anchor, dict):
            return dict(anchor)
        return None

    def _anchor_matches(self, local_anchor: Json, trusted_anchor: Json) -> bool:
        # Only compare fields the requester explicitly pinned.
        for key in (
            "height",
            "tip_hash",
            "state_root",
            "finalized_height",
            "finalized_block_id",
            "snapshot_hash",
        ):
            if key in trusted_anchor and trusted_anchor.get(key) not in (None, ""):
                if _as_str(local_anchor.get(key)) != _as_str(trusted_anchor.get(key)):
                    return False
        return True

    def _trusted_finalized_height(self, trusted_anchor: Json | None) -> int:
        if not isinstance(trusted_anchor, dict):
            return 0
        return _as_int(trusted_anchor.get("finalized_height"), 0)

    def _trusted_finalized_block_id(self, trusted_anchor: Json | None) -> str:
        if not isinstance(trusted_anchor, dict):
            return ""
        return _as_str(trusted_anchor.get("finalized_block_id") or "")

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

        reason = self._header_ok(req)
        if reason:
            return StateSyncResponseMsg(header=hdr, ok=False, reason=reason, height=0)

        st = self.state_provider()
        if not isinstance(st, dict):
            return StateSyncResponseMsg(header=hdr, ok=False, reason="bad_state", height=0)

        tip_h = int(st.get("height", 0) or 0)
        local_anchor = build_snapshot_anchor(st)
        trusted_anchor = self._trusted_anchor_from_selector(req.selector)
        if trusted_anchor is None and self.require_trusted_anchor:
            return StateSyncResponseMsg(
                header=hdr, ok=False, reason="trusted_anchor_required", height=tip_h
            )
        if trusted_anchor is not None and not self._anchor_matches(local_anchor, trusted_anchor):
            return StateSyncResponseMsg(
                header=hdr, ok=False, reason="trusted_anchor_mismatch", height=tip_h
            )

        if req.mode == "snapshot":
            snap: Json = st
            if not self._size_ok(snap, self.max_snapshot_bytes):
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="snapshot_too_large", height=tip_h
                )
            snap_hash = sha256_hex_of(snap)
            return StateSyncResponseMsg(
                header=hdr,
                ok=True,
                reason=None,
                height=tip_h,
                snapshot=snap,
                blocks=(),
                snapshot_hash=snap_hash,
                snapshot_anchor=local_anchor,
            )

        def _reply_snapshot(reason: str) -> StateSyncResponseMsg:
            snap: Json = st
            if not self._size_ok(snap, self.max_snapshot_bytes):
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="snapshot_too_large", height=tip_h
                )
            snap_hash = sha256_hex_of(snap)
            return StateSyncResponseMsg(
                header=hdr,
                ok=True,
                reason=reason,
                height=tip_h,
                snapshot=snap,
                blocks=(),
                snapshot_hash=snap_hash,
                snapshot_anchor=local_anchor,
            )

        if req.mode == "delta":
            if not self.enable_delta:
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="delta_disabled", height=tip_h
                )

            if self.block_provider is None:
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="delta_unavailable", height=tip_h
                )

            start = int(req.from_height or 0)
            if start < 0:
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="bad_from_height", height=tip_h
                )
            end = int(req.to_height) if req.to_height is not None else tip_h
            if end < 0:
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="bad_to_height", height=tip_h
                )
            end = max(start, min(end, tip_h))

            trusted_finalized_height = self._trusted_finalized_height(trusted_anchor)
            if self.enforce_finalized_anchor and trusted_finalized_height > 0:
                end = min(end, trusted_finalized_height)

            if end - start > int(self.max_delta_blocks):
                end = start + int(self.max_delta_blocks)

            blocks: list[Json] = []
            for h in range(start + 1, end + 1):
                blk = self.block_provider(h)
                if not isinstance(blk, dict):
                    if self.fallback_to_snapshot:
                        return _reply_snapshot("fallback_snapshot")
                    return StateSyncResponseMsg(
                        header=hdr, ok=False, reason="delta_missing_block", height=tip_h
                    )
                blocks.append(blk)

            if self.max_delta_bytes > 0 and not self._size_ok(blocks, self.max_delta_bytes):
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="delta_too_large", height=tip_h
                )

            return StateSyncResponseMsg(
                header=hdr,
                ok=True,
                reason=None,
                height=tip_h,
                snapshot=None,
                blocks=tuple(blocks),
                snapshot_hash=None,
                snapshot_anchor=local_anchor,
            )

        return StateSyncResponseMsg(header=hdr, ok=False, reason="bad_mode", height=tip_h)

    def verify_response(
        self, resp: StateSyncResponseMsg, trusted_anchor: Json | None = None
    ) -> None:
        if not isinstance(resp, StateSyncResponseMsg):
            raise StateSyncVerifyError("bad_response_type")
        try:
            hdr = resp.header
        except Exception as e:
            raise StateSyncVerifyError("missing_header") from e
        if hdr.type != MsgType.STATE_SYNC_RESPONSE:
            raise StateSyncVerifyError("bad_response_header:type")
        if _as_str(hdr.chain_id) != _as_str(self.chain_id):
            raise StateSyncVerifyError("bad_response_header:chain_id")
        if _as_str(hdr.schema_version) != _as_str(self.schema_version):
            raise StateSyncVerifyError("bad_response_header:schema_version")
        if _as_str(hdr.tx_index_hash) != _as_str(self.tx_index_hash):
            raise StateSyncVerifyError("bad_response_header:tx_index_hash")
        if not resp.ok:
            return

        anchor = resp.snapshot_anchor
        trusted_finalized_height = self._trusted_finalized_height(trusted_anchor)
        trusted_finalized_block_id = self._trusted_finalized_block_id(trusted_anchor)

        if trusted_anchor is not None:
            if not isinstance(anchor, dict):
                raise StateSyncVerifyError("missing_snapshot_anchor")
            if not self._anchor_matches(anchor, trusted_anchor):
                raise StateSyncVerifyError("trusted_anchor_mismatch")
            if self.enforce_finalized_anchor:
                if (
                    trusted_finalized_height > 0
                    and _as_int(anchor.get("finalized_height"), 0) != trusted_finalized_height
                ):
                    raise StateSyncVerifyError("trusted_finalized_anchor_mismatch:height")
                if (
                    trusted_finalized_block_id
                    and _as_str(anchor.get("finalized_block_id") or "")
                    != trusted_finalized_block_id
                ):
                    raise StateSyncVerifyError("trusted_finalized_anchor_mismatch:block_id")

        if isinstance(anchor, dict):
            anchor_height = _as_int(anchor.get("height"), 0)
            if (
                anchor_height > 0
                and int(resp.height or 0) > 0
                and anchor_height != int(resp.height)
            ):
                raise StateSyncVerifyError("snapshot_anchor_mismatch:height")

        if resp.snapshot is not None:
            if not isinstance(resp.snapshot, dict):
                raise StateSyncVerifyError("snapshot_not_object")
            expect_hash = sha256_hex_of(resp.snapshot)
            have_hash = resp.snapshot_hash or ""
            if not isinstance(have_hash, str) or not have_hash:
                raise StateSyncVerifyError("missing_snapshot_hash")
            if have_hash != expect_hash:
                raise StateSyncVerifyError("snapshot_hash_mismatch")

            if not isinstance(anchor, dict):
                raise StateSyncVerifyError("missing_snapshot_anchor")
            computed_anchor = build_snapshot_anchor(resp.snapshot)
            for key in (
                "height",
                "tip_hash",
                "state_root",
                "finalized_height",
                "finalized_block_id",
                "snapshot_hash",
            ):
                if _as_str(anchor.get(key)) != _as_str(computed_anchor.get(key)):
                    raise StateSyncVerifyError(f"snapshot_anchor_mismatch:{key}")
            if trusted_anchor is not None and not self._anchor_matches(
                computed_anchor, trusted_anchor
            ):
                raise StateSyncVerifyError("trusted_anchor_mismatch")

        if resp.blocks:
            if not isinstance(resp.blocks, (tuple, list)):
                raise StateSyncVerifyError("blocks_not_sequence")
            last_h: int | None = None
            last_bid: str | None = None
            for blk in resp.blocks:
                if not isinstance(blk, dict):
                    raise StateSyncVerifyError("block_not_object")
                bh = blk.get("height")
                if bh is None:
                    continue
                try:
                    bh_i = int(bh)
                except Exception as e:
                    raise StateSyncVerifyError("block_height_bad") from e
                if bh_i <= 0:
                    raise StateSyncVerifyError("block_height_bad")
                if last_h is not None and bh_i != last_h + 1:
                    raise StateSyncVerifyError("block_height_not_contiguous")
                prev = _as_str(blk.get("prev_block_hash") or blk.get("parent_block_id") or "")
                if last_bid is not None and prev and prev != last_bid:
                    raise StateSyncVerifyError("block_prev_hash_mismatch")
                last_h = bh_i
                last_bid = _as_str(blk.get("block_id") or blk.get("block_hash") or "")
            if last_h is not None and int(resp.height or 0) > 0 and last_h > int(resp.height):
                raise StateSyncVerifyError("block_height_exceeds_response_height")
            if trusted_anchor is not None:
                trusted_height = _as_int(trusted_anchor.get("height"), 0)
                if trusted_height > 0 and last_h is not None and last_h > trusted_height:
                    raise StateSyncVerifyError("block_height_exceeds_trusted_anchor")
                if (
                    self.enforce_finalized_anchor
                    and trusted_finalized_height > 0
                    and last_h is not None
                    and last_h > trusted_finalized_height
                ):
                    raise StateSyncVerifyError("block_height_exceeds_finalized_anchor")
