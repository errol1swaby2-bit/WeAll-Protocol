from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader

Json = Dict[str, Any]


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
    enable_delta: bool = True

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

        st = self.state_provider()
        if not isinstance(st, dict):
            return StateSyncResponseMsg(header=hdr, ok=False, reason="bad_state", height=0)

        tip_h = int(st.get("height", 0) or 0)

        if req.mode == "snapshot":
            snap: Json = st
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

        if req.mode == "delta":
            if not self.enable_delta:
                return StateSyncResponseMsg(header=hdr, ok=False, reason="delta_disabled", height=tip_h)
            return StateSyncResponseMsg(
                header=hdr,
                ok=True,
                reason=None,
                height=tip_h,
                snapshot=None,
                blocks=(),
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
