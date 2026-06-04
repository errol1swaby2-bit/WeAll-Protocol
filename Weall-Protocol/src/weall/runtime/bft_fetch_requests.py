from __future__ import annotations

"""BFT runtime helpers extracted from bft_runtime_adapter (bft_fetch_requests.py)."""

from weall.runtime.executor_symbols import bind_executor_globals


def _bind_executor_globals() -> None:
    bind_executor_globals(globals())

def _ensure_pending_fetch_budgets(self) -> None:
    _bind_executor_globals()
    if not hasattr(self, "_max_missing_parent_fetches_per_call"):
        self._max_missing_parent_fetches_per_call = max(
            1,
            _safe_int(os.environ.get("WEALL_BFT_MAX_MISSING_PARENT_FETCHES_PER_CALL"), 32),
        )
    if not hasattr(self, "_max_missing_qc_fetches_per_call"):
        self._max_missing_qc_fetches_per_call = max(
            1,
            _safe_int(os.environ.get("WEALL_BFT_MAX_MISSING_QC_FETCHES_PER_CALL"), 32),
        )
    if not hasattr(self, "_missing_parent_fetch_cursor"):
        self._missing_parent_fetch_cursor = 0
    if not hasattr(self, "_missing_qc_fetch_cursor"):
        self._missing_qc_fetch_cursor = 0

def _bounded_fetch_request_descriptors(self, descriptors: list[Json]) -> list[Json]:
    _bind_executor_globals()
    self._ensure_pending_fetch_budgets()
    if not descriptors:
        self._missing_parent_fetch_cursor = 0
        self._missing_qc_fetch_cursor = 0
        return []
    missing_parent: list[Json] = []
    missing_qc: list[Json] = []
    prioritized: list[Json] = []
    for item in descriptors:
        if not isinstance(item, dict):
            continue
        reason = str(item.get("reason") or "").strip()
        if reason == "missing_parent":
            missing_parent.append(dict(item))
        elif reason == "missing_qc_block":
            missing_qc.append(dict(item))
        else:
            prioritized.append(dict(item))

    out: list[Json] = list(prioritized)

    qc_limit = max(1, int(self._max_missing_qc_fetches_per_call))
    if len(missing_qc) <= qc_limit:
        self._missing_qc_fetch_cursor = 0
        out.extend(missing_qc)
    elif missing_qc:
        total = len(missing_qc)
        start = int(self._missing_qc_fetch_cursor or 0) % total
        idx = start
        for _ in range(qc_limit):
            out.append(dict(missing_qc[idx]))
            idx = (idx + 1) % total
        self._missing_qc_fetch_cursor = int(idx)

    parent_limit = max(1, int(self._max_missing_parent_fetches_per_call))
    if len(missing_parent) <= parent_limit:
        self._missing_parent_fetch_cursor = 0
        out.extend(missing_parent)
    elif missing_parent:
        total = len(missing_parent)
        start = int(self._missing_parent_fetch_cursor or 0) % total
        idx = start
        for _ in range(parent_limit):
            out.append(dict(missing_parent[idx]))
            idx = (idx + 1) % total
        self._missing_parent_fetch_cursor = int(idx)

    return out

def bft_pending_fetch_request_descriptors(self) -> list[Json]:
    _bind_executor_globals()
    wants: OrderedDict[str, Json] = OrderedDict()

    for bid in list(self._pending_missing_qc_entries().keys()):
        sbid = str(bid or "").strip()
        if not sbid:
            continue
        if self._bft_pending_block_json(sbid) is not None or self._has_local_block(sbid):
            continue
        qcj = self._pending_missing_qc_json(block_id=sbid)
        expected_hash = ""
        if isinstance(qcj, dict):
            expected_hash = str(qcj.get("block_hash") or "").strip()
        wants[sbid] = {
            "block_id": sbid,
            "block_hash": expected_hash,
            "reason": "missing_qc_block",
        }

    local_tip = str(self.state.get("tip") or "").strip()
    for bid in self._ordered_pending_block_ids():
        blk = self._bft_pending_block_json(str(bid or "").strip())
        sbid = str(bid or "").strip()
        if not sbid or self._has_local_block(sbid) or not isinstance(blk, dict):
            continue
        parent_id = str(blk.get("prev_block_id") or "").strip()
        height = self._block_height_hint(blk)
        if height <= 1 or not parent_id or parent_id == local_tip:
            continue
        if (
            self._has_local_block(parent_id)
            or self._bft_pending_block_json(parent_id) is not None
        ):
            continue
        header = blk.get("header") if isinstance(blk.get("header"), dict) else {}
        expected_hash = str(header.get("prev_block_hash") or "").strip()
        wants[parent_id] = {
            "block_id": parent_id,
            "block_hash": expected_hash,
            "reason": "missing_parent",
            "child_block_id": sbid,
        }

    out: list[Json] = []
    for bid, desc in list(wants.items()):
        sbid = str(bid or "").strip()
        if not sbid:
            continue
        d = dict(desc) if isinstance(desc, dict) else {"block_id": sbid}
        d["block_id"] = sbid
        out.append(d)
    return self._bounded_fetch_request_descriptors(out)

def _resolve_fetch_request_descriptor(self, desc: Json) -> Json | None:
    _bind_executor_globals()
    if not isinstance(desc, dict):
        return None
    bid = str(desc.get("block_id") or "").strip()
    bh = str(desc.get("block_hash") or "").strip()
    if not bid and not bh:
        return None
    resolved_bid = bid
    if bh:
        pending_bid, blk = self._resolve_pending_block_identity(block_id=bid, block_hash=bh)
        if isinstance(blk, dict) and pending_bid:
            resolved_bid = str(pending_bid).strip()
        else:
            qcached = self._pending_missing_qc_json(block_hash=bh)
            if isinstance(qcached, dict) and str(qcached.get("block_id") or "").strip():
                resolved_bid = str(qcached.get("block_id") or "").strip()
            else:
                known_bid = self._known_block_id_for_hash(bh)
                if known_bid:
                    resolved_bid = str(known_bid).strip()
    if not resolved_bid:
        resolved_bid = bid
    if not resolved_bid:
        return None
    out = dict(desc)
    out["block_id"] = resolved_bid
    if bid and resolved_bid and bid != resolved_bid:
        out["requested_block_id"] = bid
    return out

def bft_resolved_pending_fetch_request_descriptors(self) -> list[Json]:
    _bind_executor_globals()
    out: list[Json] = []
    seen: set[tuple[str, str]] = set()
    for item in self.bft_pending_fetch_request_descriptors():
        desc = self._resolve_fetch_request_descriptor(item)
        if not isinstance(desc, dict):
            continue
        bid = str(desc.get("block_id") or "").strip()
        bh = str(desc.get("block_hash") or "").strip()
        key = (bh, bid) if bh else ("", bid)
        if key in seen:
            continue
        seen.add(key)
        out.append(desc)
    return out

def bft_pending_fetch_requests(self) -> list[str]:
    _bind_executor_globals()
    return [
        str(d.get("block_id") or "").strip()
        for d in self.bft_resolved_pending_fetch_request_descriptors()
        if isinstance(d, dict) and str(d.get("block_id") or "").strip()
    ]

def bft_resolve_fetch_request_descriptor(self, desc: Json) -> Json | None:
    _bind_executor_globals()
    out = self._resolve_fetch_request_descriptor(desc)
    if isinstance(out, dict):
        out = dict(out)
        out.pop("requested_block_id", None)
    return out

