from __future__ import annotations

"""BFT runtime helpers extracted from bft_runtime_adapter (bft_pending_frontier.py)."""

from weall.runtime.bft_executor_symbols import bind_executor_globals


def _bind_executor_globals() -> None:
    bind_executor_globals(globals())

def _persist_pending_bft_artifact(self, *, kind: str, block_id: str, payload: Json) -> None:
    _bind_executor_globals()
    skind = str(kind or "").strip()
    bid = str(block_id or "").strip()
    if not skind or not bid or not isinstance(payload, dict):
        return
    now_ms = _now_ms()
    block_hash = str(payload.get("block_hash") or "").strip()
    try:
        with self._aux_db.write_tx() as con:
            row = con.execute(
                "SELECT created_ms FROM bft_pending_artifacts WHERE kind=? AND block_id=? LIMIT 1;",
                (skind, bid),
            ).fetchone()
            created_ms = int(row[0]) if row is not None and row[0] is not None else int(now_ms)
            con.execute(
                "INSERT OR REPLACE INTO bft_pending_artifacts(kind, block_id, block_hash, payload_json, created_ms, updated_ms) VALUES(?,?,?,?,?,?);",
                (skind, bid, block_hash, _canon_json(payload), int(created_ms), int(now_ms)),
            )
    except Exception:
        return

def _delete_pending_bft_artifact(self, *, kind: str, block_id: str) -> None:
    _bind_executor_globals()
    skind = str(kind or "").strip()
    bid = str(block_id or "").strip()
    if not skind or not bid:
        return
    try:
        with self._aux_db.write_tx() as con:
            con.execute(
                "DELETE FROM bft_pending_artifacts WHERE kind=? AND block_id=?;", (skind, bid)
            )
    except Exception:
        return

def _restore_pending_bft_frontier(self) -> None:
    _bind_executor_globals()
    stale_rows: list[tuple[str, str]] = []
    try:
        with self._aux_db.connection() as con:
            rows = list(
                con.execute(
                    "SELECT kind, block_id, payload_json FROM bft_pending_artifacts ORDER BY updated_ms ASC, kind ASC, block_id ASC;"
                ).fetchall()
            )
    except Exception:
        return
    for row in rows:
        try:
            kind = str(row[0] or "").strip()
            bid = str(row[1] or "").strip()
            payload = json.loads(str(row[2] or "{}"))
        except Exception:
            continue
        if not kind or not bid or not isinstance(payload, dict):
            stale_rows.append((kind, bid))
            continue
        if self._has_local_block(bid) or not self._bft_epoch_binding_matches(payload):
            stale_rows.append((kind, bid))
            continue
        if kind == "pending_remote_block":
            _bounded_put(
                self._pending_remote_blocks,
                bid,
                dict(payload),
                cap=self._max_pending_remote_blocks,
            )
            self._index_pending_remote_block(payload)
        elif kind == "pending_candidate":
            _bounded_put(
                self._pending_candidates,
                bid,
                (dict(payload), {}, [], []),
                cap=self._max_pending_candidates,
            )
            self._index_pending_candidate(payload)
        elif kind == "pending_missing_qc":
            _bounded_put(
                self._pending_missing_qcs, bid, dict(payload), cap=self._max_pending_missing_qcs
            )
            self._index_pending_missing_qc(payload)
        else:
            stale_rows.append((kind, bid))
    for kind, bid in stale_rows:
        self._delete_pending_bft_artifact(kind=kind, block_id=bid)
    self._prune_pending_bft_artifacts()

def _prune_pending_bft_artifacts_on_local_validator_transition(
    self,
    *,
    previous_epoch: int,
    previous_set_hash: str,
) -> bool:
    _bind_executor_globals()
    current_epoch = self._current_validator_epoch()
    current_set_hash = self._current_validator_set_hash() if int(current_epoch) > 0 else ""
    if (
        int(previous_epoch) == int(current_epoch)
        and str(previous_set_hash or "").strip() == str(current_set_hash or "").strip()
    ):
        return False
    return self._prune_pending_bft_artifacts()

def _cache_known_block_hash(self, block_id: str, block_hash: str) -> None:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    bh = str(block_hash or "").strip()
    if not bid or not bh:
        return
    _bounded_put(self._known_block_hashes, bid, bh, cap=self._max_known_block_hashes)
    _bounded_put(self._known_block_ids_by_hash, bh, bid, cap=self._max_known_block_ids_by_hash)

def _lookup_committed_block_hash_index(self, block_id: str) -> str:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    if not bid:
        return ""
    try:
        with self._db.connection() as con:
            row = con.execute(
                "SELECT block_hash FROM block_hash_index WHERE block_id=? LIMIT 1;",
                (bid,),
            ).fetchone()
    except Exception:
        return ""
    if row is None:
        return ""
    try:
        bh = str(row["block_hash"] or "").strip()
    except Exception:
        bh = ""
    if bh:
        self._cache_known_block_hash(bid, bh)
    return bh

def _lookup_committed_block_id_by_hash(self, block_hash: str) -> str:
    _bind_executor_globals()
    bh = str(block_hash or "").strip()
    if not bh:
        return ""
    try:
        with self._db.connection() as con:
            row = con.execute(
                "SELECT block_id FROM block_hash_index WHERE block_hash=? ORDER BY height DESC LIMIT 1;",
                (bh,),
            ).fetchone()
    except Exception:
        return ""
    if row is None:
        return ""
    try:
        bid = str(row["block_id"] or "").strip()
    except Exception:
        bid = ""
    if bid:
        self._cache_known_block_hash(bid, bh)
    return bid

def _known_block_hash_for_id(self, block_id: str, *, include_qc_cache: bool = False) -> str:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    if not bid:
        return ""

    cached = str(self._known_block_hashes.get(bid) or "").strip()
    if cached:
        _bounded_put(self._known_block_hashes, bid, cached, cap=self._max_known_block_hashes)
        return cached

    indexed = self._lookup_committed_block_hash_index(bid)
    if indexed:
        return indexed

    blocks_state = self.state.get("blocks")
    if isinstance(blocks_state, dict):
        state_entry = blocks_state.get(bid)
        if isinstance(state_entry, dict):
            known = str(state_entry.get("block_hash") or "").strip()
            if known:
                self._cache_known_block_hash(bid, known)
                return known

    if bid == str(self.state.get("tip") or "").strip():
        try:
            latest = self.get_latest_block()
            if isinstance(latest, dict):
                known = _block_hash_from_any(latest)
                if known:
                    self._cache_known_block_hash(bid, known)
                return known
        except Exception:
            return ""

    pending = self._pending_remote_blocks.get(bid)
    if isinstance(pending, dict):
        known = _block_hash_from_any(pending)
        if known:
            return known

    quarantined = self._quarantined_remote_blocks.get(bid)
    if isinstance(quarantined, dict):
        known = _block_hash_from_any(quarantined)
        if known:
            return known

    candidate = self._pending_candidates.get(bid)
    if isinstance(candidate, tuple) and candidate and isinstance(candidate[0], dict):
        known = _block_hash_from_any(candidate[0])
        if known:
            return known

    if include_qc_cache:
        qcj = self._pending_missing_qc_json(block_id=bid)
        if isinstance(qcj, dict):
            known = str(qcj.get("block_hash") or "").strip()
            if known:
                return known

    try:
        existing = self.get_block_by_id(bid)
    except Exception:
        existing = None
    if isinstance(existing, dict):
        known = _block_hash_from_any(existing)
        if known:
            self._cache_known_block_hash(bid, known)
        return known
    return ""

def _known_block_id_for_hash(self, block_hash: str) -> str:
    _bind_executor_globals()
    bh = str(block_hash or "").strip()
    if not bh:
        return ""
    cached = str(self._known_block_ids_by_hash.get(bh) or "").strip()
    if cached:
        _bounded_put(
            self._known_block_ids_by_hash, bh, cached, cap=self._max_known_block_ids_by_hash
        )
        return cached

    indexed = self._lookup_committed_block_id_by_hash(bh)
    if indexed:
        return indexed

    blocks_state = self.state.get("blocks")
    if isinstance(blocks_state, dict):
        for bid, entry in list(blocks_state.items()):
            if not isinstance(entry, dict):
                continue
            known = str(entry.get("block_hash") or "").strip()
            if known == bh:
                sbid = str(bid or "").strip()
                if sbid:
                    self._cache_known_block_hash(sbid, bh)
                    return sbid

    pending_remote_bid = str(self._pending_remote_block_ids_by_hash.get(bh) or "").strip()
    if pending_remote_bid:
        _bounded_put(
            self._pending_remote_block_ids_by_hash,
            bh,
            pending_remote_bid,
            cap=self._max_pending_remote_blocks,
        )
        self._cache_known_block_hash(pending_remote_bid, bh)
        return pending_remote_bid

    quarantined_bid = str(self._quarantined_remote_block_ids_by_hash.get(bh) or "").strip()
    if quarantined_bid:
        _bounded_put(
            self._quarantined_remote_block_ids_by_hash,
            bh,
            quarantined_bid,
            cap=self._max_quarantined_remote_blocks,
        )
        self._cache_known_block_hash(quarantined_bid, bh)
        return quarantined_bid

    pending_candidate_bid = str(self._pending_candidate_ids_by_hash.get(bh) or "").strip()
    if pending_candidate_bid:
        _bounded_put(
            self._pending_candidate_ids_by_hash,
            bh,
            pending_candidate_bid,
            cap=self._max_pending_candidates,
        )
        self._cache_known_block_hash(pending_candidate_bid, bh)
        return pending_candidate_bid

    for bid in self._ordered_pending_block_ids():
        blk = self._bft_pending_block_json(str(bid or "").strip())
        if not isinstance(blk, dict):
            continue
        if _block_hash_from_any(blk) == bh:
            sbid = str(bid or "").strip()
            if sbid:
                self._cache_known_block_hash(sbid, bh)
                self._index_pending_remote_block(blk)
                return sbid

    for bid, tup in list(self._pending_candidates.items()):
        if not (isinstance(tup, tuple) and tup and isinstance(tup[0], dict)):
            continue
        if _block_hash_from_any(tup[0]) == bh:
            sbid = str(bid or "").strip()
            if sbid:
                self._cache_known_block_hash(sbid, bh)
                self._index_pending_candidate(tup[0])
                return sbid

    try:
        latest = self.get_latest_block()
    except Exception:
        latest = None
    if isinstance(latest, dict):
        latest_hash = _block_hash_from_any(latest)
        latest_id = str(latest.get("block_id") or "").strip()
        if latest_hash == bh and latest_id:
            self._cache_known_block_hash(latest_id, bh)
            return latest_id
    return ""

def _is_conflicted_block_id(self, block_id: str) -> bool:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    return bool(bid and bid in self._conflicted_block_ids)

def _is_conflicted_block_hash(self, block_hash: str) -> bool:
    _bind_executor_globals()
    bh = str(block_hash or "").strip()
    return bool(bh and bh in self._conflicted_block_hashes)

def _drop_pending_candidate_artifacts(self, block_id: str) -> None:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    if not bid:
        return
    tup = self._pending_candidates.get(bid)
    blk = tup[0] if isinstance(tup, tuple) and tup and isinstance(tup[0], dict) else None
    self._drop_pending_hash_aliases(block_id=bid, block=blk if isinstance(blk, dict) else None)
    try:
        del self._pending_candidates[bid]
    except Exception:
        pass
    self._delete_pending_bft_artifact(kind="pending_candidate", block_id=bid)
    self._drop_pending_remote_artifacts(bid)

def _mark_block_id_conflict(
    self, *, block_id: str, known_hash: str, new_hash: str, source: str, parent_id: str = ""
) -> None:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    if not bid:
        return
    detail: Json = {
        "block_id": bid,
        "known_block_hash": str(known_hash or "").strip(),
        "new_block_hash": str(new_hash or "").strip(),
        "source": str(source or "").strip(),
    }
    pid = str(parent_id or "").strip()
    if pid:
        detail["parent_id"] = pid
    _bounded_put(self._conflicted_block_ids, bid, detail, cap=self._max_conflicted_block_ids)
    self._drop_pending_candidate_artifacts(bid)
    self._remove_pending_missing_qc(block_id=bid)
    self._bft_record_event(
        "bft_block_identity_conflict",
        block_id=bid,
        known_block_hash=str(known_hash or "").strip(),
        new_block_hash=str(new_hash or "").strip(),
        source=str(source or "").strip(),
        parent_id=pid,
    )

def _mark_block_hash_conflict(
    self,
    *,
    block_hash: str,
    known_block_id: str,
    new_block_id: str,
    source: str,
    parent_id: str = "",
) -> None:
    _bind_executor_globals()
    bh = str(block_hash or "").strip()
    if not bh:
        return
    detail: Json = {
        "block_hash": bh,
        "known_block_id": str(known_block_id or "").strip(),
        "new_block_id": str(new_block_id or "").strip(),
        "source": str(source or "").strip(),
    }
    pid = str(parent_id or "").strip()
    if pid:
        detail["parent_id"] = pid
    _bounded_put(
        self._conflicted_block_hashes, bh, detail, cap=self._max_conflicted_block_hashes
    )
    for bid in (str(known_block_id or "").strip(), str(new_block_id or "").strip()):
        if bid:
            self._drop_pending_candidate_artifacts(bid)
            self._remove_pending_missing_qc(block_id=bid)
    self._bft_record_event(
        "bft_block_hash_identity_conflict",
        block_hash=bh,
        known_block_id=str(known_block_id or "").strip(),
        new_block_id=str(new_block_id or "").strip(),
        source=str(source or "").strip(),
        parent_id=pid,
    )

def _qc_identity_conflicts(self, qcj: Json, *, source: str = "qc") -> bool:
    _bind_executor_globals()
    if not isinstance(qcj, dict):
        return False
    bid = str(qcj.get("block_id") or "").strip()
    bh = str(qcj.get("block_hash") or "").strip()
    if not bid or not bh:
        return False
    if self._is_conflicted_block_id(bid):
        return True
    existing = self._pending_missing_qcs.get(bid)
    if isinstance(existing, dict):
        existing_hash = str(existing.get("block_hash") or "").strip()
        existing_parent = str(existing.get("parent_id") or "").strip()
        if existing_hash and existing_hash != bh:
            self._mark_block_id_conflict(
                block_id=bid,
                known_hash=existing_hash,
                new_hash=bh,
                source=source,
                parent_id=str(qcj.get("parent_id") or existing_parent or ""),
            )
            return True
        parent_id = str(qcj.get("parent_id") or "").strip()
        if existing_parent and parent_id and existing_parent != parent_id:
            self._mark_block_id_conflict(
                block_id=bid,
                known_hash=existing_hash or bh,
                new_hash=bh,
                source=f"{source}_parent",
                parent_id=parent_id,
            )
            return True
    return False

def _block_identity_conflicts(self, block: Json) -> bool:
    _bind_executor_globals()
    if not isinstance(block, dict):
        return False
    bid = str(block.get("block_id") or "").strip()
    if not bid:
        return False
    if self._is_conflicted_block_id(bid):
        return True
    block_hash = _block_hash_from_any(block)
    if not block_hash:
        return False
    if self._is_conflicted_block_hash(block_hash):
        return True
    known = self._known_block_hash_for_id(bid)
    if known and known != block_hash:
        self._mark_block_id_conflict(
            block_id=bid,
            known_hash=known,
            new_hash=block_hash,
            source="block",
            parent_id=str(block.get("prev_block_id") or ""),
        )
        return True
    known_block_id = self._known_block_id_for_hash(block_hash)
    if known_block_id and known_block_id != bid:
        self._mark_block_hash_conflict(
            block_hash=block_hash,
            known_block_id=known_block_id,
            new_block_id=bid,
            source="block_hash_alias",
            parent_id=str(block.get("prev_block_id") or ""),
        )
        return True
    return False

def _block_height_hint(self, block: Json) -> int:
    _bind_executor_globals()
    if not isinstance(block, dict):
        return 0
    try:
        hdr = block.get("header") if isinstance(block.get("header"), dict) else {}
        return int(hdr.get("height") or block.get("height") or 0)
    except Exception:
        return 0

def _has_local_block(self, block_id: str) -> bool:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    if not bid:
        return False
    if bid == str(self.state.get("tip") or "").strip():
        return True
    blocks = self.state.get("blocks")
    if isinstance(blocks, dict) and bid in blocks:
        return True
    try:
        return self.get_block_by_id(bid) is not None
    except Exception:
        return False

def _index_pending_remote_block(self, block: Json) -> None:
    _bind_executor_globals()
    if not isinstance(block, dict):
        return
    bid = str(block.get("block_id") or "").strip()
    bh = _block_hash_from_any(block)
    if bid and bh:
        _bounded_put(
            self._pending_remote_block_ids_by_hash, bh, bid, cap=self._max_pending_remote_blocks
        )

def _index_quarantined_remote_block(self, block: Json) -> None:
    _bind_executor_globals()
    if not isinstance(block, dict):
        return
    bid = str(block.get("block_id") or "").strip()
    bh = _block_hash_from_any(block)
    if bid and bh:
        _bounded_put(
            self._quarantined_remote_block_ids_by_hash,
            bh,
            bid,
            cap=self._max_quarantined_remote_blocks,
        )

def _quarantine_remote_block(self, block: Json) -> None:
    _bind_executor_globals()
    if not isinstance(block, dict):
        return
    bid = str(block.get("block_id") or "").strip()
    if not bid:
        return
    existing = list(self._quarantined_remote_blocks.keys())
    incoming = dict(block)
    _bounded_put(
        self._quarantined_remote_blocks,
        bid,
        incoming,
        cap=self._max_quarantined_remote_blocks,
    )
    kept = set(str(k or "").strip() for k in self._quarantined_remote_blocks.keys())
    for evicted in existing:
        sevicted = str(evicted or "").strip()
        if sevicted and sevicted != bid and sevicted not in kept:
            self._drop_quarantined_remote_artifacts(sevicted)
    self._index_quarantined_remote_block(incoming)

def _drop_quarantined_remote_artifacts(self, block_id: str) -> None:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    if not bid:
        return
    blk = self._quarantined_remote_blocks.get(bid)
    bh = _block_hash_from_any(blk) if isinstance(blk, dict) else ""
    try:
        del self._quarantined_remote_blocks[bid]
    except Exception:
        pass
    if bh and str(self._quarantined_remote_block_ids_by_hash.get(bh) or "").strip() == bid:
        self._quarantined_remote_block_ids_by_hash.pop(bh, None)

def _put_pending_remote_block(self, *, block_id: str, block: Json) -> None:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    if not bid or not isinstance(block, dict):
        return
    existing = list(self._pending_remote_blocks.keys())
    blk = dict(block)
    _bounded_put(self._pending_remote_blocks, bid, blk, cap=self._max_pending_remote_blocks)
    kept = set(str(k or "").strip() for k in self._pending_remote_blocks.keys())
    for evicted in existing:
        sevicted = str(evicted or "").strip()
        if sevicted and sevicted != bid and sevicted not in kept:
            self._drop_pending_hash_aliases(block_id=sevicted)
            self._delete_pending_bft_artifact(kind="pending_remote_block", block_id=sevicted)
    self._persist_pending_bft_artifact(kind="pending_remote_block", block_id=bid, payload=blk)
    self._index_pending_remote_block(blk)

def _promote_quarantined_remote_block(
    self, block_id: str, *, block: Json | None = None
) -> None:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    blk = dict(block) if isinstance(block, dict) else None
    if blk is None and bid:
        cached = self._quarantined_remote_blocks.get(bid)
        if isinstance(cached, dict):
            blk = dict(cached)
    if not bid or not isinstance(blk, dict):
        return
    self._drop_quarantined_remote_artifacts(bid)
    self._put_pending_remote_block(block_id=bid, block=blk)

def _index_pending_candidate(self, block: Json) -> None:
    _bind_executor_globals()
    if not isinstance(block, dict):
        return
    bid = str(block.get("block_id") or "").strip()
    bh = _block_hash_from_any(block)
    if bid and bh:
        _bounded_put(
            self._pending_candidate_ids_by_hash, bh, bid, cap=self._max_pending_candidates
        )

def _index_pending_missing_qc(self, qcj: Json) -> None:
    _bind_executor_globals()
    if not isinstance(qcj, dict):
        return
    bh = str(qcj.get("block_hash") or "").strip()
    if bh:
        _bounded_put(
            self._pending_missing_qcs_by_hash, bh, dict(qcj), cap=self._max_pending_missing_qcs
        )

def _put_pending_missing_qc(self, qcj: Json) -> None:
    _bind_executor_globals()
    if not isinstance(qcj, dict):
        return
    bid = str(qcj.get("block_id") or "").strip()
    payload = dict(qcj)
    if bid:
        existing = list(self._pending_missing_qcs.keys())
        _bounded_put(self._pending_missing_qcs, bid, payload, cap=self._max_pending_missing_qcs)
        kept = set(str(k or "").strip() for k in self._pending_missing_qcs.keys())
        for evicted in existing:
            sevicted = str(evicted or "").strip()
            if sevicted and sevicted != bid and sevicted not in kept:
                self._drop_pending_missing_qc_aliases(block_id=sevicted)
                self._delete_pending_bft_artifact(kind="pending_missing_qc", block_id=sevicted)
        self._persist_pending_bft_artifact(
            kind="pending_missing_qc", block_id=bid, payload=payload
        )
    self._index_pending_missing_qc(payload)

def _drop_pending_missing_qc_aliases(
    self, *, block_id: str = "", qcj: Json | None = None
) -> None:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    q = dict(qcj) if isinstance(qcj, dict) else None
    if q is None and bid:
        existing = self._pending_missing_qcs.get(bid)
        if isinstance(existing, dict):
            q = existing
    bh = str((q or {}).get("block_hash") or "").strip()
    if bh:
        cached = self._pending_missing_qcs_by_hash.get(bh)
        if not isinstance(cached, dict) or str(cached.get("block_id") or "").strip() == bid:
            self._pending_missing_qcs_by_hash.pop(bh, None)

def _remove_pending_missing_qc(self, *, block_id: str) -> None:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    if not bid:
        return
    self._drop_pending_missing_qc_aliases(block_id=bid)
    try:
        self._pending_missing_qcs.pop(bid, None)
    except Exception:
        pass
    self._delete_pending_bft_artifact(kind="pending_missing_qc", block_id=bid)

def _pending_missing_qc_json(self, *, block_id: str = "", block_hash: str = "") -> Json | None:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    if bid:
        cached = self._pending_missing_qcs.get(bid)
        if isinstance(cached, dict):
            self._index_pending_missing_qc(cached)
            return dict(cached)
    bh = str(block_hash or "").strip()
    if bh:
        cached = self._pending_missing_qcs_by_hash.get(bh)
        if isinstance(cached, dict):
            cbid = str(cached.get("block_id") or "").strip()
            if cbid and cbid not in self._pending_missing_qcs:
                _bounded_put(
                    self._pending_missing_qcs,
                    cbid,
                    dict(cached),
                    cap=self._max_pending_missing_qcs,
                )
            return dict(cached)
        for qcj in list(self._pending_missing_qcs.values()):
            if not isinstance(qcj, dict):
                continue
            if str(qcj.get("block_hash") or "").strip() == bh:
                self._index_pending_missing_qc(qcj)
                return dict(qcj)
    return None

def _pending_missing_qc_entries(self) -> OrderedDict[str, Json]:
    _bind_executor_globals()
    out: OrderedDict[str, Json] = OrderedDict()
    for bid, qcj in list(self._pending_missing_qcs.items()):
        sbid = str(bid or "").strip()
        if not sbid or not isinstance(qcj, dict):
            continue
        out[sbid] = dict(qcj)
        self._index_pending_missing_qc(qcj)
    for _bh, qcj in list(self._pending_missing_qcs_by_hash.items()):
        if not isinstance(qcj, dict):
            continue
        sbid = str(qcj.get("block_id") or "").strip()
        if not sbid or sbid in out:
            continue
        out[sbid] = dict(qcj)
    return out

def _drop_pending_hash_aliases(self, *, block_id: str, block: Json | None = None) -> None:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    blk = block if isinstance(block, dict) else None
    if blk is None and bid:
        existing_remote = self._pending_remote_blocks.get(bid)
        if isinstance(existing_remote, dict):
            blk = existing_remote
        else:
            existing_candidate = self._pending_candidates.get(bid)
            if (
                isinstance(existing_candidate, tuple)
                and existing_candidate
                and isinstance(existing_candidate[0], dict)
            ):
                blk = existing_candidate[0]
    bh = _block_hash_from_any(blk) if isinstance(blk, dict) else ""
    if bh:
        if str(self._pending_remote_block_ids_by_hash.get(bh) or "").strip() == bid:
            self._pending_remote_block_ids_by_hash.pop(bh, None)
        if str(self._pending_candidate_ids_by_hash.get(bh) or "").strip() == bid:
            self._pending_candidate_ids_by_hash.pop(bh, None)

def _pending_block_identity_tuple(self, block_id: str) -> tuple[int, str, str]:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    blk = self._bft_pending_block_json(bid)
    if not isinstance(blk, dict):
        return (0, "", bid)
    return (int(self._block_height_hint(blk) or 0), _block_hash_from_any(blk), bid)

def _ordered_pending_block_ids(self) -> list[str]:
    _bind_executor_globals()
    ids = list(
        dict.fromkeys(
            list(self._pending_remote_blocks.keys())
            + list(self._quarantined_remote_blocks.keys())
            + list(self._pending_candidates.keys())
        )
    )
    ids = [str(bid or "").strip() for bid in ids if str(bid or "").strip()]
    ids.sort(key=lambda bid: self._pending_block_identity_tuple(bid))
    return ids

def _drop_pending_remote_artifacts(self, block_id: str) -> None:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    if not bid:
        return
    blk = self._pending_remote_blocks.get(bid)
    self._drop_pending_hash_aliases(block_id=bid, block=blk if isinstance(blk, dict) else None)
    try:
        del self._pending_remote_blocks[bid]
    except Exception:
        pass
    self._delete_pending_bft_artifact(kind="pending_remote_block", block_id=bid)
    self._drop_quarantined_remote_artifacts(bid)
    self._remove_pending_missing_qc(block_id=bid)

def _bft_speculative_blocks_map(self) -> dict[str, Json]:
    _bind_executor_globals()
    blocks_any = self.state.get("blocks")
    blocks_map: dict[str, Json] = dict(blocks_any) if isinstance(blocks_any, dict) else {}

    for source in (self._quarantined_remote_blocks, self._pending_remote_blocks):
        for bid, blk in list(source.items()):
            sbid = str(bid or "").strip()
            if not sbid or sbid in blocks_map or not isinstance(blk, dict):
                continue
            blocks_map[sbid] = {
                "height": int(self._block_height_hint(blk) or 0),
                "prev_block_id": str(blk.get("prev_block_id") or "").strip(),
                "block_ts_ms": _safe_int(
                    (
                        (blk.get("header") or {}) if isinstance(blk.get("header"), dict) else {}
                    ).get("block_ts_ms")
                    or blk.get("block_ts_ms"),
                    0,
                ),
                "block_hash": str(blk.get("block_hash") or "").strip(),
            }

    for bid, tup in list(self._pending_candidates.items()):
        sbid = str(bid or "").strip()
        if not sbid or sbid in blocks_map or not isinstance(tup, tuple) or not tup:
            continue
        blk = tup[0]
        if not isinstance(blk, dict):
            continue
        blocks_map[sbid] = {
            "height": int(self._block_height_hint(blk) or 0),
            "prev_block_id": str(blk.get("prev_block_id") or "").strip(),
            "block_ts_ms": _safe_int(
                ((blk.get("header") or {}) if isinstance(blk.get("header"), dict) else {}).get(
                    "block_ts_ms"
                )
                or blk.get("block_ts_ms"),
                0,
            ),
            "block_hash": str(blk.get("block_hash") or "").strip(),
        }
    return blocks_map

def _bft_pending_block_json(self, block_id: str) -> Json | None:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    if not bid or self._is_conflicted_block_id(bid):
        return None
    blk = self._pending_remote_blocks.get(bid)
    if isinstance(blk, dict):
        return dict(blk)
    blk = self._quarantined_remote_blocks.get(bid)
    if isinstance(blk, dict):
        return dict(blk)
    tup = self._pending_candidates.get(bid)
    if isinstance(tup, tuple) and tup and isinstance(tup[0], dict):
        return dict(tup[0])
    return None

def _bft_pending_block_json_by_hash(self, block_hash: str) -> Json | None:
    _bind_executor_globals()
    bh = str(block_hash or "").strip()
    if not bh or self._is_conflicted_block_hash(bh):
        return None
    pending_remote_bid = str(self._pending_remote_block_ids_by_hash.get(bh) or "").strip()
    if pending_remote_bid:
        blk = self._bft_pending_block_json(pending_remote_bid)
        if isinstance(blk, dict) and _block_hash_from_any(blk) == bh:
            self._index_pending_remote_block(blk)
            return blk
    quarantined_bid = str(self._quarantined_remote_block_ids_by_hash.get(bh) or "").strip()
    if quarantined_bid:
        blk = self._bft_pending_block_json(quarantined_bid)
        if isinstance(blk, dict) and _block_hash_from_any(blk) == bh:
            self._index_quarantined_remote_block(blk)
            return blk
    pending_candidate_bid = str(self._pending_candidate_ids_by_hash.get(bh) or "").strip()
    if pending_candidate_bid:
        blk = self._bft_pending_block_json(pending_candidate_bid)
        if isinstance(blk, dict) and _block_hash_from_any(blk) == bh:
            self._index_pending_candidate(blk)
            return blk
    for bid in self._ordered_pending_block_ids():
        blk = self._bft_pending_block_json(bid)
        if not isinstance(blk, dict):
            continue
        if _block_hash_from_any(blk) == bh:
            self._index_pending_remote_block(blk)
            self._index_pending_candidate(blk)
            return blk
    return None

def _resolve_pending_block_identity(
    self, *, block_id: str = "", block_hash: str = ""
) -> tuple[str, Json | None]:
    _bind_executor_globals()
    bid = str(block_id or "").strip()
    bh = str(block_hash or "").strip()
    blk = self._bft_pending_block_json(bid) if bid else None
    if isinstance(blk, dict):
        return (str(blk.get("block_id") or bid).strip(), blk)
    if bh:
        blk = self._bft_pending_block_json_by_hash(bh)
        if isinstance(blk, dict):
            return (str(blk.get("block_id") or "").strip(), blk)
    return (bid, None)

def _bft_pending_artifact_matches_current_epoch(self, payload: Json) -> bool:
    _bind_executor_globals()
    if not isinstance(payload, dict):
        return False
    if not self._bft_payload_phase_is_cache_compatible(payload):
        return False
    local_epoch = self._current_validator_epoch()
    local_set_hash = self._current_validator_set_hash() if int(local_epoch) > 0 else ""
    payload_epoch = _safe_int(payload.get("validator_epoch"), 0)
    payload_set_hash = str(payload.get("validator_set_hash") or "").strip()
    if (
        int(local_epoch) > 0
        and int(payload_epoch) > 0
        and int(payload_epoch) != int(local_epoch)
    ):
        return False
    if local_set_hash and payload_set_hash and payload_set_hash != local_set_hash:
        return False
    return True

def _prune_pending_bft_artifacts(self) -> bool:
    _bind_executor_globals()
    changed = False
    finalized_block_id = str(self._bft.finalized_block_id or "").strip()
    local_height = _safe_int(self.state.get("height"), 0)
    speculative = self._bft_speculative_blocks_map()

    for bid in list(self._pending_missing_qc_entries().keys()):
        sbid = str(bid or "").strip()
        qcj = self._pending_missing_qc_json(block_id=bid)
        if not sbid or not isinstance(qcj, dict):
            self._remove_pending_missing_qc(block_id=sbid)
            changed = True
            continue
        if (
            self._is_conflicted_block_id(sbid)
            or self._has_local_block(sbid)
            or not self._bft_pending_artifact_matches_current_epoch(qcj)
        ):
            self._remove_pending_missing_qc(block_id=sbid)
            changed = True
            continue
        if (
            finalized_block_id
            and sbid != finalized_block_id
            and not is_descendant(speculative, candidate=sbid, ancestor=finalized_block_id)
        ):
            self._remove_pending_missing_qc(block_id=sbid)
            changed = True

    for bid in self._ordered_pending_block_ids():
        sbid = str(bid or "").strip()
        blk = self._bft_pending_block_json(sbid)
        if not sbid or not isinstance(blk, dict):
            self._drop_pending_candidate_artifacts(sbid)
            changed = True
            continue
        if self._has_local_block(sbid) or not self._bft_pending_artifact_matches_current_epoch(
            blk
        ):
            self._drop_pending_candidate_artifacts(sbid)
            changed = True
            continue
        height = self._block_height_hint(blk)
        if (
            height > 0
            and height <= local_height
            and sbid != str(self.state.get("tip") or "").strip()
        ):
            self._drop_pending_candidate_artifacts(sbid)
            changed = True
            continue
        if finalized_block_id and not self._bft_block_is_applyable_finalized_descendant(
            blk, finalized_block_id
        ):
            self._drop_pending_candidate_artifacts(sbid)
            changed = True

    return changed

def _bft_block_is_applyable_finalized_descendant(
    self, block: Json, finalized_block_id: str
) -> bool:
    _bind_executor_globals()
    bid = str(block.get("block_id") or "").strip()
    fin = str(finalized_block_id or "").strip()
    if not bid or not fin:
        return False
    if bid == fin:
        return True
    return is_descendant(self._bft_speculative_blocks_map(), candidate=bid, ancestor=fin)

def _bft_parent_ready_for_apply(self, block: Json) -> bool:
    _bind_executor_globals()
    parent_id = str(block.get("prev_block_id") or "").strip()
    height = self._block_height_hint(block)
    if height <= 1:
        return True
    if not parent_id:
        return False
    if parent_id == str(self.state.get("tip") or "").strip():
        return True
    return self._has_local_block(parent_id)

def bft_try_apply_pending_remote_blocks(self) -> list[ExecutorMeta]:
    """Attempt deterministic catch-up replay for pending BFT blocks.

    In production, only blocks on the currently finalized path are durably
    replayed. In non-production modes we preserve the historic testnet/dev
    catch-up behavior and allow contiguous QC-backed replay from the local
    tip even before a later QC advances finalization.
    """
    _bind_executor_globals()
    results: list[ExecutorMeta] = []
    self._prune_pending_bft_artifacts()
    if _mode() == "prod" and not self._bft_phase_allows_artifact_processing():
        return results
    finalized_block_id = str(self._bft.finalized_block_id or "").strip()
    allow_qc_replay = _mode() != "prod"
    if not finalized_block_id and not allow_qc_replay:
        return results

    scan_budget = max(1, int(getattr(self, "_max_pending_replay_scans_per_call", 64) or 64))
    apply_budget = max(1, int(getattr(self, "_max_pending_replay_applies_per_call", 8) or 8))
    if not hasattr(self, "_pending_replay_cursor"):
        self._pending_replay_cursor = ""

    ordered_ids = self._ordered_pending_block_ids()
    if not ordered_ids:
        self._pending_replay_cursor = ""
        return results

    start_idx = 0
    cursor = str(getattr(self, "_pending_replay_cursor", "") or "").strip()
    if cursor and cursor in ordered_ids:
        start_idx = (ordered_ids.index(cursor) + 1) % len(ordered_ids)

    scanned = 0
    applied = 0
    idx = start_idx
    visited = 0
    made_progress = False

    while visited < len(ordered_ids) and scanned < scan_budget and applied < apply_budget:
        bid = str(ordered_ids[idx] or "").strip()
        idx = (idx + 1) % len(ordered_ids)
        visited += 1
        if not bid:
            continue
        if self._has_local_block(bid):
            self._drop_pending_candidate_artifacts(bid)
            self._pending_replay_cursor = bid
            made_progress = True
            continue
        blk = self._bft_pending_block_json(bid)
        if not isinstance(blk, dict):
            self._pending_replay_cursor = bid
            continue
        if finalized_block_id:
            if not self._bft_block_is_applyable_finalized_descendant(blk, finalized_block_id):
                self._pending_replay_cursor = bid
                scanned += 1
                continue
        else:
            qcj = self._pending_missing_qc_json(
                block_id=bid, block_hash=_block_hash_from_any(blk)
            )
            if not (allow_qc_replay and isinstance(qcj, dict)):
                self._pending_replay_cursor = bid
                scanned += 1
                continue
        scanned += 1
        self._pending_replay_cursor = bid
        if not self._bft_parent_ready_for_apply(blk):
            continue

        qcj = self._pending_missing_qc_json(block_id=bid, block_hash=_block_hash_from_any(blk))
        blk2 = dict(blk)
        if not isinstance(qcj, dict):
            embedded_qc = (
                blk2.get("justify_qc")
                if isinstance(blk2.get("justify_qc"), dict)
                else (blk2.get("qc") if isinstance(blk2.get("qc"), dict) else None)
            )
            if isinstance(embedded_qc, dict):
                verified_qc = self.bft_verify_qc_json(embedded_qc)
                if verified_qc is not None:
                    qcj = verified_qc.to_json()
                    self._put_pending_missing_qc(qcj)
        if isinstance(qcj, dict):
            existing_justify = (
                blk2.get("justify_qc") if isinstance(blk2.get("justify_qc"), dict) else None
            )
            qc_bid = str(qcj.get("block_id") or "").strip()
            qc_bh = str(qcj.get("block_hash") or "").strip()
            block_bid = str(blk2.get("block_id") or "").strip()
            parent_bid = str(blk2.get("prev_block_id") or "").strip()
            qc_is_self_commit = bool(qc_bid and block_bid and qc_bid == block_bid)
            qc_is_parent_justify = bool(qc_bid and parent_bid and qc_bid == parent_bid)
            synthetic_replay = (
                not isinstance(blk2.get("qc"), dict)
                and "validator_epoch" not in blk2
                and not str(blk2.get("validator_set_hash") or "").strip()
            )
            if existing_justify is None:
                if qc_is_parent_justify:
                    blk2["justify_qc"] = dict(qcj)
                elif qc_is_self_commit and synthetic_replay:
                    blk2["justify_qc"] = dict(qcj)
            else:
                existing_bid = str(existing_justify.get("block_id") or "").strip()
                existing_bh = str(existing_justify.get("block_hash") or "").strip()
                if (existing_bid and qc_bid and existing_bid != qc_bid) or (
                    existing_bh and qc_bh and existing_bh != qc_bh
                ):
                    self._drop_pending_candidate_artifacts(bid)
                    made_progress = True
                    continue
            if qc_is_self_commit and not synthetic_replay:
                blk2["qc"] = dict(qcj)
        try:
            replay_view = int(
                blk2.get("view")
                or blk2.get("bft_view")
                or ((qcj or {}).get("view") if isinstance(qcj, dict) else 0)
                or 0
            )
        except Exception:
            replay_view = 0
        if replay_view > 0:
            blk2["view"] = replay_view
        validators = self._active_validators()
        expected_proposer = (
            leader_for_view(validators, replay_view) if validators and replay_view >= 0 else ""
        )
        proposer = str(blk2.get("proposer") or "").strip()
        if expected_proposer and proposer != expected_proposer:
            proposer = expected_proposer
            blk2["proposer"] = proposer
        if proposer:
            proposer_pubkey = str(self._validator_pubkeys().get(proposer) or "").strip()
            if proposer_pubkey and not str(blk2.get("proposer_pubkey") or "").strip():
                blk2["proposer_pubkey"] = proposer_pubkey
        if applied >= apply_budget:
            break
        meta = self.apply_block(blk2)
        applied += 1
        if meta is None or not bool(getattr(meta, "ok", False)):
            self._drop_pending_candidate_artifacts(bid)
            made_progress = True
            continue
        self._drop_pending_candidate_artifacts(bid)
        results.append(meta)
        made_progress = True

    if not results and not made_progress and ordered_ids:
        self._pending_replay_cursor = (
            ordered_ids[(start_idx + min(scanned, len(ordered_ids)) - 1) % len(ordered_ids)]
            if scanned > 0
            else cursor
        )
    if results:
        remaining = [
            bid
            for bid in self._ordered_pending_block_ids()
            if bid and not self._has_local_block(bid)
        ]
        if remaining:
            extra = self._bft_try_apply_pending_remote_blocks_followup(
                max_extra=max(0, apply_budget - len(results))
            )
            if extra:
                results.extend(extra)
    return results

def _bft_try_apply_pending_remote_blocks_followup(
    self, *, max_extra: int
) -> list[ExecutorMeta]:
    _bind_executor_globals()
    if max_extra <= 0:
        return []
    saved = int(getattr(self, "_max_pending_replay_applies_per_call", 8) or 8)
    try:
        self._max_pending_replay_applies_per_call = max_extra
        return self.bft_try_apply_pending_remote_blocks()
    finally:
        self._max_pending_replay_applies_per_call = saved

def bft_cache_remote_block(self, block_json: Json) -> bool:
    """Cache a fetched remote block for deterministic replay.

    Returns True when the block is locally compatible and stored (or already
    present locally), else False.
    """
    _bind_executor_globals()
    if not isinstance(block_json, dict) or not block_json:
        return False
    try:
        blk, _ = ensure_block_hash(dict(block_json))
    except Exception:
        return False
    bid = str(blk.get("block_id") or "").strip()
    if not bid:
        return False
    if self._is_conflicted_block_id(bid):
        return False
    if self._block_identity_conflicts(blk):
        return False
    if self._has_local_block(bid):
        self._drop_pending_remote_artifacts(bid)
        return True
    if not self._bft_epoch_binding_matches(blk):
        return False
    qc_any = (
        blk.get("qc")
        if isinstance(blk.get("qc"), dict)
        else blk.get("justify_qc")
        if isinstance(blk.get("justify_qc"), dict)
        else None
    )
    if isinstance(qc_any, dict):
        verified_qc = self.bft_verify_qc_json(qc_any)
        if verified_qc is None:
            return False
        self._put_pending_missing_qc(verified_qc.to_json())
    self._put_pending_remote_block(block_id=bid, block=blk)
    self.bft_try_apply_pending_remote_blocks()
    return True

