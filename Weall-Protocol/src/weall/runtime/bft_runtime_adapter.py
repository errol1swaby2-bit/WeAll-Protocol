from __future__ import annotations

"""HotStuff/BFT artifact, proposal, vote, QC, timeout, and pending replay delegates.

This module is intentionally a structural extraction from ``weall.runtime.executor``.
It keeps the executor public API stable while shrinking the trusted surface area of
the monolithic facade. The extracted functions still operate on ``WeAllExecutor``
instances and intentionally preserve behavior byte-for-byte where possible.
"""


def _bind_executor_globals() -> None:
    """Lazily mirror executor globals after executor import has completed.

    The first refactor pass is deliberately behavior-preserving. Existing method
    bodies reference executor-level imports and helpers. Binding lazily avoids
    circular imports while keeping this patch focused on module boundaries rather
    than protocol semantics.
    """
    from weall.runtime import executor as _executor_mod

    for _name, _value in vars(_executor_mod).items():
        if _name not in globals():
            globals()[_name] = _value


def _restore_bft_restart_hints(self) -> None:
    _bind_executor_globals()
    try:
        info = self._bft_journal.bootstrap_state()
    except Exception:
        return
    try:
        self._bft.view = max(int(self._bft.view), int(info.get("last_view") or 0))
    except Exception:
        pass

def _bft_record_event(self, event: str, **payload: Any) -> None:
    _bind_executor_globals()
    try:
        self._bft_journal.append(event, chain_id=self.chain_id, node_id=self.node_id, **payload)
    except Exception:
        pass

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

def _bft_outbound_key(self, kind: str, payload: Json) -> str:
    _bind_executor_globals()
    try:
        if str(kind) == "vote":
            return f"vote:{int(payload.get('view') or 0)}:{str(payload.get('signer') or '')}:{str(payload.get('block_id') or '')}"
        if str(kind) == "timeout":
            return f"timeout:{int(payload.get('view') or 0)}:{str(payload.get('signer') or '')}:{str(payload.get('high_qc_id') or '')}"
        if str(kind) == "proposal":
            return f"proposal:{int(payload.get('view') or 0)}:{str(payload.get('proposer') or '')}:{str(payload.get('block_id') or '')}"
        if str(kind) == "qc":
            return f"qc:{int(payload.get('view') or 0)}:{str(payload.get('block_id') or '')}"
        return f"{str(kind)}:{_canon_json(payload)}"
    except Exception:
        return f"{str(kind)}:{repr(payload)}"

def _bft_enqueue_outbound(self, kind: str, payload: Json) -> str:
    _bind_executor_globals()
    key = self._bft_outbound_key(kind, payload)
    self._bft_record_event(
        "bft_outbound_enqueued", kind=str(kind), key=key, payload=dict(payload or {})
    )
    return key

def bft_mark_outbound_sent(self, kind: str, payload: Json) -> None:
    _bind_executor_globals()
    key = self._bft_outbound_key(kind, payload)
    self._bft_record_event("bft_outbound_sent", kind=str(kind), key=key)

def bft_pending_outbound_messages(self) -> list[Json]:
    _bind_executor_globals()
    try:
        info = self._bft_journal.bootstrap_state()
    except Exception:
        return []
    out: list[Json] = []
    for item in list(info.get("pending_outbound") or []):
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "").strip().lower()
        payload = item.get("payload")
        if kind and isinstance(payload, dict) and payload:
            out.append({"kind": kind, "payload": dict(payload)})
    return out

def _votecheck_cache_get(self, block_hash: str) -> bool | None:
    _bind_executor_globals()
    key = str(block_hash or "").strip()
    if not key:
        return None
    try:
        value = self._votecheck_cache.get(key)
        if value is None:
            return None
        _bounded_put(self._votecheck_cache, key, bool(value), cap=self._max_votecheck_cache)
        return bool(value)
    except Exception:
        return None

def _votecheck_cache_put(self, block_hash: str, ok: bool) -> None:
    _bind_executor_globals()
    key = str(block_hash or "").strip()
    if not key:
        return
    _bounded_put(self._votecheck_cache, key, bool(ok), cap=self._max_votecheck_cache)

def _proposal_votecheck_budget_ok(self, peer_id: str) -> bool:
    _bind_executor_globals()
    key = str(peer_id or "").strip() or "<unknown>"
    now_ms = _now_ms()
    entry = self._proposal_peer_budget.get(key)
    if not isinstance(entry, dict):
        entry = {"count": 0, "reset_ms": int(now_ms + self._proposal_peer_budget_window_ms)}
    reset_ms = _safe_int(
        entry.get("reset_ms"), int(now_ms + self._proposal_peer_budget_window_ms)
    )
    count = _safe_int(entry.get("count"), 0)
    if now_ms >= reset_ms:
        count = 0
        reset_ms = int(now_ms + self._proposal_peer_budget_window_ms)
    count += 1
    entry = {"count": int(count), "reset_ms": int(reset_ms)}
    _bounded_put(
        self._proposal_peer_budget, key, entry, cap=self._max_proposal_peer_budget_entries
    )
    return count <= self._proposal_peer_budget_max

def _spec_exec_paths_for_slot(self, slot: str) -> tuple[str, str]:
    _bind_executor_globals()
    root = self._spec_exec_pool_root / str(slot)
    root.mkdir(parents=True, exist_ok=True)
    db_path = str(root / "votecheck.sqlite")
    aux_path = str(root / "votecheck.aux.sqlite")
    return db_path, aux_path

def _make_spec_exec_slot(self) -> tuple[str, str]:
    _bind_executor_globals()
    slot = f"slot-{len(self._spec_exec_pool)}-{_now_ms()}"
    return self._spec_exec_paths_for_slot(slot)

def _acquire_spec_exec_slot(self) -> tuple[str, str]:
    _bind_executor_globals()
    if self._spec_exec_pool:
        return self._spec_exec_pool.pop()
    return self._make_spec_exec_slot()

def _release_spec_exec_slot(self, slot: tuple[str, str]) -> None:
    _bind_executor_globals()
    if len(self._spec_exec_pool) >= self._max_spec_exec_pool:
        return
    self._spec_exec_pool.append(slot)

def _reset_spec_exec_slot(self, slot: tuple[str, str]) -> WeAllExecutor:
    _bind_executor_globals()
    db_path, aux_path = slot
    for path in (db_path, aux_path):
        try:
            Path(path).unlink(missing_ok=True)
        except Exception:
            pass
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                Path(f"{path}{suffix}").unlink(missing_ok=True)
            except Exception:
                pass
    old_aux = os.environ.get("WEALL_AUX_DB_PATH")
    os.environ["WEALL_AUX_DB_PATH"] = str(aux_path)
    try:
        clone = WeAllExecutor(
            db_path=str(db_path),
            node_id=str(self.node_id),
            chain_id=str(self.chain_id),
            tx_index_path=str(self.tx_index_path),
        )
    finally:
        if old_aux is None:
            os.environ.pop("WEALL_AUX_DB_PATH", None)
        else:
            os.environ["WEALL_AUX_DB_PATH"] = old_aux
    return clone

def _proposal_votecheck_static_ok(self, block: Json) -> bool:
    _bind_executor_globals()
    if not isinstance(block, dict):
        return False
    header = block.get("header") if isinstance(block.get("header"), dict) else {}
    if str(header.get("chain_id") or block.get("chain_id") or "").strip() != self.chain_id:
        return False
    height = self._block_height_hint(block)
    if height <= 0:
        return False
    txs = block.get("txs")
    if not isinstance(txs, list):
        return False
    if self._max_votecheck_txs > 0 and len(txs) > self._max_votecheck_txs:
        return False
    try:
        encoded = _canon_json(block).encode("utf-8")
    except Exception:
        return False
    if self._max_votecheck_block_bytes > 0 and len(encoded) > self._max_votecheck_block_bytes:
        return False
    if self._block_identity_conflicts(block):
        return False
    helper_execution = block.get("helper_execution")
    if helper_execution is not None:
        advertised_plan_id = str(helper_execution.get("plan_id") or "") if isinstance(helper_execution, dict) else ""
        ok_helper_meta, _helper_reason = verify_block_helper_plan_metadata(
            helper_execution=helper_execution if isinstance(helper_execution, dict) else None,
            expected_plan_id=advertised_plan_id,
        )
        if not ok_helper_meta:
            return False
    return True

def _validate_remote_proposal_for_vote(self, block: Json) -> bool:
    _bind_executor_globals()
    if not isinstance(block, dict):
        return False
    try:
        block2, bh = ensure_block_hash(copy.deepcopy(block))
    except Exception:
        return False
    block_hash = str(bh or block2.get("block_hash") or "").strip()
    cached = self._votecheck_cache_get(block_hash)
    if cached is not None:
        return bool(cached)
    if not self._proposal_votecheck_static_ok(block2):
        self._votecheck_cache_put(block_hash, False)
        return False
    if self._has_local_block(str(block2.get("block_id") or "").strip()):
        self._votecheck_cache_put(block_hash, True)
        return True
    parent_id = str(block2.get("prev_block_id") or "").strip()
    if parent_id and not self._has_local_block(parent_id):
        if parent_id in self._pending_missing_fetches:
            self._votecheck_cache_put(block_hash, False)
            return False
    proposer = str(block2.get("proposer") or "").strip()
    if not self._proposal_votecheck_budget_ok(proposer):
        self._votecheck_cache_put(block_hash, False)
        return False
    acquired = self._proposal_validation_semaphore.acquire(blocking=False)
    if not acquired:
        self._votecheck_cache_put(block_hash, False)
        return False
    slot: tuple[str, str] | None = None
    try:
        slot = self._acquire_spec_exec_slot()
        clone = self._reset_spec_exec_slot(slot)
        clone.state = copy.deepcopy(self.state)
        clone._ledger_store.write(clone.state)
        clone._bft.load_from_state(clone.state)
        meta = clone.apply_block(copy.deepcopy(block2))
        ok = bool(meta.ok)
        self._votecheck_cache_put(block_hash, ok)
        return ok
    except Exception:
        self._votecheck_cache_put(block_hash, False)
        return False
    finally:
        if slot is not None:
            self._release_spec_exec_slot(slot)
        try:
            self._proposal_validation_semaphore.release()
        except Exception:
            pass

def _ensure_recent_bft_artifact_caches(self) -> None:
    _bind_executor_globals()
    if not hasattr(self, "_max_recent_bft_proposals"):
        self._max_recent_bft_proposals = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_PROPOSALS"), 2048)
        )
    if not hasattr(self, "_recent_bft_proposals") or not isinstance(
        self._recent_bft_proposals, OrderedDict
    ):
        self._recent_bft_proposals = OrderedDict()
    if not hasattr(self, "_max_recent_bft_qcs"):
        self._max_recent_bft_qcs = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_QCS"), 2048)
        )
    if not hasattr(self, "_recent_bft_qcs") or not isinstance(
        self._recent_bft_qcs, OrderedDict
    ):
        self._recent_bft_qcs = OrderedDict()
    if not hasattr(self, "_max_recent_bft_votes"):
        self._max_recent_bft_votes = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_VOTES"), 4096)
        )
    if not hasattr(self, "_recent_bft_votes") or not isinstance(
        self._recent_bft_votes, OrderedDict
    ):
        self._recent_bft_votes = OrderedDict()
    if not hasattr(self, "_max_recent_bft_timeouts"):
        self._max_recent_bft_timeouts = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_TIMEOUTS"), 4096)
        )
    if not hasattr(self, "_recent_bft_timeouts") or not isinstance(
        self._recent_bft_timeouts, OrderedDict
    ):
        self._recent_bft_timeouts = OrderedDict()
    if not hasattr(self, "_max_recent_bft_sender_budgets"):
        self._max_recent_bft_sender_budgets = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_SENDERS"), 4096)
        )
    if not hasattr(self, "_bft_sender_budget_window_ms"):
        self._bft_sender_budget_window_ms = max(
            1, _safe_int(os.environ.get("WEALL_BFT_SENDER_WINDOW_MS"), 1000)
        )
    if not hasattr(self, "_bft_sender_budget_per_window"):
        self._bft_sender_budget_per_window = max(
            1, _safe_int(os.environ.get("WEALL_BFT_SENDER_BUDGET"), 64)
        )
    if not hasattr(self, "_recent_bft_sender_budgets") or not isinstance(
        self._recent_bft_sender_budgets, OrderedDict
    ):
        self._recent_bft_sender_budgets = OrderedDict()

def _bft_sender_budget_key(self, artifact: Json) -> str:
    _bind_executor_globals()
    self._ensure_recent_bft_artifact_caches()
    if not isinstance(artifact, dict):
        return ""
    raw_sender = str(
        artifact.get("proposer")
        or artifact.get("signer")
        or artifact.get("sender")
        or artifact.get("from")
        or ""
    ).strip()
    if raw_sender:
        return raw_sender
    votes_any = artifact.get("votes")
    if isinstance(votes_any, list):
        senders: list[str] = []
        for item in votes_any:
            if not isinstance(item, dict):
                continue
            signer = str(
                item.get("signer") or item.get("sender") or item.get("from") or ""
            ).strip()
            if signer:
                senders.append(signer)
        if senders:
            senders.sort()
            return senders[0]
    return ""

def _consume_bft_sender_budget(self, artifact: Json) -> bool:
    _bind_executor_globals()
    self._ensure_recent_bft_artifact_caches()
    sender = self._bft_sender_budget_key(artifact)
    if not sender:
        return True
    now = _now_ms()
    try:
        window_start, used = self._recent_bft_sender_budgets.get(sender, (0, 0))
        if not isinstance(window_start, int):
            window_start = _safe_int(window_start, 0)
        if not isinstance(used, int):
            used = _safe_int(used, 0)
    except Exception:
        window_start, used = (0, 0)
    if (now - int(window_start)) >= int(self._bft_sender_budget_window_ms):
        window_start = now
        used = 0
    if int(used) >= int(self._bft_sender_budget_per_window):
        _bounded_put(
            self._recent_bft_sender_budgets,
            sender,
            (int(window_start), int(used)),
            cap=int(self._max_recent_bft_sender_budgets),
        )
        return False
    _bounded_put(
        self._recent_bft_sender_budgets,
        sender,
        (int(window_start), int(used) + 1),
        cap=int(self._max_recent_bft_sender_budgets),
    )
    return True

def _remember_recent_bft_proposal(self, proposal: Json) -> bool:
    _bind_executor_globals()
    self._ensure_recent_bft_artifact_caches()
    try:
        key = hashlib.sha256(_canon_json(dict(proposal)).encode("utf-8")).hexdigest()
    except Exception:
        return False
    if not key:
        return False
    if key in self._recent_bft_proposals:
        return True
    _bounded_put(
        self._recent_bft_proposals,
        key,
        _now_ms(),
        cap=int(self._max_recent_bft_proposals),
    )
    return False

def _recent_bft_qc_key(self, qcj: Json) -> str:
    _bind_executor_globals()
    self._ensure_recent_bft_artifact_caches()
    try:
        return hashlib.sha256(_canon_json(dict(qcj)).encode("utf-8")).hexdigest()
    except Exception:
        return ""

def _has_recent_bft_qc(self, qcj: Json) -> bool:
    _bind_executor_globals()
    key = self._recent_bft_qc_key(qcj)
    if not key:
        return False
    return key in self._recent_bft_qcs

def _record_recent_bft_qc(self, qcj: Json) -> None:
    _bind_executor_globals()
    key = self._recent_bft_qc_key(qcj)
    if not key:
        return
    _bounded_put(self._recent_bft_qcs, key, _now_ms(), cap=int(self._max_recent_bft_qcs))

def _remember_recent_bft_qc(self, qcj: Json) -> bool:
    _bind_executor_globals()
    if self._has_recent_bft_qc(qcj):
        return True
    self._record_recent_bft_qc(qcj)
    return False

def _remember_recent_bft_vote(self, votej: Json) -> bool:
    _bind_executor_globals()
    self._ensure_recent_bft_artifact_caches()
    try:
        key = hashlib.sha256(_canon_json(dict(votej)).encode("utf-8")).hexdigest()
    except Exception:
        return False
    if not key:
        return False
    if key in self._recent_bft_votes:
        return True
    _bounded_put(
        self._recent_bft_votes,
        key,
        _now_ms(),
        cap=int(self._max_recent_bft_votes),
    )
    return False

def _remember_recent_bft_timeout(self, timeoutj: Json) -> bool:
    _bind_executor_globals()
    self._ensure_recent_bft_artifact_caches()
    try:
        key = hashlib.sha256(_canon_json(dict(timeoutj)).encode("utf-8")).hexdigest()
    except Exception:
        return False
    if not key:
        return False
    if key in self._recent_bft_timeouts:
        return True
    _bounded_put(
        self._recent_bft_timeouts,
        key,
        _now_ms(),
        cap=int(self._max_recent_bft_timeouts),
    )
    return False

def _bft_artifact_shape_fast_fail(self, kind: str, payload: Json) -> bool:
    _bind_executor_globals()
    if not isinstance(payload, dict):
        return False

    max_field_chars = max(8, _safe_int(os.environ.get("WEALL_BFT_MAX_FIELD_CHARS"), 512))
    max_qc_votes = max(1, _safe_int(os.environ.get("WEALL_BFT_MAX_QC_VOTES_PER_ARTIFACT"), 512))

    def _str_field(name: str, *, required: bool = False, allow_empty: bool = False) -> bool:
        if name not in payload:
            return not required
        val = payload.get(name)
        if not isinstance(val, str):
            return False
        sval = val.strip()
        if not allow_empty and required and not sval:
            return False
        return len(sval) <= max_field_chars

    def _int_field(name: str, *, required: bool = False, minimum: int = 0) -> bool:
        if name not in payload:
            return not required
        val = payload.get(name)
        try:
            ival = int(val)
        except Exception:
            return False
        return ival >= minimum

    if not _str_field("chain_id", required=True):
        return False
    if str(payload.get("chain_id") or "").strip() != str(self.chain_id):
        return False

    if kind == "proposal":
        if not _str_field("block_id", required=True):
            return False
        if not _str_field("block_hash", required=True):
            return False
        if not _str_field("prev_block_id", required=False, allow_empty=True):
            return False
        if not _str_field("proposer", required=False):
            return False
        if not _int_field("view", required=True):
            return False
        if not _int_field("height", required=True):
            return False
        justify_qc = payload.get("justify_qc")
        if justify_qc is not None and not isinstance(justify_qc, dict):
            return False
        return True

    if kind == "qc":
        if not _str_field("block_id", required=True):
            return False
        if not _str_field("block_hash", required=True):
            return False
        if not _str_field("parent_id", required=False, allow_empty=True):
            return False
        if not _int_field("view", required=True):
            return False
        votes = payload.get("votes")
        if votes is not None:
            if not isinstance(votes, list):
                return False
            if len(votes) > max_qc_votes:
                return False
        return True

    if kind == "vote":
        if str(payload.get("t") or "") != "VOTE":
            return False
        for field in ("block_id", "block_hash", "signer", "pubkey", "sig"):
            if not _str_field(field, required=True):
                return False
        if not _str_field("parent_id", required=False, allow_empty=True):
            return False
        if not _int_field("view", required=True):
            return False
        if not _int_field("validator_epoch", required=False):
            return False
        return True

    if kind == "timeout":
        if str(payload.get("t") or "") != "TIMEOUT":
            return False
        for field in ("high_qc_id", "signer", "pubkey", "sig"):
            if not _str_field(field, required=True):
                return False
        if not _int_field("view", required=True):
            return False
        if not _int_field("validator_epoch", required=False):
            return False
        return True

    return False

def bft_on_proposal(self, proposal: Json) -> Json | None:
    """Handle a leader proposal.

    Returns a vote JSON if we should vote, else None.
    """
    _bind_executor_globals()
    if not isinstance(proposal, dict):
        return None

    # Canonicalize network proposal shape: accept either a raw block dict
    # or an envelope {view, proposer, block, justify_qc}.
    try:
        raw_block = (
            proposal.get("block") if isinstance(proposal.get("block"), dict) else proposal
        )
        proposal2 = dict(raw_block)
        embedded_qc = proposal2.get("qc") if isinstance(proposal2.get("qc"), dict) else None
        original_block_id = str(proposal2.get("block_id") or "").strip()
        original_prev_block_id = str(proposal2.get("prev_block_id") or "").strip()
        if "view" not in proposal2 and "view" in proposal:
            proposal2["view"] = proposal.get("view")
        if "proposer" not in proposal2 and "proposer" in proposal:
            proposal2["proposer"] = proposal.get("proposer")
        if "justify_qc" not in proposal2 and isinstance(proposal.get("justify_qc"), dict):
            proposal2["justify_qc"] = proposal.get("justify_qc")
        if "chain_id" not in proposal2 or not str(proposal2.get("chain_id") or "").strip():
            proposal2["chain_id"] = str(self.chain_id)
        header2 = proposal2.get("header") if isinstance(proposal2.get("header"), dict) else {}
        if (
            "height" not in proposal2
            and isinstance(header2, dict)
            and header2.get("height") is not None
        ):
            proposal2["height"] = header2.get("height")
        if (
            "block_ts_ms" not in proposal2
            and isinstance(header2, dict)
            and header2.get("block_ts_ms") is not None
        ):
            proposal2["block_ts_ms"] = header2.get("block_ts_ms")
        proposal2.pop("qc", None)
        proposal2, proposal_block_hash = ensure_block_hash(proposal2)
        proposal2["block_hash"] = str(proposal_block_hash)
    except Exception:
        return None

    bid = str(proposal2.get("block_id") or "").strip()
    if not bid:
        hdr = proposal2.get("header") if isinstance(proposal2.get("header"), dict) else {}
        bid = compute_block_id(
            chain_id=str(hdr.get("chain_id") or self.chain_id),
            height=int(hdr.get("height") or proposal2.get("height") or 0),
            prev_block_id=str(proposal2.get("prev_block_id") or self.state.get("tip") or ""),
            prev_block_hash=str(
                hdr.get("prev_block_hash") or proposal2.get("prev_block_hash") or ""
            ),
            ts_ms=int(hdr.get("block_ts_ms") or proposal2.get("block_ts_ms") or 0),
            node_id=str(proposal2.get("proposer") or proposal.get("proposer") or ""),
            tx_ids=[str(x) for x in (hdr.get("tx_ids") or [])] if isinstance(hdr, dict) else [],
            receipts_root=str(hdr.get("receipts_root") or ""),
        )
        proposal2["block_id"] = bid

    try:
        view = int(
            proposal2.get("view") or proposal2.get("bft_view") or proposal.get("view") or 0
        )
    except Exception:
        view = 0
    proposal2["view"] = int(view)
    if not self._bft_artifact_shape_fast_fail("proposal", proposal2):
        return None
    if self._remember_recent_bft_proposal(proposal2):
        return None
    if not self._consume_bft_sender_budget(proposal2):
        return None

    validators = self._active_validators()
    expected_leader = leader_for_view(validators, view) if validators else ""
    proposer = str(proposal2.get("proposer") or "").strip()
    require_sig = (_mode() == "prod") and _env_bool("WEALL_SIGVERIFY", True)

    if not self._bft_payload_phase_matches_current_security_model(proposal2):
        return None
    if not self._bft_epoch_binding_matches(proposal2):
        return None
    if self._is_conflicted_block_id(bid):
        return None
    if self._block_identity_conflicts(proposal2):
        return None

    # Retain the remote block in a quarantine cache once its epoch/set-hash are
    # locally compatible. Only promote it into the validated pending-remote set
    # after signature and block admission checks pass.
    if bid:
        self._quarantine_remote_block(proposal2)
    justify_qc_any = proposal2.get("justify_qc")
    explicit_justify_qc = justify_qc_any if isinstance(justify_qc_any, dict) else None
    verified_qc: QuorumCert | None = None
    verified_qc_json: Json | None = None
    embedded_qc_is_self = False
    embedded_qc_is_parent_justify = False
    if explicit_justify_qc is not None:
        verified_qc = self.bft_verify_qc_json(explicit_justify_qc)
        if verified_qc is None:
            self.bft_try_apply_pending_remote_blocks()
            return None
        verified_qc_json = verified_qc.to_json()
        proposal2["justify_qc"] = dict(verified_qc_json)
    elif isinstance(embedded_qc, dict):
        verified_qc = self.bft_verify_qc_json(embedded_qc)
        if verified_qc is None:
            self.bft_try_apply_pending_remote_blocks()
            return None
        verified_qc_json = verified_qc.to_json()
        qc_block_id = str(verified_qc.block_id or "").strip()
        qc_parent_id = str(verified_qc.parent_id or "").strip()
        effective_block_id = str(proposal2.get("block_id") or original_block_id or "").strip()
        effective_prev_block_id = str(
            proposal2.get("prev_block_id") or original_prev_block_id or ""
        ).strip()
        embedded_qc_is_self = bool(
            qc_block_id and effective_block_id and qc_block_id == effective_block_id
        )
        embedded_qc_is_parent_justify = bool(
            qc_block_id and effective_prev_block_id and qc_block_id == effective_prev_block_id
        )
        if embedded_qc_is_parent_justify:
            proposal2["justify_qc"] = dict(verified_qc_json)
        elif (
            not embedded_qc_is_self
            and qc_parent_id
            and effective_prev_block_id
            and qc_parent_id == effective_prev_block_id
        ):
            proposal2["justify_qc"] = dict(verified_qc_json)
            embedded_qc_is_parent_justify = True

    if not proposer and not require_sig and expected_leader:
        proposal2["proposer"] = expected_leader
        proposer = expected_leader
    if expected_leader and proposer and proposer != expected_leader:
        validator_set = set(validators)
        if proposer not in validator_set or require_sig:
            if bid:
                self._drop_quarantined_remote_artifacts(bid)
            self.bft_try_apply_pending_remote_blocks()
            return None

    # Enforce signed leader-authored proposals in normal/prod verification modes,
    # while preserving legacy dev/test paths when signature verification is disabled.
    has_proposal_sig = bool(str(proposal2.get("proposer_sig") or "").strip())
    has_proposal_pub = bool(str(proposal2.get("proposer_pubkey") or "").strip())
    if require_sig or has_proposal_sig or has_proposal_pub:
        if not verify_proposal_json(
            proposal=proposal2,
            validators=validators,
            vpub=self._validator_pubkeys(),
            expected_leader=expected_leader,
        ):
            self.bft_try_apply_pending_remote_blocks()
            return None

    has_embedded_commit_qc_only = (
        explicit_justify_qc is None
        and isinstance(embedded_qc, dict)
        and not embedded_qc_is_parent_justify
    )
    if not has_embedded_commit_qc_only:
        ok, _rej = _call_admit_bft_block(
            block=proposal2,
            state=self.state,
            bft_enabled=effective_bft_enabled(executor=self, default=False),
        )
        if not ok:
            self.bft_try_apply_pending_remote_blocks()
            return None

    if bid and isinstance(verified_qc_json, dict):
        self._put_pending_missing_qc(verified_qc_json)
        if verified_qc is not None:
            # Observe verified proposal-carried or embedded committed-block QC before replay.
            self._bft.observe_qc(blocks=self.state.get("blocks") or {}, qc=verified_qc)
    self._promote_quarantined_remote_block(bid, block=proposal2)
    self.bft_try_apply_pending_remote_blocks()

    if has_embedded_commit_qc_only:
        return None

    if not _env_bool("WEALL_AUTOVOTE", False):
        return None

    if not self._validate_remote_proposal_for_vote(proposal2):
        return None

    self._bft.bump_view(view)

    parent_id = str(proposal2.get("prev_block_id") or "").strip()
    if not parent_id:
        parent_id = str(self.state.get("tip") or "").strip()

    blocks_map = self.state.get("blocks")
    if not isinstance(blocks_map, dict):
        blocks_map = {}
    else:
        blocks_map = dict(blocks_map)
    blocks_map[bid] = {
        "height": int(proposal2.get("height") or 0),
        "prev_block_id": parent_id,
        "block_ts_ms": _safe_int(
            (
                (proposal2.get("header") or {})
                if isinstance(proposal2.get("header"), dict)
                else {}
            ).get("block_ts_ms")
            or proposal2.get("block_ts_ms"),
            0,
        ),
        "block_hash": str(proposal2.get("block_hash") or "").strip(),
    }

    justify_qc = (
        qc_from_json(proposal2.get("justify_qc"))
        if isinstance(proposal2.get("justify_qc"), dict)
        else None
    )
    if not self._bft.can_vote_for(blocks=blocks_map, block_id=bid, justify_qc=justify_qc):
        self._drop_quarantined_remote_artifacts(bid)
        try:
            self._drop_pending_candidate_artifacts(bid)
        except Exception:
            self._pending_remote_blocks.pop(str(bid or ""), None)
        if isinstance(verified_qc_json, dict):
            rejected_qc_bid = str(verified_qc_json.get("block_id") or "").strip()
            rejected_qc_bh = str(verified_qc_json.get("block_hash") or "").strip()
            if rejected_qc_bid:
                self._pending_missing_qcs.pop(rejected_qc_bid, None)
            if rejected_qc_bh and hasattr(self, "_pending_missing_qcs_by_hash"):
                self._pending_missing_qcs_by_hash.pop(rejected_qc_bh, None)
        return None

    block_hash = str(proposal2.get("block_hash") or "").strip()
    if not block_hash:
        return None

    votej = self.bft_make_vote_for_block(
        view=view, block_id=bid, block_hash=block_hash, parent_id=parent_id
    )
    if not isinstance(votej, dict) or not votej:
        return None

    if not self._bft.record_local_vote(view=view, block_id=bid):
        return None
    self._bft.last_progress_ms = _now_ms()
    self._persist_bft_state()
    self._bft_enqueue_outbound("vote", votej)
    return votej

def bft_on_vote(self, vote: Json) -> Json | None:
    """Handle a vote and return a QC JSON if one was formed."""
    _bind_executor_globals()
    qc = self.bft_handle_vote(vote)
    return qc.to_json() if qc is not None else None

def bft_on_qc(self, qcj: Json) -> ExecutorMeta | None:
    """Handle a QC and commit if it refers to a known block."""
    _bind_executor_globals()
    if not isinstance(qcj, dict):
        return None
    if not self._bft_artifact_shape_fast_fail("qc", qcj):
        return None
    if self._has_recent_bft_qc(qcj):
        return None
    if not self._consume_bft_sender_budget(qcj):
        return None
    qc = self.bft_verify_qc_json(qcj)
    if qc is None:
        return None
    self._record_recent_bft_qc(qcj)

    # Observe first.
    self.bft_handle_qc(qcj)

    bid = str(qc.block_id)
    block_hash = str(qc.block_hash or "").strip()

    # Cache the QC, update BFT state, and only apply once the finalized frontier advances.
    meta = self.bft_commit_if_ready(qc)
    if meta is not None:
        return meta

    resolved_bid, blk = self._resolve_pending_block_identity(
        block_id=bid, block_hash=block_hash
    )
    if not isinstance(blk, dict):
        self._put_pending_missing_qc(qc.to_json())
        self.bft_try_apply_pending_remote_blocks()
        return None

    if resolved_bid and resolved_bid != bid:
        qcj = qc.to_json()
        qcj["block_id"] = resolved_bid
        self._put_pending_missing_qc(qcj)
    else:
        self._put_pending_missing_qc(qc.to_json())
    metas = self.bft_try_apply_pending_remote_blocks()
    if metas:
        return metas[-1]
    return None

def bft_on_timeout(self, timeoutj: Json) -> Json | None:
    """Handle a timeout and return a QC JSON if one was formed."""
    _bind_executor_globals()
    qc = self.bft_handle_timeout(timeoutj)
    return qc.to_json() if qc is not None else None

def bft_drive_timeouts(self, now_ms: int) -> list[Json]:
    """Return any timeout messages we should broadcast."""
    _bind_executor_globals()
    if not _env_bool("WEALL_AUTOTIMEOUT", False):
        return []
    try:
        local = self._local_validator_account()
        validators = self._active_validators()
        if local not in set(validators):
            return []
        view = int(self._bft.view)
        if leader_for_view(validators, view) == local:
            return []
        # If we believe we're not the leader and haven't seen progress, emit a timeout.
        # HotStuffBFT itself doesn't know wall clock; this is a minimal adapter.
        t = self.bft_make_timeout(view=view)
        return [t] if isinstance(t, dict) else []
    except Exception:
        return []

def _active_validators(self) -> list[str]:
    """Return the consensus validator set, with role-set fallback only for legacy states.

    ROLE_VALIDATOR_ACTIVATE records validator-role eligibility. It must not be
    enough, by itself, to make a node a consensus signer. The explicit
    consensus validator-set object created by VALIDATOR_SET_UPDATE is the
    authoritative production source. The role active_set fallback remains only
    for older tests/persisted states that predate the consensus validator_set.
    """
    _bind_executor_globals()
    st = getattr(self, "state", {})
    if not isinstance(st, dict):
        st = {}
    c = st.get("consensus")
    if isinstance(c, dict):
        vs = c.get("validator_set")
        if isinstance(vs, dict) and isinstance(vs.get("active_set"), list):
            out: list[str] = []
            seen: set[str] = set()
            for x in vs.get("active_set") or []:
                s = str(x).strip()
                if s and s not in seen:
                    seen.add(s)
                    out.append(s)
            return normalize_validators(out)
    roles = st.get("roles")
    if isinstance(roles, dict):
        v = roles.get("validators")
        if isinstance(v, dict) and isinstance(v.get("active_set"), list):
            out2: list[str] = []
            seen2: set[str] = set()
            for x in v.get("active_set") or []:
                s = str(x).strip()
                if s and s not in seen2:
                    seen2.add(s)
                    out2.append(s)
            return normalize_validators(out2)
    return []

def _validator_pubkeys(self) -> dict[str, str]:
    _bind_executor_globals()
    out: dict[str, str] = {}
    c = self.state.get("consensus")
    if not isinstance(c, dict):
        return out
    v = c.get("validators")
    if not isinstance(v, dict):
        return out
    reg = v.get("registry")
    if not isinstance(reg, dict):
        return out
    for acct, rec in reg.items():
        if not isinstance(rec, dict):
            continue
        pk = str(rec.get("pubkey") or "").strip()
        if pk:
            out[str(acct).strip()] = pk
    return out

def _current_validator_epoch(self) -> int:
    _bind_executor_globals()
    c = self.state.get("consensus")
    if isinstance(c, dict):
        ep = c.get("epochs")
        if isinstance(ep, dict):
            cur = _safe_int(ep.get("current"), 0)
            if cur > 0:
                return cur
        vs = c.get("validator_set")
        if isinstance(vs, dict):
            cur2 = _safe_int(vs.get("epoch"), 0)
            if cur2 > 0:
                return cur2
    return 0

def _current_validator_set_hash(self) -> str:
    _bind_executor_globals()
    c = self.state.get("consensus")
    if isinstance(c, dict):
        vs = c.get("validator_set")
        if isinstance(vs, dict):
            have = str(vs.get("set_hash") or "").strip()
            if have:
                return have
    vals = normalize_validators(self._active_validators())
    return validator_set_hash(vals) if vals else ""

def _current_consensus_phase(self) -> str:
    _bind_executor_globals()
    c = self.state.get("consensus")
    phase_raw = ""
    if isinstance(c, dict):
        phase_root = c.get("phase")
        if isinstance(phase_root, dict):
            phase_raw = str(phase_root.get("current") or "").strip()
    active_count = len(self._active_validators())
    if phase_raw:
        return normalize_consensus_phase(phase_raw, validator_count=active_count)

    # Back-compat fallback for older persisted states/tests that predate the
    # committed consensus phase field. Large validator sets historically implied
    # active BFT semantics even before the phase field existed.
    if active_count >= int(BFT_MIN_VALIDATORS):
        return CONSENSUS_PHASE_BFT_ACTIVE
    return normalize_consensus_phase("", validator_count=active_count)

def _bft_phase_allows_artifact_processing(self) -> bool:
    # Pre-phase legacy/dev/test states still rely on BFT artifacts, so only the
    # explicit committed bootstrap phases in production suppress vote/timeout/QC
    # processing. Non-production modes retain their historical behavior.
    _bind_executor_globals()
    if _mode() != "prod":
        return True
    return self._current_consensus_phase() == CONSENSUS_PHASE_BFT_ACTIVE

def _pending_consensus_phase(self) -> str:
    _bind_executor_globals()
    c = self.state.get("consensus")
    pending_phase = ""
    active_count = len(self._active_validators())
    if isinstance(c, dict):
        phase_root = c.get("phase")
        if isinstance(phase_root, dict):
            pending = phase_root.get("pending")
            if isinstance(pending, dict):
                pending_phase = str(pending.get("phase") or "").strip()
        vs = c.get("validator_set")
        if isinstance(vs, dict):
            pending_vs = vs.get("pending")
            if isinstance(pending_vs, dict):
                active_count = len(
                    normalize_validators(
                        [
                            str(x).strip()
                            for x in (pending_vs.get("active_set") or [])
                            if str(x).strip()
                        ]
                    )
                )
                if not pending_phase:
                    pending_phase = str(pending_vs.get("phase") or "").strip()
    if not pending_phase:
        return ""
    return normalize_consensus_phase(pending_phase, validator_count=active_count)

def _bft_payload_phase_matches_current_security_model(self, payload: Json) -> bool:
    _bind_executor_globals()
    if not isinstance(payload, dict):
        return False
    payload_phase = str(payload.get("consensus_phase") or "").strip()
    current_phase = self._current_consensus_phase()
    if payload_phase:
        normalized_payload_phase = normalize_consensus_phase(
            payload_phase, validator_count=len(self._active_validators())
        )
        if normalized_payload_phase != current_phase:
            return False
    if _mode() != "prod":
        return True
    if current_phase != CONSENSUS_PHASE_BFT_ACTIVE:
        return False
    return True

def _bft_payload_phase_is_cache_compatible(self, payload: Json) -> bool:
    """Return True when a pending artifact may be cached for diagnostics/lookups.

    In production bootstrap phases we still want to retain unlabeled remote
    block artifacts for deterministic identity tracking, fetch diagnostics,
    and conflict detection. What must stay disabled there is *BFT artifact
    processing* (vote / timeout / QC acceptance and catch-up replay), not the
    ability to remember a fetched block. Explicitly phase-labeled artifacts
    must still match the committed security model.
    """
    _bind_executor_globals()
    if not isinstance(payload, dict):
        return False
    payload_phase = str(payload.get("consensus_phase") or "").strip()
    if not payload_phase:
        return True
    current_phase = self._current_consensus_phase()
    normalized_payload_phase = normalize_consensus_phase(
        payload_phase, validator_count=len(self._active_validators())
    )
    return normalized_payload_phase == current_phase

def _validator_epoch(self) -> tuple[int, str]:
    """Back-compat helper used by existing tests/batches."""
    _bind_executor_globals()
    return (self._current_validator_epoch(), self._current_validator_set_hash())

def _bft_strict_epoch_binding_enabled(self) -> bool:
    _bind_executor_globals()
    raw = os.environ.get("WEALL_BFT_STRICT_EPOCH_BINDING")
    if raw is not None:
        return str(raw).strip().lower() in {"1", "true", "yes", "y", "on"}
    return (os.environ.get("WEALL_MODE") or "prod").strip().lower() == "prod"

def _bft_epoch_binding_matches(self, payload: Json) -> bool:
    _bind_executor_globals()
    if not isinstance(payload, dict):
        return False
    local_epoch = self._current_validator_epoch()
    local_set_hash = self._current_validator_set_hash()
    if local_epoch <= 0:
        return True
    payload_epoch = _safe_int(payload.get("validator_epoch"), 0)
    payload_set_hash = str(payload.get("validator_set_hash") or "").strip()
    if self._bft_strict_epoch_binding_enabled():
        if payload_epoch != local_epoch:
            return False
        if not payload_set_hash or payload_set_hash != local_set_hash:
            return False
        return True
    if payload_epoch > 0 and payload_epoch != local_epoch:
        return False
    if payload_set_hash and payload_set_hash != local_set_hash:
        return False
    return True

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

def _local_validator_account(self) -> str:
    _bind_executor_globals()
    registry = self._validator_pubkeys()
    env_pubkey = str(os.environ.get("WEALL_NODE_PUBKEY") or "").strip()
    configured = str(os.environ.get("WEALL_VALIDATOR_ACCOUNT") or "").strip()
    if configured:
        if configured in set(self._active_validators()):
            expected = str(registry.get(configured) or "").strip()
            if not expected or not env_pubkey or expected == env_pubkey:
                return configured
        return ""
    if env_pubkey:
        for acct, pk in registry.items():
            if str(pk or "").strip() == env_pubkey and acct in set(self._active_validators()):
                return str(acct).strip()
    local = str(self.node_id or "").strip()
    if local and local in set(self._active_validators()):
        expected = str(registry.get(local) or "").strip()
        if not expected or not env_pubkey or expected == env_pubkey:
            return local
    return ""

def _local_validator_identity(self) -> tuple[str, str, str]:
    _bind_executor_globals()
    signer = self._local_validator_account()
    pubkey = str(os.environ.get("WEALL_NODE_PUBKEY") or "").strip()
    privkey = str(os.environ.get("WEALL_NODE_PRIVKEY") or "").strip()
    if not signer or not pubkey or not privkey:
        return ("", "", "")
    expected = str(self._validator_pubkeys().get(signer) or "").strip()
    if expected and expected != pubkey:
        return ("", "", "")
    return (signer, pubkey, privkey)

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

def _committed_chain_recent_timestamps_ms(self, *, limit: int = 11) -> list[int]:
    _bind_executor_globals()
    try:
        blocks_map = self.state.get("blocks")
        if not isinstance(blocks_map, dict):
            return []
        cur = str(self.state.get("tip") or "").strip()
        out: list[int] = []
        seen = set()
        while cur and cur not in seen and len(out) < max(1, int(limit)):
            seen.add(cur)
            meta = blocks_map.get(cur)
            if not isinstance(meta, dict):
                break
            ts_ms = _safe_int(meta.get("block_ts_ms"), 0)
            if ts_ms > 0:
                out.append(int(ts_ms))
            cur = str(meta.get("prev_block_id") or "").strip()
        return out
    except Exception:
        return []

def committed_chain_median_time_past_ms(self, *, limit: int = 11) -> int:
    _bind_executor_globals()
    vals = sorted(self._committed_chain_recent_timestamps_ms(limit=limit))
    if not vals:
        return _safe_int(self.state.get("tip_ts_ms") or self.state.get("last_block_ts_ms"), 0)
    return int(vals[len(vals) // 2])

def chain_time_floor_ms(self) -> int:
    _bind_executor_globals()
    tip_ts_ms = _safe_int(self.state.get("tip_ts_ms") or self.state.get("last_block_ts_ms"), 0)
    mtp_ms = self.committed_chain_median_time_past_ms()
    return max(int(tip_ts_ms), int(mtp_ms))

def bft_diagnostics(self) -> Json:
    _bind_executor_globals()
    pending_pruned = self._prune_pending_bft_artifacts()
    pending_remote_blocks = self._ordered_pending_block_ids()
    pending_remote_block_hashes = [
        _block_hash_from_any(self._bft_pending_block_json(bid) or {})
        for bid in pending_remote_blocks
        if _block_hash_from_any(self._bft_pending_block_json(bid) or {})
    ]
    pending_block_identity_descriptors = []
    for bid in pending_remote_blocks:
        blk = self._bft_pending_block_json(bid) or {}
        if not isinstance(blk, dict):
            continue
        pending_block_identity_descriptors.append(
            {
                "block_id": str(bid or "").strip(),
                "block_hash": _block_hash_from_any(blk),
                "height": int(self._block_height_hint(blk) or 0),
            }
        )
    pending_missing_qc_entries = self._pending_missing_qc_entries()
    pending_missing_qcs = list(pending_missing_qc_entries.keys())
    pending_missing_qc_block_hashes = []
    for qcj in list(pending_missing_qc_entries.values()):
        if isinstance(qcj, dict):
            bh = str(qcj.get("block_hash") or "").strip()
            if bh:
                pending_missing_qc_block_hashes.append(bh)
    pending_fetch_requests = self.bft_pending_fetch_requests()
    pending_fetch_request_descriptors = self.bft_pending_fetch_request_descriptors()
    pending_fetch_request_hashes = [
        str(d.get("block_hash") or "").strip()
        for d in pending_fetch_request_descriptors
        if isinstance(d, dict) and str(d.get("block_hash") or "").strip()
    ]
    pending_candidates = [
        bid for bid in pending_remote_blocks if bid in self._pending_candidates
    ]
    pending_candidate_block_hashes = [
        _block_hash_from_any(self._bft_pending_block_json(bid) or {})
        for bid in pending_candidates
        if _block_hash_from_any(self._bft_pending_block_json(bid) or {})
    ]
    quarantined_remote_blocks = [
        str(bid or "").strip()
        for bid in list(self._quarantined_remote_blocks.keys())
        if str(bid or "").strip()
    ]
    quarantined_remote_block_hashes = [
        _block_hash_from_any(self._quarantined_remote_blocks.get(bid) or {})
        for bid in quarantined_remote_blocks
        if _block_hash_from_any(self._quarantined_remote_blocks.get(bid) or {})
    ]
    conflicted_block_ids = list(self._conflicted_block_ids.keys())
    conflicted_block_hashes = list(self._conflicted_block_hashes.keys())
    finalized_block_id = str(self._bft.finalized_block_id or "")
    tip = str(self.state.get("tip") or "").strip()
    tip_height = _safe_int(self.state.get("height"), 0)
    finalized_height = _safe_int(
        (self.state.get("finalized") or {}).get("height")
        if isinstance(self.state.get("finalized"), dict)
        else 0,
        0,
    )
    tip_ts_ms = _safe_int(self.state.get("tip_ts_ms") or self.state.get("last_block_ts_ms"), 0)
    median_time_past_ms = int(self.committed_chain_median_time_past_ms())
    chain_time_floor_ms = int(max(tip_ts_ms, median_time_past_ms))
    proposed_next_ts_ms = max(1, int(chain_time_floor_ms) + 1)
    now_ms = _now_ms()
    clock_skew_ahead_ms = max(0, int(tip_ts_ms) - int(now_ms)) if tip_ts_ms > 0 else 0
    clock_skew_warning = (
        bool(clock_skew_ahead_ms >= int(CLOCK_SKEW_WARN_MS)) if tip_ts_ms > 0 else False
    )

    stalled = False
    stall_reason = "idle"
    if pending_fetch_requests:
        stalled = True
        stall_reason = "waiting_for_parent"
    elif pending_missing_qcs:
        stalled = True
        stall_reason = "waiting_for_qc"
    elif pending_remote_blocks or pending_candidates:
        stalled = True
        stall_reason = (
            "waiting_for_finalized_descendant_apply"
            if finalized_block_id
            else "waiting_for_finalization"
        )
    elif _mode() == "prod" and finalized_block_id and tip and finalized_block_id != tip:
        stall_reason = "tip_not_finalized_yet"

    return {
        "view": int(self._bft.view),
        "high_qc_id": str(self._bft.high_qc.block_id if self._bft.high_qc is not None else ""),
        "locked_qc_id": str(
            self._bft.locked_qc.block_id if self._bft.locked_qc is not None else ""
        ),
        "finalized_block_id": finalized_block_id,
        "tip_block_id": tip,
        "tip_height": int(tip_height),
        "finalized_height": int(finalized_height),
        "pending_remote_blocks": pending_remote_blocks,
        "pending_remote_blocks_count": int(len(pending_remote_blocks)),
        "pending_remote_block_hashes": pending_remote_block_hashes,
        "pending_remote_block_hashes_count": int(len(pending_remote_block_hashes)),
        "pending_block_identity_descriptors": pending_block_identity_descriptors,
        "pending_candidates": pending_candidates,
        "pending_candidates_count": int(len(pending_candidates)),
        "pending_candidate_block_hashes": pending_candidate_block_hashes,
        "pending_candidate_block_hashes_count": int(len(pending_candidate_block_hashes)),
        "quarantined_remote_blocks": quarantined_remote_blocks,
        "quarantined_remote_blocks_count": int(len(quarantined_remote_blocks)),
        "quarantined_remote_block_hashes": quarantined_remote_block_hashes,
        "quarantined_remote_block_hashes_count": int(len(quarantined_remote_block_hashes)),
        "votecheck_concurrency_limit": int(self._proposal_validation_limit),
        "votecheck_spec_exec_pool_size": int(len(self._spec_exec_pool)),
        "votecheck_peer_budget_entries": int(len(self._proposal_peer_budget)),
        "pending_missing_qcs": pending_missing_qcs,
        "pending_missing_qcs_count": int(len(pending_missing_qcs)),
        "pending_missing_qc_block_hashes": pending_missing_qc_block_hashes,
        "pending_missing_qc_block_hashes_count": int(len(pending_missing_qc_block_hashes)),
        "pending_fetch_requests": pending_fetch_requests,
        "pending_fetch_requests_count": int(len(pending_fetch_requests)),
        "pending_fetch_request_descriptors": pending_fetch_request_descriptors,
        "pending_fetch_request_hashes": pending_fetch_request_hashes,
        "pending_fetch_request_hashes_count": int(len(pending_fetch_request_hashes)),
        "conflicted_block_ids": conflicted_block_ids,
        "conflicted_block_ids_count": int(len(conflicted_block_ids)),
        "conflicted_block_hashes": conflicted_block_hashes,
        "conflicted_block_hashes_count": int(len(conflicted_block_hashes)),
        "known_block_hash_cache_count": int(len(self._known_block_hashes)),
        "pending_artifacts_pruned": bool(pending_pruned),
        "pacemaker_timeout_ms": int(self._bft.pacemaker_timeout_ms()),
        "stalled": bool(stalled),
        "stall_reason": stall_reason,
        "tip_ts_ms": int(tip_ts_ms),
        "median_time_past_ms": int(median_time_past_ms),
        "chain_time_floor_ms": int(chain_time_floor_ms),
        "proposed_next_ts_ms": int(proposed_next_ts_ms),
        "timestamp_rule": "chain_time_successor_only",
        "uses_wall_clock_future_guard": False,
        "clock_skew_ahead_ms": int(clock_skew_ahead_ms),
        "clock_skew_warning": bool(clock_skew_warning),
        "protocol_profile_hash": str(
            (
                (self.state.get("meta") or {})
                if isinstance(self.state.get("meta"), dict)
                else {}
            ).get("production_consensus_profile_hash")
            or ""
        ),
        "schema_version": str(
            (
                (self.state.get("meta") or {})
                if isinstance(self.state.get("meta"), dict)
                else {}
            ).get("schema_version")
            or ""
        ),
        "tx_index_hash": str(
            (
                (self.state.get("meta") or {})
                if isinstance(self.state.get("meta"), dict)
                else {}
            ).get("tx_index_hash")
            or ""
        ),
        "reputation_scale": int(
            _safe_int(
                (
                    (
                        (self.state.get("meta") or {})
                        if isinstance(self.state.get("meta"), dict)
                        else {}
                    ).get("reputation_scale")
                ),
                REPUTATION_SCALE,
            )
        ),
        "max_block_future_drift_ms": int(
            _safe_int(
                (
                    (
                        (self.state.get("meta") or {})
                        if isinstance(self.state.get("meta"), dict)
                        else {}
                    ).get("max_block_future_drift_ms")
                ),
                MAX_BLOCK_FUTURE_DRIFT_MS,
            )
        ),
        "max_block_time_advance_ms": int(MAX_BLOCK_TIME_ADVANCE_MS),
        "clock_skew_warn_ms": int(
            _safe_int(
                (
                    (
                        (self.state.get("meta") or {})
                        if isinstance(self.state.get("meta"), dict)
                        else {}
                    ).get("clock_skew_warn_ms")
                ),
                CLOCK_SKEW_WARN_MS,
            )
        ),
        "startup_clock_sanity_required": bool(
            (
                (self.state.get("meta") or {})
                if isinstance(self.state.get("meta"), dict)
                else {}
            ).get(
                "startup_clock_sanity_required",
                PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required,
            )
        ),
        "startup_clock_hard_fail_ms": int(
            _safe_int(
                (
                    (
                        (self.state.get("meta") or {})
                        if isinstance(self.state.get("meta"), dict)
                        else {}
                    ).get("startup_clock_hard_fail_ms")
                ),
                STARTUP_CLOCK_HARD_FAIL_MS,
            )
        ),
        "clock_warning": (
            (
                (self.state.get("meta") or {})
                if isinstance(self.state.get("meta"), dict)
                else {}
            ).get("clock_warning")
            if isinstance(
                (
                    (
                        (self.state.get("meta") or {})
                        if isinstance(self.state.get("meta"), dict)
                        else {}
                    ).get("clock_warning")
                ),
                dict,
            )
            else None
        ),
        "helper_execution_profile": _sanitize_helper_execution_profile(
            (
                (self.state.get("meta") or {})
                if isinstance(self.state.get("meta"), dict)
                else {}
            ).get("helper_execution_profile")
            or self._requested_helper_execution_profile()
        ),
        "helper_execution_profile_hash": str(
            (
                (self.state.get("meta") or {})
                if isinstance(self.state.get("meta"), dict)
                else {}
            ).get("helper_execution_profile_hash")
            or _helper_execution_profile_hash(self._requested_helper_execution_profile())
        ),
        "validator_signing_enabled": bool(self.validator_signing_enabled()),
        "observer_mode": bool(self.observer_mode()),
        "signing_block_reason": str(self._effective_signing_block_reason() or ""),
        "last_shutdown_clean": bool(
            (
                (self.state.get("meta") or {})
                if isinstance(self.state.get("meta"), dict)
                else {}
            ).get("last_shutdown_clean", True)
        ),
        "recent_rejection_summary": self.bft_recent_rejection_summary(limit=25),
        "journal_tail": self._bft_journal.read_tail(limit=25),
    }

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

def bft_recent_rejection_summary(self, *, limit: int = 25) -> Json:
    _bind_executor_globals()
    tail = list(self._bft_journal.read_tail(limit=max(1, int(limit) * 4)) or [])
    items: list[Json] = []
    by_reason: dict[str, int] = {}
    by_message_type: dict[str, int] = {}
    latest: Json | None = None
    for item in reversed(tail):
        if not isinstance(item, dict) or str(item.get("event") or "") != "bft_message_rejected":
            continue
        payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
        reason = str(payload.get("reason") or item.get("reason") or "")
        mtype = str(payload.get("message_type") or item.get("message_type") or "")
        summary = (
            dict(payload.get("summary") or item.get("summary") or {})
            if isinstance(payload.get("summary") or item.get("summary"), dict)
            else {}
        )
        by_reason[reason] = int(by_reason.get(reason, 0)) + 1
        by_message_type[mtype] = int(by_message_type.get(mtype, 0)) + 1
        rec = {
            "message_type": mtype,
            "reason": reason,
            "summary": summary,
            "ts_ms": int(item.get("ts_ms") or 0),
        }
        items.append(rec)
        if latest is None:
            latest = {
                "ts_ms": rec["ts_ms"],
                "message_type": mtype,
                "reason": reason,
                **summary,
            }
        if len(items) >= int(limit):
            break
    return {
        "items": items,
        "count": len(items),
        "by_reason": by_reason,
        "by_message_type": by_message_type,
        "latest": latest or {},
    }

def bft_current_view(self) -> int:
    _bind_executor_globals()
    return int(self._bft.view)

def bft_current_validator_epoch(self) -> int:
    _bind_executor_globals()
    return int(self._current_validator_epoch())

def bft_current_validator_set_hash(self) -> str:
    _bind_executor_globals()
    return str(self._current_validator_set_hash() or "").strip()

def bft_set_view(self, view: int) -> None:
    _bind_executor_globals()
    requested = int(view)
    current = int(self._bft.view)
    if requested > current:
        self._bft.view = requested
    self._persist_bft_state()

def _prune_bft_liveness_caches_for_current_epoch(self) -> None:
    _bind_executor_globals()
    local_epoch = int(self._current_validator_epoch())
    local_set_hash = (
        str(self._current_validator_set_hash() or "").strip() if local_epoch > 0 else ""
    )
    if local_epoch <= 0:
        return
    try:
        pruned_votes = {}
        for key, bucket in list(getattr(self._bft, "_votes", {}).items()):
            if not isinstance(bucket, dict):
                continue
            kept = {}
            for signer, payload in bucket.items():
                if not isinstance(payload, dict):
                    continue
                payload_epoch = int(payload.get("validator_epoch") or 0)
                payload_set_hash = str(payload.get("validator_set_hash") or "").strip()
                if payload_epoch != local_epoch:
                    continue
                if local_set_hash and payload_set_hash and payload_set_hash != local_set_hash:
                    continue
                kept[str(signer)] = dict(payload)
            if kept:
                pruned_votes[key] = kept
        self._bft._votes = pruned_votes
    except Exception:
        pass
    try:
        pruned_timeouts = {}
        for view, bucket in list(getattr(self._bft, "_timeouts", {}).items()):
            if not isinstance(bucket, dict):
                continue
            kept = {}
            for signer, payload in bucket.items():
                if not isinstance(payload, dict):
                    continue
                payload_epoch = int(payload.get("validator_epoch") or 0)
                payload_set_hash = str(payload.get("validator_set_hash") or "").strip()
                if payload_epoch != local_epoch:
                    continue
                if local_set_hash and payload_set_hash and payload_set_hash != local_set_hash:
                    continue
                kept[str(signer)] = dict(payload)
            if kept:
                pruned_timeouts[int(view)] = kept
        self._bft._timeouts = pruned_timeouts
    except Exception:
        pass
    try:
        tc = getattr(self._bft, "last_timeout_certificate", None)
        if tc is not None:
            if int(getattr(tc, "validator_epoch", 0) or 0) != local_epoch:
                self._bft.last_timeout_certificate = None
            elif local_set_hash and str(
                getattr(tc, "validator_set_hash", "") or ""
            ).strip() not in {"", local_set_hash}:
                self._bft.last_timeout_certificate = None
    except Exception:
        pass
    try:
        self._bft._prune_local_liveness_caches()
    except Exception:
        pass

def _persist_bft_state(self) -> None:
    _bind_executor_globals()
    self._prune_bft_liveness_caches_for_current_epoch()
    self.state["bft"] = self._bft.export_state()
    maybe_trigger_failpoint("bft_state_before_persist")
    self._ledger_store.write(self.state)
    maybe_trigger_failpoint("bft_state_after_persist")
    self._bft_record_event(
        "bft_state_persisted",
        view=int(self._bft.view),
        finalized_block_id=str(self._bft.finalized_block_id or ""),
    )

def bft_verify_qc_json(self, qcj: Json) -> QuorumCert | None:
    _bind_executor_globals()
    if not self._bft_phase_allows_artifact_processing():
        return None
    if not self._bft_payload_phase_matches_current_security_model(qcj):
        return None
    qc = qc_from_json(qcj)
    if qc is None:
        return None
    if not self._bft_epoch_binding_matches(qcj):
        return None
    if self._qc_identity_conflicts(qcj, source="qc_verify"):
        return None
    validators = self._active_validators()
    vpub = self._validator_pubkeys()
    if not verify_qc(qc=qc, validators=validators, validator_pubkeys=vpub):
        return None
    return qc

def bft_handle_qc(self, qcj: Json) -> bool:
    _bind_executor_globals()
    qc = self.bft_verify_qc_json(qcj)
    if qc is None:
        return False
    blocks_map = self._bft_speculative_blocks_map()
    prev_finalized = str(self._bft.finalized_block_id or "").strip()
    self._bft.observe_qc(blocks=blocks_map, qc=qc)
    self._put_pending_missing_qc(qc.to_json())
    next_finalized = str(self._bft.finalized_block_id or "").strip()
    if next_finalized and next_finalized != prev_finalized:
        maybe_trigger_failpoint("bft_finalized_frontier_advanced")
    self._persist_bft_state()
    self._bft_record_event(
        "bft_qc_observed",
        block_id=str(qc.block_id),
        view=int(qc.view),
        parent_id=str(qc.parent_id),
    )
    return True

def _bft_best_justify_qc_json(self) -> Json | None:
    _bind_executor_globals()
    if self._bft.high_qc is not None:
        return self._bft.high_qc.to_json()

    tc = getattr(self._bft, "best_timeout_certificate", lambda: None)()
    if tc is None:
        return None
    qid = str(getattr(tc, "high_qc_id", "") or "").strip()
    if not qid:
        return None
    cached = self._pending_missing_qc_json(block_id=qid)
    if isinstance(cached, dict):
        qc = self.bft_verify_qc_json(cached)
        if qc is not None:
            return qc.to_json()
    return None

def bft_leader_propose(self, *, max_txs: int = 1000) -> Json | None:
    _bind_executor_globals()
    if not self._validator_signing_permitted():
        return None

    validators = self._active_validators()
    local_validator = self._local_validator_account()
    view = int(self._bft.view)
    expected_leader = leader_for_view(validators, view) if validators else ""
    if validators:
        if local_validator not in set(validators):
            return None
        if expected_leader and local_validator != expected_leader:
            return None

    blk, st2, applied_ids, invalid_ids, err = self.build_block_candidate(
        max_txs=max_txs, allow_empty=True
    )
    if err and err != "empty":
        return None
    if blk is None or st2 is None:
        return None

    justify_qc_id = ""
    best_justify_qc = self._bft_best_justify_qc_json()
    if isinstance(best_justify_qc, dict):
        blk["justify_qc"] = best_justify_qc
        justify_qc_id = str(best_justify_qc.get("block_id") or "")

    epoch = self._current_validator_epoch()
    if epoch > 0:
        blk["validator_epoch"] = int(epoch)
    vset_hash = self._current_validator_set_hash()
    if vset_hash:
        blk["validator_set_hash"] = vset_hash

    blk["chain_id"] = str(self.chain_id)
    blk["view"] = int(view)
    blk["proposer"] = local_validator
    blk["consensus_phase"] = self._current_consensus_phase()

    bid = str(blk.get("block_id") or "").strip()
    block_hash = str(blk.get("block_hash") or "").strip()
    parent_id = str(blk.get("prev_block_id") or "").strip()
    proposer_pubkey = str(os.environ.get("WEALL_NODE_PUBKEY") or "").strip()
    proposer_privkey = str(os.environ.get("WEALL_NODE_PRIVKEY") or "").strip()
    if bid and not self._bft.record_local_proposal(view=view, block_id=bid):
        return None

    if bid and proposer_pubkey and proposer_privkey and local_validator:
        msg = canonical_proposal_message(
            chain_id=self.chain_id,
            view=view,
            block_id=bid,
            block_hash=block_hash,
            parent_id=parent_id,
            proposer=local_validator,
            validator_epoch=int(epoch),
            validator_set_hash=vset_hash,
            justify_qc_id=justify_qc_id,
        )
        blk["proposer_pubkey"] = proposer_pubkey
        blk["proposer_sig"] = sign_ed25519(
            message=msg, privkey=proposer_privkey, encoding="hex"
        )

    if bid:
        self._persist_bft_state()
        _bounded_put(
            self._pending_candidates,
            bid,
            (blk, st2, applied_ids, invalid_ids),
            cap=self._max_pending_candidates,
        )
        self._persist_pending_bft_artifact(
            kind="pending_candidate", block_id=bid, payload=dict(blk)
        )
        self._index_pending_candidate(blk)
    return blk

def bft_handle_vote(self, vote_json: Json) -> QuorumCert | None:
    _bind_executor_globals()
    if not isinstance(vote_json, dict):
        return None
    if str(vote_json.get("t") or "") != "VOTE":
        return None
    if not self._bft_artifact_shape_fast_fail("vote", vote_json):
        return None
    if not self._bft_phase_allows_artifact_processing():
        return None
    if not self._bft_payload_phase_matches_current_security_model(vote_json):
        return None
    if not self._bft_epoch_binding_matches(vote_json):
        return None
    if self._remember_recent_bft_vote(vote_json):
        return None
    if not self._consume_bft_sender_budget(vote_json):
        return None

    validators = self._active_validators()
    vpub = self._validator_pubkeys()

    vote = BftVote(
        chain_id=str(vote_json.get("chain_id") or self.chain_id).strip(),
        view=int(vote_json.get("view") or 0),
        block_id=str(vote_json.get("block_id") or "").strip(),
        block_hash=str(vote_json.get("block_hash") or "").strip(),
        parent_id=str(vote_json.get("parent_id") or "").strip(),
        signer=str(vote_json.get("signer") or "").strip(),
        pubkey=str(vote_json.get("pubkey") or "").strip(),
        sig=str(vote_json.get("sig") or "").strip(),
        validator_epoch=int(vote_json.get("validator_epoch") or 0),
        validator_set_hash=str(vote_json.get("validator_set_hash") or "").strip(),
    )

    # NOTE: HotStuffBFT validates signatures + threshold internally.
    # Use the engine's canonical accept_vote API.
    qc = self._bft.accept_vote(vote_json=vote.to_json(), validators=validators, vpub=vpub)
    if qc is None:
        self._persist_bft_state()
        return None

    blocks_map = self._bft_speculative_blocks_map()
    prev_finalized = str(self._bft.finalized_block_id or "").strip()
    self._bft.observe_qc(blocks=blocks_map, qc=qc)
    self._put_pending_missing_qc(qc.to_json())
    next_finalized = str(self._bft.finalized_block_id or "").strip()
    if next_finalized and next_finalized != prev_finalized:
        maybe_trigger_failpoint("bft_finalized_frontier_advanced")
    self._persist_bft_state()
    return qc

def bft_commit_if_ready(self, qc: QuorumCert) -> ExecutorMeta | None:
    _bind_executor_globals()
    validators = self._active_validators()
    vpub = self._validator_pubkeys()
    if not verify_qc(qc=qc, validators=validators, validator_pubkeys=vpub):
        return None

    self._put_pending_missing_qc(qc.to_json())

    metas = self.bft_try_apply_pending_remote_blocks()
    if metas:
        return metas[-1]
    self._persist_bft_state()
    return None

def bft_make_vote_for_block(
    self, *, view: int, block_id: str, block_hash: str, parent_id: str
) -> Json | None:
    _bind_executor_globals()
    if not self._validator_signing_permitted():
        return None
    if not self._bft_phase_allows_artifact_processing():
        return None

    signer, pubkey, privkey = self._local_validator_identity()
    if not signer or not pubkey or not privkey:
        return None

    validator_epoch = self._current_validator_epoch()
    validator_set_hash = self._current_validator_set_hash() if int(validator_epoch) > 0 else ""
    msg = canonical_vote_message(
        chain_id=self.chain_id,
        view=int(view),
        block_id=str(block_id),
        block_hash=str(block_hash),
        parent_id=str(parent_id),
        signer=signer,
        validator_epoch=int(validator_epoch),
        validator_set_hash=validator_set_hash,
    )
    sig = sign_ed25519(message=msg, privkey=privkey, encoding="hex")

    vote = BftVote(
        chain_id=self.chain_id,
        view=int(view),
        block_id=str(block_id),
        block_hash=str(block_hash),
        parent_id=str(parent_id),
        signer=signer,
        pubkey=pubkey,
        sig=sig,
        validator_epoch=int(validator_epoch),
        validator_set_hash=validator_set_hash,
    )
    out = vote.to_json()
    out["consensus_phase"] = self._current_consensus_phase()
    return out

def bft_make_timeout(self, *, view: int) -> Json | None:
    _bind_executor_globals()
    if not self._validator_signing_permitted():
        return None
    if not self._bft_phase_allows_artifact_processing():
        return None

    signer, pubkey, privkey = self._local_validator_identity()
    if not signer or not pubkey or not privkey:
        return None

    high_qc_id = "genesis"
    if self._bft.high_qc is not None and str(self._bft.high_qc.block_id or "").strip():
        high_qc_id = str(self._bft.high_qc.block_id)

    validator_epoch = self._current_validator_epoch()
    validator_set_hash = self._current_validator_set_hash() if int(validator_epoch) > 0 else ""
    msg = canonical_timeout_message(
        chain_id=self.chain_id,
        view=int(view),
        high_qc_id=high_qc_id,
        signer=signer,
        validator_epoch=int(validator_epoch),
        validator_set_hash=validator_set_hash,
    )
    sig = sign_ed25519(message=msg, privkey=privkey, encoding="hex")
    self._bft.note_timeout_emitted(view=int(view))
    tmo = BftTimeout(
        chain_id=self.chain_id,
        view=int(view),
        high_qc_id=high_qc_id,
        signer=signer,
        pubkey=pubkey,
        sig=sig,
        validator_epoch=int(validator_epoch),
        validator_set_hash=validator_set_hash,
    )
    tjson = tmo.to_json()
    tjson["consensus_phase"] = self._current_consensus_phase()
    self._bft_record_event(
        "bft_timeout_emitted",
        view=int(view),
        high_qc_id=high_qc_id,
        timeout_ms=int(self._bft.pacemaker_timeout_ms()),
    )
    self._bft_enqueue_outbound("timeout", tjson)
    return tjson

def bft_handle_timeout(self, timeout_json: Json) -> int | None:
    _bind_executor_globals()
    if not isinstance(timeout_json, dict):
        return None
    if str(timeout_json.get("t") or "") != "TIMEOUT":
        return None
    if not self._bft_artifact_shape_fast_fail("timeout", timeout_json):
        return None
    if not self._bft_phase_allows_artifact_processing():
        return None
    if not self._bft_payload_phase_matches_current_security_model(timeout_json):
        return None
    if not self._bft_epoch_binding_matches(timeout_json):
        return None
    if self._remember_recent_bft_timeout(timeout_json):
        return None
    if not self._consume_bft_sender_budget(timeout_json):
        return None

    validators = self._active_validators()
    vpub = self._validator_pubkeys()

    tmo = BftTimeout(
        chain_id=str(timeout_json.get("chain_id") or self.chain_id).strip(),
        view=int(timeout_json.get("view") or 0),
        high_qc_id=str(timeout_json.get("high_qc_id") or "").strip(),
        signer=str(timeout_json.get("signer") or "").strip(),
        pubkey=str(timeout_json.get("pubkey") or "").strip(),
        sig=str(timeout_json.get("sig") or "").strip(),
        validator_epoch=int(timeout_json.get("validator_epoch") or 0),
        validator_set_hash=str(timeout_json.get("validator_set_hash") or "").strip(),
    )
    # NOTE: HotStuffBFT validates signatures + threshold internally.
    # Use the engine's canonical accept_timeout API. It returns the new view
    # to advance to once threshold is reached.
    new_view = self._bft.accept_timeout(
        timeout_json=tmo.to_json(), validators=validators, vpub=vpub
    )
    if new_view is not None:
        self._persist_bft_state()
        return int(new_view)

    self._persist_bft_state()
    return None

def bft_timeout_check(self) -> Json | None:
    _bind_executor_globals()
    timeout_ms = int(self._bft.pacemaker_timeout_ms())
    now = _now_ms()
    if (now - int(self._bft.last_progress_ms)) < timeout_ms:
        return None
    local = self._local_validator_account()
    validators = self._active_validators()
    if local not in set(validators):
        return None
    view = int(self._bft.view)
    if leader_for_view(validators, view) == local:
        return None
    tmo = self.bft_make_timeout(view=view)
    if not isinstance(tmo, dict):
        return None
    self.bft_handle_timeout(tmo)
    return tmo

