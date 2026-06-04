from __future__ import annotations

"""BFT runtime helpers extracted from bft_runtime_adapter (bft_votecheck.py)."""

from weall.runtime.bft_executor_symbols import bind_executor_globals


def _bind_executor_globals() -> None:
    bind_executor_globals(globals())

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

