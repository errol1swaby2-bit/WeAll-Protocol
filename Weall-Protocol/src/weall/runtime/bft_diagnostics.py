from __future__ import annotations

"""BFT runtime helpers extracted from bft_runtime_adapter (bft_diagnostics.py)."""

from weall.runtime.executor_symbols import bind_executor_globals


def _bind_executor_globals() -> None:
    bind_executor_globals(globals())

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

