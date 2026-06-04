from __future__ import annotations

"""Leader-side block production and candidate construction delegates.

This module is intentionally a structural extraction from ``weall.runtime.executor``.
It keeps the executor public API stable while shrinking the trusted surface area of
the monolithic facade. The extracted functions still operate on ``WeAllExecutor``
instances and intentionally preserve behavior byte-for-byte where possible.
"""

from weall.runtime.runtime_context import RuntimeContext
from weall.runtime.scheduler_pipeline import (
    emit_system_txs,
    prune_emitted,
    run_leader_post_schedulers,
    run_leader_pre_schedulers,
)


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

    # These symbols are intentionally refreshed on every delegated call. Several
    # fail-closed regression tests monkeypatch the public executor module, which
    # was the pre-refactor import location. The extracted modules must continue
    # observing those patches until the tests and call sites move to explicit
    # dependency-injected contexts.
    for _name in (
        "apply_tx_atomic_meta",
        "schedule_poh_async_system_txs",
        "schedule_poh_tier2_system_txs",
        "schedule_poh_live_system_txs",
        "schedule_node_operator_system_txs",
        "schedule_reputation_accrual_system_txs",
        "tick_governance_lifecycle",
        "tick_dispute_lifecycle",
        "system_tx_emitter",
        "prune_emitted_system_queue",
    ):
        if hasattr(_executor_mod, _name):
            globals()[_name] = getattr(_executor_mod, _name)


def produce_block(
    self,
    *,
    max_txs: int = 1000,
    allow_empty: bool | None = None,
) -> ExecutorMeta:
    _bind_executor_globals()
    h0 = _safe_int(self.state.get("height"), 0)

    block_forbidden_reason = self._prod_observer_block_production_reason()
    if block_forbidden_reason:
        return ExecutorMeta(
            ok=False,
            error=f"block_production_forbidden:{block_forbidden_reason}",
            height=int(h0),
            block_id=str(self.state.get("tip") or ""),
            applied_count=0,
        )

    if allow_empty is None:
        try:
            _clock_manifest = load_chain_manifest(
                required=False, mode=str(os.environ.get("WEALL_MODE", "") or "")
            )
        except Exception:
            _clock_manifest = None
        _clock_policy = policy_from_manifest(_clock_manifest)
        if bool(_clock_policy.enabled):
            allow_empty = bool(_clock_policy.empty_blocks_enabled)
        else:
            allow_empty = str(os.environ.get("WEALL_PRODUCE_EMPTY_BLOCKS") or "").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }

    blk, st2, applied_ids, invalid_ids, err = self.build_block_candidate(
        max_txs=int(max_txs),
        allow_empty=bool(allow_empty),
    )

    if err in ("", "empty", "no_applicable"):
        if blk is None or st2 is None:
            return ExecutorMeta(
                ok=True,
                error="",
                height=int(h0),
                block_id=str(self.state.get("tip") or ""),
                applied_count=0,
            )

    if err:
        return ExecutorMeta(
            ok=False,
            error=str(err),
            height=int(h0),
            block_id=str(self.state.get("tip") or ""),
            applied_count=0,
        )

    if blk is None or st2 is None:
        return ExecutorMeta(
            ok=False,
            error="produce_failed",
            height=int(h0),
            block_id=str(self.state.get("tip") or ""),
            applied_count=0,
        )

    return self.commit_block_candidate(
        block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids
    )

def build_block_candidate(
    self,
    *,
    max_txs: int = 1000,
    allow_empty: bool = False,
    force_ts_ms: int | None = None,
    helper_certificates: dict[str, HelperExecutionCertificate] | None = None,
    helper_receipts_by_lane: dict[str, list[Json]] | None = None,
) -> tuple[Json | None, Json | None, list[str], list[str], str]:
    _bind_executor_globals()
    runtime_ctx = RuntimeContext.from_executor(self)
    scheduler_set = runtime_ctx.scheduler_set
    apply_tx_fn = runtime_ctx.tx_execution_set.apply_tx_atomic_meta
    height = _safe_int(self.state.get("height"), 0)
    tip = str(self.state.get("tip") or "")
    tip_hash = str(self.state.get("tip_hash") or "")

    chain_floor_ms = self.chain_time_floor_ms()
    successor_ts_ms = max(1, int(chain_floor_ms) + 1)

    try:
        _clock_manifest = load_chain_manifest(required=False, mode=str(os.environ.get("WEALL_MODE", "") or ""))
    except Exception:
        _clock_manifest = None
    clock_policy = policy_from_manifest(_clock_manifest)
    next_height_for_clock = int(height) + 1
    if bool(clock_policy.enabled):
        expected_ts_ms = expected_block_time_ms(clock_policy, height=next_height_for_clock)
        if force_ts_ms is not None and int(force_ts_ms) != int(expected_ts_ms):
            return None, None, [], [], "invalid_block_ts:not_constitutional_slot"
        # The wall clock may only decide whether a producer is too early; it
        # never decides procedure eligibility.  genesis_time_ms=0 is kept as
        # a legacy/dev fixture value and intentionally disables real-time
        # not-before gating until a launch manifest pins a real genesis time.
        if int(getattr(clock_policy, "genesis_time_ms", 0) or 0) > 0 and is_too_early(
            clock_policy, height=next_height_for_clock
        ):
            return None, None, [], [], "invalid_block_ts:before_constitutional_slot"
        ts_ms = int(expected_ts_ms)
    elif force_ts_ms is not None:
        ts_ms = int(force_ts_ms)
    else:
        ts_ms = successor_ts_ms

    if not bool(clock_policy.enabled):
        if ts_ms < successor_ts_ms:
            return None, None, [], [], "invalid_block_ts:before_chain_floor"
        if ts_ms > int(chain_floor_ms) + int(MAX_BLOCK_TIME_ADVANCE_MS):
            return None, None, [], [], "invalid_block_ts:beyond_chain_time_window"

    runtime_selection_policy = _normalize_mempool_selection_policy(
        str(getattr(self._mempool, "selection_policy", lambda: "canonical")())
    )
    pinned_selection_policy = _pinned_mempool_selection_policy(
        self.state,
        runtime_selection_policy,
    )
    fetch_for_block = getattr(self._mempool, "fetch_for_block", None)
    if callable(fetch_for_block):
        txs = list(fetch_for_block(limit=int(max_txs), policy=pinned_selection_policy))
    else:
        txs = self._mempool.peek(limit=int(max_txs))
    runtime_helper_execution_profile = self._requested_helper_execution_profile()
    pinned_helper_execution_profile = _pinned_helper_execution_profile(
        self.state,
        runtime_helper_execution_profile,
    )
    self._last_mempool_selection_diag = {
        "policy": pinned_selection_policy,
        "requested_limit": int(max_txs),
        "fetched_count": int(len(txs)),
        "selected_count": 0,
        "invalid_count": 0,
        "rejected_count": 0,
        "selected_tx_ids": [],
    }
    if not txs and not bool(allow_empty):
        return None, None, [], [], "empty"

    working: Json = copy.deepcopy(self.state)
    if bool(clock_policy.enabled):
        commit_clock_policy_to_state(working, clock_policy)

    applied_ids: list[str] = []
    invalid_ids: list[str] = []
    applied_envs: list[Json] = []
    receipts: list[Json] = []

    next_height = int(height) + 1

    def _apply_system_env(env: TxEnvelope) -> None:
        try:
            meta = apply_tx_fn(working, env, consume_nonce_on_fail=False)
        except ApplyError:
            j = env.to_json()
            tx_id2 = compute_tx_id(j, chain_id=self.chain_id)
            invalid_ids.append(tx_id2)
            return
        if meta is None:
            return

        j = env.to_json()
        tx_id2 = compute_tx_id(j, chain_id=self.chain_id)
        j["tx_id"] = tx_id2
        applied_envs.append(j)
        applied_ids.append(tx_id2)

        receipts.append(
            {
                "tx_id": tx_id2,
                "tx_type": str(getattr(env, "tx_type", "") or ""),
                "signer": str(getattr(env, "signer", "") or ""),
                "nonce": int(getattr(env, "nonce", 0) or 0),
                "ok": True,
            }
        )

    # Phase: schedule PoH system txs. These mutate consensus-visible state
    # before candidate tx admission, so production must fail closed here the
    # same way follower-side replay does.
    try:
        run_leader_pre_schedulers(working, next_height=next_height, scheduler_set=scheduler_set)
    except Exception as exc:
        if _consensus_fail_closed():
            return None, None, [], [], f"poh_schedule_failed:{type(exc).__name__}"

    # Phase: system emitter pre. These side effects also feed state_root and
    # must not be swallowed during local proposal construction in production.
    try:
        sys_pre = emit_system_txs(working, self.tx_index, next_height=next_height, phase="pre", scheduler_set=scheduler_set)
        for env in sys_pre:
            _apply_system_env(env)
    except Exception as exc:
        if _consensus_fail_closed():
            return None, None, [], [], f"system_emitter_pre_failed:{type(exc).__name__}"

    # Parse envelopes
    env_objs: list[TxEnvelope] = []
    tx_ids: list[str] = []

    for env in txs:
        if not isinstance(env, dict):
            env_objs.append(TxEnvelope.from_json({}))
            tx_ids.append("")
            continue

        tx_id = str(env.get("tx_id") or "").strip()
        tx_ids.append(tx_id)

        try:
            env_objs.append(TxEnvelope.from_json(env))
        except Exception:
            env_objs.append(TxEnvelope.from_json({}))

    # Block-level + per-tx admission for inclusion
    #
    # Production hardening: local candidate construction must enforce the
    # same non-system signature rules that remote replay/apply enforces.
    # Otherwise a malicious or buggy local ingress path can waste proposer
    # slots with txs that deterministic followers will later reject. Keep
    # non-prod behavior permissive so existing unsigned dev/test fixtures
    # can still exercise candidate construction flows.
    ledger_for_block = LedgerView.from_ledger(working)
    verify_candidate_signatures = (
        str(os.environ.get("WEALL_MODE") or "").strip().lower() == "prod"
    )
    ok, block_reject, per_tx = admit_block_txs(
        env_objs,
        ledger_for_block,
        self.tx_index,
        verify_signatures=verify_candidate_signatures,
    )
    if (not ok) and block_reject is not None:
        self._last_mempool_selection_diag["rejected_count"] = int(len([x for x in per_tx if x is not None]))
        return None, None, [], [], f"block_reject:{block_reject.code}:{block_reject.reason}"

    # Apply txs (fail-atomic) and always emit deterministic receipts.
    # Nonces are only consumed on success, so any later non-system tx from a
    # signer whose earlier tx rejected during apply must also be rejected
    # deterministically within this block.
    blocked_signers_after_apply_reject: set[str] = set()

    for env, env_obj, tx_id, rej in zip(txs, env_objs, tx_ids, per_tx, strict=False):
        if not tx_id:
            invalid_ids.append(tx_id)
            continue

        if bool(getattr(env_obj, "system", False)):
            payload_for_phase = env.get("payload") if isinstance(env, dict) else None
            qid_for_phase = (
                str((payload_for_phase or {}).get("_system_queue_id") or "").strip()
                if isinstance(payload_for_phase, dict)
                else ""
            )
            phase_for_binding = _queue_item_phase(qid_for_phase) or "post"
            ok_binding, why_binding = validate_system_tx_queue_binding(
                working,
                self.tx_index,
                env_obj,
                next_height=next_height,
                phase=phase_for_binding,
            )
            if not ok_binding:
                return (
                    None,
                    None,
                    [],
                    invalid_ids,
                    f"system_queue_binding:{why_binding}",
                )

        if rej is not None:
            invalid_ids.append(tx_id)
            continue

        signer = str(getattr(env_obj, "signer", "") or "")
        is_system = bool(getattr(env_obj, "system", False))

        applied_ok = False
        err_code = ""
        err_reason = ""
        err_details: Any = None

        if (not is_system) and signer and signer in blocked_signers_after_apply_reject:
            applied_ok = False
            err_code = "prior_apply_reject"
            err_reason = "nonce_not_consumed_after_prior_apply_reject"
            err_details = {"signer": signer}
        else:
            try:
                meta = apply_tx_fn(working, env, consume_nonce_on_fail=False)
                applied_ok = meta is not None
            except ApplyError as e:
                applied_ok = False
                err_code = str(getattr(e, "code", "") or "")
                err_reason = str(getattr(e, "reason", "") or "")
                err_details = getattr(e, "details", None)
            except Exception as e:
                if _consensus_fail_closed():
                    return None, None, [], [], f"tx_apply_failed:{type(e).__name__}"
                applied_ok = False
                err_code = type(e).__name__
                err_reason = str(e)

        if (not applied_ok) and (not is_system) and signer:
            blocked_signers_after_apply_reject.add(signer)

        applied_envs.append(env)
        applied_ids.append(tx_id)

        receipt: Json = {
            "tx_id": str(tx_id),
            "tx_type": str(getattr(env_obj, "tx_type", "") or ""),
            "signer": str(getattr(env_obj, "signer", "") or ""),
            "nonce": int(getattr(env_obj, "nonce", 0) or 0),
            "ok": bool(applied_ok),
        }
        if not applied_ok:
            receipt["code"] = err_code or "apply_error"
            receipt["reason"] = err_reason or "rejected"
            if err_details is not None:
                receipt["details"] = err_details
        receipts.append(receipt)

        if not applied_ok:
            invalid_ids.append(tx_id)

    # Phase: schedule PoH system txs. In production these deterministic
    # side effects are consensus-adjacent and must fail closed.
    try:
        run_leader_post_schedulers(working, next_height=next_height, scheduler_set=scheduler_set)
    except Exception as exc:
        if _consensus_fail_closed():
            return None, None, [], invalid_ids, f"poh_schedule_failed:{type(exc).__name__}"

    # Phase: system emitter post. Same fail-closed rule in production.
    try:
        sys_post = emit_system_txs(working, self.tx_index, next_height=next_height, phase="post", scheduler_set=scheduler_set)
        for env in sys_post:
            _apply_system_env(env)
    except Exception as exc:
        if _consensus_fail_closed():
            return (
                None,
                None,
                [],
                invalid_ids,
                f"system_emitter_post_failed:{type(exc).__name__}",
            )

    # System queue items are consensus scheduling scratch. Once their
    # envelopes have been emitted into this block and applied, the leader
    # prunes them before committing the ledger snapshot. The state root must
    # commit to that same durable post-prune state; otherwise followers can
    # verify the block against a transient pre-prune root and then diverge
    # when replaying later blocks from the durable committed state.
    try:
        prune_emitted(working, scheduler_set=scheduler_set)
    except Exception as exc:
        if _consensus_fail_closed():
            return None, None, [], invalid_ids, f"system_queue_prune_failed:{type(exc).__name__}"

    self._last_mempool_selection_diag["selected_count"] = int(len(applied_ids))
    self._last_mempool_selection_diag["invalid_count"] = int(len(invalid_ids))
    self._last_mempool_selection_diag["rejected_count"] = int(len([x for x in per_tx if x is not None]))
    self._last_mempool_selection_diag["selected_tx_ids"] = [str(x) for x in applied_ids[:64]]

    meta_root_working = working.get("meta")
    if not isinstance(meta_root_working, dict):
        meta_root_working = {}
        working["meta"] = meta_root_working
    meta_root_working["mempool_selection_policy"] = str(pinned_selection_policy)
    meta_root_working["mempool_selection_last"] = _sanitize_mempool_selection_marker(
        self._last_mempool_selection_diag,
        default_policy=pinned_selection_policy,
        default_limit=int(max_txs),
    )
    meta_root_working["helper_execution_profile"] = dict(pinned_helper_execution_profile)
    meta_root_working["helper_execution_profile_hash"] = _helper_execution_profile_hash(
        pinned_helper_execution_profile
    )

    if not applied_envs and not bool(allow_empty):
        return None, None, [], invalid_ids, "no_applicable"

    new_height = next_height
    receipts_root = compute_receipts_root(receipts=receipts)
    block_id = compute_block_id(
        chain_id=self.chain_id,
        height=new_height,
        prev_block_id=str(tip),
        prev_block_hash=str(tip_hash),
        ts_ms=int(ts_ms),
        node_id=str(self.node_id),
        tx_ids=list(applied_ids),
        receipts_root=receipts_root,
    )

    # Update ancestry + tip fields before computing roots.
    # Do not record block_hash in consensus state during candidate construction:
    # the final block hash is not available until after the canonical block
    # object is assembled and hashed, and threading it into state here would
    # either be impossible or introduce circular commitments.
    blocks_map = working.get("blocks")
    if not isinstance(blocks_map, dict):
        blocks_map = {}
        working["blocks"] = blocks_map
    blocks_map[str(block_id)] = {
        "height": int(new_height),
        "prev_block_id": str(tip),
        "block_ts_ms": int(ts_ms),
    }

    working["height"] = int(new_height)
    working["tip"] = str(block_id)

    # Update the working tip first; the state root must commit to the post-apply state.
    # Record deterministic "chain time" derived from the produced block timestamp.
    # Phase gates (e.g. Genesis economic lock) use state["time"] (seconds).
    try:
        working["time"] = int(int(ts_ms) // 1000)
    except Exception:
        pass
    if bool(clock_policy.enabled):
        try:
            meta_clock = working.get("meta") if isinstance(working.get("meta"), dict) else {}
            meta_clock["constitutional_clock"] = policy_to_json(
                clock_policy, current_height=constitutional_procedure_height(working)
            )
            working["meta"] = meta_clock
        except Exception:
            pass

    # ------------------------------------------------------------
    # Verifiable randomness ("sig-VRF")
    # ------------------------------------------------------------
    # - Producer includes vrf record in the block header.
    # - Producer also stores it in state under state["rand"]["vrf"], so
    #   downstream deterministic logic (e.g., PoH juror selection) can use
    #   the output without needing the block object.
    # - Fail-closed if WEALL_REQUIRE_VRF=1 and node keys are unavailable.
    vrf: Json | None = None
    require_vrf = runtime_vrf_required()
    try:
        pubkey = (os.environ.get("WEALL_NODE_PUBKEY") or "").strip()
        privkey = (os.environ.get("WEALL_NODE_PRIVKEY") or "").strip()
        if pubkey and privkey:
            vrf = make_vrf_record(
                chain_id=self.chain_id,
                height=new_height,
                prev_block_hash=tip_hash,
                block_ts_ms=ts_ms,
                pubkey=pubkey,
                privkey=privkey,
            )
            rand = working.get("rand")
            if not isinstance(rand, dict):
                rand = {}
                working["rand"] = rand
            rand["vrf"] = {"height": int(new_height), **(vrf if isinstance(vrf, dict) else {})}
        elif require_vrf:
            # Unit/integration tests often instantiate a prod-mode executor
            # directly to exercise unrelated persistence, nonce, replay,
            # and apply-block invariants.  Keep production fail-closed for
            # real network/BFT/signing/block-loop postures, while allowing
            # pytest-local, non-network fixtures to continue producing
            # deterministic local blocks without carrying node keys.
            if not self._pytest_local_missing_vrf_allowed():
                return None, None, [], invalid_ids, "vrf_missing_node_key"
    except Exception:
        if require_vrf:
            if not self._pytest_local_missing_vrf_allowed():
                return None, None, [], invalid_ids, "vrf_generate_failed"

    helper_execution = self._build_helper_execution_metadata(
        applied_envs=applied_envs,
        receipts=receipts,
        block_height=int(new_height),
        started_ms=int(ts_ms),
        helper_certificates=helper_certificates,
        helper_receipts_by_lane=helper_receipts_by_lane,
        helper_state_deltas_by_lane=None,
    )
    helper_execution_root = (
        compute_helper_execution_root(helper_execution=helper_execution)
        if isinstance(helper_execution, dict) and helper_execution
        else ""
    )

    # Production commitment to post-apply state.
    state_root = compute_state_root(working)

    header = make_block_header(
        chain_id=self.chain_id,
        height=new_height,
        prev_block_hash=tip_hash,
        block_ts_ms=ts_ms,
        tx_ids=applied_ids,
        receipts_root=receipts_root,
        state_root=state_root,
        helper_execution_root=helper_execution_root or None,
        vrf=vrf,
    )
    block: Json = {
        "block_id": block_id,
        "height": new_height,
        "prev_block_id": tip,
        "prev_block_hash": tip_hash,
        "block_ts_ms": ts_ms,
        "header": header,
        "txs": applied_envs,
        "receipts": receipts,
    }
    if helper_execution:
        block["helper_execution"] = helper_execution

    mempool_selection_marker: Json = _sanitize_mempool_selection_marker(
        meta_root_working.get("mempool_selection_last"),
        default_policy=pinned_selection_policy,
        default_limit=int(max_txs),
    )
    block["mempool_selection"] = dict(mempool_selection_marker)

    if helper_execution:
        meta_root = working.get("meta")
        if not isinstance(meta_root, dict):
            meta_root = {}
            working["meta"] = meta_root
        meta_root["helper_execution_last"] = {
            "height": int(new_height),
            "block_id": str(block_id),
            "view": int(helper_execution.get("view") or 0),
            "validator_epoch": int(helper_execution.get("validator_epoch") or 0),
            "validator_set_hash": str(helper_execution.get("validator_set_hash") or ""),
            "lanes": list(helper_execution.get("lanes") or []),
            "timed_out_lanes": list(helper_execution.get("timed_out_lanes") or []),
            "merge_summary": dict(helper_execution.get("merge_summary") or {}),
            "audit_summary": dict(helper_execution.get("audit_summary") or {}),
            "fraud_suspected": bool(helper_execution.get("fraud_suspected") or False),
            "fraud_lane_ids": list(helper_execution.get("fraud_lane_ids") or []),
            "helper_reputation": dict(helper_execution.get("helper_reputation") or {}),
        }
        meta_root["helper_reputation"] = dict(helper_execution.get("helper_reputation", {}).get("state") or {})

    transition_guardrail = _summarize_transition_guardrail_receipts(
        receipts,
        height=int(new_height),
        block_id=str(block_id),
    )
    meta_root = working.get("meta")
    if not isinstance(meta_root, dict):
        meta_root = {}
        working["meta"] = meta_root
    if transition_guardrail:
        meta_root["transition_guardrail_last"] = transition_guardrail
    else:
        meta_root.pop("transition_guardrail_last", None)

    try:
        block, bh = ensure_block_hash(block)
        working["tip_hash"] = str(bh)
        working["tip_ts_ms"] = int(ts_ms)
    except Exception as exc:
        return None, None, [], invalid_ids, f"block_hash_commitment_failed:{type(exc).__name__}"

    return block, working, applied_ids, invalid_ids, ""

