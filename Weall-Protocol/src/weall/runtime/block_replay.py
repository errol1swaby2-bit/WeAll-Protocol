from __future__ import annotations

import os

"""Follower-side received block replay and commitment verification delegate.

This module is intentionally a structural extraction from ``weall.runtime.executor``.
It keeps the executor public API stable while shrinking the trusted surface area of
the monolithic facade. The extracted functions still operate on ``WeAllExecutor``
instances and intentionally preserve behavior byte-for-byte where possible.
"""

from weall.runtime.executor import (
    ApplyError,
    ExecutorMeta,
    Json,
    LedgerView,
    MAX_BLOCK_TIME_ADVANCE_MS,
    TxEnvelope,
    _call_admit_bft_commit_block,
    _consensus_fail_closed,
    _helper_execution_profile_hash,
    _mode,
    _normalize_mempool_selection_policy,
    _pinned_helper_execution_profile,
    _pinned_mempool_selection_policy,
    _safe_int,
    _sanitize_mempool_selection_marker,
    _summarize_transition_guardrail_receipts,
    admit_block_txs,
    compute_block_hash,
    compute_block_id,
    compute_helper_execution_root,
    compute_receipts_root,
    compute_state_root,
    copy,
    effective_bft_enabled,
    ensure_block_hash,
    runtime_mode,
    runtime_vrf_required,
    validate_system_tx_queue_binding,
    verify_vrf_record,
)

from weall.runtime.block_time_admission import runtime_block_clock_policy, validate_block_timestamp
from weall.runtime.runtime_context import RuntimeContext
from weall.runtime.scheduler_pipeline import (
    emit_system_txs,
    prune_emitted,
    queue_item_phase,
    run_replay_post_schedulers,
    run_replay_pre_schedulers,
)



def apply_block(self, block: Json) -> ExecutorMeta:
    """Validate and commit a received block.

    Production goal:
      - nodes can converge by applying blocks received over the network
      - commit is fail-closed on any mismatch (roots, height, prev hash)

    Notes:
      - This method **does not** generate new system txs for inclusion.
      - However, it MUST run the same deterministic schedulers/emitter side-effects
        that the producing node ran while computing commitments (e.g., ensure PoH
        subtrees exist, enqueue system queue items, confirm emitted queue items).
      - We verify receipts_root and state_root (if present) against a fresh replay.
    """
    runtime_ctx = RuntimeContext.from_executor(self)
    scheduler_set = runtime_ctx.scheduler_set
    apply_tx_fn = runtime_ctx.tx_execution_set.apply_tx_atomic_meta
    if not isinstance(block, dict):
        return ExecutorMeta(ok=False, error="bad_block:not_object", height=0, block_id="")

    try:
        block2, bh = ensure_block_hash(block)
    except Exception:
        return ExecutorMeta(ok=False, error="bad_block:bad_hash", height=0, block_id="")

    if self._block_identity_conflicts(block2):
        return ExecutorMeta(
            ok=False, error="bad_block:block_id_hash_conflict", height=0, block_id=""
        )

    header = block2.get("header")
    if not isinstance(header, dict):
        return ExecutorMeta(ok=False, error="bad_block:missing_header", height=0, block_id="")

    if str(header.get("chain_id") or "").strip() != self.chain_id:
        return ExecutorMeta(
            ok=False, error="bad_block:chain_id_mismatch", height=0, block_id=""
        )

    if effective_bft_enabled(executor=self, default=False):
        strict_bft_apply = (
            _mode() == "prod"
            or isinstance(block2.get("justify_qc"), dict)
            or not isinstance(block2.get("qc"), dict)
        )
        if strict_bft_apply:
            ok_bft, rej_bft = _call_admit_bft_commit_block(
                block=block2,
                state=self.state,
                blocks_map=self._bft_speculative_blocks_map(),
                bft_enabled=effective_bft_enabled(executor=self, default=False),
            )
            if not ok_bft:
                code = str(rej_bft.code) if rej_bft is not None else "bft_reject"
                return ExecutorMeta(
                    ok=False,
                    error=f"bad_block:{code}",
                    height=0,
                    block_id=str(block2.get("block_id") or ""),
                )

    height = int(header.get("height") or block2.get("height") or 0)
    if height <= 0:
        return ExecutorMeta(ok=False, error="bad_block:height", height=0, block_id="")

    want_h = _safe_int(self.state.get("height"), 0) + 1
    if height != want_h:
        return ExecutorMeta(ok=False, error="bad_block:height_mismatch", height=0, block_id="")

    prev_bh = str(header.get("prev_block_hash") or "").strip()
    tip_hash = str(self.state.get("tip_hash") or "").strip()
    # Genesis: allow first block when tip_hash is empty.
    if tip_hash and prev_bh != tip_hash:
        return ExecutorMeta(
            ok=False, error="bad_block:prev_hash_mismatch", height=0, block_id=""
        )

    ts_ms = int(header.get("block_ts_ms") or block2.get("block_ts_ms") or 0)
    if ts_ms <= 0:
        return ExecutorMeta(ok=False, error="bad_block:ts", height=0, block_id="")
    chain_floor_ms = self.chain_time_floor_ms()
    time_verdict = validate_block_timestamp(
        state=self.state,
        height=int(height),
        block_ts_ms=int(ts_ms),
        chain_floor_ms=int(chain_floor_ms),
        max_block_time_advance_ms=int(MAX_BLOCK_TIME_ADVANCE_MS),
        mode=str(os.environ.get("WEALL_MODE", "") or ""),
    )
    if not bool(time_verdict.ok):
        code = str(time_verdict.code or "ts")
        if code == "not_constitutional_slot":
            return ExecutorMeta(ok=False, error="bad_block:ts_not_constitutional_slot", height=0, block_id="")
        if code == "before_constitutional_slot":
            return ExecutorMeta(ok=False, error="bad_block:ts_before_constitutional_slot", height=0, block_id="")
        return ExecutorMeta(ok=False, error=f"bad_block:{code}", height=0, block_id="")

    txs = block2.get("txs")
    if not isinstance(txs, list):
        return ExecutorMeta(ok=False, error="bad_block:txs", height=0, block_id="")

    # Replay exactly the tx list the leader committed to.
    working: Json = copy.deepcopy(self.state)
    clock_policy = runtime_block_clock_policy(
        state=self.state, mode=str(os.environ.get("WEALL_MODE", "") or "")
    )
    if bool(clock_policy.enabled):
        from weall.runtime.constitutional_clock import commit_clock_policy_to_state

        commit_clock_policy_to_state(working, clock_policy)

    # IMPORTANT: match deterministic scheduler/elector side-effects that occur
    # during block production. These may initialize subtrees and/or enqueue
    # system queue items (and confirm emission) which affect state_root.
    next_height = int(height)

    def _run_poh_schedulers() -> None:
        run_replay_pre_schedulers(working, next_height=next_height, scheduler_set=scheduler_set)

    def _run_post_schedulers() -> None:
        run_replay_post_schedulers(working, next_height=next_height, scheduler_set=scheduler_set)

    def _run_system_emitter_side_effects(phase: str) -> None:
        # We discard envelopes; the block already contains the tx list.
        _ = emit_system_txs(
            working, self.tx_index, next_height=next_height, phase=str(phase), proposer="", scheduler_set=scheduler_set
        )

    def _queue_item_phase(queue_id: str) -> str:
        return queue_item_phase(working, queue_id)

    # Production path: pre schedulers + pre emitter side-effects.
    try:
        _run_poh_schedulers()
    except Exception as exc:
        if _consensus_fail_closed():
            return ExecutorMeta(
                ok=False,
                error=f"bad_block:poh_schedule_failed:{type(exc).__name__}",
                height=0,
                block_id="",
            )
    try:
        _run_system_emitter_side_effects("pre")
    except Exception as exc:
        if _consensus_fail_closed():
            return ExecutorMeta(
                ok=False,
                error=f"bad_block:system_emitter_pre_failed:{type(exc).__name__}",
                height=0,
                block_id="",
            )

    applied_ids: list[str] = []
    invalid_ids: list[str] = []
    receipts: list[Json] = []
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

    # Inclusion gates (fail-closed)
    ledger_for_block = LedgerView.from_ledger(working)
    verify_block_signatures = bool(runtime_mode() == "prod")
    ok, block_reject, per_tx = admit_block_txs(
        env_objs,
        ledger_for_block,
        self.tx_index,
        verify_signatures=verify_block_signatures,
    )
    if (not ok) and block_reject is not None:
        return ExecutorMeta(
            ok=False, error=f"bad_block:block_reject:{block_reject.code}", height=0, block_id=""
        )
    first_tx_reject = next((rej for rej in per_tx if rej is not None), None)
    if first_tx_reject is not None:
        return ExecutorMeta(
            ok=False, error=f"bad_block:tx_reject:{first_tx_reject.code}", height=0, block_id=""
        )

    # Apply txs in the provided order.
    # If we encounter a system tx that the producer would have emitted in the
    # post phase, we must first run the post schedulers/emitter side-effects
    # (because those side-effects can depend on state after user txs).
    # Nonces are only consumed on success, so any later non-system tx from a
    # signer whose earlier tx rejected during apply must also be rejected
    # deterministically within this block.
    post_ran = False
    blocked_signers_after_apply_reject: set[str] = set()

    for env, env_obj, tx_id, rej in zip(txs, env_objs, tx_ids, per_tx, strict=False):
        if not post_ran and bool(getattr(env_obj, "system", False)):
            try:
                payload = env.get("payload") if isinstance(env, dict) else None
                qid = (
                    str((payload or {}).get("_system_queue_id") or "").strip()
                    if isinstance(payload, dict)
                    else ""
                )
                if qid and _queue_item_phase(qid) == "post":
                    try:
                        _run_post_schedulers()
                    except Exception as exc:
                        if _consensus_fail_closed():
                            return ExecutorMeta(
                                ok=False,
                                error=f"bad_block:poh_schedule_failed:{type(exc).__name__}",
                                height=0,
                                block_id="",
                            )
                    try:
                        _run_system_emitter_side_effects("post")
                    except Exception as exc:
                        if _consensus_fail_closed():
                            return ExecutorMeta(
                                ok=False,
                                error=f"bad_block:system_emitter_post_failed:{type(exc).__name__}",
                                height=0,
                                block_id="",
                            )
                    post_ran = True
            except Exception:
                pass

        if not tx_id:
            invalid_ids.append(tx_id)
            continue

        if rej is not None:
            # Still record a deterministic receipt.
            invalid_ids.append(tx_id)
            receipts.append(
                {
                    "tx_id": str(tx_id),
                    "tx_type": str(getattr(env_obj, "tx_type", "") or ""),
                    "signer": str(getattr(env_obj, "signer", "") or ""),
                    "nonce": int(getattr(env_obj, "nonce", 0) or 0),
                    "ok": False,
                    "code": str(getattr(rej, "code", "") or "admission_reject"),
                    "reason": str(getattr(rej, "reason", "") or "rejected"),
                }
            )
            applied_ids.append(tx_id)
            continue

        signer = str(getattr(env_obj, "signer", "") or "")
        is_system = bool(getattr(env_obj, "system", False))

        if is_system:
            payload_for_binding = env.get("payload") if isinstance(env, dict) else None
            qid_for_binding = (
                str((payload_for_binding or {}).get("_system_queue_id") or "").strip()
                if isinstance(payload_for_binding, dict)
                else ""
            )
            phase_for_binding = _queue_item_phase(qid_for_binding)

            # Post-phase system txs are enqueued only after user txs have
            # replayed on the follower. If the tx references a queue item
            # that is not present yet, run the post schedulers/emitter once
            # before binding. Missing/unknown queue ids still fail closed
            # below; this only gives legitimate post-phase system txs the
            # same deterministic queue state the proposer had.
            if qid_for_binding and not phase_for_binding and not post_ran:
                try:
                    _run_poh_schedulers()
                except Exception as exc:
                    if _consensus_fail_closed():
                        return ExecutorMeta(
                            ok=False,
                            error=f"bad_block:poh_schedule_failed:{type(exc).__name__}",
                            height=0,
                            block_id="",
                        )
                try:
                    _run_system_emitter_side_effects("post")
                except Exception as exc:
                    if _consensus_fail_closed():
                        return ExecutorMeta(
                            ok=False,
                            error=f"bad_block:system_emitter_post_failed:{type(exc).__name__}",
                            height=0,
                            block_id="",
                        )
                post_ran = True
                phase_for_binding = _queue_item_phase(qid_for_binding)

            ok_binding, why_binding = validate_system_tx_queue_binding(
                working,
                self.tx_index,
                env_obj,
                next_height=next_height,
                phase=phase_for_binding or "post",
            )
            if not ok_binding:
                return ExecutorMeta(
                    ok=False,
                    error=f"bad_block:system_queue_binding:{why_binding}",
                    height=0,
                    block_id="",
                )

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
                    return ExecutorMeta(
                    ok=False,
                    error=f"bad_block:tx_apply_failed:{type(e).__name__}",
                    height=0,
                    block_id="",
                )
                applied_ok = False
                err_code = type(e).__name__
                err_reason = str(e)

        if (not applied_ok) and (not is_system) and signer:
            blocked_signers_after_apply_reject.add(signer)

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
            invalid_ids.append(tx_id)

        receipts.append(receipt)

    if not post_ran:
        try:
            _run_poh_schedulers()
        except Exception as exc:
            if _consensus_fail_closed():
                return ExecutorMeta(
                    ok=False,
                    error=f"bad_block:poh_schedule_failed:{type(exc).__name__}",
                    height=0,
                    block_id="",
                )
        try:
            _run_system_emitter_side_effects("post")
        except Exception as exc:
            if _consensus_fail_closed():
                return ExecutorMeta(
                    ok=False,
                    error=f"bad_block:system_emitter_post_failed:{type(exc).__name__}",
                    height=0,
                    block_id="",
                )

    # Match leader-side durable state before verifying commitments. Emitted
    # system queue entries are scheduling scratch once the corresponding
    # system envelopes are in the block. Prune them here before computing the
    # state root, then commit_block_candidate() will prune again as a no-op.
    try:
        prune_emitted(working, scheduler_set=scheduler_set)
    except Exception as exc:
        if _consensus_fail_closed():
            return ExecutorMeta(
                ok=False,
                error=f"bad_block:system_queue_prune_failed:{type(exc).__name__}",
                height=0,
                block_id="",
            )

    # Verify block commitments fail-closed.
    receipts_root = compute_receipts_root(receipts=receipts)

    # Update ancestry + tip fields and time exactly as the leader should have.
    block_id = str(block2.get("block_id") or "").strip()
    if not block_id:
        block_id = compute_block_id(
            chain_id=str(header.get("chain_id") or self.chain_id),
            height=int(height),
            prev_block_id=str(block2.get("prev_block_id") or self.state.get("tip") or ""),
            prev_block_hash=str(
                header.get("prev_block_hash") or block2.get("prev_block_hash") or ""
            ),
            ts_ms=int(ts_ms),
            node_id=str(block2.get("proposer") or block2.get("node_id") or ""),
            tx_ids=list(applied_ids),
            receipts_root=receipts_root,
        )
        block2["block_id"] = block_id

    blocks_map = working.get("blocks")
    if not isinstance(blocks_map, dict):
        blocks_map = {}
        working["blocks"] = blocks_map
    # Mirror build_block_candidate() exactly before computing state_root:
    # the committed state records ancestry + timestamp, but does not yet
    # thread block_hash/tip_hash into the state root commitment.
    blocks_map[str(block_id)] = {
        "height": int(height),
        "prev_block_id": str(self.state.get("tip") or ""),
        "block_ts_ms": int(ts_ms),
    }

    working["height"] = int(height)
    working["tip"] = str(block_id)
    working["time"] = int(int(ts_ms) // 1000)

    have_rr = str(header.get("receipts_root") or "").strip()
    if not have_rr:
        return ExecutorMeta(
            ok=False, error="bad_block:missing_receipts_root", height=0, block_id=""
        )
    if receipts_root != have_rr:
        return ExecutorMeta(
            ok=False, error="bad_block:receipts_root_mismatch", height=0, block_id=""
        )

    # ------------------------------------------------------------
    # VRF injection + verification (affects state_root)
    # ------------------------------------------------------------
    vrf_any = header.get("vrf")
    if isinstance(vrf_any, dict) and vrf_any:
        ok_vrf, why = verify_vrf_record(
            vrf=vrf_any,
            chain_id=self.chain_id,
            height=int(height),
            prev_block_hash=str(header.get("prev_block_hash") or ""),
            block_ts_ms=int(ts_ms),
        )
        if not ok_vrf:
            return ExecutorMeta(ok=False, error=f"bad_block:vrf:{why}", height=0, block_id="")

        # Ensure VRF pubkey belongs to an active validator (fail-closed).
        try:
            pubkey = str(vrf_any.get("pubkey") or "").strip()
            vroot = working.get("validators")
            reg = vroot.get("registry") if isinstance(vroot, dict) else None
            roles = working.get("roles")
            vroles = roles.get("validators") if isinstance(roles, dict) else None
            active = vroles.get("active_set") if isinstance(vroles, dict) else None

            active_accounts: list[str] = []
            if isinstance(active, list):
                for a in active:
                    s = str(a or "").strip()
                    if s:
                        active_accounts.append(s)

            pub_ok = False
            if isinstance(reg, dict) and pubkey and active_accounts:
                for acct in active_accounts:
                    rec = reg.get(acct)
                    if not isinstance(rec, dict):
                        continue
                    if str(rec.get("pubkey") or "").strip() == pubkey:
                        pub_ok = True
                        break

            if not pub_ok:
                return ExecutorMeta(
                    ok=False, error="bad_block:vrf:not_active_validator", height=0, block_id=""
                )
        except Exception:
            return ExecutorMeta(
                ok=False, error="bad_block:vrf:validator_check_failed", height=0, block_id=""
            )

        # Deterministically store VRF in state so state_root commits to it.
        rand = working.get("rand")
        if not isinstance(rand, dict):
            rand = {}
            working["rand"] = rand
        rand["vrf"] = {"height": int(height), **vrf_any}
    else:
        # If required, reject blocks without VRF.  A narrow pytest-only
        # compatibility allowance mirrors block construction for local
        # persistence/replay fixtures that run in prod mode without network,
        # BFT, validator signing, or loop autostart.
        if runtime_vrf_required() and not self._pytest_local_missing_vrf_allowed():
            return ExecutorMeta(ok=False, error="bad_block:vrf:missing", height=0, block_id="")

    helper_execution_for_root = block2.get("helper_execution")
    if isinstance(helper_execution_for_root, dict) and helper_execution_for_root:
        helper_rep = helper_execution_for_root.get("helper_reputation")
        if isinstance(helper_rep, dict):
            rep_state = helper_rep.get("state")
            if isinstance(rep_state, dict):
                working["helper_reputation"] = dict(rep_state)

    state_root = compute_state_root(working)
    have_sr = str(header.get("state_root") or "").strip()
    if not have_sr:
        return ExecutorMeta(
            ok=False, error="bad_block:missing_state_root", height=0, block_id=""
        )
    if state_root != have_sr:
        return ExecutorMeta(
            ok=False, error="bad_block:state_root_mismatch", height=0, block_id=""
        )

    if isinstance(helper_execution_for_root, dict) and helper_execution_for_root:
        from weall.runtime.parallel_execution import verify_block_helper_plan_metadata

        advertised_plan_id = str(helper_execution_for_root.get("plan_id") or "").strip()
        ok_helper_meta, helper_reason = verify_block_helper_plan_metadata(
            helper_execution=helper_execution_for_root,
            expected_plan_id=advertised_plan_id,
        )
        if not ok_helper_meta:
            return ExecutorMeta(
                ok=False,
                error=f"bad_block:helper_execution_metadata_invalid:{helper_reason}",
                height=0,
                block_id="",
            )
    header_helper_root = str(header.get("helper_execution_root") or "").strip()
    if isinstance(helper_execution_for_root, dict) and helper_execution_for_root:
        computed_helper_root = compute_helper_execution_root(helper_execution=helper_execution_for_root)
        if not header_helper_root:
            return ExecutorMeta(
                ok=False, error="bad_block:missing_helper_execution_root", height=0, block_id=""
            )
        if computed_helper_root != header_helper_root:
            return ExecutorMeta(
                ok=False, error="bad_block:helper_execution_root_mismatch", height=0, block_id=""
            )
    elif header_helper_root:
        return ExecutorMeta(
            ok=False, error="bad_block:unexpected_helper_execution_root", height=0, block_id=""
        )

    existing_block_hash = str(block2.get("block_hash") or "").strip()
    if existing_block_hash and compute_block_hash(header=header) != existing_block_hash:
        return ExecutorMeta(ok=False, error="bad_block:block_hash_mismatch", height=0, block_id="")

    # Ensure we persist the same tip hash commitment.
    try:
        working["tip_hash"] = str(bh)
        working["tip_ts_ms"] = int(ts_ms)
    except Exception:
        pass

    meta_root = working.get("meta")
    if not isinstance(meta_root, dict):
        meta_root = {}
        working["meta"] = meta_root

    mempool_selection = block2.get("mempool_selection")
    if isinstance(mempool_selection, dict):
        local_mempool_selection_policy = _normalize_mempool_selection_policy(
            getattr(self._mempool, "selection_policy", lambda: "canonical")()
        )
        pinned_mempool_selection_policy = _pinned_mempool_selection_policy(
            {"meta": meta_root},
            local_mempool_selection_policy,
        )
        remote_mempool_selection_policy = _normalize_mempool_selection_policy(
            mempool_selection.get("policy") or pinned_mempool_selection_policy
        )
        if remote_mempool_selection_policy != pinned_mempool_selection_policy:
            return ExecutorMeta(
                ok=False,
                error="bad_block:mempool_selection_policy_mismatch",
                height=0,
                block_id="",
            )
        meta_root["mempool_selection_policy"] = str(pinned_mempool_selection_policy)
        meta_root["mempool_selection_last"] = _sanitize_mempool_selection_marker(
            mempool_selection,
            default_policy=pinned_mempool_selection_policy,
            default_limit=0,
        )
    local_helper_execution_profile = self._requested_helper_execution_profile()
    pinned_helper_execution_profile = _pinned_helper_execution_profile(
        {"meta": meta_root},
        local_helper_execution_profile,
    )
    meta_root["helper_execution_profile"] = dict(pinned_helper_execution_profile)
    meta_root["helper_execution_profile_hash"] = _helper_execution_profile_hash(
        pinned_helper_execution_profile
    )

    helper_execution = block2.get("helper_execution")
    if isinstance(helper_execution, dict):
        meta_root["helper_execution_last"] = {
            "height": int(height),
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
        height=int(height),
        block_id=str(block_id),
    )
    if transition_guardrail:
        meta_root["transition_guardrail_last"] = transition_guardrail
    else:
        meta_root.pop("transition_guardrail_last", None)

    # Commit.
    meta = self.commit_block_candidate(
        block=block2, new_state=working, applied_ids=applied_ids, invalid_ids=invalid_ids
    )
    return meta

