from __future__ import annotations

"""Helper lane planning, helper metadata, and helper execution profile delegates.

This module is intentionally a structural extraction from ``weall.runtime.executor``.
It keeps the executor public API stable while shrinking the trusted surface area of
the monolithic facade. The extracted functions still operate on ``WeAllExecutor``
instances and intentionally preserve behavior byte-for-byte where possible.
"""



from weall.runtime.executor import (
    HelperCertificateStore,
    HelperDispatchContext,
    HelperLaneJournal,
    Json,
    Path,
    _helper_execution_profile,
    apply_helper_quarantine_to_lane_plans,
    build_lane_audit_plan,
    build_validator_execution_manifest,
    canonical_lane_plan_fingerprint,
    evaluate_lane_audit_plan,
    merge_helper_lane_results,
    plan_parallel_execution,
    sign_validator_execution_manifest,
    summarize_assignment_counts,
    summarize_helper_capabilities,
    summarize_helper_capacity_usage,
    summarize_helper_reputation_state,
    summarize_lane_audit_results,
    update_helper_reputation_state,
    validator_execution_summary,
    verify_block_helper_plan_metadata,
)



def _root_committed_map(self, key: str) -> Json:
    """Return a root-committed helper planning map.

    ``state["meta"]`` is excluded from ``compute_state_root`` and may carry
    node-local diagnostics.  Helper planning/assignment inputs are consensus
    relevant whenever the helper fast path is enabled, so they must be read only
    from root-visible state keys.
    """
    raw = self.state.get(str(key))
    return dict(raw) if isinstance(raw, dict) else {}

def _helper_mode_enabled_runtime(self) -> bool:
    return bool(getattr(self, "_helper_mode_enabled_effective", False))

def _requested_helper_execution_profile(self) -> Json:
    return _helper_execution_profile(
        helper_mode_enabled=bool(self._helper_mode_enabled_default),
        helper_fast_path_enabled=bool(self._helper_fast_path_enabled_default),
        helper_timeout_ms=int(getattr(self, "_helper_timeout_ms", 5000)),
    )

def _effective_helper_execution_profile(self) -> Json:
    return _helper_execution_profile(
        helper_mode_enabled=bool(self._helper_mode_enabled_runtime()),
        helper_fast_path_enabled=bool(self._helper_fast_path_enabled()),
        helper_timeout_ms=int(getattr(self, "_helper_timeout_ms", 5000)),
    )

def _helper_fast_path_enabled(self) -> bool:
    return bool(getattr(self, "_helper_fast_path_enabled_effective", False))

def _helper_lane_journal_path(self, *, block_height: int) -> str:
    name = f"lane_journal_h{int(block_height)}.jsonl"
    return str(Path(self._helper_lane_journal_dir) / name)

def _helper_dispatch_context(
    self,
    *,
    block_height: int,
    manifest_hash: str = "",
    coordinator_pubkey: str = "",
    manifest_signature: str = "",
    manifest_signed: bool = False,
    manifest_signature_required: bool = False,
    manifest_payload: Json | None = None,
    strict_helper_certificate_consistency: bool = False,
    strict_helper_receipts_root: bool = False,
    strict_helper_state_delta_hash: bool = False,
    plan_id: str = "",
) -> HelperDispatchContext:
    return HelperDispatchContext(
        chain_id=self.chain_id,
        block_height=int(block_height),
        view=int(self._bft.view),
        leader_id=str(self.node_id),
        validator_epoch=int(self._current_validator_epoch()),
        validator_set_hash=str(self._current_validator_set_hash()),
        manifest_hash=str(manifest_hash or ""),
        coordinator_pubkey=str(coordinator_pubkey or ""),
        manifest_signature=str(manifest_signature or ""),
        manifest_signed=bool(manifest_signed),
        manifest_signature_required=bool(manifest_signature_required),
        manifest_payload=dict(manifest_payload or {}) if isinstance(manifest_payload, dict) else None,
        strict_helper_certificate_consistency=bool(strict_helper_certificate_consistency),
        strict_helper_receipts_root=bool(strict_helper_receipts_root),
        strict_helper_state_delta_hash=bool(strict_helper_state_delta_hash),
        plan_id=str(plan_id or ""),
    )

def _build_helper_execution_metadata(
    self,
    *,
    applied_envs: list[Json],
    receipts: list[Json],
    block_height: int,
    started_ms: int,
    helper_certificates: dict[str, HelperExecutionCertificate] | None = None,
    helper_receipts_by_lane: dict[str, list[Json]] | None = None,
    helper_state_deltas_by_lane: dict[str, list[Json]] | None = None,
) -> Json:
    if not self._helper_fast_path_enabled():
        return {}
    ctx0 = self._helper_dispatch_context(block_height=int(block_height))
    meta_root_existing = self.state.get("meta") if isinstance(self.state.get("meta"), dict) else {}
    helper_reputation_state = _root_committed_map(self, "helper_reputation")
    helper_capacity_by_helper = _root_committed_map(self, "helper_capacity_by_helper")
    helper_capabilities_by_helper = _root_committed_map(self, "helper_capabilities_by_helper")
    helper_reputation_pre_summary = summarize_helper_reputation_state(
        helper_reputation_state=helper_reputation_state,
        now_ms=int(started_ms),
    )
    lane_plans = plan_parallel_execution(
        txs=list(applied_envs or []),
        validators=self._active_validators(),
        validator_set_hash=str(ctx0.validator_set_hash),
        view=int(ctx0.view),
        leader_id=str(ctx0.leader_id),
        state_snapshot_metadata={
            "validator_epoch": int(ctx0.validator_epoch),
            "quarantined_helper_ids": list(helper_reputation_pre_summary.get("quarantined_helper_ids") or []),
            "helper_capacity_by_helper": dict(helper_capacity_by_helper),
            "helper_capabilities_by_helper": dict(helper_capabilities_by_helper),
            "helper_planning_inputs_source": "state_root",
            "allow_helper_overcommit": True,
        },
    )
    lane_plans = apply_helper_quarantine_to_lane_plans(
        lane_plans,
        helper_reputation_state=helper_reputation_state,
        now_ms=int(started_ms),
    )
    helper_plan_id = canonical_lane_plan_fingerprint(tuple(lane_plans or ()))
    manifest = build_validator_execution_manifest(
        chain_id=str(ctx0.chain_id),
        block_height=int(ctx0.block_height),
        view=int(ctx0.view),
        leader_id=str(ctx0.leader_id),
        validator_epoch=int(ctx0.validator_epoch),
        validator_set_hash=str(ctx0.validator_set_hash),
        validators=self._active_validators(),
        lane_plans=lane_plans,
    )
    signer, coordinator_pubkey, coordinator_privkey = self._local_validator_identity()
    if signer and signer == str(manifest.coordinator_id) and coordinator_pubkey and coordinator_privkey:
        manifest = sign_validator_execution_manifest(
            manifest,
            coordinator_pubkey=coordinator_pubkey,
            coordinator_privkey=coordinator_privkey,
        )
    ctx = self._helper_dispatch_context(
        block_height=int(block_height),
        manifest_hash=manifest.manifest_hash(),
        coordinator_pubkey=str(manifest.coordinator_pubkey),
        manifest_signature=str(manifest.manifest_signature),
        manifest_signed=bool(manifest.manifest_signed),
        manifest_signature_required=bool(manifest.manifest_signed),
        manifest_payload=manifest.to_payload(),
        strict_helper_certificate_consistency=True,
        strict_helper_receipts_root=True,
        strict_helper_state_delta_hash=bool(helper_state_deltas_by_lane),
        plan_id=helper_plan_id,
    )
    journal = HelperLaneJournal(self._helper_lane_journal_path(block_height=int(block_height)))
    store = HelperCertificateStore(
        context=ctx,
        lane_plans=lane_plans,
        helper_pubkeys=self._validator_pubkeys(),
        journal=journal,
        helper_timeout_ms=int(self._helper_timeout_ms),
    )
    lane_rows: list[Json] = []
    for lane_plan in lane_plans:
        row: Json = {
            "lane_id": str(lane_plan.lane_id),
            "helper_id": str(lane_plan.helper_id or ""),
            "helper_candidates": list(getattr(lane_plan, "helper_candidates", ()) or ()),
            "original_helper_id": str(getattr(lane_plan, "original_helper_id", "") or ""),
            "rerouted_from_helper_id": str(getattr(lane_plan, "rerouted_from_helper_id", "") or ""),
            "tx_ids": list(lane_plan.tx_ids),
            "tx_count": len(lane_plan.tx_ids),
            "namespace_prefixes": list(lane_plan.namespace_prefixes),
            "coordinator_id": str(manifest.coordinator_id),
            "plan_id": str(helper_plan_id),
            "routing_mode": str(getattr(lane_plan, "routing_mode", "helper" if lane_plan.helper_id else "serial") or "serial"),
            "lane_class": str(getattr(lane_plan, "lane_class", "serial") or "serial"),
            "lane_tx_types": list(getattr(lane_plan, "lane_tx_types", ()) or ()),
            "capability_restricted": bool(getattr(lane_plan, "capability_restricted", False)),
            "lane_cost_units": int(getattr(lane_plan, "lane_cost_units", 1) or 1),
            "helper_capacity_units": int(getattr(lane_plan, "helper_capacity_units", 0) or 0),
            "descriptor_hash": str(getattr(lane_plan, "descriptor_hash", "") or ""),
            "quarantined_helper": bool(
                lane_plan.helper_id is None and any(
                    item.get("lane_id") == str(lane_plan.lane_id)
                    for item in list(
                        helper_reputation_pre_summary.get("quarantined_lane_overrides")
                        or []
                    )
                )
            ),
            "manifest_hash": str(manifest.manifest_hash()),
            "coordinator_pubkey": str(manifest.coordinator_pubkey),
            "manifest_signature": str(manifest.manifest_signature),
            "manifest_signed": bool(manifest.manifest_signed),
            "strict_helper_certificate_consistency": True,
            "strict_helper_receipts_root": True,
            "strict_helper_state_delta_hash": bool(helper_state_deltas_by_lane),
        }
        if lane_plan.lane_id != "SERIAL" and lane_plan.helper_id:
            store.start_request(lane_id=str(lane_plan.lane_id), started_ms=int(started_ms))
            row["request_started_ms"] = int(started_ms)
        lane_rows.append(row)

    accepted: list[Json] = []
    for cert in dict(helper_certificates or {}).values():
        status = store.ingest_certificate(cert=cert, peer_id=str(cert.helper_id or ""))
        accepted.append(
            {
                "lane_id": str(status.lane_id),
                "helper_id": str(status.helper_id),
                "accepted": bool(status.accepted),
                "code": str(status.code),
                "manifest_hash": str(ctx.manifest_hash),
                "manifest_signed": bool(ctx.manifest_signed),
                "plan_id": str(getattr(cert, "plan_id", "") or helper_plan_id),
            }
        )

    merge_summary: Json = {"attempted": False, "receipt_equivalent": False}
    audit_summary: Json = {
        "planned": 0,
        "selected": 0,
        "checked": 0,
        "fraud_suspected": False,
        "fraud_lane_ids": [],
        "plan": [],
        "results": [],
    }
    audit_results = ()
    accepted_certs = store.accepted_certificates()
    if accepted_certs and helper_receipts_by_lane:
        canonical_receipts_by_tx_id: dict[str, Json] = {}
        for rec in list(receipts or []):
            if not isinstance(rec, dict):
                continue
            tx_id = str(rec.get("tx_id") or "").strip()
            if tx_id:
                canonical_receipts_by_tx_id[tx_id] = dict(rec)

        def _receipt_projection(txs: list[Json]) -> tuple[list[Json], Json]:
            lane_receipts: list[Json] = []
            for tx in list(txs or []):
                tx_id = str(tx.get("tx_id") or "").strip()
                rec = canonical_receipts_by_tx_id.get(tx_id)
                if rec is not None:
                    lane_receipts.append(dict(rec))
            return lane_receipts, {}

        merged = merge_helper_lane_results(
            canonical_txs=list(applied_envs or []),
            lane_plans=lane_plans,
            helper_certificates=accepted_certs,
            serial_executor=_receipt_projection,
            leader_context={
                "chain_id": str(ctx.chain_id),
                "block_height": int(ctx.block_height),
                "view": int(ctx.view),
                "leader_id": str(ctx.leader_id),
                "validator_epoch": int(ctx.validator_epoch),
                "validator_set_hash": str(ctx.validator_set_hash),
                "manifest_hash": str(ctx.manifest_hash),
                "manifest_signed": bool(ctx.manifest_signed),
                "helper_receipts": dict(helper_receipts_by_lane or {}),
                "helper_state_deltas": dict(helper_state_deltas_by_lane or {}),
                "helper_pubkeys": self._validator_pubkeys(),
                "enforce_helper_signature": True,
                "enforce_helper_certificate_consistency": True,
                "enforce_helper_tx_order_hash": True,
                "enforce_helper_namespace_hash": True,
                "enforce_helper_receipts_root": True,
                "enforce_helper_state_delta_hash": bool(helper_state_deltas_by_lane),
            },
        )
        merge_summary = {
            "attempted": True,
            "receipt_equivalent": list(merged.receipts) == list(receipts or []),
            "lane_decisions": [
                {
                    "lane_id": str(item.lane_id),
                    "used_helper": bool(item.used_helper),
                    "fallback_reason": str(item.fallback_reason),
                    "tx_ids": list(item.tx_ids),
                }
                for item in merged.lane_decisions
            ],
        }
        canonical_receipts_by_lane: dict[str, list[Json]] = {}
        for lane_plan in lane_plans:
            lane_receipts, _ = _receipt_projection(list(lane_plan.txs))
            canonical_receipts_by_lane[str(lane_plan.lane_id)] = list(lane_receipts)
        audit_plan = build_lane_audit_plan(
            lane_plans=lane_plans,
            manifest_hash=str(ctx.manifest_hash),
            sample_percent=15,
            always_audit_high_risk=True,
        )
        audit_results = evaluate_lane_audit_plan(
            audit_plan=audit_plan,
            canonical_receipts_by_lane=canonical_receipts_by_lane,
            helper_receipts_by_lane=dict(helper_receipts_by_lane or {}),
            canonical_state_deltas_by_lane={},
            helper_state_deltas_by_lane=dict(helper_state_deltas_by_lane or {}),
            expected_plan_id=helper_plan_id,
        )
        audit_summary = summarize_lane_audit_results(
            audit_plan=audit_plan,
            audit_results=audit_results,
        )

    timed_out = list(store.timed_out_lanes(now_ms=int(started_ms)))
    helper_reputation_state = update_helper_reputation_state(
        helper_reputation_state=helper_reputation_state,
        audit_results=audit_results,
        timed_out_lane_ids=timed_out,
        lane_plans=lane_plans,
        now_ms=int(started_ms),
    )
    helper_reputation_summary = summarize_helper_reputation_state(
        helper_reputation_state=helper_reputation_state,
        now_ms=int(started_ms),
    )
    helper_assignment_summary = summarize_assignment_counts(
        candidates_by_lane={str(plan.lane_id): tuple(getattr(plan, "helper_candidates", ()) or ()) for plan in lane_plans},
        assignment_counts={
            str(plan.helper_id): sum(1 for item in lane_plans if getattr(item, "helper_id", None) == getattr(plan, "helper_id", None))
            for plan in lane_plans
            if getattr(plan, "helper_id", None)
        },
        chosen_by_lane={str(plan.lane_id): str(plan.helper_id or "") for plan in lane_plans if getattr(plan, "helper_id", None)},
        quarantined_helpers=helper_reputation_summary.get("quarantined_helper_ids"),
    )
    helper_capability_summary = summarize_helper_capabilities(helper_capabilities_by_helper)
    helper_capacity_summary = summarize_helper_capacity_usage(
        helper_capacity_by_helper=dict(helper_capacity_by_helper),
        helper_load_by_helper={
            str(plan.helper_id): sum(int(getattr(item, "lane_cost_units", 1) or 1) for item in lane_plans if getattr(item, "helper_id", None) == getattr(plan, "helper_id", None))
            for plan in lane_plans
            if getattr(plan, "helper_id", None)
        },
    )
    validator_model = validator_execution_summary(manifest=manifest, local_node_id=str(self.node_id))
    helper_execution_meta = {
        "enabled": True,
        "mode": "planner_only" if not accepted_certs else "certificate_observed",
        "validator_model": str(validator_model.get("model") or "coordinator_helper"),
        "plan_id": str(helper_plan_id),
        "state_delta_binding": bool(helper_state_deltas_by_lane),
        "manifest_hash": str(validator_model.get("manifest_hash") or ""),
        "manifest_signed": bool(validator_model.get("manifest_signed") or False),
        "coordinator_pubkey": str(validator_model.get("coordinator_pubkey") or ""),
        "manifest_signature": str(validator_model.get("manifest_signature") or ""),
        "coordinator_id": str(manifest.coordinator_id),
        "local_role": str(validator_model.get("local_role") or "observer"),
        "view": int(ctx.view),
        "validator_epoch": int(ctx.validator_epoch),
        "validator_set_hash": str(ctx.validator_set_hash),
        "journal_path": self._helper_lane_journal_path(block_height=int(block_height)),
        "lanes": lane_rows,
        "accepted_certificates": accepted,
        "timed_out_lanes": timed_out,
        "merge_summary": merge_summary,
        "helper_reputation": helper_reputation_summary,
        "helper_assignment": helper_assignment_summary,
        "helper_capacity": helper_capacity_summary,
        "helper_capabilities": helper_capability_summary,
        "helper_planning_inputs": {
            "source": "state_root",
            "state_root_keys": [
                "helper_reputation",
                "helper_capacity_by_helper",
                "helper_capabilities_by_helper",
            ],
            "meta_ignored_for_consensus": True,
        },
        "assignment_summary": validator_model,
    }
    ok_helper_meta, helper_meta_reason = verify_block_helper_plan_metadata(
        helper_execution=helper_execution_meta,
        expected_plan_id=helper_plan_id,
    )
    if not ok_helper_meta:
        raise RuntimeError(f"helper_execution_metadata_invalid:{helper_meta_reason}")
    return helper_execution_meta

