from __future__ import annotations

"""HotStuff/BFT artifact, proposal, vote, QC, timeout, and pending replay delegates.

This module is intentionally a structural extraction from ``weall.runtime.executor``.
It keeps the executor public API stable while shrinking the trusted surface area of
the monolithic facade. The extracted functions still operate on ``WeAllExecutor``
instances and intentionally preserve behavior byte-for-byte where possible.
"""

from weall.runtime.executor import (
    BFT_MIN_VALIDATORS,
    BftTimeout,
    BftVote,
    CONSENSUS_PHASE_BFT_ACTIVE,
    Json,
    QuorumCert,
    _bounded_put,
    _call_admit_bft_block,
    _env_bool,
    _mode,
    _now_ms,
    _safe_int,
    canonical_proposal_message,
    canonical_timeout_message,
    canonical_vote_message,
    compute_block_id,
    effective_bft_enabled,
    ensure_block_hash,
    leader_for_view,
    maybe_trigger_failpoint,
    normalize_consensus_phase,
    normalize_validators,
    os,
    qc_from_json,
    verify_proposal_json,
    verify_qc,
)

from weall.runtime.bft_hotstuff import validator_set_hash
from weall.crypto.sig import sign_signature_for_profile
from weall.crypto.signature_profiles import (
    PQ_MLDSA_V1,
    default_signature_profile_for_mode,
    normalize_signature_profile_id,
)

from weall.runtime import bft_artifact_cache as _bft_artifact_cache
from weall.runtime import bft_diagnostics as _bft_diagnostics
from weall.runtime import bft_fetch_requests as _bft_fetch_requests
from weall.runtime import bft_outbound as _bft_outbound
from weall.runtime import bft_pending_frontier as _bft_pending_frontier
from weall.runtime import bft_votecheck as _bft_votecheck


def _restore_bft_restart_hints(self, *args, **kwargs):
    return _bft_outbound._restore_bft_restart_hints(self, *args, **kwargs)


def _bft_record_event(self, *args, **kwargs):
    return _bft_outbound._bft_record_event(self, *args, **kwargs)


def _persist_pending_bft_artifact(self, *args, **kwargs):
    return _bft_pending_frontier._persist_pending_bft_artifact(self, *args, **kwargs)


def _delete_pending_bft_artifact(self, *args, **kwargs):
    return _bft_pending_frontier._delete_pending_bft_artifact(self, *args, **kwargs)


def _restore_pending_bft_frontier(self, *args, **kwargs):
    return _bft_pending_frontier._restore_pending_bft_frontier(self, *args, **kwargs)


def _bft_outbound_key(self, *args, **kwargs):
    return _bft_outbound._bft_outbound_key(self, *args, **kwargs)


def _bft_enqueue_outbound(self, *args, **kwargs):
    return _bft_outbound._bft_enqueue_outbound(self, *args, **kwargs)


def bft_mark_outbound_sent(self, *args, **kwargs):
    return _bft_outbound.bft_mark_outbound_sent(self, *args, **kwargs)


def bft_pending_outbound_messages(self, *args, **kwargs):
    return _bft_outbound.bft_pending_outbound_messages(self, *args, **kwargs)


def _votecheck_cache_get(self, *args, **kwargs):
    return _bft_votecheck._votecheck_cache_get(self, *args, **kwargs)


def _votecheck_cache_put(self, *args, **kwargs):
    return _bft_votecheck._votecheck_cache_put(self, *args, **kwargs)


def _proposal_votecheck_budget_ok(self, *args, **kwargs):
    return _bft_votecheck._proposal_votecheck_budget_ok(self, *args, **kwargs)


def _spec_exec_paths_for_slot(self, *args, **kwargs):
    return _bft_votecheck._spec_exec_paths_for_slot(self, *args, **kwargs)


def _make_spec_exec_slot(self, *args, **kwargs):
    return _bft_votecheck._make_spec_exec_slot(self, *args, **kwargs)


def _acquire_spec_exec_slot(self, *args, **kwargs):
    return _bft_votecheck._acquire_spec_exec_slot(self, *args, **kwargs)


def _release_spec_exec_slot(self, *args, **kwargs):
    return _bft_votecheck._release_spec_exec_slot(self, *args, **kwargs)


def _reset_spec_exec_slot(self, *args, **kwargs):
    return _bft_votecheck._reset_spec_exec_slot(self, *args, **kwargs)


def _proposal_votecheck_static_ok(self, *args, **kwargs):
    return _bft_votecheck._proposal_votecheck_static_ok(self, *args, **kwargs)


def _validate_remote_proposal_for_vote(self, *args, **kwargs):
    return _bft_votecheck._validate_remote_proposal_for_vote(self, *args, **kwargs)


def _ensure_recent_bft_artifact_caches(self, *args, **kwargs):
    return _bft_artifact_cache._ensure_recent_bft_artifact_caches(self, *args, **kwargs)


def _bft_sender_budget_key(self, *args, **kwargs):
    return _bft_artifact_cache._bft_sender_budget_key(self, *args, **kwargs)


def _consume_bft_sender_budget(self, *args, **kwargs):
    return _bft_artifact_cache._consume_bft_sender_budget(self, *args, **kwargs)


def _remember_recent_bft_proposal(self, *args, **kwargs):
    return _bft_artifact_cache._remember_recent_bft_proposal(self, *args, **kwargs)


def _recent_bft_qc_key(self, *args, **kwargs):
    return _bft_artifact_cache._recent_bft_qc_key(self, *args, **kwargs)


def _has_recent_bft_qc(self, *args, **kwargs):
    return _bft_artifact_cache._has_recent_bft_qc(self, *args, **kwargs)


def _record_recent_bft_qc(self, *args, **kwargs):
    return _bft_artifact_cache._record_recent_bft_qc(self, *args, **kwargs)


def _remember_recent_bft_qc(self, *args, **kwargs):
    return _bft_artifact_cache._remember_recent_bft_qc(self, *args, **kwargs)


def _remember_recent_bft_vote(self, *args, **kwargs):
    return _bft_artifact_cache._remember_recent_bft_vote(self, *args, **kwargs)


def _remember_recent_bft_timeout(self, *args, **kwargs):
    return _bft_artifact_cache._remember_recent_bft_timeout(self, *args, **kwargs)


def _bft_artifact_shape_fast_fail(self, *args, **kwargs):
    return _bft_artifact_cache._bft_artifact_shape_fast_fail(self, *args, **kwargs)


def bft_on_proposal(self, proposal: Json) -> Json | None:
    """Handle a leader proposal.

    Returns a vote JSON if we should vote, else None.
    """
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
    # while preserving non-production paths when signature verification is disabled.
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
    qc = self.bft_handle_vote(vote)
    return qc.to_json() if qc is not None else None

def bft_on_qc(self, qcj: Json) -> ExecutorMeta | None:
    """Handle a QC and commit if it refers to a known block."""
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
    qc = self.bft_handle_timeout(timeoutj)
    return qc.to_json() if qc is not None else None

def bft_drive_timeouts(self, now_ms: int) -> list[Json]:
    """Return any timeout messages we should broadcast."""
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
        profile = normalize_signature_profile_id(rec.get("sig_profile") or rec.get("signature_profile"))
        pk = str(rec.get("pubkey") or "").strip()
        if profile == PQ_MLDSA_V1:
            pubkeys = rec.get("pubkeys") if isinstance(rec.get("pubkeys"), dict) else {}
            pk = str(pubkeys.get("mldsa") or pk).strip()
        if pk:
            out[str(acct).strip()] = pk
    return out

def _validator_signature_profiles(self) -> dict[str, str]:
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
        profile = normalize_signature_profile_id(rec.get("sig_profile") or rec.get("signature_profile"))
        if not profile:
            profile = PQ_MLDSA_V1
        out[str(acct).strip()] = profile
    return out


def _local_validator_sig_profile(self) -> str:
    explicit = normalize_signature_profile_id(os.environ.get("WEALL_NODE_SIG_PROFILE"))
    if explicit:
        return explicit
    signer = self._local_validator_account()
    profile = self._validator_signature_profiles().get(signer, "")
    if profile:
        return profile
    return default_signature_profile_for_mode()


def _current_validator_epoch(self) -> int:
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
    if _mode() != "prod":
        return True
    return self._current_consensus_phase() == CONSENSUS_PHASE_BFT_ACTIVE

def _pending_consensus_phase(self) -> str:
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
    return (self._current_validator_epoch(), self._current_validator_set_hash())

def _bft_strict_epoch_binding_enabled(self) -> bool:
    raw = os.environ.get("WEALL_BFT_STRICT_EPOCH_BINDING")
    if raw is not None:
        return str(raw).strip().lower() in {"1", "true", "yes", "y", "on"}
    return (os.environ.get("WEALL_MODE") or "prod").strip().lower() == "prod"

def _bft_epoch_binding_matches(self, payload: Json) -> bool:
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

def _prune_pending_bft_artifacts_on_local_validator_transition(self, *args, **kwargs):
    return _bft_pending_frontier._prune_pending_bft_artifacts_on_local_validator_transition(self, *args, **kwargs)


def _local_validator_account(self) -> str:
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
    signer = self._local_validator_account()
    pubkey = str(os.environ.get("WEALL_NODE_PUBKEY") or "").strip()
    privkey = str(os.environ.get("WEALL_NODE_PRIVKEY") or "").strip()
    if not signer or not pubkey or not privkey:
        return ("", "", "")
    expected = str(self._validator_pubkeys().get(signer) or "").strip()
    if expected and expected != pubkey:
        return ("", "", "")
    return (signer, pubkey, privkey)

def _cache_known_block_hash(self, *args, **kwargs):
    return _bft_pending_frontier._cache_known_block_hash(self, *args, **kwargs)


def _lookup_committed_block_hash_index(self, *args, **kwargs):
    return _bft_pending_frontier._lookup_committed_block_hash_index(self, *args, **kwargs)


def _lookup_committed_block_id_by_hash(self, *args, **kwargs):
    return _bft_pending_frontier._lookup_committed_block_id_by_hash(self, *args, **kwargs)


def _known_block_hash_for_id(self, *args, **kwargs):
    return _bft_pending_frontier._known_block_hash_for_id(self, *args, **kwargs)


def _known_block_id_for_hash(self, *args, **kwargs):
    return _bft_pending_frontier._known_block_id_for_hash(self, *args, **kwargs)


def _is_conflicted_block_id(self, *args, **kwargs):
    return _bft_pending_frontier._is_conflicted_block_id(self, *args, **kwargs)


def _is_conflicted_block_hash(self, *args, **kwargs):
    return _bft_pending_frontier._is_conflicted_block_hash(self, *args, **kwargs)


def _drop_pending_candidate_artifacts(self, *args, **kwargs):
    return _bft_pending_frontier._drop_pending_candidate_artifacts(self, *args, **kwargs)


def _mark_block_id_conflict(self, *args, **kwargs):
    return _bft_pending_frontier._mark_block_id_conflict(self, *args, **kwargs)


def _mark_block_hash_conflict(self, *args, **kwargs):
    return _bft_pending_frontier._mark_block_hash_conflict(self, *args, **kwargs)


def _qc_identity_conflicts(self, *args, **kwargs):
    return _bft_pending_frontier._qc_identity_conflicts(self, *args, **kwargs)


def _block_identity_conflicts(self, *args, **kwargs):
    return _bft_pending_frontier._block_identity_conflicts(self, *args, **kwargs)


def _block_height_hint(self, *args, **kwargs):
    return _bft_pending_frontier._block_height_hint(self, *args, **kwargs)


def _has_local_block(self, *args, **kwargs):
    return _bft_pending_frontier._has_local_block(self, *args, **kwargs)


def _index_pending_remote_block(self, *args, **kwargs):
    return _bft_pending_frontier._index_pending_remote_block(self, *args, **kwargs)


def _index_quarantined_remote_block(self, *args, **kwargs):
    return _bft_pending_frontier._index_quarantined_remote_block(self, *args, **kwargs)


def _quarantine_remote_block(self, *args, **kwargs):
    return _bft_pending_frontier._quarantine_remote_block(self, *args, **kwargs)


def _drop_quarantined_remote_artifacts(self, *args, **kwargs):
    return _bft_pending_frontier._drop_quarantined_remote_artifacts(self, *args, **kwargs)


def _put_pending_remote_block(self, *args, **kwargs):
    return _bft_pending_frontier._put_pending_remote_block(self, *args, **kwargs)


def _promote_quarantined_remote_block(self, *args, **kwargs):
    return _bft_pending_frontier._promote_quarantined_remote_block(self, *args, **kwargs)


def _index_pending_candidate(self, *args, **kwargs):
    return _bft_pending_frontier._index_pending_candidate(self, *args, **kwargs)


def _index_pending_missing_qc(self, *args, **kwargs):
    return _bft_pending_frontier._index_pending_missing_qc(self, *args, **kwargs)


def _put_pending_missing_qc(self, *args, **kwargs):
    return _bft_pending_frontier._put_pending_missing_qc(self, *args, **kwargs)


def _drop_pending_missing_qc_aliases(self, *args, **kwargs):
    return _bft_pending_frontier._drop_pending_missing_qc_aliases(self, *args, **kwargs)


def _remove_pending_missing_qc(self, *args, **kwargs):
    return _bft_pending_frontier._remove_pending_missing_qc(self, *args, **kwargs)


def _pending_missing_qc_json(self, *args, **kwargs):
    return _bft_pending_frontier._pending_missing_qc_json(self, *args, **kwargs)


def _pending_missing_qc_entries(self, *args, **kwargs):
    return _bft_pending_frontier._pending_missing_qc_entries(self, *args, **kwargs)


def _drop_pending_hash_aliases(self, *args, **kwargs):
    return _bft_pending_frontier._drop_pending_hash_aliases(self, *args, **kwargs)


def _pending_block_identity_tuple(self, *args, **kwargs):
    return _bft_pending_frontier._pending_block_identity_tuple(self, *args, **kwargs)


def _ordered_pending_block_ids(self, *args, **kwargs):
    return _bft_pending_frontier._ordered_pending_block_ids(self, *args, **kwargs)


def _drop_pending_remote_artifacts(self, *args, **kwargs):
    return _bft_pending_frontier._drop_pending_remote_artifacts(self, *args, **kwargs)


def _bft_speculative_blocks_map(self, *args, **kwargs):
    return _bft_pending_frontier._bft_speculative_blocks_map(self, *args, **kwargs)


def _bft_pending_block_json(self, *args, **kwargs):
    return _bft_pending_frontier._bft_pending_block_json(self, *args, **kwargs)


def _bft_pending_block_json_by_hash(self, *args, **kwargs):
    return _bft_pending_frontier._bft_pending_block_json_by_hash(self, *args, **kwargs)


def _resolve_pending_block_identity(self, *args, **kwargs):
    return _bft_pending_frontier._resolve_pending_block_identity(self, *args, **kwargs)


def _bft_pending_artifact_matches_current_epoch(self, *args, **kwargs):
    return _bft_pending_frontier._bft_pending_artifact_matches_current_epoch(self, *args, **kwargs)


def _prune_pending_bft_artifacts(self, *args, **kwargs):
    return _bft_pending_frontier._prune_pending_bft_artifacts(self, *args, **kwargs)


def _bft_block_is_applyable_finalized_descendant(self, *args, **kwargs):
    return _bft_pending_frontier._bft_block_is_applyable_finalized_descendant(self, *args, **kwargs)


def _bft_parent_ready_for_apply(self, *args, **kwargs):
    return _bft_pending_frontier._bft_parent_ready_for_apply(self, *args, **kwargs)


def bft_try_apply_pending_remote_blocks(self, *args, **kwargs):
    return _bft_pending_frontier.bft_try_apply_pending_remote_blocks(self, *args, **kwargs)


def _bft_try_apply_pending_remote_blocks_followup(self, *args, **kwargs):
    return _bft_pending_frontier._bft_try_apply_pending_remote_blocks_followup(self, *args, **kwargs)


def _committed_chain_recent_timestamps_ms(self, *, limit: int = 11) -> list[int]:
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
    vals = sorted(self._committed_chain_recent_timestamps_ms(limit=limit))
    if not vals:
        return _safe_int(self.state.get("tip_ts_ms") or self.state.get("last_block_ts_ms"), 0)
    return int(vals[len(vals) // 2])

def chain_time_floor_ms(self) -> int:
    tip_ts_ms = _safe_int(self.state.get("tip_ts_ms") or self.state.get("last_block_ts_ms"), 0)
    mtp_ms = self.committed_chain_median_time_past_ms()
    return max(int(tip_ts_ms), int(mtp_ms))

def bft_diagnostics(self, *args, **kwargs):
    return _bft_diagnostics.bft_diagnostics(self, *args, **kwargs)


def bft_cache_remote_block(self, *args, **kwargs):
    return _bft_pending_frontier.bft_cache_remote_block(self, *args, **kwargs)


def _ensure_pending_fetch_budgets(self, *args, **kwargs):
    return _bft_fetch_requests._ensure_pending_fetch_budgets(self, *args, **kwargs)


def _bounded_fetch_request_descriptors(self, *args, **kwargs):
    return _bft_fetch_requests._bounded_fetch_request_descriptors(self, *args, **kwargs)


def bft_pending_fetch_request_descriptors(self, *args, **kwargs):
    return _bft_fetch_requests.bft_pending_fetch_request_descriptors(self, *args, **kwargs)


def _resolve_fetch_request_descriptor(self, *args, **kwargs):
    return _bft_fetch_requests._resolve_fetch_request_descriptor(self, *args, **kwargs)


def bft_resolved_pending_fetch_request_descriptors(self, *args, **kwargs):
    return _bft_fetch_requests.bft_resolved_pending_fetch_request_descriptors(self, *args, **kwargs)


def bft_pending_fetch_requests(self, *args, **kwargs):
    return _bft_fetch_requests.bft_pending_fetch_requests(self, *args, **kwargs)


def bft_resolve_fetch_request_descriptor(self, *args, **kwargs):
    return _bft_fetch_requests.bft_resolve_fetch_request_descriptor(self, *args, **kwargs)


def bft_recent_rejection_summary(self, *args, **kwargs):
    return _bft_diagnostics.bft_recent_rejection_summary(self, *args, **kwargs)


def bft_current_view(self, *args, **kwargs):
    return _bft_diagnostics.bft_current_view(self, *args, **kwargs)


def bft_current_validator_epoch(self, *args, **kwargs):
    return _bft_diagnostics.bft_current_validator_epoch(self, *args, **kwargs)


def bft_current_validator_set_hash(self, *args, **kwargs):
    return _bft_diagnostics.bft_current_validator_set_hash(self, *args, **kwargs)


def bft_set_view(self, view: int) -> None:
    requested = int(view)
    current = int(self._bft.view)
    if requested > current:
        self._bft.view = requested
    self._persist_bft_state()

def _prune_bft_liveness_caches_for_current_epoch(self) -> None:
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
        sig_profile = _local_validator_sig_profile(self)
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
            sig_profile=sig_profile,
        )
        blk["proposer_pubkey"] = proposer_pubkey
        blk["proposer_sig_profile"] = sig_profile
        blk["proposer_signature"] = {"alg": "ML-DSA", "pubkey": proposer_pubkey}
        blk["proposer_sig"] = sign_signature_for_profile(
            sig_profile=sig_profile, message=msg, privkey=proposer_privkey, encoding="hex"
        )
        blk["proposer_signature"]["sig"] = blk["proposer_sig"]

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
        sig_profile=normalize_signature_profile_id(vote_json.get("sig_profile") or vote_json.get("signature_profile")),
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
    if not self._validator_signing_permitted():
        return None
    if not self._bft_phase_allows_artifact_processing():
        return None

    signer, pubkey, privkey = self._local_validator_identity()
    if not signer or not pubkey or not privkey:
        return None

    validator_epoch = self._current_validator_epoch()
    validator_set_hash = self._current_validator_set_hash() if int(validator_epoch) > 0 else ""
    sig_profile = _local_validator_sig_profile(self)
    msg = canonical_vote_message(
        chain_id=self.chain_id,
        view=int(view),
        block_id=str(block_id),
        block_hash=str(block_hash),
        parent_id=str(parent_id),
        signer=signer,
        validator_epoch=int(validator_epoch),
        validator_set_hash=validator_set_hash,
        sig_profile=sig_profile,
    )
    sig = sign_signature_for_profile(sig_profile=sig_profile, message=msg, privkey=privkey, encoding="hex")

    vote = BftVote(
        chain_id=self.chain_id,
        view=int(view),
        block_id=str(block_id),
        block_hash=str(block_hash),
        parent_id=str(parent_id),
        signer=signer,
        pubkey=pubkey,
        sig=sig,
        sig_profile=sig_profile,
        validator_epoch=int(validator_epoch),
        validator_set_hash=validator_set_hash,
    )
    out = vote.to_json()
    out["consensus_phase"] = self._current_consensus_phase()
    return out

def bft_make_timeout(self, *, view: int) -> Json | None:
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
    sig_profile = _local_validator_sig_profile(self)
    msg = canonical_timeout_message(
        chain_id=self.chain_id,
        view=int(view),
        high_qc_id=high_qc_id,
        signer=signer,
        validator_epoch=int(validator_epoch),
        validator_set_hash=validator_set_hash,
        sig_profile=sig_profile,
    )
    sig = sign_signature_for_profile(sig_profile=sig_profile, message=msg, privkey=privkey, encoding="hex")
    self._bft.note_timeout_emitted(view=int(view))
    tmo = BftTimeout(
        chain_id=self.chain_id,
        view=int(view),
        high_qc_id=high_qc_id,
        signer=signer,
        pubkey=pubkey,
        sig=sig,
        sig_profile=sig_profile,
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
        sig_profile=normalize_signature_profile_id(timeout_json.get("sig_profile") or timeout_json.get("signature_profile")),
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

