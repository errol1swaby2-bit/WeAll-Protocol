from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from weall.runtime.runtime_env import (
    _bounded_put,
    _compact_error_text,
    _consensus_fail_closed,
    _env_bool,
    _env_int,
    _format_commit_failure,
    _mode,
    _safe_int,
)
from weall.runtime.runtime_time import _now_ms

from weall.crypto.sig import sign_ed25519
from weall.ledger.roles_schema import ensure_roles_schema
from weall.ledger.state import LedgerView
from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import StateSyncService, StateSyncVerifyError, build_snapshot_anchor
from weall.runtime.attestation_pool import PersistentAttestationPool
from weall.runtime.bft_hotstuff import (
    BFT_MIN_VALIDATORS,
    CONSENSUS_PHASE_BFT_ACTIVE,
    BftTimeout,
    BftVote,
    HotStuffBFT,
    QuorumCert,
    canonical_proposal_message,
    canonical_timeout_message,
    canonical_vote_message,
    is_descendant,
    leader_for_view,
    normalize_consensus_phase,
    normalize_validators,
    qc_from_json,
    validator_set_hash,
    verify_proposal_json,
    verify_qc,
)
from weall.runtime.bft_journal import BftJournal
from weall.runtime.block_admission import admit_bft_block, admit_bft_commit_block, admit_block_txs
from weall.runtime.bootstrap_audit import record_bootstrap_tier2_grant
from weall.runtime.block_hash import RECENT_BLOCK_ANCHOR_ACTIVATION_HEIGHT, compute_block_hash, compute_helper_execution_root, compute_receipts_root, compute_recent_block_anchor, ensure_block_hash, make_block_header, recent_block_ids_from_state, recent_block_anchor_required_for_height
from weall.runtime.block_id import compute_block_id
from weall.runtime.chain_config import load_chain_config
from weall.runtime.chain_manifest import load_chain_manifest
from weall.runtime.constitutional_clock import (
    commit_clock_policy_to_state,
    expected_block_time_ms,
    is_too_early,
    policy_from_manifest,
    policy_to_json,
    procedure_height as constitutional_procedure_height,
)
from weall.runtime.gov_engine import tick_governance_lifecycle
from weall.runtime.dispute_engine import tick_dispute_lifecycle
from weall.runtime.domain_apply import ApplyError, apply_tx_atomic_meta
from weall.runtime.executor_boot import prepare_executor_init_paths
from weall.runtime.failpoints import maybe_trigger_failpoint
from weall.runtime.mempool import PersistentMempool, compute_tx_id
from weall.runtime.node_lifecycle import evaluate_node_lifecycle_status
from weall.runtime.node_runtime_config import PRODUCTION_SERVICE
from weall.runtime.runtime_authority import effective_bft_enabled
from weall.runtime.poh.async_scheduler import schedule_poh_async_system_txs
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs
from weall.runtime.poh.live_scheduler import schedule_poh_live_system_txs
from weall.runtime.reputation_accrual import schedule_reputation_accrual_system_txs
from weall.runtime.node_operator_scheduler import schedule_node_operator_system_txs
from weall.runtime.protocol_profile import (
    GENESIS_CREATED_MS,
    PRODUCTION_CONSENSUS_PROFILE,
    PROTOCOL_VERSION,
    runtime_clock_skew_warn_ms,
    runtime_max_block_future_drift_ms,
    runtime_mode,
    runtime_startup_clock_hard_fail_ms,
    runtime_vrf_required,
    validate_runtime_consensus_profile,
)
from weall.runtime.helper_dispatch import HelperCertificateStore, HelperDispatchContext
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.parallel_execution import (
    canonical_lane_plan_fingerprint,
    merge_helper_lane_results,
    plan_parallel_execution,
    verify_block_helper_plan_metadata,
)
from weall.runtime.helper_certificates import HelperExecutionCertificate
from weall.runtime.helper_assignment import summarize_assignment_counts
from weall.runtime.helper_capabilities import summarize_helper_capabilities
from weall.runtime.helper_capacity import summarize_helper_capacity_usage
from weall.runtime.helper_audit import (
    build_lane_audit_plan,
    evaluate_lane_audit_plan,
    summarize_lane_audit_results,
)
from weall.runtime.helper_reputation import (
    apply_helper_quarantine_to_lane_plans,
    summarize_helper_reputation_state,
    update_helper_reputation_state,
)
from weall.runtime.validator_execution_model import (
    build_validator_execution_manifest,
    sign_validator_execution_manifest,
    validator_execution_summary,
)
from weall.runtime.reputation_units import (
    REPUTATION_SCALE,
    account_reputation_units,
    sync_account_reputation,
    threshold_to_units,
    units_to_reputation,
    units_to_reputation_text,
)
from weall.runtime.sqlite_db import SqliteDB, SqliteLedgerStore, _canon_json
from weall.runtime.state_hash import compute_state_root

# SqliteLedgerStore is defined in weall.runtime.sqlite_db in this repo layout
from weall.runtime.system_tx_engine import prune_emitted_system_queue, system_tx_emitter, validate_system_tx_queue_binding
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.vrf_sig import make_vrf_record, verify_vrf_record
from weall.tx.canon import TxIndex

Json = dict[str, Any]

# Rehearsal env-to-genesis parameter source markers.
# Keep these literal mappings visible in executor.py because several reviewer
# regression tests assert the public runtime facade still documents the local
# rehearsal env contract even though the implementation lives in
# genesis_bootstrap.py after the executor module split.
_REHEARSAL_GENESIS_PARAM_ENV_MARKERS: dict[str, str] = {
    "async_n_jurors": "WEALL_POH_ASYNC_N_JURORS",
    "async_min_reviews": "WEALL_POH_ASYNC_MIN_REVIEWS",
    "async_approval_threshold": "WEALL_POH_ASYNC_APPROVAL_THRESHOLD",
    "async_rejection_threshold": "WEALL_POH_ASYNC_REJECTION_THRESHOLD",
    "async_min_rep_milli": "WEALL_POH_ASYNC_MIN_REP_MILLI",
    "live_min_rep_milli": "WEALL_POH_LIVE_MIN_REP_MILLI",
    "live_pass_threshold_num": "WEALL_POH_LIVE_PASS_THRESHOLD_NUM",
    "live_pass_threshold_den": "WEALL_POH_LIVE_PASS_THRESHOLD_DEN",
    "live_partial_until_height": "WEALL_POH_LIVE_PARTIAL_UNTIL_HEIGHT",
    "live_partial_panels_enabled": "WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED",
}
# Static reviewer marker preserved from the pre-split executor body:
# poh_params["live_partial_panels_enabled"] = True


def _call_admit_bft_block(
    *,
    block: Json,
    state: Json,
    bft_enabled: bool,
) -> tuple[bool, Any]:
    try:
        return admit_bft_block(block=block, state=state, bft_enabled=bft_enabled)
    except TypeError as exc:
        if "unexpected keyword argument 'bft_enabled'" not in str(exc):
            raise
        return admit_bft_block(block, state)


def _call_admit_bft_commit_block(
    *,
    block: Json,
    state: Json,
    blocks_map: Mapping[str, Json],
    bft_enabled: bool,
) -> tuple[bool, Any]:
    try:
        return admit_bft_commit_block(
            block=block,
            state=state,
            blocks_map=blocks_map,
            bft_enabled=bft_enabled,
        )
    except TypeError as exc:
        if "unexpected keyword argument 'bft_enabled'" not in str(exc):
            raise
        return admit_bft_commit_block(block, state, blocks_map)


_TRANSITION_GUARDRAIL_REASONS: tuple[str, ...] = (
    "treasury_spend_open",
    "group_treasury_spend_open",
    "emissary_election_open",
)


def _normalize_mempool_selection_policy(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    if s in {"canonical", "canon", "stable", "deterministic"}:
        return "canonical"
    return "fifo"


def _sanitize_mempool_selection_marker(
    marker: Any, *, default_policy: str = "canonical", default_limit: int = 0
) -> Json:
    base = marker if isinstance(marker, dict) else {}
    selected_tx_ids = base.get("selected_tx_ids") if isinstance(base, dict) else []
    return {
        "policy": _normalize_mempool_selection_policy(base.get("policy") if isinstance(base, dict) else default_policy),
        "requested_limit": int((base.get("requested_limit") if isinstance(base, dict) else default_limit) or 0),
        "fetched_count": int((base.get("fetched_count") if isinstance(base, dict) else 0) or 0),
        "selected_count": int((base.get("selected_count") if isinstance(base, dict) else 0) or 0),
        "invalid_count": int((base.get("invalid_count") if isinstance(base, dict) else 0) or 0),
        "rejected_count": int((base.get("rejected_count") if isinstance(base, dict) else 0) or 0),
        "selected_tx_ids": [str(x) for x in list(selected_tx_ids or [])[:64]] if isinstance(selected_tx_ids, list) else [],
    }


def _normalize_helper_timeout_ms(raw: Any, default: int = 5000) -> int:
    return max(1, _safe_int(raw, default))


def _helper_execution_profile(*, helper_mode_enabled: bool, helper_fast_path_enabled: bool, helper_timeout_ms: int) -> Json:
    return {
        "helper_mode_enabled": bool(helper_mode_enabled),
        "helper_fast_path_enabled": bool(helper_fast_path_enabled),
        "helper_timeout_ms": int(_normalize_helper_timeout_ms(helper_timeout_ms, 5000)),
        "enforce_helper_signature": True,
        "enforce_helper_certificate_consistency": True,
        "enforce_helper_tx_order_hash": True,
        "enforce_helper_namespace_hash": True,
        "enforce_helper_receipts_root": True,
    }


def _sanitize_helper_execution_profile(marker: Any) -> Json:
    base = marker if isinstance(marker, dict) else {}
    return {
        "helper_mode_enabled": bool(base.get("helper_mode_enabled", False)),
        "helper_fast_path_enabled": bool(base.get("helper_fast_path_enabled", False)),
        "helper_timeout_ms": int(_normalize_helper_timeout_ms(base.get("helper_timeout_ms"), 5000)),
        "enforce_helper_signature": bool(base.get("enforce_helper_signature", True)),
        "enforce_helper_certificate_consistency": bool(base.get("enforce_helper_certificate_consistency", True)),
        "enforce_helper_tx_order_hash": bool(base.get("enforce_helper_tx_order_hash", True)),
        "enforce_helper_namespace_hash": bool(base.get("enforce_helper_namespace_hash", True)),
        "enforce_helper_receipts_root": bool(base.get("enforce_helper_receipts_root", True)),
    }


def _helper_execution_profile_hash(profile: Any) -> str:
    safe = _sanitize_helper_execution_profile(profile)
    return hashlib.sha256(_canon_json(safe).encode("utf-8")).hexdigest()


def _state_meta_view(state: Mapping[str, Any] | Any) -> Mapping[str, Any]:
    meta = state.get("meta") if isinstance(state, Mapping) else {}
    return meta if isinstance(meta, Mapping) else {}


def _pinned_mempool_selection_policy(state: Mapping[str, Any] | Any, fallback: str) -> str:
    meta = _state_meta_view(state)
    return _normalize_mempool_selection_policy(meta.get("mempool_selection_policy") or fallback or "canonical")


def _genesis_bootstrap_profile_hash(profile: Mapping[str, Any] | Any) -> str:
    safe = profile if isinstance(profile, Mapping) else {}
    canon = json.dumps(dict(safe), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _pinned_helper_execution_profile(state: Mapping[str, Any] | Any, fallback: Mapping[str, Any] | Any) -> Json:
    meta = _state_meta_view(state)
    marker = meta.get("helper_execution_profile") if isinstance(meta, Mapping) else {}
    if isinstance(marker, Mapping) and marker:
        return _sanitize_helper_execution_profile(marker)
    return _sanitize_helper_execution_profile(fallback)


def _summarize_transition_guardrail_receipts(
    receipts: list[Json],
    *,
    height: int,
    block_id: str,
) -> Json:
    reason_counts: dict[str, int] = {}
    tx_type_counts: dict[str, dict[str, int]] = {}
    recent_events: list[Json] = []
    for raw in receipts:
        if not isinstance(raw, dict) or bool(raw.get("ok") or False):
            continue
        reason = str(raw.get("reason") or "").strip()
        if reason not in _TRANSITION_GUARDRAIL_REASONS:
            continue
        tx_type = str(raw.get("tx_type") or "").strip() or "unknown"
        reason_counts[reason] = int(reason_counts.get(reason, 0)) + 1
        by_type = tx_type_counts.setdefault(tx_type, {})
        by_type[reason] = int(by_type.get(reason, 0)) + 1
        event: Json = {
            "tx_id": str(raw.get("tx_id") or ""),
            "tx_type": tx_type,
            "signer": str(raw.get("signer") or ""),
            "reason": reason,
            "code": str(raw.get("code") or "apply_error"),
        }
        details = raw.get("details")
        if isinstance(details, dict) and details:
            event["details"] = dict(details)
        recent_events.append(event)
    if not reason_counts:
        return {}
    return {
        "height": int(height),
        "block_id": str(block_id or ""),
        "rejection_count": int(sum(reason_counts.values())),
        "reason_counts": {k: int(reason_counts[k]) for k in sorted(reason_counts)},
        "tx_type_counts": {
            tx_type: {reason: int(counts[reason]) for reason in sorted(counts)}
            for tx_type, counts in sorted(tx_type_counts.items())
        },
        "recent_events": recent_events[-10:],
    }




def _ensure_parent(path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
















def _block_hash_from_any(block: Json) -> str:
    try:
        blk, bh = ensure_block_hash(dict(block))
        return str(bh or blk.get("block_hash") or "").strip()
    except Exception:
        return str(block.get("block_hash") or "").strip()


# Timestamp policy for produced blocks.
MAX_BLOCK_FUTURE_DRIFT_MS = runtime_max_block_future_drift_ms()
MAX_BLOCK_TIME_ADVANCE_MS = MAX_BLOCK_FUTURE_DRIFT_MS
CLOCK_SKEW_WARN_MS = runtime_clock_skew_warn_ms()
STARTUP_CLOCK_HARD_FAIL_MS = runtime_startup_clock_hard_fail_ms()


@dataclass
class ExecutorMeta:
    ok: bool
    error: str = ""
    height: int = 0
    block_id: str = ""
    applied_count: int = 0


class ExecutorError(RuntimeError):
    pass




def _resolve_repo_relative_path(raw: str) -> Path:
    path = Path(str(raw or "").strip()).expanduser()
    if path.is_absolute():
        return path
    if path.exists():
        return path.resolve()
    return (Path(__file__).resolve().parents[3] / path).resolve()


def _production_genesis_ledger_path() -> str:
    raw = str(os.environ.get("WEALL_GENESIS_LEDGER_PATH") or "").strip()
    if raw:
        return str(_resolve_repo_relative_path(raw))
    if _mode() == "prod" and _env_bool("WEALL_REQUIRE_PRODUCTION_GENESIS_LEDGER", False):
        default = Path(__file__).resolve().parents[3] / "configs" / "genesis.ledger.prod.json"
        return str(default.resolve())
    return ""


def _load_production_genesis_ledger_or_none(*, chain_id: str) -> Json | None:
    path_raw = _production_genesis_ledger_path()
    if not path_raw:
        return None
    path = Path(path_raw)
    if not path.is_file():
        raise ExecutorError(f"production_genesis_ledger_missing:{path}")
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ExecutorError(f"production_genesis_ledger_invalid_json:{path}") from exc
    if not isinstance(obj, dict):
        raise ExecutorError("production_genesis_ledger_root_not_object")
    if str(obj.get("chain_id") or "").strip() != str(chain_id or "").strip():
        raise ExecutorError("production_genesis_ledger_chain_id_mismatch")
    try:
        height = int(obj.get("height") or 0)
    except Exception:
        height = -1
    if height != 0:
        raise ExecutorError("production_genesis_ledger_height_not_zero")

    manifest_path = str(
        os.environ.get("WEALL_CHAIN_MANIFEST_PATH")
        or os.environ.get("WEALL_CHAIN_MANIFEST")
        or ""
    ).strip()
    if manifest_path:
        mpath = _resolve_repo_relative_path(manifest_path)
    else:
        mpath = Path(__file__).resolve().parents[3] / "configs" / "chains" / "weall-genesis.json"
    if mpath.is_file():
        try:
            manifest = json.loads(mpath.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ExecutorError(f"production_genesis_manifest_invalid_json:{mpath}") from exc
        if isinstance(manifest, dict):
            expected_hash = str(manifest.get("genesis_hash") or "").strip().lower()
            expected_root = str(manifest.get("genesis_state_root") or "").strip().lower()
            canon = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            actual_hash = hashlib.sha256(canon.encode("utf-8")).hexdigest()
            if expected_hash and expected_hash != actual_hash:
                raise ExecutorError("production_genesis_ledger_manifest_hash_mismatch")
            try:
                from weall.runtime.state_hash import compute_state_root

                actual_root = str(compute_state_root(obj)).strip().lower()
            except Exception:
                actual_root = actual_hash
            if expected_root and expected_root != actual_root:
                raise ExecutorError("production_genesis_ledger_manifest_state_root_mismatch")
    obj.setdefault("meta", {})
    if isinstance(obj.get("meta"), dict):
        obj["meta"].setdefault("production_genesis_ledger_path", str(path))
        obj["meta"].setdefault("production_genesis_ledger_loaded", True)
    return obj

class WeAllExecutor:
    """WeAll executor using SQLite for persistence (ledger + queues)."""

    def __init__(
        self,
        *,
        db_path: str,
        node_id: str,
        chain_id: str,
        tx_index_path: str,
    ) -> None:
        self.node_id = str(node_id)
        self.chain_id = str(chain_id)
        self.tx_index_path = str(tx_index_path)

        _init_paths = prepare_executor_init_paths(
            db_path=str(db_path),
            tx_index_path=self.tx_index_path,
        )
        self.db_path = _init_paths.db_path
        db_file_existed_before_init = _init_paths.db_file_existed_before_init
        self.aux_db_path = _init_paths.aux_db_path

        validate_runtime_consensus_profile()

        self._schema_version_cached = _init_paths.schema_version
        self._tx_index_hash = _init_paths.tx_index_hash

        self._db = SqliteDB(path=self.db_path)
        self._db.init_schema()
        self._aux_db = SqliteDB(path=self.aux_db_path)
        self._aux_db.init_schema()

        self._ledger_store = SqliteLedgerStore(db=self._db)
        # Keep mempool in the main DB so block commit can atomically persist
        # block rows, tx index updates, snapshot updates, and mempool cleanup in
        # one transaction. Move only non-consensus local pools to the aux DB.
        self._mempool = PersistentMempool(db=self._db, chain_id=self.chain_id)
        self._att_pool = PersistentAttestationPool(db=self._aux_db)
        self._helper_mode_enabled_default = _env_bool("WEALL_HELPER_MODE_ENABLED", False)
        helper_fast_path_requested = _env_bool("WEALL_HELPER_FAST_PATH", False)
        if helper_fast_path_requested and not self._helper_mode_enabled_default:
            raise ExecutorError(
                "helper fast path requires WEALL_HELPER_MODE_ENABLED=1. Refuse to start."
            )
        self._helper_fast_path_enabled_default = bool(
            self._helper_mode_enabled_default and helper_fast_path_requested
        )
        self._helper_timeout_ms = _normalize_helper_timeout_ms(
            os.environ.get("WEALL_HELPER_TIMEOUT_MS"), 5000
        )

        # Load or initialize state.
        if self._ledger_store.exists():
            self.state = self._ledger_store.read()
        else:
            if (
                _mode() == "prod"
                and db_file_existed_before_init
                and _env_bool("WEALL_PREVENT_REBOOTSTRAP_ON_EXISTING_DB", True)
            ):
                raise ExecutorError("production_rebootstrap_refused_existing_db_without_ledger")
            pinned_genesis = _load_production_genesis_ledger_or_none(chain_id=self.chain_id)
            if pinned_genesis is not None:
                self.state = pinned_genesis
            else:
                self.state = self._initial_state()
                # Genesis-only bootstrap hooks.
                # IMPORTANT: never "auto-elevate" based on being the first node.
                # Any bootstrap privileges must be explicit in the genesis builder.
                self._apply_genesis_bootstrap_live(self.state)
            self._ledger_store.write(self.state)

        # Storage-boundary block identity caches must exist before any startup
        # consistency checks that may load blocks from disk.
        self._max_known_block_hashes: int = _safe_int(
            os.environ.get("WEALL_MAX_KNOWN_BLOCK_HASHES"), 4096
        )
        self._known_block_hashes: OrderedDict[str, str] = OrderedDict()
        self._max_known_block_ids_by_hash: int = _safe_int(
            os.environ.get("WEALL_MAX_KNOWN_BLOCK_IDS_BY_HASH"), 4096
        )
        self._known_block_ids_by_hash: OrderedDict[str, str] = OrderedDict()

        # Fail-closed if on-disk DB invariants do not match the snapshot.
        self._check_db_consistency_fail_closed()

        # Fail-closed on chain_id mismatch once state is present.
        st_chain_id = str(self.state.get("chain_id") or "").strip()
        meta = self.state.get("meta") if isinstance(self.state.get("meta"), dict) else {}
        st_protocol_version = str(meta.get("protocol_version") or "").strip()
        st_profile_hash = str(meta.get("production_consensus_profile_hash") or "").strip()
        st_schema_version = str(meta.get("schema_version") or "").strip()
        st_tx_index_hash = str(meta.get("tx_index_hash") or "").strip()
        st_rep_scale = _safe_int(meta.get("reputation_scale"), 0)
        st_future_drift_ms = _safe_int(meta.get("max_block_future_drift_ms"), 0)
        st_mempool_selection_policy = _normalize_mempool_selection_policy(
            meta.get("mempool_selection_policy") or ""
        )
        st_helper_execution_profile = _sanitize_helper_execution_profile(
            meta.get("helper_execution_profile") or {}
        )
        st_helper_execution_profile_hash = str(meta.get("helper_execution_profile_hash") or "").strip()
        st_genesis_bootstrap_profile = meta.get("genesis_bootstrap_profile") if isinstance(meta.get("genesis_bootstrap_profile"), dict) else {}
        st_recent_block_anchor_activation = _safe_int(meta.get("recent_block_anchor_activation_height"), 0)
        st_genesis_bootstrap_profile_hash = str(meta.get("genesis_bootstrap_profile_hash") or "").strip()
        runtime_mempool_selection_policy = _normalize_mempool_selection_policy(
            getattr(self._mempool, "selection_policy", lambda: "canonical")()
        )
        mempool_selection_policy_env_raw = os.environ.get("WEALL_MEMPOOL_SELECTION_POLICY")
        current_mempool_selection_policy = runtime_mempool_selection_policy
        legacy_unpinned_policy_snapshot = (
            not st_profile_hash
            and not st_schema_version
            and not st_tx_index_hash
        )
        legacy_mempool_policy_upgrade = False
        if (
            mempool_selection_policy_env_raw is None
            and st_mempool_selection_policy
            and st_mempool_selection_policy != runtime_mempool_selection_policy
        ):
            if _mode() != "prod":
                # Backward-compatible restart posture for pre-pin or locally
                # drifted dev databases. When the operator has not explicitly
                # requested a runtime policy, preserve the on-disk pinned policy
                # so sequential restarts do not fail closed solely because the
                # process default changed.
                current_mempool_selection_policy = st_mempool_selection_policy
            elif (
                legacy_unpinned_policy_snapshot
                and st_mempool_selection_policy == "fifo"
                and runtime_mempool_selection_policy == "canonical"
            ):
                # Narrow production compatibility path for legacy snapshots that
                # predate the profile/schema/tx-index pin set and are upgrading
                # from fifo -> canonical defaults. Treat this as an in-memory
                # metadata migration and continue under canonical policy.
                st_mempool_selection_policy = runtime_mempool_selection_policy
                legacy_mempool_policy_upgrade = True
        # Pin the helper execution profile to the explicit local runtime request
        # at startup. Lifecycle overrides are applied later and may narrow the
        # effective authority for production_service nodes, but bootstrap/dev
        # nodes must preserve their requested helper posture for restart
        # compatibility and deterministic replay diagnostics.
        current_helper_execution_profile = self._requested_helper_execution_profile()
        current_genesis_bootstrap_profile = self._current_genesis_bootstrap_profile()
        current_genesis_bootstrap_profile_hash = _genesis_bootstrap_profile_hash(current_genesis_bootstrap_profile)
        if _mode() == "prod" and current_mempool_selection_policy != "canonical":
            raise ExecutorError(
                f"mempool_selection_policy mismatch: runtime={current_mempool_selection_policy!r} required='canonical'. Refuse to start."
            )
        current_helper_execution_profile_hash = _helper_execution_profile_hash(current_helper_execution_profile)
        expected_profile_hash = PRODUCTION_CONSENSUS_PROFILE.profile_hash()
        if st_protocol_version and st_protocol_version != PROTOCOL_VERSION:
            raise ExecutorError(
                f"protocol_version mismatch: db={st_protocol_version!r} binary={PROTOCOL_VERSION!r}. Refuse to start."
            )
        if st_profile_hash and st_profile_hash != expected_profile_hash:
            raise ExecutorError(
                f"production_consensus_profile_hash mismatch: db={st_profile_hash!r} binary={expected_profile_hash!r}. Refuse to start."
            )
        if st_schema_version and st_schema_version != self._schema_version_cached:
            raise ExecutorError(
                f"schema_version mismatch: db={st_schema_version!r} executor={self._schema_version_cached!r}. Refuse to start."
            )
        if st_tx_index_hash and st_tx_index_hash != self._tx_index_hash:
            raise ExecutorError(
                f"tx_index_hash mismatch: db={st_tx_index_hash!r} executor={self._tx_index_hash!r}. Refuse to start."
            )
        if st_rep_scale and st_rep_scale != REPUTATION_SCALE:
            raise ExecutorError(
                f"reputation_scale mismatch: db={st_rep_scale!r} binary={REPUTATION_SCALE!r}. Refuse to start."
            )
        if st_future_drift_ms and st_future_drift_ms != MAX_BLOCK_FUTURE_DRIFT_MS:
            raise ExecutorError(
                f"max_block_future_drift_ms mismatch: db={st_future_drift_ms!r} binary={MAX_BLOCK_FUTURE_DRIFT_MS!r}. Refuse to start."
            )
        if st_mempool_selection_policy and st_mempool_selection_policy != current_mempool_selection_policy:
            raise ExecutorError(
                "mempool_selection_policy mismatch: "
                f"db={st_mempool_selection_policy!r} executor={current_mempool_selection_policy!r}. Refuse to start."
            )
        if st_helper_execution_profile_hash and st_helper_execution_profile_hash != current_helper_execution_profile_hash:
            raise ExecutorError(
                "helper_execution_profile mismatch: "
                f"db={st_helper_execution_profile_hash!r} executor={current_helper_execution_profile_hash!r}. Refuse to start."
            )
        if st_helper_execution_profile and st_helper_execution_profile != current_helper_execution_profile:
            raise ExecutorError(
                "helper_execution_profile mismatch: "
                f"db={st_helper_execution_profile!r} executor={current_helper_execution_profile!r}. Refuse to start."
            )
        if st_genesis_bootstrap_profile_hash and st_genesis_bootstrap_profile_hash != current_genesis_bootstrap_profile_hash:
            raise ExecutorError(
                "genesis_bootstrap_profile mismatch: "
                f"db={st_genesis_bootstrap_profile_hash!r} executor={current_genesis_bootstrap_profile_hash!r}. Refuse to start."
            )
        if st_genesis_bootstrap_profile and st_genesis_bootstrap_profile != current_genesis_bootstrap_profile:
            raise ExecutorError(
                "genesis_bootstrap_profile mismatch: "
                f"db={st_genesis_bootstrap_profile!r} executor={current_genesis_bootstrap_profile!r}. Refuse to start."
            )
        if st_chain_id and st_chain_id != self.chain_id:
            raise ExecutorError(
                f"chain_id mismatch: db={st_chain_id!r} executor={self.chain_id!r}. Refuse to start."
            )

        # Ensure chain_id is set in state if missing.
        if not st_chain_id:
            self.state["chain_id"] = self.chain_id
        meta = self.state.get("meta")
        if not isinstance(meta, dict):
            meta = {}
            self.state["meta"] = meta
        meta.setdefault("protocol_version", PROTOCOL_VERSION)
        meta["production_consensus_profile"] = PRODUCTION_CONSENSUS_PROFILE.to_json()
        meta["production_consensus_profile_hash"] = expected_profile_hash
        meta.setdefault("schema_version", self._schema_version_cached)
        meta.setdefault("tx_index_hash", self._tx_index_hash)
        meta.setdefault("reputation_scale", REPUTATION_SCALE)
        meta.setdefault("max_block_future_drift_ms", MAX_BLOCK_FUTURE_DRIFT_MS)
        meta.setdefault("clock_skew_warn_ms", CLOCK_SKEW_WARN_MS)
        if legacy_mempool_policy_upgrade:
            meta["mempool_selection_policy"] = current_mempool_selection_policy
        else:
            meta.setdefault("mempool_selection_policy", current_mempool_selection_policy)
        meta.setdefault("helper_execution_profile", current_helper_execution_profile)
        meta.setdefault("helper_execution_profile_hash", current_helper_execution_profile_hash)
        meta.setdefault("genesis_bootstrap_profile", current_genesis_bootstrap_profile)
        meta.setdefault("genesis_bootstrap_profile_hash", current_genesis_bootstrap_profile_hash)
        meta.setdefault("recent_block_anchor_activation_height", int(RECENT_BLOCK_ANCHOR_ACTIVATION_HEIGHT))
        meta["startup_clock_sanity_required"] = bool(
            PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required
        )
        meta["startup_clock_hard_fail_ms"] = STARTUP_CLOCK_HARD_FAIL_MS
        self._startup_clock_observer_required = False
        self._startup_clock_observer_reason = ""
        if (
            not st_chain_id
            or not st_profile_hash
            or not st_schema_version
            or not st_tx_index_hash
            or not st_rep_scale
            or not st_future_drift_ms
            or not st_mempool_selection_policy
            or not st_helper_execution_profile_hash
            or not st_genesis_bootstrap_profile_hash
            or not st_recent_block_anchor_activation
        ):
            meta["helper_execution_profile"] = current_helper_execution_profile
            meta["helper_execution_profile_hash"] = current_helper_execution_profile_hash
            meta["genesis_bootstrap_profile"] = current_genesis_bootstrap_profile
            meta["genesis_bootstrap_profile_hash"] = current_genesis_bootstrap_profile_hash
            meta.setdefault("recent_block_anchor_activation_height", int(RECENT_BLOCK_ANCHOR_ACTIVATION_HEIGHT))
            self._ledger_store.write(self.state)

        wall_now_ms = _now_ms()
        tip_ts_ms = _safe_int(self.state.get("tip_ts_ms"), 0)
        clock_skew_ahead_ms = max(0, int(tip_ts_ms) - int(wall_now_ms)) if tip_ts_ms > 0 else 0
        catastrophic_skew = bool(clock_skew_ahead_ms > STARTUP_CLOCK_HARD_FAIL_MS)
        if clock_skew_ahead_ms > CLOCK_SKEW_WARN_MS:
            self._startup_clock_observer_required = bool(_mode() == "prod" and catastrophic_skew)
            self._startup_clock_observer_reason = (
                "clock_skew_ahead" if self._startup_clock_observer_required else ""
            )
            meta["clock_warning"] = {
                "wall_now_ms": int(wall_now_ms),
                "tip_ts_ms": int(tip_ts_ms),
                "skew_ms": int(clock_skew_ahead_ms),
                "warning_threshold_ms": int(CLOCK_SKEW_WARN_MS),
                "startup_hard_fail_threshold_ms": int(STARTUP_CLOCK_HARD_FAIL_MS),
                "startup_clock_sanity_required": bool(
                    PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required
                ),
                "startup_blocked": False,
                "observer_mode_recommended": True,
                "observer_mode_forced": bool(self._startup_clock_observer_required),
                "consensus_impact": "operator_warning_only",
            }
            self._ledger_store.write(self.state)

        # Back-compat / migration: ensure tip fields exist.
        self.state.setdefault("tip_hash", "")
        self.state.setdefault("tip_ts_ms", 0)
        self.state.setdefault(
            "blocks", {}
        )  # minimal ancestry map: block_id -> {height, prev_block_id}
        self.state.setdefault(
            "finalized", {"height": 0, "block_id": ""}
        )  # legacy finality placeholder

        # Canon tx index.
        self.tx_index: TxIndex = TxIndex.load_from_file(self.tx_index_path)

        # BFT engine (HotStuff)
        self._bft = HotStuffBFT(chain_id=self.chain_id)
        self._bft.load_from_state(self.state)
        self._bft.timeout_base_ms = max(
            250, _safe_int(os.environ.get("WEALL_BFT_TIMEOUT_BASE_MS"), 10_000)
        )
        self._bft.timeout_backoff_cap = max(
            0, _safe_int(os.environ.get("WEALL_BFT_TIMEOUT_BACKOFF_CAP"), 4)
        )

        journal_path = os.environ.get("WEALL_BFT_JOURNAL_PATH") or f"{db_path}.bft_journal.jsonl"
        self._bft_journal = BftJournal(
            path=str(journal_path),
            max_events=_safe_int(os.environ.get("WEALL_BFT_JOURNAL_MAX_EVENTS"), 2000),
        )
        helper_lane_dir = str(os.environ.get("WEALL_HELPER_LANE_JOURNAL_DIR") or "").strip()
        if helper_lane_dir:
            self._helper_lane_journal_dir = helper_lane_dir
        else:
            aux_path = Path(self.aux_db_path)
            self._helper_lane_journal_dir = str(
                aux_path.parent / f"{aux_path.stem}_helper_lanes"
            )
        Path(self._helper_lane_journal_dir).mkdir(parents=True, exist_ok=True)
        self._restore_bft_restart_hints()

        # In-memory cache for candidate blocks awaiting QC (leader side)
        # block_id -> (block_dict, state_after_apply, applied_ids, invalid_ids)
        # Strict mode: these caches are hard-capped to prevent memory DoS.
        self._max_pending_candidates: int = _safe_int(
            os.environ.get("WEALL_MAX_PENDING_CANDIDATES"), 128
        )
        self._pending_candidates: OrderedDict[str, tuple[Json, Json, list[str], list[str]]] = (
            OrderedDict()
        )
        self._pending_candidate_ids_by_hash: OrderedDict[str, str] = OrderedDict()

        # In-memory cache for remote proposals we may need to commit once a QC arrives
        # block_id -> block_dict
        # Strict mode: hard-cap to prevent unbounded growth from untrusted peers.
        self._max_pending_remote_blocks: int = _env_int("WEALL_MAX_PENDING_REMOTE_BLOCKS", 256)
        self._pending_remote_blocks: OrderedDict[str, Json] = OrderedDict()
        self._pending_remote_block_ids_by_hash: OrderedDict[str, str] = OrderedDict()

        # Unverified remote proposals are quarantined under a tighter cap until
        # leader/signature/admission checks pass. This prevents untrusted proposal
        # floods from competing directly with validated pending replay artifacts.
        self._max_quarantined_remote_blocks: int = _env_int(
            "WEALL_MAX_QUARANTINED_REMOTE_BLOCKS", 64
        )
        self._quarantined_remote_blocks: OrderedDict[str, Json] = OrderedDict()
        self._quarantined_remote_block_ids_by_hash: OrderedDict[str, str] = OrderedDict()

        # QC objects that arrived before their referenced block proposal. These are
        # retained in a bounded cache so the networking layer can fetch the missing
        # proposal/block and complete replay deterministically on restart/rejoin.
        self._max_pending_missing_qcs: int = _safe_int(
            os.environ.get("WEALL_MAX_PENDING_MISSING_QCS"), 256
        )
        self._pending_missing_qcs: OrderedDict[str, Json] = OrderedDict()
        self._pending_missing_qcs_by_hash: OrderedDict[str, Json] = OrderedDict()
        self._max_missing_parent_fetches_per_call: int = max(
            1,
            _safe_int(os.environ.get("WEALL_BFT_MAX_MISSING_PARENT_FETCHES_PER_CALL"), 32),
        )
        self._max_missing_qc_fetches_per_call: int = max(
            1,
            _safe_int(os.environ.get("WEALL_BFT_MAX_MISSING_QC_FETCHES_PER_CALL"), 32),
        )
        self._missing_parent_fetch_cursor: int = 0
        self._missing_qc_fetch_cursor: int = 0

        # Contain block_id/block_hash ambiguity fail-closed. If we ever observe
        # two different hashes for the same block_id, quarantine that block_id so
        # pending replay and QC pairing cannot silently mix identities.
        self._max_conflicted_block_ids: int = _safe_int(
            os.environ.get("WEALL_MAX_CONFLICTED_BLOCK_IDS"), 256
        )
        self._conflicted_block_ids: OrderedDict[str, Json] = OrderedDict()
        self._max_conflicted_block_hashes: int = _safe_int(
            os.environ.get("WEALL_MAX_CONFLICTED_BLOCK_HASHES"), 256
        )
        self._conflicted_block_hashes: OrderedDict[str, Json] = OrderedDict()
        self._last_mempool_selection_diag: Json = {
            "policy": str(current_mempool_selection_policy),
            "requested_limit": 0,
            "fetched_count": 0,
            "selected_count": 0,
            "invalid_count": 0,
            "rejected_count": 0,
            "selected_tx_ids": [],
        }
        meta_root = self.state.get("meta") if isinstance(self.state.get("meta"), dict) else {}
        persisted_selection_diag = (
            meta_root.get("mempool_selection_last") if isinstance(meta_root.get("mempool_selection_last"), dict) else None
        )
        if isinstance(persisted_selection_diag, dict):
            restored_diag = _sanitize_mempool_selection_marker(
                persisted_selection_diag,
                default_policy=current_mempool_selection_policy,
                default_limit=0,
            )
            self._last_mempool_selection_diag = restored_diag
        self._restore_pending_bft_frontier()

        # Remote proposal vote validation can be expensive because the strict path
        # replays the proposal in a temporary SQLite-backed executor. Cache results
        # by exact block_hash and apply hard caps before any clone/replay work so an
        # untrusted peer cannot force repeated expensive validations for the same
        # payload or for obviously too-large proposals.
        self._max_votecheck_cache: int = _safe_int(
            os.environ.get("WEALL_BFT_VOTECHECK_CACHE_SIZE"), 1024
        )
        self._votecheck_cache: OrderedDict[str, bool] = OrderedDict()
        self._max_votecheck_txs: int = max(
            0, _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_MAX_TXS"), 2048)
        )
        self._max_votecheck_block_bytes: int = max(
            0, _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_MAX_BLOCK_BYTES"), 1_000_000)
        )
        self._proposal_validation_limit: int = max(
            1, _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_MAX_CONCURRENT"), 4)
        )
        self._proposal_validation_semaphore = threading.BoundedSemaphore(
            self._proposal_validation_limit
        )
        self._proposal_peer_budget_window_ms: int = max(
            100, _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_PEER_WINDOW_MS"), 1000)
        )
        self._proposal_peer_budget_max: int = max(
            1, _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_PEER_MAX_PER_WINDOW"), 8)
        )
        self._max_proposal_peer_budget_entries: int = max(
            8, _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_MAX_PEERS"), 512)
        )
        self._proposal_peer_budget: OrderedDict[str, Json] = OrderedDict()

        # Duplicate suppression for untrusted inbound BFT artifacts. These caches
        # are strictly local resource guards: they must not affect consensus state
        # or block validity, but they prevent malicious peers from repeatedly
        # re-triggering the same expensive validation/replay path with identical
        # proposal and QC payloads.
        self._max_recent_bft_proposals: int = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_PROPOSALS"), 2048)
        )
        self._recent_bft_proposals: OrderedDict[str, int] = OrderedDict()
        self._max_recent_bft_qcs: int = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_QCS"), 2048)
        )
        self._recent_bft_qcs: OrderedDict[str, int] = OrderedDict()
        self._max_recent_bft_votes: int = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_VOTES"), 4096)
        )
        self._recent_bft_votes: OrderedDict[str, int] = OrderedDict()
        self._max_recent_bft_timeouts: int = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_TIMEOUTS"), 4096)
        )
        self._recent_bft_timeouts: OrderedDict[str, int] = OrderedDict()
        self._max_recent_bft_sender_budgets: int = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_SENDERS"), 4096)
        )
        self._bft_sender_budget_window_ms: int = max(
            1, _safe_int(os.environ.get("WEALL_BFT_SENDER_WINDOW_MS"), 1000)
        )
        self._bft_sender_budget_per_window: int = max(
            1, _safe_int(os.environ.get("WEALL_BFT_SENDER_BUDGET"), 64)
        )
        self._recent_bft_sender_budgets: OrderedDict[str, tuple[int, int]] = OrderedDict()

        self._max_spec_exec_pool: int = max(
            1, _safe_int(os.environ.get("WEALL_BFT_SPEC_EXEC_POOL_SIZE"), 4)
        )
        self._spec_exec_pool: list[tuple[str, str]] = []
        self._spec_exec_pool_root = (
            Path(os.environ.get("WEALL_BFT_SPEC_EXEC_TMPDIR") or tempfile.gettempdir())
            / f"weall-bft-specpool-{os.getpid()}"
        )
        self._spec_exec_pool_root.mkdir(parents=True, exist_ok=True)

        # SQLite maintenance cadence (WAL checkpoint, optimize). These are
        # best-effort and are disabled by default in non-prod to keep tests
        # deterministic and fast.
        self._last_sqlite_maint_ms: int = 0

        mode = (os.environ.get("WEALL_MODE") or "prod").strip().lower()
        self._sqlite_maintenance_enabled = (
            os.environ.get("WEALL_SQLITE_MAINTENANCE") or ""
        ).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if os.environ.get("WEALL_SQLITE_MAINTENANCE") is None:
            # Default policy: enabled in prod, disabled elsewhere.
            self._sqlite_maintenance_enabled = mode == "prod"

        self._sqlite_checkpoint_interval_ms = _safe_int(
            os.environ.get("WEALL_SQLITE_CHECKPOINT_INTERVAL_MS"),
            30_000 if mode == "prod" else 0,
        )
        # Optimize less frequently; default daily in prod.
        self._sqlite_optimize_interval_ms = _safe_int(
            os.environ.get("WEALL_SQLITE_OPTIMIZE_INTERVAL_MS"),
            24 * 60 * 60 * 1000 if mode == "prod" else 0,
        )
        self._last_sqlite_optimize_ms: int = 0

        self._validator_signing_enabled: bool = True
        self._observer_mode_forced: bool = False
        self._signing_block_reason: str = ""
        self._node_lifecycle_effective_state: str = ""
        self._service_roles_effective: tuple[str, ...] = ()
        self._helper_mode_enabled_effective: bool = False
        self._helper_fast_path_enabled_effective: bool = False
        self._bft_enabled_effective: bool = False
        self._enforce_node_lifecycle_startup()
        self._apply_node_lifecycle_runtime_overrides()
        self._init_validator_runtime_posture()

    def _runtime_meta(self) -> Json:
        from weall.runtime import runtime_posture as _impl
        return _impl._runtime_meta(self)

    def _persist_runtime_meta(self) -> None:
        from weall.runtime import runtime_posture as _impl
        return _impl._persist_runtime_meta(self)

    def _evaluate_node_lifecycle_status(self):
        from weall.runtime import runtime_posture as _impl
        return _impl._evaluate_node_lifecycle_status(self)


    def _apply_node_lifecycle_runtime_overrides(self) -> None:
        from weall.runtime import runtime_posture as _impl
        return _impl._apply_node_lifecycle_runtime_overrides(self)

    def _helper_mode_enabled_runtime(self) -> bool:
        from weall.runtime import helper_execution_runtime as _impl
        return _impl._helper_mode_enabled_runtime(self)

    def _requested_helper_execution_profile(self) -> Json:
        from weall.runtime import helper_execution_runtime as _impl
        return _impl._requested_helper_execution_profile(self)

    def _effective_helper_execution_profile(self) -> Json:
        from weall.runtime import helper_execution_runtime as _impl
        return _impl._effective_helper_execution_profile(self)

    def _persist_node_lifecycle_meta(self) -> None:
        from weall.runtime import runtime_posture as _impl
        return _impl._persist_node_lifecycle_meta(self)

    def _enforce_node_lifecycle_startup(self) -> None:
        from weall.runtime import runtime_posture as _impl
        return _impl._enforce_node_lifecycle_startup(self)

    def _init_validator_runtime_posture(self) -> None:
        from weall.runtime import runtime_posture as _impl
        return _impl._init_validator_runtime_posture(self)

    def mark_clean_shutdown(self) -> None:
        from weall.runtime import runtime_posture as _impl
        return _impl.mark_clean_shutdown(self)

    def _pytest_local_prod_status_compat_allows_requested_signing(self) -> bool:
        from weall.runtime import runtime_posture as _impl
        return _impl._pytest_local_prod_status_compat_allows_requested_signing(self)

    def _effective_validator_signing_state(self) -> tuple[bool, str]:
        from weall.runtime import runtime_posture as _impl
        return _impl._effective_validator_signing_state(self)

    def node_lifecycle_status(self) -> Json:
        from weall.runtime import runtime_posture as _impl
        return _impl.node_lifecycle_status(self)

    def validator_signing_enabled(self) -> bool:
        # Runtime/operator status surface: whether this node is currently
        # allowed to sign as a validator under committed chain state.  This must
        # reflect validator-set membership, consensus phase, and minimum BFT
        # validator count rather than only the startup/env request bit.  BFT
        # test helpers that manufacture signed artifacts can still use
        # _validator_signing_permitted(), which has the narrow pytest-local
        # compatibility override below.
        from weall.runtime import runtime_posture as _impl
        return _impl.validator_signing_enabled(self)

    def _effective_signing_block_reason(self) -> str:
        from weall.runtime import runtime_posture as _impl
        return _impl._effective_signing_block_reason(self)

    def _pytest_local_missing_vrf_allowed(self) -> bool:
        from weall.runtime import runtime_posture as _impl
        return _impl._pytest_local_missing_vrf_allowed(self)

    def _explicit_validator_signing_override(self) -> bool:
        from weall.runtime import runtime_posture as _impl
        return _impl._explicit_validator_signing_override(self)

    def _validator_signing_permitted(self) -> bool:
        from weall.runtime import runtime_posture as _impl
        return _impl._validator_signing_permitted(self)

    def observer_mode(self) -> bool:
        from weall.runtime import runtime_posture as _impl
        return _impl.observer_mode(self)

    def _prod_observer_block_production_reason(self) -> str:
        from weall.runtime import runtime_posture as _impl
        return _impl._prod_observer_block_production_reason(self)

    def _restore_bft_restart_hints(self) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._restore_bft_restart_hints(self)

    def _bft_record_event(self, event: str, **payload: Any) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_record_event(self, event, **payload)

    def _persist_pending_bft_artifact(self, *, kind: str, block_id: str, payload: Json) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._persist_pending_bft_artifact(self, kind=kind, block_id=block_id, payload=payload)

    def _delete_pending_bft_artifact(self, *, kind: str, block_id: str) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._delete_pending_bft_artifact(self, kind=kind, block_id=block_id)

    def _restore_pending_bft_frontier(self) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._restore_pending_bft_frontier(self)

    def _bft_outbound_key(self, kind: str, payload: Json) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_outbound_key(self, kind, payload)

    def _bft_enqueue_outbound(self, kind: str, payload: Json) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_enqueue_outbound(self, kind, payload)

    def bft_mark_outbound_sent(self, kind: str, payload: Json) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_mark_outbound_sent(self, kind, payload)

    def bft_pending_outbound_messages(self) -> list[Json]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_pending_outbound_messages(self)

    def _current_genesis_bootstrap_profile(self) -> Json:
        from weall.runtime import genesis_bootstrap as _impl
        return _impl._current_genesis_bootstrap_profile(self)

    def _initial_state(self) -> Json:
        from weall.runtime import genesis_bootstrap as _impl
        return _impl._initial_state(self)

    # ----------------------------
    # Genesis bootstrap hooks
    # ----------------------------

    @staticmethod
    def _mk_key_id(pubkey: str) -> str:
        from weall.runtime import genesis_bootstrap as _impl
        return _impl._mk_key_id(pubkey)

    def _apply_genesis_bootstrap_live(self, state: Json) -> None:
        from weall.runtime import genesis_bootstrap as _impl
        return _impl._apply_genesis_bootstrap_live(self, state)

    # ----------------------------
    # DB consistency checks
    # ----------------------------

    def _check_db_consistency_fail_closed(self) -> None:
        """Fail-closed if persisted DB invariants do not match the snapshot."""
        st_h = _safe_int(self.state.get("height"), 0)

        with self._db.connection() as con:
            row = con.execute("SELECT MAX(height) AS h FROM blocks;").fetchone()
            max_h = int(row["h"]) if (row is not None and row["h"] is not None) else 0

        if st_h <= 0:
            if max_h > 0:
                raise ExecutorError(
                    f"db_invariant_violation: snapshot height {st_h} but persisted blocks exist up to {max_h}. "
                    "Refuse to start."
                )
            return

        if st_h > max_h:
            raise ExecutorError(
                f"db_invariant_violation: snapshot height {st_h} exceeds max persisted block height {max_h}. "
                "Refuse to start."
            )

        blk = self.get_block_by_height(st_h)
        if blk is None:
            raise ExecutorError(
                f"db_invariant_violation: snapshot height {st_h} has no persisted block. Refuse to start."
            )

        try:
            blk2, bh = ensure_block_hash(blk)
            st_tip_hash = str(self.state.get("tip_hash") or "").strip()
            if st_tip_hash and st_tip_hash != str(bh):
                raise ExecutorError(
                    "db_invariant_violation: snapshot tip_hash does not match persisted block hash. Refuse to start."
                )
            if not st_tip_hash:
                self.state["tip_hash"] = str(bh)
            if not _safe_int(self.state.get("tip_ts_ms"), 0):
                self.state["tip_ts_ms"] = _safe_int(
                    blk2.get("block_ts_ms") or blk2.get("created_ms"), 0
                )
        except ExecutorError:
            raise
        except Exception:
            raise ExecutorError(
                "db_invariant_violation: cannot compute persisted tip hash. Refuse to start."
            )

    # ----------------------------
    # Public accessors
    # ----------------------------

    @property
    def mempool(self) -> PersistentMempool:
        from weall.runtime import diagnostics as _impl
        return _impl.mempool(self)

    @property
    def attestation_pool(self) -> PersistentAttestationPool:
        from weall.runtime import diagnostics as _impl
        return _impl.attestation_pool(self)

    def read_mempool(self, *, limit: int = 10_000) -> list[Json]:
        from weall.runtime import diagnostics as _impl
        return _impl.read_mempool(self, limit=limit)

    def mempool_selection_diagnostics(self, *, preview_limit: int = 10) -> Json:
        from weall.runtime import diagnostics as _impl
        return _impl.mempool_selection_diagnostics(self, preview_limit=preview_limit)

    def helper_execution_diagnostics(self) -> Json:
        from weall.runtime import diagnostics as _impl
        return _impl.helper_execution_diagnostics(self)

    def transition_guardrail_diagnostics(self) -> Json:
        from weall.runtime import diagnostics as _impl
        return _impl.transition_guardrail_diagnostics(self)

    def get_tx_status(self, tx_id: str) -> dict[str, object]:
        from weall.runtime import diagnostics as _impl
        return _impl.get_tx_status(self, tx_id)

    def read_state(self) -> Json:
        from weall.runtime import diagnostics as _impl
        return _impl.read_state(self)

    # ----------------------------
    # Tx + att submission
    # ----------------------------

    def tx_index_hash(self) -> str:
        from weall.runtime import diagnostics as _impl
        return _impl.tx_index_hash(self)

    # ----------------------------
    # SQLite maintenance
    # ----------------------------

    def sqlite_maintenance_tick(self) -> None:
        from weall.runtime import diagnostics as _impl
        return _impl.sqlite_maintenance_tick(self)

    def _ledger_with_pending_nonce_cursor(self, *, signer: str, pending_nonce: int) -> LedgerView:
        """Return a ledger view whose account nonce reflects contiguous mempool state.

        This is only used for non-block admission. It lets the mempool accept
        ``nonce N+1`` when ``nonce N`` is already pending for the same signer,
        while consensus/block admission continues to replay against real chain
        state and reject duplicate or gapped nonces deterministically.
        """

        return LedgerView.from_ledger(self.read_state()).with_account_nonce(
            str(signer or ""), max(0, int(pending_nonce or 0))
        )

    def _pending_nonce_cursor_for_submit(self, *, signer: str, chain_nonce: int) -> int:
        mp = getattr(self, "_mempool", None) or getattr(self, "mempool", None)
        if mp is None or not callable(getattr(mp, "contiguous_pending_nonce", None)):
            return max(0, int(chain_nonce or 0))
        try:
            return int(mp.contiguous_pending_nonce(signer, after_nonce=int(chain_nonce or 0)))
        except Exception:
            return max(0, int(chain_nonce or 0))

    def _submit_context_for_ingress(self, ingress: str = "local_fixture") -> str:
        ingress_mode = str(ingress or "local_fixture").strip().lower()
        context = "mempool" if ingress_mode in {"", "local", "local_fixture", "fixture", "test_fixture"} else ingress_mode
        if context not in {"mempool", "http", "gossip", "peer", "operator"}:
            context = "operator"
        if context == "peer":
            context = "gossip"
        return context

    @staticmethod
    def _batch_timing_ms(start_ns: int) -> float:
        elapsed_ns = max(0, time.perf_counter_ns() - int(start_ns))
        return round(elapsed_ns / 1_000_000, 3)

    @staticmethod
    def _empty_submit_batch_timings() -> dict[str, float]:
        return {
            "tx_submit_total_wall_ms": 0.0,
            "tx_signature_verify_wall_ms": 0.0,
            "tx_canonicalize_or_hash_wall_ms": 0.0,
            "tx_nonce_check_wall_ms": 0.0,
            "tx_mempool_insert_wall_ms": 0.0,
            "tx_reject_wall_ms": 0.0,
            "tx_duplicate_check_wall_ms": 0.0,
        }

    @staticmethod
    def _add_submit_batch_timing(timings: dict[str, float], key: str, start_ns: int) -> None:
        current = timings.get(key, 0.0)
        if not isinstance(current, (int, float)):
            current = 0.0
        timings[key] = round(current + WeAllExecutor._batch_timing_ms(start_ns), 3)

    def submit_txs_batch(
        self,
        envs: list[Json],
        *,
        ingress: str = "local_fixture",
        include_timings: bool = False,
    ) -> list[Json]:
        """Submit many transactions while preserving serial admission results.

        The public/API semantics remain per-transaction ``submit_tx``.  This
        method is an internal/harness fast path for deterministic load tests and
        future batch gossip ingestion: it admits envelopes in the same order,
        keeps the same failure codes, and writes accepted envelopes through one
        bounded mempool batch transaction.
        """

        if not isinstance(envs, list):
            return [{"ok": False, "error": "bad_envs:not_list"}]

        timings = self._empty_submit_batch_timings() if include_timings else None
        total_start = time.perf_counter_ns()
        context = self._submit_context_for_ingress(ingress)
        state = self.read_state()
        ledger = LedgerView.from_ledger(state)
        current_height = _safe_int(self.state.get("height"), 0)

        pending_cursors: dict[str, int] = {}
        chain_nonces: dict[str, int] = {}
        admitted_envs: list[Json] = []
        admitted_result_indexes: list[int] = []
        results: list[Json] = []

        for env in envs:
            if not isinstance(env, dict):
                start = time.perf_counter_ns()
                results.append({"ok": False, "error": "bad_env:not_object"})
                if timings is not None:
                    self._add_submit_batch_timing(timings, "tx_reject_wall_ms", start)
                continue

            signer = str(env.get("signer") or "").strip()
            try:
                wanted_nonce = int(env.get("nonce") or 0)
            except Exception:
                wanted_nonce = 0

            admission_ledger = ledger
            if signer:
                start = time.perf_counter_ns()
                if signer not in chain_nonces:
                    acct = (ledger.accounts or {}).get(signer)
                    chain_nonces[signer] = int(acct.get("nonce") or 0) if isinstance(acct, dict) else 0
                chain_nonce = int(chain_nonces.get(signer, 0))
                if signer not in pending_cursors:
                    pending_cursors[signer] = self._pending_nonce_cursor_for_submit(
                        signer=signer, chain_nonce=chain_nonce
                    )
                pending_cursor = int(pending_cursors.get(signer, chain_nonce))
                if pending_cursor > chain_nonce and wanted_nonce == pending_cursor + 1:
                    admission_ledger = ledger.with_account_nonce(signer, pending_cursor)
                if timings is not None:
                    self._add_submit_batch_timing(timings, "tx_nonce_check_wall_ms", start)

            verdict = admit_tx(tx=env, ledger=admission_ledger, canon=self.tx_index, context=context)
            if not verdict.ok and verdict.code == "bad_nonce" and context in {"mempool", "http", "gossip", "operator"} and signer:
                start = time.perf_counter_ns()
                chain_nonce = int(chain_nonces.get(signer, 0))
                pending_cursor = int(pending_cursors.get(signer, chain_nonce))
                if pending_cursor > chain_nonce and wanted_nonce == pending_cursor + 1:
                    pending_ledger = ledger.with_account_nonce(signer, pending_cursor)
                    verdict = admit_tx(tx=env, ledger=pending_ledger, canon=self.tx_index, context=context)
                if timings is not None:
                    self._add_submit_batch_timing(timings, "tx_nonce_check_wall_ms", start)

            if not verdict.ok:
                start = time.perf_counter_ns()
                results.append(
                    {
                        "ok": False,
                        "error": verdict.code,
                        "reason": verdict.reason,
                        "details": verdict.details,
                    }
                )
                if timings is not None:
                    self._add_submit_batch_timing(timings, "tx_reject_wall_ms", start)
                continue

            results.append({"ok": True, "_pending_mempool_add": True})
            admitted_result_indexes.append(len(results) - 1)
            admitted_envs.append(env)
            if signer and wanted_nonce > 0:
                chain_nonce = int(chain_nonces.get(signer, 0))
                pending_cursors[signer] = max(int(pending_cursors.get(signer, chain_nonce)), int(wanted_nonce))

        if admitted_envs:
            add_many = getattr(self._mempool, "add_many", None)
            if callable(add_many):
                mempool_results = add_many(
                    admitted_envs,
                    current_height=current_height,
                    include_timings=bool(include_timings),
                )
            else:
                mempool_results = [
                    self._mempool.add(env, current_height=current_height) for env in admitted_envs
                ]
            mempool_timings: dict[str, Any] | None = None
            for result_index, mempool_result in zip(admitted_result_indexes, mempool_results):
                results[result_index] = dict(mempool_result)
                if mempool_timings is None and isinstance(mempool_result, dict) and isinstance(mempool_result.get("timings_ms"), dict):
                    mempool_timings = mempool_result.get("timings_ms")
            if timings is not None and isinstance(mempool_timings, dict):
                for key in timings:
                    if key == "tx_submit_total_wall_ms":
                        continue
                    current = timings.get(key, 0.0)
                    incoming = mempool_timings.get(key, 0.0)
                    if not isinstance(current, (int, float)) or not isinstance(incoming, (int, float)):
                        continue
                    timings[key] = round(current + incoming, 3)

        if timings is not None:
            timings["tx_submit_total_wall_ms"] = self._batch_timing_ms(total_start)
            timings = {k: round(v, 3) if isinstance(v, (int, float)) else v for k, v in timings.items()}
            for result in results:
                result["timings_ms"] = dict(timings)
        return results

    def submit_tx(self, env: Json, *, ingress: str = "local_fixture") -> Json:
        if not isinstance(env, dict):
            return {"ok": False, "error": "bad_env:not_object"}

        # Historical tests and deterministic local fixtures use the permissive
        # mempool context. Production ingress surfaces must pass an explicit
        # boundary context so signature/origin policy mirrors HTTP/gossip.
        # Unknown explicit ingress is safest as an operator boundary, not as a
        # local fixture. In production, tx_admission requires full
        # signature/domain verification for this context.
        context = self._submit_context_for_ingress(ingress)

        state = self.read_state()
        ledger = LedgerView.from_ledger(state)
        verdict = admit_tx(tx=env, ledger=ledger, canon=self.tx_index, context=context)
        if not verdict.ok and verdict.code == "bad_nonce" and context in {"mempool", "http", "gossip", "operator"}:
            signer = str(env.get("signer") or "").strip()
            try:
                wanted_nonce = int(env.get("nonce") or 0)
            except Exception:
                wanted_nonce = 0
            acct = (ledger.accounts or {}).get(signer) if signer else None
            chain_nonce = int(acct.get("nonce") or 0) if isinstance(acct, dict) else 0
            pending_cursor = self._pending_nonce_cursor_for_submit(signer=signer, chain_nonce=chain_nonce)
            if pending_cursor > chain_nonce and wanted_nonce == pending_cursor + 1:
                pending_ledger = self._ledger_with_pending_nonce_cursor(
                    signer=signer, pending_nonce=pending_cursor
                )
                verdict = admit_tx(tx=env, ledger=pending_ledger, canon=self.tx_index, context=context)

        if not verdict.ok:
            return {
                "ok": False,
                "error": verdict.code,
                "reason": verdict.reason,
                "details": verdict.details,
            }

        return self._mempool.add(env, current_height=_safe_int(self.state.get("height"), 0))

    def submit_attestation(self, env: Json) -> Json:
        if not isinstance(env, dict):
            return {"ok": False, "error": "bad_env:not_object"}

        ledger = LedgerView.from_ledger(self.read_state())
        verdict = admit_tx(tx=env, ledger=ledger, canon=self.tx_index, context="http")
        if not verdict.ok:
            return {
                "ok": False,
                "error": verdict.code,
                "reason": verdict.reason,
                "details": verdict.details,
            }

        tx_type = str(env.get("tx_type") or "").strip().upper()
        if tx_type != "BLOCK_ATTEST":
            return {"ok": False, "error": "invalid_tx_type", "reason": "attestation_requires_block_attest"}

        signer = str(env.get("signer") or "").strip()
        payload = env.get("payload") if isinstance(env.get("payload"), dict) else {}
        payload_validator = str(payload.get("validator") or "").strip()
        if payload_validator and payload_validator != signer:
            return {
                "ok": False,
                "error": "validator_mismatch",
                "reason": "payload_validator_must_match_signer",
                "details": {"signer": signer, "payload_validator": payload_validator},
            }

        normalized_payload = dict(payload)
        normalized_payload["validator"] = signer
        normalized = dict(env)
        normalized["payload"] = normalized_payload
        normalized["block_id"] = str(
            normalized_payload.get("block_id") or normalized_payload.get("id") or ""
        ).strip()
        return self._att_pool.add(normalized)

    # ----------------------------
    # Simple block producer (SQLite-backed)
    # ----------------------------

    def _helper_fast_path_enabled(self) -> bool:
        from weall.runtime import helper_execution_runtime as _impl
        return _impl._helper_fast_path_enabled(self)

    def _helper_lane_journal_path(self, *, block_height: int) -> str:
        from weall.runtime import helper_execution_runtime as _impl
        return _impl._helper_lane_journal_path(self, block_height=block_height)

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
        from weall.runtime import helper_execution_runtime as _impl
        return _impl._helper_dispatch_context(self, block_height=block_height, manifest_hash=manifest_hash, coordinator_pubkey=coordinator_pubkey, manifest_signature=manifest_signature, manifest_signed=manifest_signed, manifest_signature_required=manifest_signature_required, manifest_payload=manifest_payload, strict_helper_certificate_consistency=strict_helper_certificate_consistency, strict_helper_receipts_root=strict_helper_receipts_root, strict_helper_state_delta_hash=strict_helper_state_delta_hash, plan_id=plan_id)

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
        from weall.runtime import helper_execution_runtime as _impl
        return _impl._build_helper_execution_metadata(self, applied_envs=applied_envs, receipts=receipts, block_height=block_height, started_ms=started_ms, helper_certificates=helper_certificates, helper_receipts_by_lane=helper_receipts_by_lane, helper_state_deltas_by_lane=helper_state_deltas_by_lane)

    def produce_block(
        self,
        *,
        max_txs: int = 1000,
        allow_empty: bool | None = None,
    ) -> ExecutorMeta:
        from weall.runtime import block_builder as _impl
        return _impl.produce_block(self, max_txs=max_txs, allow_empty=allow_empty)

    # ----------------------------
    # Block candidate builder (proposal)
    # ----------------------------

    def build_block_candidate(
        self,
        *,
        max_txs: int = 1000,
        allow_empty: bool = False,
        force_ts_ms: int | None = None,
        helper_certificates: dict[str, HelperExecutionCertificate] | None = None,
        helper_receipts_by_lane: dict[str, list[Json]] | None = None,
    ) -> tuple[Json | None, Json | None, list[str], list[str], str]:
        from weall.runtime import block_builder as _impl
        return _impl.build_block_candidate(self, max_txs=max_txs, allow_empty=allow_empty, force_ts_ms=force_ts_ms, helper_certificates=helper_certificates, helper_receipts_by_lane=helper_receipts_by_lane)

    # ----------------------------
    # Commit candidate
    # ----------------------------

    def commit_block_candidate(
        self,
        *,
        block: Json,
        new_state: Json,
        applied_ids: list[str],
        invalid_ids: list[str],
    ) -> ExecutorMeta:
        from weall.runtime import block_commit as _impl
        return _impl.commit_block_candidate(self, block=block, new_state=new_state, applied_ids=applied_ids, invalid_ids=invalid_ids)

    # ----------------------------
    # Apply a received block (network / sync)
    # ----------------------------

    def apply_block(self, block: Json) -> ExecutorMeta:
        from weall.runtime import block_replay as _impl
        return _impl.apply_block(self, block)

    # ----------------------------
    # Network-facing BFT adapters
    # ----------------------------

    def _votecheck_cache_get(self, block_hash: str) -> bool | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._votecheck_cache_get(self, block_hash)

    def _votecheck_cache_put(self, block_hash: str, ok: bool) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._votecheck_cache_put(self, block_hash, ok)

    def _proposal_votecheck_budget_ok(self, peer_id: str) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._proposal_votecheck_budget_ok(self, peer_id)

    def _spec_exec_paths_for_slot(self, slot: str) -> tuple[str, str]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._spec_exec_paths_for_slot(self, slot)

    def _make_spec_exec_slot(self) -> tuple[str, str]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._make_spec_exec_slot(self)

    def _acquire_spec_exec_slot(self) -> tuple[str, str]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._acquire_spec_exec_slot(self)

    def _release_spec_exec_slot(self, slot: tuple[str, str]) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._release_spec_exec_slot(self, slot)

    def _reset_spec_exec_slot(self, slot: tuple[str, str]) -> WeAllExecutor:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._reset_spec_exec_slot(self, slot)

    def _proposal_votecheck_static_ok(self, block: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._proposal_votecheck_static_ok(self, block)

    def _validate_remote_proposal_for_vote(self, block: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._validate_remote_proposal_for_vote(self, block)

    def _ensure_recent_bft_artifact_caches(self) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._ensure_recent_bft_artifact_caches(self)

    def _bft_sender_budget_key(self, artifact: Json) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_sender_budget_key(self, artifact)

    def _consume_bft_sender_budget(self, artifact: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._consume_bft_sender_budget(self, artifact)

    def _remember_recent_bft_proposal(self, proposal: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._remember_recent_bft_proposal(self, proposal)

    def _recent_bft_qc_key(self, qcj: Json) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._recent_bft_qc_key(self, qcj)

    def _has_recent_bft_qc(self, qcj: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._has_recent_bft_qc(self, qcj)

    def _record_recent_bft_qc(self, qcj: Json) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._record_recent_bft_qc(self, qcj)

    def _remember_recent_bft_qc(self, qcj: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._remember_recent_bft_qc(self, qcj)

    def _remember_recent_bft_vote(self, votej: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._remember_recent_bft_vote(self, votej)

    def _remember_recent_bft_timeout(self, timeoutj: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._remember_recent_bft_timeout(self, timeoutj)

    def _bft_artifact_shape_fast_fail(self, kind: str, payload: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_artifact_shape_fast_fail(self, kind, payload)

    def bft_on_proposal(self, proposal: Json) -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_on_proposal(self, proposal)

    def bft_on_vote(self, vote: Json) -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_on_vote(self, vote)

    def bft_on_qc(self, qcj: Json) -> ExecutorMeta | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_on_qc(self, qcj)

    def bft_on_timeout(self, timeoutj: Json) -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_on_timeout(self, timeoutj)

    def bft_drive_timeouts(self, now_ms: int) -> list[Json]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_drive_timeouts(self, now_ms)

    # ----------------------------
    # BFT helpers
    # ----------------------------

    def _active_validators(self) -> list[str]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._active_validators(self)

    def _validator_pubkeys(self) -> dict[str, str]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._validator_pubkeys(self)

    def _current_validator_epoch(self) -> int:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._current_validator_epoch(self)

    def _current_validator_set_hash(self) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._current_validator_set_hash(self)

    def _current_consensus_phase(self) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._current_consensus_phase(self)

    def _bft_phase_allows_artifact_processing(self) -> bool:
        # Pre-phase legacy/dev/test states still rely on BFT artifacts, so only the
        # explicit committed bootstrap phases in production suppress vote/timeout/QC
        # processing. Non-production modes retain their historical behavior.
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_phase_allows_artifact_processing(self)

    def _pending_consensus_phase(self) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._pending_consensus_phase(self)

    def _bft_payload_phase_matches_current_security_model(self, payload: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_payload_phase_matches_current_security_model(self, payload)

    def _bft_payload_phase_is_cache_compatible(self, payload: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_payload_phase_is_cache_compatible(self, payload)

    def _validator_epoch(self) -> tuple[int, str]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._validator_epoch(self)

    def _bft_strict_epoch_binding_enabled(self) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_strict_epoch_binding_enabled(self)

    def _bft_epoch_binding_matches(self, payload: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_epoch_binding_matches(self, payload)

    def _prune_pending_bft_artifacts_on_local_validator_transition(
        self,
        *,
        previous_epoch: int,
        previous_set_hash: str,
    ) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._prune_pending_bft_artifacts_on_local_validator_transition(self, previous_epoch=previous_epoch, previous_set_hash=previous_set_hash)

    def _local_validator_account(self) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._local_validator_account(self)

    def _local_validator_identity(self) -> tuple[str, str, str]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._local_validator_identity(self)

    def _cache_known_block_hash(self, block_id: str, block_hash: str) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._cache_known_block_hash(self, block_id, block_hash)

    def _lookup_committed_block_hash_index(self, block_id: str) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._lookup_committed_block_hash_index(self, block_id)

    def _lookup_committed_block_id_by_hash(self, block_hash: str) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._lookup_committed_block_id_by_hash(self, block_hash)

    def _known_block_hash_for_id(self, block_id: str, *, include_qc_cache: bool = False) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._known_block_hash_for_id(self, block_id, include_qc_cache=include_qc_cache)

    def _known_block_id_for_hash(self, block_hash: str) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._known_block_id_for_hash(self, block_hash)

    def _is_conflicted_block_id(self, block_id: str) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._is_conflicted_block_id(self, block_id)

    def _is_conflicted_block_hash(self, block_hash: str) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._is_conflicted_block_hash(self, block_hash)

    def _drop_pending_candidate_artifacts(self, block_id: str) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._drop_pending_candidate_artifacts(self, block_id)

    def _mark_block_id_conflict(
        self, *, block_id: str, known_hash: str, new_hash: str, source: str, parent_id: str = ""
    ) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._mark_block_id_conflict(self, block_id=block_id, known_hash=known_hash, new_hash=new_hash, source=source, parent_id=parent_id)

    def _mark_block_hash_conflict(
        self,
        *,
        block_hash: str,
        known_block_id: str,
        new_block_id: str,
        source: str,
        parent_id: str = "",
    ) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._mark_block_hash_conflict(self, block_hash=block_hash, known_block_id=known_block_id, new_block_id=new_block_id, source=source, parent_id=parent_id)

    def _qc_identity_conflicts(self, qcj: Json, *, source: str = "qc") -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._qc_identity_conflicts(self, qcj, source=source)

    def _block_identity_conflicts(self, block: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._block_identity_conflicts(self, block)

    def _block_height_hint(self, block: Json) -> int:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._block_height_hint(self, block)

    def _has_local_block(self, block_id: str) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._has_local_block(self, block_id)

    def _index_pending_remote_block(self, block: Json) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._index_pending_remote_block(self, block)

    def _index_quarantined_remote_block(self, block: Json) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._index_quarantined_remote_block(self, block)

    def _quarantine_remote_block(self, block: Json) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._quarantine_remote_block(self, block)

    def _drop_quarantined_remote_artifacts(self, block_id: str) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._drop_quarantined_remote_artifacts(self, block_id)

    def _put_pending_remote_block(self, *, block_id: str, block: Json) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._put_pending_remote_block(self, block_id=block_id, block=block)

    def _promote_quarantined_remote_block(
        self, block_id: str, *, block: Json | None = None
    ) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._promote_quarantined_remote_block(self, block_id, block=block)

    def _index_pending_candidate(self, block: Json) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._index_pending_candidate(self, block)

    def _index_pending_missing_qc(self, qcj: Json) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._index_pending_missing_qc(self, qcj)

    def _put_pending_missing_qc(self, qcj: Json) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._put_pending_missing_qc(self, qcj)

    def _drop_pending_missing_qc_aliases(
        self, *, block_id: str = "", qcj: Json | None = None
    ) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._drop_pending_missing_qc_aliases(self, block_id=block_id, qcj=qcj)

    def _remove_pending_missing_qc(self, *, block_id: str) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._remove_pending_missing_qc(self, block_id=block_id)

    def _pending_missing_qc_json(self, *, block_id: str = "", block_hash: str = "") -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._pending_missing_qc_json(self, block_id=block_id, block_hash=block_hash)

    def _pending_missing_qc_entries(self) -> OrderedDict[str, Json]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._pending_missing_qc_entries(self)

    def _drop_pending_hash_aliases(self, *, block_id: str, block: Json | None = None) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._drop_pending_hash_aliases(self, block_id=block_id, block=block)

    def _pending_block_identity_tuple(self, block_id: str) -> tuple[int, str, str]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._pending_block_identity_tuple(self, block_id)

    def _ordered_pending_block_ids(self) -> list[str]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._ordered_pending_block_ids(self)

    def _drop_pending_remote_artifacts(self, block_id: str) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._drop_pending_remote_artifacts(self, block_id)

    def _bft_speculative_blocks_map(self) -> dict[str, Json]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_speculative_blocks_map(self)

    def _bft_pending_block_json(self, block_id: str) -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_pending_block_json(self, block_id)

    def _bft_pending_block_json_by_hash(self, block_hash: str) -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_pending_block_json_by_hash(self, block_hash)

    def _resolve_pending_block_identity(
        self, *, block_id: str = "", block_hash: str = ""
    ) -> tuple[str, Json | None]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._resolve_pending_block_identity(self, block_id=block_id, block_hash=block_hash)

    def _bft_pending_artifact_matches_current_epoch(self, payload: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_pending_artifact_matches_current_epoch(self, payload)

    def _prune_pending_bft_artifacts(self) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._prune_pending_bft_artifacts(self)

    def _bft_block_is_applyable_finalized_descendant(
        self, block: Json, finalized_block_id: str
    ) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_block_is_applyable_finalized_descendant(self, block, finalized_block_id)

    def _bft_parent_ready_for_apply(self, block: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_parent_ready_for_apply(self, block)

    def bft_try_apply_pending_remote_blocks(self) -> list[ExecutorMeta]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_try_apply_pending_remote_blocks(self)

    def _bft_try_apply_pending_remote_blocks_followup(
        self, *, max_extra: int
    ) -> list[ExecutorMeta]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_try_apply_pending_remote_blocks_followup(self, max_extra=max_extra)

    def _committed_chain_recent_timestamps_ms(self, *, limit: int = 11) -> list[int]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._committed_chain_recent_timestamps_ms(self, limit=limit)

    def committed_chain_median_time_past_ms(self, *, limit: int = 11) -> int:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.committed_chain_median_time_past_ms(self, limit=limit)

    def chain_time_floor_ms(self) -> int:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.chain_time_floor_ms(self)

    def bft_diagnostics(self) -> Json:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_diagnostics(self)

    def bft_cache_remote_block(self, block_json: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_cache_remote_block(self, block_json)

    def _ensure_pending_fetch_budgets(self) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._ensure_pending_fetch_budgets(self)

    def _bounded_fetch_request_descriptors(self, descriptors: list[Json]) -> list[Json]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bounded_fetch_request_descriptors(self, descriptors)

    def bft_pending_fetch_request_descriptors(self) -> list[Json]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_pending_fetch_request_descriptors(self)

    def _resolve_fetch_request_descriptor(self, desc: Json) -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._resolve_fetch_request_descriptor(self, desc)

    def bft_resolved_pending_fetch_request_descriptors(self) -> list[Json]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_resolved_pending_fetch_request_descriptors(self)

    def bft_pending_fetch_requests(self) -> list[str]:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_pending_fetch_requests(self)

    def bft_resolve_fetch_request_descriptor(self, desc: Json) -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_resolve_fetch_request_descriptor(self, desc)

    def bft_recent_rejection_summary(self, *, limit: int = 25) -> Json:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_recent_rejection_summary(self, limit=limit)

    def bft_current_view(self) -> int:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_current_view(self)

    def bft_current_validator_epoch(self) -> int:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_current_validator_epoch(self)

    def bft_current_validator_set_hash(self) -> str:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_current_validator_set_hash(self)

    def bft_set_view(self, view: int) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_set_view(self, view)

    def _prune_bft_liveness_caches_for_current_epoch(self) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._prune_bft_liveness_caches_for_current_epoch(self)

    def _persist_bft_state(self) -> None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._persist_bft_state(self)

    def bft_verify_qc_json(self, qcj: Json) -> QuorumCert | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_verify_qc_json(self, qcj)

    def bft_handle_qc(self, qcj: Json) -> bool:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_handle_qc(self, qcj)

    def _bft_best_justify_qc_json(self) -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl._bft_best_justify_qc_json(self)

    def bft_leader_propose(self, *, max_txs: int = 1000) -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_leader_propose(self, max_txs=max_txs)

    def bft_handle_vote(self, vote_json: Json) -> QuorumCert | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_handle_vote(self, vote_json)

    def bft_commit_if_ready(self, qc: QuorumCert) -> ExecutorMeta | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_commit_if_ready(self, qc)

    def bft_make_vote_for_block(
        self, *, view: int, block_id: str, block_hash: str, parent_id: str
    ) -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_make_vote_for_block(self, view=view, block_id=block_id, block_hash=block_hash, parent_id=parent_id)

    def bft_make_timeout(self, *, view: int) -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_make_timeout(self, view=view)

    def bft_handle_timeout(self, timeout_json: Json) -> int | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_handle_timeout(self, timeout_json)

    def bft_timeout_check(self) -> Json | None:
        from weall.runtime import bft_runtime_adapter as _impl
        return _impl.bft_timeout_check(self)

    # ----------------------------
    # Block + history APIs
    # ----------------------------

    def get_block_by_id(self, block_id: str) -> Json | None:
        bid = str(block_id or "").strip()
        if not bid:
            return None

        if bid == str(self.state.get("tip") or "").strip():
            blk = self.get_latest_block()
            if isinstance(blk, dict):
                return blk

        with self._db.connection() as con:
            row = con.execute(
                "SELECT block_json FROM blocks WHERE block_id=? ORDER BY height DESC LIMIT 1;",
                (bid,),
            ).fetchone()
            if row is None:
                return None
            blk = json.loads(str(row["block_json"]))
            if isinstance(blk, dict):
                blk, bh = ensure_block_hash(blk)
                self._cache_known_block_hash(str(blk.get("block_id") or ""), str(bh))
            return blk

    def get_block_by_height(self, height: int) -> Json | None:
        with self._db.connection() as con:
            row = con.execute(
                "SELECT block_json FROM blocks WHERE height=? LIMIT 1;", (int(height),)
            ).fetchone()
            if row is None:
                return None
            blk = json.loads(str(row["block_json"]))
            if isinstance(blk, dict):
                blk, bh = ensure_block_hash(blk)
                self._cache_known_block_hash(str(blk.get("block_id") or ""), str(bh))
            return blk

    def get_latest_block(self) -> Json | None:
        with self._db.connection() as con:
            row = con.execute(
                "SELECT block_json FROM blocks ORDER BY height DESC LIMIT 1;"
            ).fetchone()
            if row is None:
                return None
            blk = json.loads(str(row["block_json"]))
            if isinstance(blk, dict):
                blk, bh = ensure_block_hash(blk)
                self._cache_known_block_hash(str(blk.get("block_id") or ""), str(bh))
            return blk

    def _schema_version(self) -> str:
        return (
            str(
                getattr(self, "_schema_version_cached", "")
                or os.environ.get("WEALL_SCHEMA_VERSION")
                or "1"
            ).strip()
            or "1"
        )

    def build_state_sync_trusted_anchor(self) -> Json:
        return build_snapshot_anchor(self.state)

    def _state_sync_service(self) -> StateSyncService:
        return StateSyncService(
            chain_id=self.chain_id,
            schema_version=self._schema_version(),
            tx_index_hash=self._tx_index_hash,
            state_provider=lambda: dict(self.state),
            block_provider=self.get_block_by_height,
            bft_enabled=bool(effective_bft_enabled(executor=self, default=False)),
        )

    def apply_state_sync_response(
        self,
        resp: StateSyncResponseMsg,
        *,
        trusted_anchor: Json | None = None,
        allow_snapshot_bootstrap: bool = False,
    ) -> list[ExecutorMeta]:
        """Verify and deterministically apply a state-sync response.

        Safety properties:
        - response header must match local chain/schema/tx-index hash
        - trusted_anchor, when provided, must match the responder's advertised anchor
        - delta blocks must be contiguous from the current local height
        - blocks are applied strictly in parent order using apply_block()

        Snapshot replacement is intentionally disabled by default because replacing
        a non-empty local ledger from a remote peer is a trust-sensitive operation.
        """
        if not isinstance(resp, StateSyncResponseMsg):
            raise ExecutorError("bad_state_sync_response_type")

        svc = self._state_sync_service()
        try:
            svc.verify_response(resp, trusted_anchor=trusted_anchor)
        except StateSyncVerifyError as e:
            raise ExecutorError(f"state_sync_verify_failed:{e}") from e

        if not bool(resp.ok):
            raise ExecutorError(f"state_sync_remote_error:{str(resp.reason or 'unknown')}")

        if resp.snapshot is not None:
            if not allow_snapshot_bootstrap:
                raise ExecutorError("state_sync_snapshot_requires_explicit_allow")
            if int(self.state.get("height") or 0) != 0:
                raise ExecutorError("state_sync_snapshot_only_allowed_on_empty_ledger")
            snap = dict(resp.snapshot)
            snap_chain = str(snap.get("chain_id") or self.chain_id).strip()
            if snap_chain != self.chain_id:
                raise ExecutorError("state_sync_snapshot_chain_mismatch")
            self.state = snap
            self._ledger_store.write(self.state)
            self._check_db_consistency_fail_closed()
            return []

        metas: list[ExecutorMeta] = []
        local_height = int(self.state.get("height") or 0)
        pending: list[tuple[int, str, Json]] = []

        for blk in list(resp.blocks or ()):
            if not isinstance(blk, dict):
                raise ExecutorError("state_sync_delta_bad_block")
            blk2, _ = ensure_block_hash(dict(blk))
            bid = str(blk2.get("block_id") or "").strip()
            h = self._block_height_hint(blk2)
            if h <= 0 or not bid:
                raise ExecutorError("state_sync_delta_bad_block_identity")
            pending.append((h, bid, blk2))

        pending.sort(key=lambda item: (int(item[0]), item[1]))

        expected_height = local_height + 1
        expected_parent = str(self.state.get("tip") or "").strip()
        for h, bid, blk in pending:
            if h <= local_height:
                # Harmless duplicate during retry/rejoin. Skip if already committed.
                if self._has_local_block(bid):
                    continue
                raise ExecutorError("state_sync_delta_height_regression")
            if h != expected_height:
                raise ExecutorError("state_sync_delta_gap")
            parent_id = str(blk.get("prev_block_id") or "").strip()
            if expected_height > 1 and parent_id != expected_parent:
                raise ExecutorError("state_sync_delta_parent_mismatch")
            expected_height += 1
            expected_parent = str(bid)

        for _h, _bid, blk in pending:
            if self._has_local_block(_bid):
                continue
            meta = self.apply_block(dict(blk))
            if meta is None or not bool(getattr(meta, "ok", False)):
                err = getattr(meta, "error", "apply_failed") if meta is not None else "apply_failed"
                raise ExecutorError(f"state_sync_delta_apply_failed:{err}")
            metas.append(meta)

        target_height = _safe_int((trusted_anchor or {}).get("height"), 0)
        finalized_target_height = _safe_int((trusted_anchor or {}).get("finalized_height"), 0)
        enforce_finalized_anchor = bool(
            getattr(self._state_sync_service(), "enforce_finalized_anchor", False)
        )
        if enforce_finalized_anchor and finalized_target_height > 0:
            target_height = min(target_height or finalized_target_height, finalized_target_height)

        new_height = int(self.state.get("height") or 0)
        if resp.snapshot is None and target_height > local_height and new_height <= local_height:
            raise ExecutorError("state_sync_delta_no_progress")
        if target_height > 0 and new_height > target_height:
            raise ExecutorError("state_sync_delta_exceeds_trusted_anchor")
        if target_height > 0 and new_height == target_height:
            final_anchor = build_snapshot_anchor(self.state)
            if enforce_finalized_anchor and finalized_target_height > 0:
                if int(final_anchor.get("finalized_height") or 0) != finalized_target_height or str(
                    final_anchor.get("finalized_block_id") or ""
                ) != str((trusted_anchor or {}).get("finalized_block_id") or ""):
                    raise ExecutorError("state_sync_final_anchor_mismatch")
            elif str(final_anchor.get("tip_hash") or "") != str(
                (trusted_anchor or {}).get("tip_hash") or ""
            ) or str(final_anchor.get("state_root") or "") != str(
                (trusted_anchor or {}).get("state_root") or ""
            ):
                raise ExecutorError("state_sync_final_anchor_mismatch")

        return metas

    def request_and_apply_state_sync(
        self,
        net_node: Any,
        peer_id: str,
        *,
        trusted_anchor: Json,
        timeout_ms: int | None = None,
        pump: Any | None = None,
        sleep_ms: int = 10,
    ) -> list[ExecutorMeta]:
        """Request delta state sync from a peer in bounded rounds until the trusted anchor is reached.

        Expects the transport node to implement request_state_sync(peer_id, req, ...).
        """
        if not hasattr(net_node, "request_state_sync"):
            raise ExecutorError("state_sync_transport_missing_request_state_sync")

        target_height = _safe_int((trusted_anchor or {}).get("height"), 0)
        finalized_target_height = _safe_int((trusted_anchor or {}).get("finalized_height"), 0)
        enforce_finalized_anchor = bool(
            getattr(self._state_sync_service(), "enforce_finalized_anchor", False)
        )
        if enforce_finalized_anchor and finalized_target_height > 0:
            target_height = min(target_height or finalized_target_height, finalized_target_height)
        local_height = int(self.state.get("height") or 0)
        if target_height <= local_height:
            return []

        max_delta_blocks = max(1, _env_int("WEALL_SYNC_MAX_DELTA_BLOCKS", 128))
        max_rounds = max(
            1,
            _env_int(
                "WEALL_SYNC_MAX_ROUNDS",
                max(
                    4,
                    ((target_height - local_height + max_delta_blocks - 1) // max_delta_blocks) + 2,
                ),
            ),
        )
        all_metas: list[ExecutorMeta] = []
        rounds = 0

        while int(self.state.get("height") or 0) < target_height:
            rounds += 1
            if rounds > max_rounds:
                raise ExecutorError("state_sync_max_rounds_exceeded")

            from_height = int(self.state.get("height") or 0)
            to_height = min(target_height, from_height + max_delta_blocks)
            corr_id = hashlib.sha256(
                f"{self.chain_id}:{self.node_id}:{peer_id}:{from_height}:{to_height}:{target_height}:{_now_ms()}".encode()
            ).hexdigest()[:24]
            hdr = WireHeader(
                type=MsgType.STATE_SYNC_REQUEST,
                chain_id=self.chain_id,
                schema_version=self._schema_version(),
                tx_index_hash=self._tx_index_hash,
                sent_ts_ms=_now_ms(),
                corr_id=corr_id,
            )
            req = StateSyncRequestMsg(
                header=hdr,
                mode="delta",
                from_height=from_height,
                to_height=to_height,
                selector={"trusted_anchor": dict(trusted_anchor)},
            )
            resp = net_node.request_state_sync(
                str(peer_id),
                req,
                timeout_ms=timeout_ms,
                pump=pump,
                sleep_ms=int(sleep_ms),
            )
            if resp is None:
                raise ExecutorError("state_sync_timeout")

            try:
                metas = self.apply_state_sync_response(resp, trusted_anchor=trusted_anchor)
            except ExecutorError as exc:
                if str(exc) == "state_sync_delta_no_progress":
                    raise ExecutorError("state_sync_no_progress") from exc
                raise
            new_height = int(self.state.get("height") or 0)
            if new_height <= from_height:
                raise ExecutorError("state_sync_no_progress")
            all_metas.extend(metas)

        final_anchor = build_snapshot_anchor(self.state)
        if enforce_finalized_anchor and finalized_target_height > 0:
            if int(final_anchor.get("finalized_height") or 0) != finalized_target_height or str(
                final_anchor.get("finalized_block_id") or ""
            ) != str((trusted_anchor or {}).get("finalized_block_id") or ""):
                raise ExecutorError("state_sync_final_anchor_mismatch")
        elif str(final_anchor.get("tip_hash") or "") != str(
            (trusted_anchor or {}).get("tip_hash") or ""
        ) or str(final_anchor.get("state_root") or "") != str(
            (trusted_anchor or {}).get("state_root") or ""
        ):
            raise ExecutorError("state_sync_final_anchor_mismatch")
        return all_metas

    # ----------------------------
    # Maintenance
    # ----------------------------

    def prune_mempool_expired(self) -> int:
        return self._mempool.prune_expired()

    def prune_attestations_expired(self) -> int:
        return self._att_pool.prune_expired()

    def prune_history_tick(self) -> None:
        """Best-effort DB retention/pruning tick.

        Non-consensus: bounds local history tables (blocks, bft_candidates).
        Defaults to enabled only in prod.
        """
        mode = (os.environ.get("WEALL_MODE") or "prod").strip().lower()
        enabled = (os.environ.get("WEALL_DB_PRUNE") or "").strip().lower()
        if enabled in {"0", "false", "no"}:
            return
        if enabled not in {"1", "true", "yes"} and mode != "prod":
            return

        try:
            interval_ms = int(os.environ.get("WEALL_DB_PRUNE_INTERVAL_MS") or "60000")
        except Exception:
            interval_ms = 60_000
        interval_ms = max(5_000, int(interval_ms))

        now = _now_ms()
        last = int(getattr(self, "_last_db_prune_ms", 0) or 0)
        if (now - last) < interval_ms:
            return
        self._last_db_prune_ms = now

        try:
            retain_n = int(os.environ.get("WEALL_BLOCK_RETENTION_COUNT") or "10000")
        except Exception:
            retain_n = 10_000
        retain_n = max(0, int(retain_n))

        try:
            retain_ms = int(os.environ.get("WEALL_BLOCK_RETENTION_MS") or "0")
        except Exception:
            retain_ms = 0
        retain_ms = max(0, int(retain_ms))

        try:
            cand_ms = int(os.environ.get("WEALL_BFT_CANDIDATE_RETENTION_MS") or "86400000")
        except Exception:
            cand_ms = 86_400_000
        cand_ms = max(0, int(cand_ms))

        try:
            res = self._db.prune_history(
                retain_last_blocks=retain_n,
                retain_blocks_ms=retain_ms,
                retain_bft_candidates_ms=cand_ms,
            )
            if isinstance(res, dict):
                try:
                    from weall.runtime.metrics import inc_counter

                    inc_counter(
                        "db_prune_deleted_blocks_total", int(res.get("deleted_blocks") or 0)
                    )
                    inc_counter(
                        "db_prune_deleted_bft_candidates_total",
                        int(res.get("deleted_bft_candidates") or 0),
                    )
                except Exception:
                    pass
        except Exception:
            try:
                from weall.runtime.metrics import inc_counter

                inc_counter("db_prune_errors_total", 1)
            except Exception:
                pass
            return

    # ----------------------------
    # Compatibility / orchestration hooks
    # ----------------------------

    @classmethod
    def from_env(cls) -> WeAllExecutor:
        cfg = load_chain_config()
        return cls(
            db_path=cfg.db_path,
            node_id=cfg.node_id,
            chain_id=cfg.chain_id,
            tx_index_path=cfg.tx_index_path,
        )


