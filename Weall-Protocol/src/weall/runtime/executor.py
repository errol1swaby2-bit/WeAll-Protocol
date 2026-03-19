from __future__ import annotations

import copy
from collections import OrderedDict
import json
import os
import time
import hashlib
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from weall.crypto.sig import sign_ed25519
from weall.ledger.state import LedgerView
from weall.ledger.roles_schema import ensure_roles_schema
from weall.runtime.attestation_pool import PersistentAttestationPool
from weall.runtime.bft_hotstuff import (
    BftTimeout,
    BftVote,
    HotStuffBFT,
    QuorumCert,
    BFT_MIN_VALIDATORS,
    CONSENSUS_PHASE_BFT_ACTIVE,
    canonical_proposal_message,
    canonical_timeout_message,
    canonical_vote_message,
    leader_for_view,
    normalize_consensus_phase,
    normalize_validators,
    is_descendant,
    qc_from_json,
    verify_proposal_json,
    verify_qc,
    validator_set_hash,
)
from weall.runtime.block_admission import admit_bft_block, admit_bft_commit_block, admit_block_txs
from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import StateSyncService, StateSyncVerifyError, build_snapshot_anchor
from weall.runtime.block_hash import compute_receipts_root, ensure_block_hash, make_block_header
from weall.runtime.block_id import compute_block_id
from weall.runtime.vrf_sig import make_vrf_record, verify_vrf_record
from weall.runtime.state_hash import compute_state_root
from weall.runtime.chain_config import load_chain_config
from weall.runtime.failpoints import maybe_trigger_failpoint
from weall.runtime.bft_journal import BftJournal
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
from weall.runtime.domain_apply import ApplyError, apply_tx_atomic_meta
from weall.runtime.mempool import PersistentMempool, compute_tx_id
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs
from weall.runtime.poh.tier3_scheduler import schedule_poh_tier3_system_txs
from weall.runtime.reputation_units import (
    REPUTATION_SCALE,
    account_reputation_units,
    sync_account_reputation,
    threshold_to_units,
    units_to_reputation,
)
from weall.runtime.sqlite_db import SqliteDB, SqliteLedgerStore, _canon_json, derive_aux_db_path
# SqliteLedgerStore is defined in weall.runtime.sqlite_db in this repo layout
from weall.runtime.system_tx_engine import prune_emitted_system_queue, system_tx_emitter
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex

Json = Dict[str, Any]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _ensure_parent(path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)


def _safe_int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def _mode() -> str:
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _bounded_put(od: "OrderedDict[str, Any]", key: str, value: Any, *, cap: int) -> None:
    """Insert into an OrderedDict while enforcing a hard cap.

    Strict mode / production hardening: untrusted inbound data MUST NOT be able to
    grow in-memory caches without bound.
    """
    if cap <= 0:
        return
    try:
        if key in od:
            del od[key]
        od[key] = value
        while len(od) > cap:
            od.popitem(last=False)
    except Exception:
        # Fail-closed would be too disruptive here; bounded caches are best-effort.
        # The caller still validates and rejects invalid blocks/txs elsewhere.
        return


def _consensus_fail_closed() -> bool:
    return _mode() == "prod"


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

        self.db_path = str(db_path)
        _ensure_parent(self.db_path)
        aux_db_override = str(os.environ.get("WEALL_AUX_DB_PATH") or "").strip()
        self.aux_db_path = aux_db_override or derive_aux_db_path(self.db_path)
        _ensure_parent(self.aux_db_path)

        validate_runtime_consensus_profile()

        self._schema_version_cached = str(os.environ.get("WEALL_SCHEMA_VERSION") or "1").strip() or "1"
        try:
            _b = Path(self.tx_index_path).read_bytes()
            self._tx_index_hash = hashlib.sha256(_b).hexdigest()
        except Exception:
            self._tx_index_hash = ""

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

        # Back-compat alias used by some tests that reached into the storage layer.
        self._store = self._ledger_store

        # Load or initialize state.
        if self._ledger_store.exists():
            self.state = self._ledger_store.read()
        else:
            self.state = self._initial_state()
            # Genesis-only bootstrap hooks.
            # IMPORTANT: never "auto-elevate" based on being the first node.
            # Any bootstrap privileges must be explicit in the genesis builder.
            self._apply_genesis_bootstrap_tier3(self.state)
            self._ledger_store.write(self.state)

        # Storage-boundary block identity caches must exist before any startup
        # consistency checks that may load blocks from disk.
        self._max_known_block_hashes: int = _safe_int(os.environ.get("WEALL_MAX_KNOWN_BLOCK_HASHES"), 4096)
        self._known_block_hashes: "OrderedDict[str, str]" = OrderedDict()
        self._max_known_block_ids_by_hash: int = _safe_int(os.environ.get("WEALL_MAX_KNOWN_BLOCK_IDS_BY_HASH"), 4096)
        self._known_block_ids_by_hash: "OrderedDict[str, str]" = OrderedDict()

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
        meta["startup_clock_sanity_required"] = bool(PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required)
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
        ):
            self._ledger_store.write(self.state)

        wall_now_ms = _now_ms()
        tip_ts_ms = _safe_int(self.state.get("tip_ts_ms"), 0)
        clock_skew_ahead_ms = max(0, int(tip_ts_ms) - int(wall_now_ms)) if tip_ts_ms > 0 else 0
        catastrophic_skew = bool(clock_skew_ahead_ms > STARTUP_CLOCK_HARD_FAIL_MS)
        if clock_skew_ahead_ms > CLOCK_SKEW_WARN_MS:
            self._startup_clock_observer_required = bool(_mode() == "prod" and catastrophic_skew)
            self._startup_clock_observer_reason = "clock_skew_ahead" if self._startup_clock_observer_required else ""
            meta["clock_warning"] = {
                "wall_now_ms": int(wall_now_ms),
                "tip_ts_ms": int(tip_ts_ms),
                "skew_ms": int(clock_skew_ahead_ms),
                "warning_threshold_ms": int(CLOCK_SKEW_WARN_MS),
                "startup_hard_fail_threshold_ms": int(STARTUP_CLOCK_HARD_FAIL_MS),
                "startup_clock_sanity_required": bool(PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required),
                "startup_blocked": False,
                "observer_mode_recommended": True,
                "observer_mode_forced": bool(self._startup_clock_observer_required),
                "consensus_impact": "operator_warning_only",
            }
            self._ledger_store.write(self.state)

        # Back-compat / migration: ensure tip fields exist.
        self.state.setdefault("tip_hash", "")
        self.state.setdefault("tip_ts_ms", 0)
        self.state.setdefault("blocks", {})  # minimal ancestry map: block_id -> {height, prev_block_id}
        self.state.setdefault("finalized", {"height": 0, "block_id": ""})  # legacy finality placeholder

        # Canon tx index.
        self.tx_index: TxIndex = TxIndex.load_from_file(self.tx_index_path)


        # BFT engine (HotStuff)
        self._bft = HotStuffBFT(chain_id=self.chain_id)
        self._bft.load_from_state(self.state)
        self._bft.timeout_base_ms = max(250, _safe_int(os.environ.get("WEALL_BFT_TIMEOUT_BASE_MS"), 10_000))
        self._bft.timeout_backoff_cap = max(0, _safe_int(os.environ.get("WEALL_BFT_TIMEOUT_BACKOFF_CAP"), 4))

        journal_path = os.environ.get("WEALL_BFT_JOURNAL_PATH") or f"{db_path}.bft_journal.jsonl"
        self._bft_journal = BftJournal(path=str(journal_path), max_events=_safe_int(os.environ.get("WEALL_BFT_JOURNAL_MAX_EVENTS"), 2000))
        self._restore_bft_restart_hints()

        # In-memory cache for candidate blocks awaiting QC (leader side)
        # block_id -> (block_dict, state_after_apply, applied_ids, invalid_ids)
        # Strict mode: these caches are hard-capped to prevent memory DoS.
        self._max_pending_candidates: int = _safe_int(os.environ.get("WEALL_MAX_PENDING_CANDIDATES"), 128)
        self._pending_candidates: "OrderedDict[str, Tuple[Json, Json, List[str], List[str]]]" = OrderedDict()
        self._pending_candidate_ids_by_hash: "OrderedDict[str, str]" = OrderedDict()

        # In-memory cache for remote proposals we may need to commit once a QC arrives
        # block_id -> block_dict
        # Strict mode: hard-cap to prevent unbounded growth from untrusted peers.
        self._max_pending_remote_blocks: int = _env_int("WEALL_MAX_PENDING_REMOTE_BLOCKS", 256)
        self._pending_remote_blocks: "OrderedDict[str, Json]" = OrderedDict()
        self._pending_remote_block_ids_by_hash: "OrderedDict[str, str]" = OrderedDict()

        # Unverified remote proposals are quarantined under a tighter cap until
        # leader/signature/admission checks pass. This prevents untrusted proposal
        # floods from competing directly with validated pending replay artifacts.
        self._max_quarantined_remote_blocks: int = _env_int("WEALL_MAX_QUARANTINED_REMOTE_BLOCKS", 64)
        self._quarantined_remote_blocks: "OrderedDict[str, Json]" = OrderedDict()
        self._quarantined_remote_block_ids_by_hash: "OrderedDict[str, str]" = OrderedDict()

        # QC objects that arrived before their referenced block proposal. These are
        # retained in a bounded cache so the networking layer can fetch the missing
        # proposal/block and complete replay deterministically on restart/rejoin.
        self._max_pending_missing_qcs: int = _safe_int(os.environ.get("WEALL_MAX_PENDING_MISSING_QCS"), 256)
        self._pending_missing_qcs: "OrderedDict[str, Json]" = OrderedDict()
        self._pending_missing_qcs_by_hash: "OrderedDict[str, Json]" = OrderedDict()

        # Contain block_id/block_hash ambiguity fail-closed. If we ever observe
        # two different hashes for the same block_id, quarantine that block_id so
        # pending replay and QC pairing cannot silently mix identities.
        self._max_conflicted_block_ids: int = _safe_int(os.environ.get("WEALL_MAX_CONFLICTED_BLOCK_IDS"), 256)
        self._conflicted_block_ids: "OrderedDict[str, Json]" = OrderedDict()
        self._max_conflicted_block_hashes: int = _safe_int(os.environ.get("WEALL_MAX_CONFLICTED_BLOCK_HASHES"), 256)
        self._conflicted_block_hashes: "OrderedDict[str, Json]" = OrderedDict()
        self._restore_pending_bft_frontier()

        # Remote proposal vote validation can be expensive because the strict path
        # replays the proposal in a temporary SQLite-backed executor. Cache results
        # by exact block_hash and apply hard caps before any clone/replay work so an
        # untrusted peer cannot force repeated expensive validations for the same
        # payload or for obviously too-large proposals.
        self._max_votecheck_cache: int = _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_CACHE_SIZE"), 1024)
        self._votecheck_cache: "OrderedDict[str, bool]" = OrderedDict()
        self._max_votecheck_txs: int = max(0, _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_MAX_TXS"), 2048))
        self._max_votecheck_block_bytes: int = max(0, _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_MAX_BLOCK_BYTES"), 1_000_000))
        self._proposal_validation_limit: int = max(1, _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_MAX_CONCURRENT"), 4))
        self._proposal_validation_semaphore = threading.BoundedSemaphore(self._proposal_validation_limit)
        self._proposal_peer_budget_window_ms: int = max(100, _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_PEER_WINDOW_MS"), 1000))
        self._proposal_peer_budget_max: int = max(1, _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_PEER_MAX_PER_WINDOW"), 8))
        self._max_proposal_peer_budget_entries: int = max(8, _safe_int(os.environ.get("WEALL_BFT_VOTECHECK_MAX_PEERS"), 512))
        self._proposal_peer_budget: "OrderedDict[str, Json]" = OrderedDict()
        self._max_spec_exec_pool: int = max(1, _safe_int(os.environ.get("WEALL_BFT_SPEC_EXEC_POOL_SIZE"), 4))
        self._spec_exec_pool: List[Tuple[str, str]] = []
        self._spec_exec_pool_root = Path(os.environ.get("WEALL_BFT_SPEC_EXEC_TMPDIR") or tempfile.gettempdir()) / f"weall-bft-specpool-{os.getpid()}"
        self._spec_exec_pool_root.mkdir(parents=True, exist_ok=True)

        # SQLite maintenance cadence (WAL checkpoint, optimize). These are
        # best-effort and are disabled by default in non-prod to keep tests
        # deterministic and fast.
        self._last_sqlite_maint_ms: int = 0

        mode = (os.environ.get("WEALL_MODE") or "prod").strip().lower()
        self._sqlite_maintenance_enabled = (os.environ.get("WEALL_SQLITE_MAINTENANCE") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if os.environ.get("WEALL_SQLITE_MAINTENANCE") is None:
            # Default policy: enabled in prod, disabled elsewhere.
            self._sqlite_maintenance_enabled = (mode == "prod")

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
        self._init_validator_runtime_posture()

    def _runtime_meta(self) -> Json:
        meta = self.state.get("meta")
        if not isinstance(meta, dict):
            meta = {}
            self.state["meta"] = meta
        return meta

    def _persist_runtime_meta(self) -> None:
        self._ledger_store.write(self.state)

    def _init_validator_runtime_posture(self) -> None:
        meta = self._runtime_meta()
        previous_clean = bool(meta.get("last_shutdown_clean", True))
        observer_requested = _env_bool("WEALL_OBSERVER_MODE", False)
        signing_requested = _env_bool("WEALL_VALIDATOR_SIGNING_ENABLED", True)
        allow_dirty_signing = _env_bool("WEALL_ALLOW_DIRTY_SIGNING", False)

        forced_observer = False
        reason = ""
        if observer_requested:
            signing_requested = False
            forced_observer = True
            reason = "observer_mode_env"
        elif _mode() == "prod" and getattr(self, "_startup_clock_observer_required", False) and signing_requested and not allow_dirty_signing:
            signing_requested = False
            forced_observer = True
            reason = str(getattr(self, "_startup_clock_observer_reason", "") or "clock_skew_warning")
        elif _mode() == "prod" and not previous_clean and signing_requested and not allow_dirty_signing:
            signing_requested = False
            forced_observer = True
            reason = "unclean_shutdown"

        self._validator_signing_enabled = bool(signing_requested)
        self._observer_mode_forced = bool(forced_observer)
        self._signing_block_reason = str(reason) if not self._validator_signing_enabled else ""

        meta["last_startup_ms"] = int(_now_ms())
        meta["last_shutdown_clean"] = False
        meta["validator_signing_enabled"] = bool(self._validator_signing_enabled)
        meta["observer_mode"] = bool(not self._validator_signing_enabled)
        if self._signing_block_reason:
            meta["signing_block_reason"] = str(self._signing_block_reason)
        else:
            meta.pop("signing_block_reason", None)
        self._persist_runtime_meta()

    def mark_clean_shutdown(self) -> None:
        meta = self._runtime_meta()
        meta["last_shutdown_clean"] = True
        meta["validator_signing_enabled"] = bool(self._validator_signing_enabled)
        meta["observer_mode"] = bool(not self._validator_signing_enabled)
        if self._signing_block_reason:
            meta["signing_block_reason"] = str(self._signing_block_reason)
        else:
            meta.pop("signing_block_reason", None)
        meta["last_clean_shutdown_ms"] = int(_now_ms())
        self._persist_runtime_meta()

    def validator_signing_enabled(self) -> bool:
        return bool(self._validator_signing_enabled)

    def _explicit_validator_signing_override(self) -> bool:
        """Allow explicit local signing tools to function even in observer posture.

        Observer mode still blocks normal automatic validator behavior, but tests and
        recovery tooling sometimes intentionally reopen a DB and provide a full
        validator identity tuple explicitly via environment. In that case we allow
        local signing helpers to emit the exact same vote/timeout/proposal again
        without weakening the persisted observer diagnostics.
        """
        acct = str(os.environ.get("WEALL_VALIDATOR_ACCOUNT") or "").strip()
        pub = str(os.environ.get("WEALL_NODE_PUBKEY") or "").strip()
        priv = str(os.environ.get("WEALL_NODE_PRIVKEY") or "").strip()
        if not acct or not pub or not priv:
            return False
        active = set(self._active_validators())
        if acct not in active:
            return False
        expected = str(self._validator_pubkeys().get(acct) or "").strip()
        return (not expected) or expected == pub

    def _validator_signing_permitted(self) -> bool:
        return bool(self._validator_signing_enabled) or self._explicit_validator_signing_override()

    def observer_mode(self) -> bool:
        return not bool(self._validator_signing_enabled)

    def _restore_bft_restart_hints(self) -> None:
        try:
            info = self._bft_journal.bootstrap_state()
        except Exception:
            return
        try:
            self._bft.view = max(int(self._bft.view), int(info.get("last_view") or 0))
        except Exception:
            pass

    def _bft_record_event(self, event: str, **payload: Any) -> None:
        try:
            self._bft_journal.append(event, chain_id=self.chain_id, node_id=self.node_id, **payload)
        except Exception:
            pass

    def _persist_pending_bft_artifact(self, *, kind: str, block_id: str, payload: Json) -> None:
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
        skind = str(kind or "").strip()
        bid = str(block_id or "").strip()
        if not skind or not bid:
            return
        try:
            with self._aux_db.write_tx() as con:
                con.execute("DELETE FROM bft_pending_artifacts WHERE kind=? AND block_id=?;", (skind, bid))
        except Exception:
            return

    def _restore_pending_bft_frontier(self) -> None:
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
                _bounded_put(self._pending_remote_blocks, bid, dict(payload), cap=self._max_pending_remote_blocks)
                self._index_pending_remote_block(payload)
            elif kind == "pending_candidate":
                _bounded_put(self._pending_candidates, bid, (dict(payload), {}, [], []), cap=self._max_pending_candidates)
                self._index_pending_candidate(payload)
            elif kind == "pending_missing_qc":
                _bounded_put(self._pending_missing_qcs, bid, dict(payload), cap=self._max_pending_missing_qcs)
                self._index_pending_missing_qc(payload)
            else:
                stale_rows.append((kind, bid))
        for kind, bid in stale_rows:
            self._delete_pending_bft_artifact(kind=kind, block_id=bid)
        self._prune_pending_bft_artifacts()

    def _bft_outbound_key(self, kind: str, payload: Json) -> str:
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
        key = self._bft_outbound_key(kind, payload)
        self._bft_record_event("bft_outbound_enqueued", kind=str(kind), key=key, payload=dict(payload or {}))
        return key

    def bft_mark_outbound_sent(self, kind: str, payload: Json) -> None:
        key = self._bft_outbound_key(kind, payload)
        self._bft_record_event("bft_outbound_sent", kind=str(kind), key=key)

    def bft_pending_outbound_messages(self) -> list[Json]:
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

    def _initial_state(self) -> Json:
        # IMPORTANT: this must include the core consensus/authorization subtrees.
        # Many tests and admission/gate logic assume these keys exist.
        return {
            "chain_id": self.chain_id,
            "created_ms": GENESIS_CREATED_MS,

            # Monotonic chain time (ts_ms) tracked by the executor.
            # Initialized at genesis so session-gated logic can behave deterministically.
            "time": 0,

            "meta": {
                "protocol_version": PROTOCOL_VERSION,
                "production_consensus_profile": PRODUCTION_CONSENSUS_PROFILE.to_json(),
                "production_consensus_profile_hash": PRODUCTION_CONSENSUS_PROFILE.profile_hash(),
                "reputation_scale": REPUTATION_SCALE,
                "max_block_future_drift_ms": MAX_BLOCK_FUTURE_DRIFT_MS,
                "clock_skew_warn_ms": CLOCK_SKEW_WARN_MS,
            },

            # Core ledger subtrees
            "accounts": {},
            "roles": {},
            "params": {},
            "poh": {},
            "last_block_ts_ms": 0,

            # Chain tip / ancestry
            "height": 0,
            "tip": "",
            "tip_hash": "",
            "tip_ts_ms": 0,
            "blocks": {},
            "finalized": {"height": 0, "block_id": ""},
        }

    # ----------------------------
    # Genesis bootstrap hooks
    # ----------------------------

    @staticmethod
    def _mk_key_id(pubkey: str) -> str:
        """Stable deterministic key id for accounts[acct]["keys"]["by_id"]."""
        h = hashlib.sha256(str(pubkey).encode("utf-8")).hexdigest()
        return f"k:{h[:16]}"

    def _apply_genesis_bootstrap_tier3(self, state: Json) -> None:
        """Genesis bootstrap for the founder/operator account.

        This executes only when the ledger is first created (height == 0).
        It seeds the configured bootstrap account with:
          - a registered main key
          - Tier 3 PoH
          - adequate starting reputation for operator duties
          - an active node-operator role record
          - an enabled storage-operator record

        Env contract:
          - WEALL_GENESIS_BOOTSTRAP_ENABLE=1: required to activate bootstrap
          - WEALL_GENESIS_BOOTSTRAP_ACCOUNT: required with PUBKEY when enabled
          - WEALL_GENESIS_BOOTSTRAP_PUBKEY: required with ACCOUNT when enabled
          - WEALL_GENESIS_BOOTSTRAP_REPUTATION: optional, default 1.0
          - WEALL_GENESIS_BOOTSTRAP_STORAGE_CAPACITY_BYTES: optional, default 0

        Safety properties:
          - No implicit "first node" auto-elevation.
          - Bootstrap is off by default unless WEALL_GENESIS_BOOTSTRAP_ENABLE=1.
          - If enabled, missing or partial config fails closed.
          - If WEALL_NODE_ID is set and differs from BOOTSTRAP_ACCOUNT, fail-closed.
        """

        try:
            height = int(state.get("height", 0) or 0)
        except Exception:
            height = 0
        if height != 0:
            return

        enabled = _env_bool("WEALL_GENESIS_BOOTSTRAP_ENABLE", False)
        acct = str(os.environ.get("WEALL_GENESIS_BOOTSTRAP_ACCOUNT") or "").strip()
        pk = str(os.environ.get("WEALL_GENESIS_BOOTSTRAP_PUBKEY") or "").strip()

        if not enabled:
            return

        if not acct and not pk:
            raise ExecutorError(
                "genesis_bootstrap_config_error: WEALL_GENESIS_BOOTSTRAP_ENABLE=1 requires both "
                "WEALL_GENESIS_BOOTSTRAP_ACCOUNT and WEALL_GENESIS_BOOTSTRAP_PUBKEY."
            )

        if not acct or not pk:
            raise ExecutorError(
                "genesis_bootstrap_config_error: both WEALL_GENESIS_BOOTSTRAP_ACCOUNT and "
                "WEALL_GENESIS_BOOTSTRAP_PUBKEY must be set (or neither)."
            )

        node_id = str(os.environ.get("WEALL_NODE_ID") or self.node_id or "").strip()
        if node_id and node_id != acct:
            raise ExecutorError(
                "genesis_bootstrap_config_error: WEALL_NODE_ID does not match "
                "WEALL_GENESIS_BOOTSTRAP_ACCOUNT (refuse to grant Tier 3 to a different account)."
            )

        bootstrap_rep_raw = os.environ.get("WEALL_GENESIS_BOOTSTRAP_REPUTATION")
        bootstrap_rep_units = threshold_to_units(
            bootstrap_rep_raw if bootstrap_rep_raw is not None else "1.0",
            default=REPUTATION_SCALE,
        )
        if bootstrap_rep_units < 0:
            bootstrap_rep_units = 0

        try:
            storage_capacity = int(os.environ.get("WEALL_GENESIS_BOOTSTRAP_STORAGE_CAPACITY_BYTES") or 0)
        except Exception:
            storage_capacity = 0
        if storage_capacity < 0:
            storage_capacity = 0

        accounts = state.get("accounts")
        if not isinstance(accounts, dict):
            accounts = {}
            state["accounts"] = accounts

        a = accounts.get(acct)
        if not isinstance(a, dict):
            a = {
                "nonce": 0,
                "poh_tier": 0,
                "banned": False,
                "locked": False,
                "reputation": 0.0,
                "reputation_milli": 0,
                "balance": 0,
                "keys": {"by_id": {}},
                "devices": {"by_id": {}},
                "recovery": {"config": None, "proposals": {}},
                "session_keys": {},
            }
            accounts[acct] = a
        sync_account_reputation(a, default_units=0)

        keys = a.get("keys")
        if not isinstance(keys, dict):
            keys = {"by_id": {}}
            a["keys"] = keys
        by_id = keys.get("by_id")
        if not isinstance(by_id, dict):
            by_id = {}
            keys["by_id"] = by_id

        kid = self._mk_key_id(pk)
        rec = by_id.get(kid)
        if not isinstance(rec, dict):
            by_id[kid] = {"pubkey": pk, "key_type": "main", "revoked": False, "revoked_at": None}
        else:
            rec.setdefault("pubkey", pk)
            rec.setdefault("key_type", "main")
            rec.setdefault("revoked", False)
            rec.setdefault("revoked_at", None)

        a["poh_tier"] = 3
        cur_rep_units = account_reputation_units(a, default=0)
        a["reputation_milli"] = max(cur_rep_units, bootstrap_rep_units)
        a["reputation"] = units_to_reputation(a["reputation_milli"])
        a["banned"] = False
        a["locked"] = False

        poh_meta = a.get("poh")
        if not isinstance(poh_meta, dict):
            poh_meta = {}
            a["poh"] = poh_meta
        poh_meta.setdefault("tier3_source", "genesis_bootstrap")
        poh_meta.setdefault("tier3_reason", "genesis_bootstrap_tier3")
        poh_meta.setdefault("bootstrap_operator_bundle", True)

        roles = ensure_roles_schema(state)
        node_ops = roles.get("node_operators")
        if not isinstance(node_ops, dict):
            node_ops = {"by_id": {}, "active_set": []}
            roles["node_operators"] = node_ops
        by_id_ops = node_ops.get("by_id")
        if not isinstance(by_id_ops, dict):
            by_id_ops = {}
            node_ops["by_id"] = by_id_ops
        rec_op = by_id_ops.get(acct)
        if not isinstance(rec_op, dict):
            rec_op = {}
        rec_op["enrolled"] = True
        rec_op["active"] = True
        rec_op.setdefault("enrolled_at_nonce", 0)
        rec_op.setdefault("activated_at_nonce", 0)
        rec_op.setdefault("source", "genesis_bootstrap")
        by_id_ops[acct] = rec_op
        aset = node_ops.get("active_set")
        if not isinstance(aset, list):
            aset = []
        if acct not in aset:
            aset = sorted({*(str(x) for x in aset if str(x).strip()), acct})
        node_ops["active_set"] = aset

        storage = state.get("storage")
        if not isinstance(storage, dict):
            storage = {}
            state["storage"] = storage
        if not isinstance(storage.get("operators"), dict):
            storage["operators"] = {}
        op_rec_any = storage["operators"].get(acct)
        op_rec = op_rec_any if isinstance(op_rec_any, dict) else {"account_id": acct}
        op_rec["enabled"] = True
        op_rec.setdefault("used_bytes", 0)
        op_rec["capacity_bytes"] = max(int(op_rec.get("capacity_bytes") or 0), int(storage_capacity))
        op_rec.setdefault("updated_at_nonce", 0)
        op_rec.setdefault("source", "genesis_bootstrap")
        storage["operators"][acct] = op_rec

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
                self.state["tip_ts_ms"] = _safe_int(blk2.get("block_ts_ms") or blk2.get("created_ms"), 0)
        except ExecutorError:
            raise
        except Exception:
            raise ExecutorError("db_invariant_violation: cannot compute persisted tip hash. Refuse to start.")

    # ----------------------------
    # Public accessors
    # ----------------------------

    @property
    def mempool(self) -> PersistentMempool:
        return self._mempool

    @property
    def attestation_pool(self) -> PersistentAttestationPool:
        return self._att_pool

    def read_mempool(self, *, limit: int = 10_000) -> List[Json]:
        """Ops/test helper: inspect the current mempool."""
        lim = int(limit) if int(limit) > 0 else 10_000
        return self._mempool.peek(limit=lim)


    def get_tx_status(self, tx_id: str) -> dict[str, object]:
        """Resolve transaction lifecycle state.

        Order of checks:
          1. confirmed (tx_index)
          2. pending (mempool)
          3. unknown

        This is the canonical runtime interface used by tests and by the API
        tx-status route. Keeping this logic inside the executor avoids direct
        database access from callers and ensures tx lifecycle semantics stay
        centralized.
        """
        tx_id = str(tx_id or "").strip()
        if not tx_id:
            return {"ok": True, "tx_id": tx_id, "status": "unknown"}

        with self._db.connection() as con:
            row = con.execute(
                """
                SELECT tx_id, height, block_id, tx_type, signer, nonce, ok, included_ts_ms
                FROM tx_index
                WHERE tx_id = ?
                LIMIT 1
                """,
                (tx_id,),
            ).fetchone()
            if row is not None:
                return {
                    "ok": True,
                    "tx_id": str(row["tx_id"]),
                    "status": "confirmed",
                    "height": int(row["height"]),
                    "block_id": str(row["block_id"]),
                    "tx_type": str(row["tx_type"]),
                    "signer": str(row["signer"]),
                    "nonce": int(row["nonce"]),
                    "included_ts_ms": int(row["included_ts_ms"]),
                }

            row = con.execute(
                """
                SELECT tx_id
                FROM mempool
                WHERE tx_id = ?
                LIMIT 1
                """,
                (tx_id,),
            ).fetchone()
            if row is not None:
                return {
                    "ok": True,
                    "tx_id": tx_id,
                    "status": "pending",
                }

        return {
            "ok": True,
            "tx_id": tx_id,
            "status": "unknown",
        }

    def read_state(self) -> Json:
        """Return the latest persisted ledger snapshot.

        This keeps read-only API processes coherent when a separate producer
        process commits blocks into the shared SQLite store.
        """
        try:
            self.state = self._ledger_store.read()
        except Exception:
            pass
        return self.state

    # ----------------------------
    # Tx + att submission
    # ----------------------------

    # Back-compat: legacy route modules call `executor.snapshot()`.
    def snapshot(self) -> Json:
        """Return a full in-memory snapshot of chain state."""
        return self.read_state()

    def tx_index_hash(self) -> str:
        """Return SHA-256 hex digest of the canonical tx index file."""
        return str(getattr(self, "_tx_index_hash", "") or "")

    # ----------------------------
    # SQLite maintenance
    # ----------------------------

    def sqlite_maintenance_tick(self) -> None:
        """Best-effort SQLite maintenance.

        - periodic WAL checkpoint to keep WAL bounded
        - occasional PRAGMA optimize

        This must never be consensus-critical: it should not mutate chain state.
        """
        if not getattr(self, "_sqlite_maintenance_enabled", False):
            return

        now = _now_ms()

        # WAL checkpoint
        interval = int(getattr(self, "_sqlite_checkpoint_interval_ms", 0) or 0)
        if interval > 0 and (now - int(getattr(self, "_last_sqlite_maint_ms", 0) or 0)) >= interval:
            try:
                # PASSIVE is non-blocking; it will not stall writers for long.
                self._db.wal_checkpoint(mode="PASSIVE")
            except Exception:
                # Never crash the node due to maintenance.
                pass
            self._last_sqlite_maint_ms = now

        # Optimize
        opt_interval = int(getattr(self, "_sqlite_optimize_interval_ms", 0) or 0)
        if opt_interval > 0 and (now - int(getattr(self, "_last_sqlite_optimize_ms", 0) or 0)) >= opt_interval:
            try:
                self._db.optimize()
            except Exception:
                pass
            self._last_sqlite_optimize_ms = now

    def submit_tx(self, env: Json) -> Json:
        if not isinstance(env, dict):
            return {"ok": False, "error": "bad_env:not_object"}

        ledger = LedgerView.from_ledger(self.read_state())
        verdict = admit_tx(tx=env, ledger=ledger, canon=self.tx_index, context="mempool")
        if not verdict.ok:
            return {"ok": False, "error": verdict.code, "reason": verdict.reason, "details": verdict.details}

        return self._mempool.add(env)

    def submit_attestation(self, env: Json) -> Json:
        return self._att_pool.add(env)

    # ----------------------------
    # Simple block producer (SQLite-backed)
    # ----------------------------

    def produce_block(self, *, max_txs: int = 1000) -> ExecutorMeta:
        h0 = _safe_int(self.state.get("height"), 0)

        blk, st2, applied_ids, invalid_ids, err = self.build_block_candidate(
            max_txs=int(max_txs),
            allow_empty=False,
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

        return self.commit_block_candidate(block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids)

    # ----------------------------
    # Block candidate builder (proposal)
    # ----------------------------

    def build_block_candidate(
        self,
        *,
        max_txs: int = 1000,
        allow_empty: bool = False,
        force_ts_ms: Optional[int] = None,
    ) -> Tuple[Optional[Json], Optional[Json], List[str], List[str], str]:
        height = _safe_int(self.state.get("height"), 0)
        tip = str(self.state.get("tip") or "")
        tip_hash = str(self.state.get("tip_hash") or "")

        chain_floor_ms = self.chain_time_floor_ms()
        successor_ts_ms = max(1, int(chain_floor_ms) + 1)

        if force_ts_ms is not None:
            ts_ms = int(force_ts_ms)
        else:
            ts_ms = successor_ts_ms

        if ts_ms < successor_ts_ms:
            return None, None, [], [], "invalid_block_ts:before_chain_floor"
        if ts_ms > int(chain_floor_ms) + int(MAX_BLOCK_TIME_ADVANCE_MS):
            return None, None, [], [], "invalid_block_ts:beyond_chain_time_window"

        txs = self._mempool.peek(limit=int(max_txs))
        if not txs and not bool(allow_empty):
            return None, None, [], [], "empty"

        working: Json = copy.deepcopy(self.state)

        applied_ids: List[str] = []
        invalid_ids: List[str] = []
        applied_envs: List[Json] = []
        receipts: List[Json] = []

        next_height = int(height) + 1

        def _apply_system_env(env: TxEnvelope) -> None:
            try:
                meta = apply_tx_atomic_meta(working, env, consume_nonce_on_fail=False)
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

        # Phase: schedule PoH system txs (best-effort)
        try:
            schedule_poh_tier2_system_txs(working, next_height=next_height)
            schedule_poh_tier3_system_txs(working, next_height=next_height)
        except Exception:
            pass

        # Phase: system emitter pre
        try:
            sys_pre = system_tx_emitter(working, self.tx_index, next_height=next_height, phase="pre")
            for env in sys_pre:
                _apply_system_env(env)
        except Exception:
            pass

        # Parse envelopes
        env_objs: List[TxEnvelope] = []
        tx_ids: List[str] = []

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
        ledger_for_block = LedgerView.from_ledger(working)
        ok, block_reject, per_tx = admit_block_txs(
            env_objs,
            ledger_for_block,
            self.tx_index,
            verify_signatures=False,
        )
        if (not ok) and block_reject is not None:
            return None, None, [], [], f"block_reject:{block_reject.code}:{block_reject.reason}"

        # Apply txs (fail-atomic) and always emit deterministic receipts
        for env, env_obj, tx_id, rej in zip(txs, env_objs, tx_ids, per_tx, strict=False):
            if not tx_id:
                invalid_ids.append(tx_id)
                continue

            if rej is not None:
                invalid_ids.append(tx_id)
                continue

            applied_ok = False
            err_code = ""
            err_reason = ""
            err_details: Any = None

            try:
                meta = apply_tx_atomic_meta(working, env, consume_nonce_on_fail=True)
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
            schedule_poh_tier2_system_txs(working, next_height=next_height)
            schedule_poh_tier3_system_txs(working, next_height=next_height)
        except Exception as exc:
            if _consensus_fail_closed():
                return None, None, [], invalid_ids, f"poh_schedule_failed:{type(exc).__name__}"

        # Phase: system emitter post. Same fail-closed rule in production.
        try:
            sys_post = system_tx_emitter(working, self.tx_index, next_height=next_height, phase="post")
            for env in sys_post:
                _apply_system_env(env)
        except Exception as exc:
            if _consensus_fail_closed():
                return None, None, [], invalid_ids, f"system_emitter_post_failed:{type(exc).__name__}"

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
                return None, None, [], invalid_ids, "vrf_missing_node_key"
        except Exception:
            if require_vrf:
                return None, None, [], invalid_ids, "vrf_generate_failed"

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

        try:
            block, bh = ensure_block_hash(block)
            working["tip_hash"] = str(bh)
            working["tip_ts_ms"] = int(ts_ms)
        except Exception as exc:
            return None, None, [], invalid_ids, f"block_hash_commitment_failed:{type(exc).__name__}"

        return block, working, applied_ids, invalid_ids, ""

    # ----------------------------
    # Commit candidate
    # ----------------------------

    def commit_block_candidate(
        self,
        *,
        block: Json,
        new_state: Json,
        applied_ids: List[str],
        invalid_ids: List[str],
    ) -> ExecutorMeta:
        """Atomically persist a block + mempool cleanup + ledger snapshot.

        Production invariant: a node crash or SIGKILL during commit must not leave
        a partially-committed DB (e.g., block row without ledger_state update).
        """
        try:
            height = int(block.get("height") or 0)
            block_id = str(block.get("block_id") or "")
            if not block_id or height <= 0:
                return ExecutorMeta(ok=False, error="bad_block", height=0, block_id="")

            try:
                prune_emitted_system_queue(new_state)
            except Exception as exc:
                if _consensus_fail_closed():
                    return ExecutorMeta(ok=False, error=f"system_queue_prune_failed:{type(exc).__name__}", height=0, block_id="")

            block2, _bh = ensure_block_hash(block)
            now = _now_ms()
            block_json = _canon_json(block2)

            ids: List[str] = []
            seen: set[str] = set()
            for tx_id in list(applied_ids) + list(invalid_ids):
                t = str(tx_id or "").strip()
                if not t or t in seen:
                    continue
                seen.add(t)
                ids.append(t)

            receipts_any = block2.get("receipts")
            receipts_list = receipts_any if isinstance(receipts_any, list) else []
            tx_index_rows: List[Tuple[str, int, str, str, str, int, int, int]] = []
            seen_index_ids: set[str] = set()
            for rec_any in receipts_list:
                if not isinstance(rec_any, dict):
                    continue
                tx_id = str(rec_any.get("tx_id") or "").strip()
                if not tx_id or tx_id in seen_index_ids:
                    continue
                seen_index_ids.add(tx_id)
                tx_index_rows.append(
                    (
                        tx_id,
                        int(height),
                        str(block_id),
                        str(rec_any.get("tx_type") or ""),
                        str(rec_any.get("signer") or ""),
                        int(rec_any.get("nonce") or 0),
                        1 if bool(rec_any.get("ok")) else 0,
                        int(block2.get("block_ts_ms") or now),
                    )
                )

            snap_height = int(new_state.get("height", height))
            snap_tip = str(new_state.get("tip") or block_id).strip()
            state_json = _canon_json(new_state)

            with self._db.write_tx() as con:
                con.execute(
                    "INSERT INTO blocks(height, block_id, block_json, created_ts_ms) VALUES(?,?,?,?);",
                    (int(height), str(block_id), block_json, int(now)),
                )
                con.execute(
                    """
                    INSERT INTO block_hash_index(block_id, block_hash, height, created_ts_ms)
                    VALUES(?,?,?,?)
                    ON CONFLICT(block_id) DO UPDATE SET
                      block_hash=excluded.block_hash,
                      height=excluded.height,
                      created_ts_ms=excluded.created_ts_ms;
                    """,
                    (str(block_id), str(block2.get("block_hash") or ""), int(height), int(now)),
                )

                # TEST-ONLY crash hook: give tests a window to SIGKILL this process
                marker = os.environ.get("WEALL_TEST_MARKER_PATH", "").strip()
                if marker:
                    try:
                        Path(marker).parent.mkdir(parents=True, exist_ok=True)
                        Path(marker).write_text("ready\n")
                    except Exception:
                        pass
                # after the block insert but before ledger_state is updated.
                try:
                    sleep_ms = int(os.environ.get("WEALL_TEST_SLEEP_AFTER_BLOCK_INSERT_MS", "0"))
                except Exception:
                    sleep_ms = 0
                if sleep_ms > 0:
                    time.sleep(sleep_ms / 1000.0)

                # TEST-ONLY fail hook: simulate an exception after the block row is inserted
                # but before mempool cleanup + ledger_state write.
                if os.environ.get("WEALL_TEST_FAIL_AFTER_BLOCK_INSERT", "").strip().lower() in {"1", "true", "yes"}:
                    raise RuntimeError("test_fail_after_block_insert")

                maybe_trigger_failpoint("block_commit_after_block_insert")

                for tx_id in ids:
                    con.execute("DELETE FROM mempool WHERE tx_id=?;", (tx_id,))

                if tx_index_rows:
                    con.executemany(
                        """
                        INSERT INTO tx_index(
                          tx_id,
                          height,
                          block_id,
                          tx_type,
                          signer,
                          nonce,
                          ok,
                          included_ts_ms
                        )
                        VALUES(?,?,?,?,?,?,?,?)
                        ON CONFLICT(tx_id) DO UPDATE SET
                          height=excluded.height,
                          block_id=excluded.block_id,
                          tx_type=excluded.tx_type,
                          signer=excluded.signer,
                          nonce=excluded.nonce,
                          ok=excluded.ok,
                          included_ts_ms=excluded.included_ts_ms;
                        """,
                        tx_index_rows,
                    )

                maybe_trigger_failpoint("block_commit_before_ledger_state")

                con.execute(
                    """
                    INSERT INTO ledger_state(id, height, block_id, state_json, updated_ts_ms)
                    VALUES(1, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      height=excluded.height,
                      block_id=excluded.block_id,
                      state_json=excluded.state_json,
                      updated_ts_ms=excluded.updated_ts_ms;
                    """,
                    (int(snap_height), str(snap_tip), state_json, int(now)),
                )

            previous_epoch = self._current_validator_epoch()
            previous_set_hash = self._current_validator_set_hash() if int(previous_epoch) > 0 else ""
            self.state = new_state
            self._bft.load_from_state(self.state)
            self._cache_known_block_hash(str(block_id), str(block2.get("block_hash") or ""))
            self._prune_pending_bft_artifacts_on_local_validator_transition(
                previous_epoch=int(previous_epoch),
                previous_set_hash=str(previous_set_hash or ""),
            )

            return ExecutorMeta(
                ok=True,
                error="",
                height=int(height),
                block_id=str(block_id),
                applied_count=len(applied_ids),
            )
        except Exception as e:
            return ExecutorMeta(ok=False, error=f"commit_failed:{type(e).__name__}", height=0, block_id="")

    # ----------------------------
    # Apply a received block (network / sync)
    # ----------------------------

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
        if not isinstance(block, dict):
            return ExecutorMeta(ok=False, error="bad_block:not_object", height=0, block_id="")

        try:
            block2, bh = ensure_block_hash(block)
        except Exception:
            return ExecutorMeta(ok=False, error="bad_block:bad_hash", height=0, block_id="")

        if self._block_identity_conflicts(block2):
            return ExecutorMeta(ok=False, error="bad_block:block_id_hash_conflict", height=0, block_id="")

        header = block2.get("header")
        if not isinstance(header, dict):
            return ExecutorMeta(ok=False, error="bad_block:missing_header", height=0, block_id="")

        if str(header.get("chain_id") or "").strip() != self.chain_id:
            return ExecutorMeta(ok=False, error="bad_block:chain_id_mismatch", height=0, block_id="")

        if _env_bool("WEALL_BFT_ENABLED", False):
            strict_bft_apply = _mode() == "prod" or isinstance(block2.get("justify_qc"), dict) or not isinstance(block2.get("qc"), dict)
            if strict_bft_apply:
                ok_bft, rej_bft = admit_bft_commit_block(block=block2, state=self.state, blocks_map=self._bft_speculative_blocks_map())
                if not ok_bft:
                    code = str(rej_bft.code) if rej_bft is not None else "bft_reject"
                    return ExecutorMeta(ok=False, error=f"bad_block:{code}", height=0, block_id=str(block2.get("block_id") or ""))

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
            return ExecutorMeta(ok=False, error="bad_block:prev_hash_mismatch", height=0, block_id="")

        ts_ms = int(header.get("block_ts_ms") or block2.get("block_ts_ms") or 0)
        if ts_ms <= 0:
            return ExecutorMeta(ok=False, error="bad_block:ts", height=0, block_id="")
        chain_floor_ms = self.chain_time_floor_ms()
        successor_ts_ms = max(1, int(chain_floor_ms) + 1)
        if ts_ms < successor_ts_ms:
            return ExecutorMeta(ok=False, error="bad_block:ts_before_chain_floor", height=0, block_id="")
        if ts_ms > int(chain_floor_ms) + int(MAX_BLOCK_TIME_ADVANCE_MS):
            return ExecutorMeta(ok=False, error="bad_block:ts_beyond_chain_time_window", height=0, block_id="")

        txs = block2.get("txs")
        if not isinstance(txs, list):
            return ExecutorMeta(ok=False, error="bad_block:txs", height=0, block_id="")

        # Replay exactly the tx list the leader committed to.
        working: Json = copy.deepcopy(self.state)

        # IMPORTANT: match deterministic scheduler/elector side-effects that occur
        # during block production. These may initialize subtrees and/or enqueue
        # system queue items (and confirm emission) which affect state_root.
        next_height = int(height)

        def _run_poh_schedulers() -> None:
            schedule_poh_tier2_system_txs(working, next_height=next_height)
            schedule_poh_tier3_system_txs(working, next_height=next_height)

        def _run_system_emitter_side_effects(phase: str) -> None:
            # We discard envelopes; the block already contains the tx list.
            _ = system_tx_emitter(working, self.tx_index, next_height=next_height, phase=str(phase), proposer="")

        def _queue_item_phase(queue_id: str) -> str:
            try:
                q = working.get("system_queue")
                if not isinstance(q, list):
                    return ""
                qid = str(queue_id or "").strip()
                if not qid:
                    return ""
                for obj in q:
                    if not isinstance(obj, dict):
                        continue
                    if str(obj.get("queue_id") or "").strip() == qid:
                        return str(obj.get("phase") or "").strip().lower()
                return ""
            except Exception:
                return ""

        # Production path: pre schedulers + pre emitter side-effects.
        try:
            _run_poh_schedulers()
        except Exception as exc:
            if _consensus_fail_closed():
                return ExecutorMeta(ok=False, error=f"bad_block:poh_schedule_failed:{type(exc).__name__}", height=0, block_id="")
        try:
            _run_system_emitter_side_effects("pre")
        except Exception as exc:
            if _consensus_fail_closed():
                return ExecutorMeta(ok=False, error=f"bad_block:system_emitter_pre_failed:{type(exc).__name__}", height=0, block_id="")

        applied_ids: List[str] = []
        invalid_ids: List[str] = []
        receipts: List[Json] = []
        env_objs: List[TxEnvelope] = []
        tx_ids: List[str] = []

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
            return ExecutorMeta(ok=False, error=f"bad_block:block_reject:{block_reject.code}", height=0, block_id="")
        first_tx_reject = next((rej for rej in per_tx if rej is not None), None)
        if first_tx_reject is not None:
            return ExecutorMeta(ok=False, error=f"bad_block:tx_reject:{first_tx_reject.code}", height=0, block_id="")

        # Apply txs in the provided order.
        # If we encounter a system tx that the producer would have emitted in the
        # post phase, we must first run the post schedulers/emitter side-effects
        # (because those side-effects can depend on state after user txs).
        post_ran = False

        for env, env_obj, tx_id, rej in zip(txs, env_objs, tx_ids, per_tx, strict=False):
            if not post_ran and bool(getattr(env_obj, "system", False)):
                try:
                    payload = env.get("payload") if isinstance(env, dict) else None
                    qid = str((payload or {}).get("_system_queue_id") or "").strip() if isinstance(payload, dict) else ""
                    if qid and _queue_item_phase(qid) == "post":
                        try:
                            _run_poh_schedulers()
                        except Exception as exc:
                            if _consensus_fail_closed():
                                return ExecutorMeta(ok=False, error=f"bad_block:poh_schedule_failed:{type(exc).__name__}", height=0, block_id="")
                        try:
                            _run_system_emitter_side_effects("post")
                        except Exception as exc:
                            if _consensus_fail_closed():
                                return ExecutorMeta(ok=False, error=f"bad_block:system_emitter_post_failed:{type(exc).__name__}", height=0, block_id="")
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

            applied_ok = False
            err_code = ""
            err_reason = ""
            err_details: Any = None

            try:
                meta = apply_tx_atomic_meta(working, env, consume_nonce_on_fail=True)
                applied_ok = meta is not None
            except ApplyError as e:
                applied_ok = False
                err_code = str(getattr(e, "code", "") or "")
                err_reason = str(getattr(e, "reason", "") or "")
                err_details = getattr(e, "details", None)
            except Exception as e:
                if _consensus_fail_closed():
                    return ExecutorMeta(ok=False, error=f"bad_block:tx_apply_failed:{type(e).__name__}", height=0, block_id="")
                applied_ok = False
                err_code = type(e).__name__
                err_reason = str(e)

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
                    return ExecutorMeta(ok=False, error=f"bad_block:poh_schedule_failed:{type(exc).__name__}", height=0, block_id="")
            try:
                _run_system_emitter_side_effects("post")
            except Exception as exc:
                if _consensus_fail_closed():
                    return ExecutorMeta(ok=False, error=f"bad_block:system_emitter_post_failed:{type(exc).__name__}", height=0, block_id="")

        # Verify block commitments fail-closed.
        receipts_root = compute_receipts_root(receipts=receipts)

        # Update ancestry + tip fields and time exactly as the leader should have.
        block_id = str(block2.get("block_id") or "").strip()
        if not block_id:
            block_id = compute_block_id(
                chain_id=str(header.get("chain_id") or self.chain_id),
                height=int(height),
                prev_block_id=str(block2.get("prev_block_id") or self.state.get("tip") or ""),
                prev_block_hash=str(header.get("prev_block_hash") or block2.get("prev_block_hash") or ""),
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
            return ExecutorMeta(ok=False, error="bad_block:missing_receipts_root", height=0, block_id="")
        if receipts_root != have_rr:
            return ExecutorMeta(ok=False, error="bad_block:receipts_root_mismatch", height=0, block_id="")

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

                active_accounts: List[str] = []
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
                    return ExecutorMeta(ok=False, error="bad_block:vrf:not_active_validator", height=0, block_id="")
            except Exception:
                return ExecutorMeta(ok=False, error="bad_block:vrf:validator_check_failed", height=0, block_id="")

            # Deterministically store VRF in state so state_root commits to it.
            rand = working.get("rand")
            if not isinstance(rand, dict):
                rand = {}
                working["rand"] = rand
            rand["vrf"] = {"height": int(height), **vrf_any}
        else:
            # If required, reject blocks without VRF.
            if runtime_vrf_required():
                return ExecutorMeta(ok=False, error="bad_block:vrf:missing", height=0, block_id="")

        state_root = compute_state_root(working)
        have_sr = str(header.get("state_root") or "").strip()
        if not have_sr:
            return ExecutorMeta(ok=False, error="bad_block:missing_state_root", height=0, block_id="")
        if state_root != have_sr:
            return ExecutorMeta(ok=False, error="bad_block:state_root_mismatch", height=0, block_id="")

        # Ensure we persist the same tip hash commitment.
        try:
            working["tip_hash"] = str(bh)
            working["tip_ts_ms"] = int(ts_ms)
        except Exception:
            pass

        # Commit.
        meta = self.commit_block_candidate(block=block2, new_state=working, applied_ids=applied_ids, invalid_ids=invalid_ids)
        return meta
    # ----------------------------
    # Network-facing BFT adapters
    # ----------------------------

    def _votecheck_cache_get(self, block_hash: str) -> Optional[bool]:
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
        key = str(block_hash or "").strip()
        if not key:
            return
        _bounded_put(self._votecheck_cache, key, bool(ok), cap=self._max_votecheck_cache)

    def _proposal_votecheck_budget_ok(self, peer_id: str) -> bool:
        key = str(peer_id or "").strip() or "<unknown>"
        now_ms = _now_ms()
        entry = self._proposal_peer_budget.get(key)
        if not isinstance(entry, dict):
            entry = {"count": 0, "reset_ms": int(now_ms + self._proposal_peer_budget_window_ms)}
        reset_ms = _safe_int(entry.get("reset_ms"), int(now_ms + self._proposal_peer_budget_window_ms))
        count = _safe_int(entry.get("count"), 0)
        if now_ms >= reset_ms:
            count = 0
            reset_ms = int(now_ms + self._proposal_peer_budget_window_ms)
        count += 1
        entry = {"count": int(count), "reset_ms": int(reset_ms)}
        _bounded_put(self._proposal_peer_budget, key, entry, cap=self._max_proposal_peer_budget_entries)
        return count <= self._proposal_peer_budget_max

    def _spec_exec_paths_for_slot(self, slot: str) -> Tuple[str, str]:
        root = self._spec_exec_pool_root / str(slot)
        root.mkdir(parents=True, exist_ok=True)
        db_path = str(root / "votecheck.sqlite")
        aux_path = str(root / "votecheck.aux.sqlite")
        return db_path, aux_path

    def _make_spec_exec_slot(self) -> Tuple[str, str]:
        slot = f"slot-{len(self._spec_exec_pool)}-{_now_ms()}"
        return self._spec_exec_paths_for_slot(slot)

    def _acquire_spec_exec_slot(self) -> Tuple[str, str]:
        if self._spec_exec_pool:
            return self._spec_exec_pool.pop()
        return self._make_spec_exec_slot()

    def _release_spec_exec_slot(self, slot: Tuple[str, str]) -> None:
        if len(self._spec_exec_pool) >= self._max_spec_exec_pool:
            return
        self._spec_exec_pool.append(slot)

    def _reset_spec_exec_slot(self, slot: Tuple[str, str]) -> WeAllExecutor:
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
        return True

    def _validate_remote_proposal_for_vote(self, block: Json) -> bool:
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
        slot: Optional[Tuple[str, str]] = None
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

    def bft_on_proposal(self, proposal: Json) -> Optional[Json]:
        """Handle a leader proposal.

        Returns a vote JSON if we should vote, else None.
        """
        if not isinstance(proposal, dict):
            return None

        # Canonicalize network proposal shape: accept either a raw block dict
        # or an envelope {view, proposer, block, justify_qc}.
        try:
            raw_block = proposal.get("block") if isinstance(proposal.get("block"), dict) else proposal
            proposal2 = dict(raw_block)
            embedded_qc = proposal2.get("qc") if isinstance(proposal2.get("qc"), dict) else None
            if "view" not in proposal2 and "view" in proposal:
                proposal2["view"] = proposal.get("view")
            if "proposer" not in proposal2 and "proposer" in proposal:
                proposal2["proposer"] = proposal.get("proposer")
            if "justify_qc" not in proposal2 and isinstance(proposal.get("justify_qc"), dict):
                proposal2["justify_qc"] = proposal.get("justify_qc")
            if "chain_id" not in proposal2 or not str(proposal2.get("chain_id") or "").strip():
                proposal2["chain_id"] = str(self.chain_id)
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
                prev_block_hash=str(hdr.get("prev_block_hash") or proposal2.get("prev_block_hash") or ""),
                ts_ms=int(hdr.get("block_ts_ms") or proposal2.get("block_ts_ms") or 0),
                node_id=str(proposal2.get("proposer") or proposal.get("proposer") or ""),
                tx_ids=[str(x) for x in (hdr.get("tx_ids") or [])] if isinstance(hdr, dict) else [],
                receipts_root=str(hdr.get("receipts_root") or ""),
            )
            proposal2["block_id"] = bid

        try:
            view = int(proposal2.get("view") or proposal2.get("bft_view") or proposal.get("view") or 0)
        except Exception:
            view = 0
        proposal2["view"] = int(view)

        validators = self._active_validators()
        expected_leader = leader_for_view(validators, view) if validators else ""
        proposer = str(proposal2.get("proposer") or "").strip()
        require_sig = _env_bool("WEALL_SIGVERIFY", True)

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
        cached_qc_any = justify_qc_any if isinstance(justify_qc_any, dict) else embedded_qc
        if bid and isinstance(cached_qc_any, dict):
            verified_qc = self.bft_verify_qc_json(cached_qc_any)
            if verified_qc is not None:
                self._put_pending_missing_qc(verified_qc.to_json())

        if not proposer and not require_sig and expected_leader:
            proposal2["proposer"] = expected_leader
            proposer = expected_leader
        if expected_leader and proposer and proposer != expected_leader:
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

        ok, _rej = admit_bft_block(block=proposal2, state=self.state)
        if not ok:
            self._drop_quarantined_remote_artifacts(bid)
            self.bft_try_apply_pending_remote_blocks()
            return None

        self._promote_quarantined_remote_block(bid, block=proposal2)
        self.bft_try_apply_pending_remote_blocks()

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
        blocks_map[bid] = {"height": int(proposal2.get("height") or 0), "prev_block_id": parent_id, "block_ts_ms": _safe_int(((proposal2.get("header") or {}) if isinstance(proposal2.get("header"), dict) else {}).get("block_ts_ms") or proposal2.get("block_ts_ms"), 0), "block_hash": str(proposal2.get("block_hash") or "").strip()}

        justify_qc = qc_from_json(proposal2.get("justify_qc")) if isinstance(proposal2.get("justify_qc"), dict) else None
        if not self._bft.can_vote_for(blocks=blocks_map, block_id=bid, justify_qc=justify_qc):
            return None

        block_hash = str(proposal2.get("block_hash") or "").strip()
        if not block_hash:
            return None

        votej = self.bft_make_vote_for_block(view=view, block_id=bid, block_hash=block_hash, parent_id=parent_id)
        if not isinstance(votej, dict) or not votej:
            return None

        if not self._bft.record_local_vote(view=view, block_id=bid):
            return None
        self._bft.last_progress_ms = _now_ms()
        self._persist_bft_state()
        self._bft_enqueue_outbound("vote", votej)
        return votej

    def bft_on_vote(self, vote: Json) -> Optional[Json]:
        """Handle a vote and return a QC JSON if one was formed."""
        qc = self.bft_handle_vote(vote)
        return qc.to_json() if qc is not None else None

    def bft_on_qc(self, qcj: Json) -> Optional[ExecutorMeta]:
        """Handle a QC and commit if it refers to a known block."""
        qc = self.bft_verify_qc_json(qcj)
        if qc is None:
            return None

        # Observe first.
        self.bft_handle_qc(qcj)

        bid = str(qc.block_id)
        block_hash = str(qc.block_hash or "").strip()

        # Cache the QC, update BFT state, and only apply once the finalized frontier advances.
        meta = self.bft_commit_if_ready(qc)
        if meta is not None:
            return meta

        resolved_bid, blk = self._resolve_pending_block_identity(block_id=bid, block_hash=block_hash)
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

    def bft_on_timeout(self, timeoutj: Json) -> Optional[Json]:
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
# ----------------------------
    # BFT helpers
    # ----------------------------

    def _active_validators(self) -> List[str]:
        st = self.state
        roles = st.get("roles")
        if isinstance(roles, dict):
            v = roles.get("validators")
            if isinstance(v, dict) and isinstance(v.get("active_set"), list):
                out: List[str] = []
                seen: set[str] = set()
                for x in v.get("active_set") or []:
                    s = str(x).strip()
                    if s and s not in seen:
                        seen.add(s)
                        out.append(s)
                return normalize_validators(out)
        c = st.get("consensus")
        if isinstance(c, dict):
            vs = c.get("validator_set")
            if isinstance(vs, dict) and isinstance(vs.get("active_set"), list):
                out2: List[str] = []
                seen2: set[str] = set()
                for x in vs.get("active_set") or []:
                    s = str(x).strip()
                    if s and s not in seen2:
                        seen2.add(s)
                        out2.append(s)
                return normalize_validators(out2)
        return []

    def _validator_pubkeys(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
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
                    active_count = len(normalize_validators([str(x).strip() for x in (pending_vs.get("active_set") or []) if str(x).strip()]))
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
            normalized_payload_phase = normalize_consensus_phase(payload_phase, validator_count=len(self._active_validators()))
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
        normalized_payload_phase = normalize_consensus_phase(payload_phase, validator_count=len(self._active_validators()))
        return normalized_payload_phase == current_phase

    def _validator_epoch(self) -> Tuple[int, str]:
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

    def _prune_pending_bft_artifacts_on_local_validator_transition(
        self,
        *,
        previous_epoch: int,
        previous_set_hash: str,
    ) -> bool:
        current_epoch = self._current_validator_epoch()
        current_set_hash = self._current_validator_set_hash() if int(current_epoch) > 0 else ""
        if int(previous_epoch) == int(current_epoch) and str(previous_set_hash or "").strip() == str(current_set_hash or "").strip():
            return False
        return self._prune_pending_bft_artifacts()


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

    def _local_validator_identity(self) -> Tuple[str, str, str]:
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
        bid = str(block_id or "").strip()
        bh = str(block_hash or "").strip()
        if not bid or not bh:
            return
        _bounded_put(self._known_block_hashes, bid, bh, cap=self._max_known_block_hashes)
        _bounded_put(self._known_block_ids_by_hash, bh, bid, cap=self._max_known_block_ids_by_hash)

    def _lookup_committed_block_hash_index(self, block_id: str) -> str:
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
        bh = str(block_hash or "").strip()
        if not bh:
            return ""
        cached = str(self._known_block_ids_by_hash.get(bh) or "").strip()
        if cached:
            _bounded_put(self._known_block_ids_by_hash, bh, cached, cap=self._max_known_block_ids_by_hash)
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
            _bounded_put(self._pending_remote_block_ids_by_hash, bh, pending_remote_bid, cap=self._max_pending_remote_blocks)
            self._cache_known_block_hash(pending_remote_bid, bh)
            return pending_remote_bid

        quarantined_bid = str(self._quarantined_remote_block_ids_by_hash.get(bh) or "").strip()
        if quarantined_bid:
            _bounded_put(self._quarantined_remote_block_ids_by_hash, bh, quarantined_bid, cap=self._max_quarantined_remote_blocks)
            self._cache_known_block_hash(quarantined_bid, bh)
            return quarantined_bid

        pending_candidate_bid = str(self._pending_candidate_ids_by_hash.get(bh) or "").strip()
        if pending_candidate_bid:
            _bounded_put(self._pending_candidate_ids_by_hash, bh, pending_candidate_bid, cap=self._max_pending_candidates)
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
        bid = str(block_id or "").strip()
        return bool(bid and bid in self._conflicted_block_ids)

    def _is_conflicted_block_hash(self, block_hash: str) -> bool:
        bh = str(block_hash or "").strip()
        return bool(bh and bh in self._conflicted_block_hashes)

    def _drop_pending_candidate_artifacts(self, block_id: str) -> None:
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

    def _mark_block_id_conflict(self, *, block_id: str, known_hash: str, new_hash: str, source: str, parent_id: str = "") -> None:
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

    def _mark_block_hash_conflict(self, *, block_hash: str, known_block_id: str, new_block_id: str, source: str, parent_id: str = "") -> None:
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
        _bounded_put(self._conflicted_block_hashes, bh, detail, cap=self._max_conflicted_block_hashes)
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
                self._mark_block_id_conflict(block_id=bid, known_hash=existing_hash, new_hash=bh, source=source, parent_id=str(qcj.get("parent_id") or existing_parent or ""))
                return True
            parent_id = str(qcj.get("parent_id") or "").strip()
            if existing_parent and parent_id and existing_parent != parent_id:
                self._mark_block_id_conflict(block_id=bid, known_hash=existing_hash or bh, new_hash=bh, source=f"{source}_parent", parent_id=parent_id)
                return True
        return False

    def _block_identity_conflicts(self, block: Json) -> bool:
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
            self._mark_block_id_conflict(block_id=bid, known_hash=known, new_hash=block_hash, source="block", parent_id=str(block.get("prev_block_id") or ""))
            return True
        known_block_id = self._known_block_id_for_hash(block_hash)
        if known_block_id and known_block_id != bid:
            self._mark_block_hash_conflict(block_hash=block_hash, known_block_id=known_block_id, new_block_id=bid, source="block_hash_alias", parent_id=str(block.get("prev_block_id") or ""))
            return True
        return False

    def _block_height_hint(self, block: Json) -> int:
        if not isinstance(block, dict):
            return 0
        try:
            hdr = block.get("header") if isinstance(block.get("header"), dict) else {}
            return int(hdr.get("height") or block.get("height") or 0)
        except Exception:
            return 0

    def _has_local_block(self, block_id: str) -> bool:
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
        if not isinstance(block, dict):
            return
        bid = str(block.get("block_id") or "").strip()
        bh = _block_hash_from_any(block)
        if bid and bh:
            _bounded_put(self._pending_remote_block_ids_by_hash, bh, bid, cap=self._max_pending_remote_blocks)

    def _index_quarantined_remote_block(self, block: Json) -> None:
        if not isinstance(block, dict):
            return
        bid = str(block.get("block_id") or "").strip()
        bh = _block_hash_from_any(block)
        if bid and bh:
            _bounded_put(self._quarantined_remote_block_ids_by_hash, bh, bid, cap=self._max_quarantined_remote_blocks)

    def _quarantine_remote_block(self, block: Json) -> None:
        if not isinstance(block, dict):
            return
        bid = str(block.get("block_id") or "").strip()
        if not bid:
            return
        _bounded_put(self._quarantined_remote_blocks, bid, dict(block), cap=self._max_quarantined_remote_blocks)
        self._index_quarantined_remote_block(block)

    def _drop_quarantined_remote_artifacts(self, block_id: str) -> None:
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

    def _promote_quarantined_remote_block(self, block_id: str, *, block: Optional[Json] = None) -> None:
        bid = str(block_id or "").strip()
        blk = dict(block) if isinstance(block, dict) else None
        if blk is None and bid:
            cached = self._quarantined_remote_blocks.get(bid)
            if isinstance(cached, dict):
                blk = dict(cached)
        if not bid or not isinstance(blk, dict):
            return
        self._drop_quarantined_remote_artifacts(bid)
        _bounded_put(self._pending_remote_blocks, bid, dict(blk), cap=self._max_pending_remote_blocks)
        self._persist_pending_bft_artifact(kind="pending_remote_block", block_id=bid, payload=dict(blk))
        self._index_pending_remote_block(blk)

    def _index_pending_candidate(self, block: Json) -> None:
        if not isinstance(block, dict):
            return
        bid = str(block.get("block_id") or "").strip()
        bh = _block_hash_from_any(block)
        if bid and bh:
            _bounded_put(self._pending_candidate_ids_by_hash, bh, bid, cap=self._max_pending_candidates)

    def _index_pending_missing_qc(self, qcj: Json) -> None:
        if not isinstance(qcj, dict):
            return
        bh = str(qcj.get("block_hash") or "").strip()
        if bh:
            _bounded_put(self._pending_missing_qcs_by_hash, bh, dict(qcj), cap=self._max_pending_missing_qcs)

    def _put_pending_missing_qc(self, qcj: Json) -> None:
        if not isinstance(qcj, dict):
            return
        bid = str(qcj.get("block_id") or "").strip()
        if bid:
            _bounded_put(self._pending_missing_qcs, bid, dict(qcj), cap=self._max_pending_missing_qcs)
            self._persist_pending_bft_artifact(kind="pending_missing_qc", block_id=bid, payload=dict(qcj))
        self._index_pending_missing_qc(qcj)

    def _drop_pending_missing_qc_aliases(self, *, block_id: str = "", qcj: Optional[Json] = None) -> None:
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
        bid = str(block_id or "").strip()
        if not bid:
            return
        self._drop_pending_missing_qc_aliases(block_id=bid)
        try:
            self._pending_missing_qcs.pop(bid, None)
        except Exception:
            pass
        self._delete_pending_bft_artifact(kind="pending_missing_qc", block_id=bid)

    def _pending_missing_qc_json(self, *, block_id: str = "", block_hash: str = "") -> Optional[Json]:
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
                    _bounded_put(self._pending_missing_qcs, cbid, dict(cached), cap=self._max_pending_missing_qcs)
                return dict(cached)
            for qid, qcj in list(self._pending_missing_qcs.items()):
                if not isinstance(qcj, dict):
                    continue
                if str(qcj.get("block_hash") or "").strip() == bh:
                    self._index_pending_missing_qc(qcj)
                    return dict(qcj)
        return None

    def _pending_missing_qc_entries(self) -> "OrderedDict[str, Json]":
        out: "OrderedDict[str, Json]" = OrderedDict()
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

    def _drop_pending_hash_aliases(self, *, block_id: str, block: Optional[Json] = None) -> None:
        bid = str(block_id or "").strip()
        blk = block if isinstance(block, dict) else None
        if blk is None and bid:
            existing_remote = self._pending_remote_blocks.get(bid)
            if isinstance(existing_remote, dict):
                blk = existing_remote
            else:
                existing_candidate = self._pending_candidates.get(bid)
                if isinstance(existing_candidate, tuple) and existing_candidate and isinstance(existing_candidate[0], dict):
                    blk = existing_candidate[0]
        bh = _block_hash_from_any(blk) if isinstance(blk, dict) else ""
        if bh:
            if str(self._pending_remote_block_ids_by_hash.get(bh) or "").strip() == bid:
                self._pending_remote_block_ids_by_hash.pop(bh, None)
            if str(self._pending_candidate_ids_by_hash.get(bh) or "").strip() == bid:
                self._pending_candidate_ids_by_hash.pop(bh, None)

    def _pending_block_identity_tuple(self, block_id: str) -> Tuple[int, str, str]:
        bid = str(block_id or "").strip()
        blk = self._bft_pending_block_json(bid)
        if not isinstance(blk, dict):
            return (0, "", bid)
        return (int(self._block_height_hint(blk) or 0), _block_hash_from_any(blk), bid)

    def _ordered_pending_block_ids(self) -> List[str]:
        ids = list(dict.fromkeys(list(self._pending_remote_blocks.keys()) + list(self._quarantined_remote_blocks.keys()) + list(self._pending_candidates.keys())))
        ids = [str(bid or "").strip() for bid in ids if str(bid or "").strip()]
        ids.sort(key=lambda bid: self._pending_block_identity_tuple(bid))
        return ids

    def _drop_pending_remote_artifacts(self, block_id: str) -> None:
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

    def _bft_speculative_blocks_map(self) -> Dict[str, Json]:
        blocks_any = self.state.get("blocks")
        blocks_map: Dict[str, Json] = dict(blocks_any) if isinstance(blocks_any, dict) else {}

        for source in (self._quarantined_remote_blocks, self._pending_remote_blocks):
            for bid, blk in list(source.items()):
                sbid = str(bid or "").strip()
                if not sbid or sbid in blocks_map or not isinstance(blk, dict):
                    continue
                blocks_map[sbid] = {
                    "height": int(self._block_height_hint(blk) or 0),
                    "prev_block_id": str(blk.get("prev_block_id") or "").strip(),
                    "block_ts_ms": _safe_int(((blk.get("header") or {}) if isinstance(blk.get("header"), dict) else {}).get("block_ts_ms") or blk.get("block_ts_ms"), 0),
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
                "block_ts_ms": _safe_int(((blk.get("header") or {}) if isinstance(blk.get("header"), dict) else {}).get("block_ts_ms") or blk.get("block_ts_ms"), 0),
                "block_hash": str(blk.get("block_hash") or "").strip(),
            }
        return blocks_map

    def _bft_pending_block_json(self, block_id: str) -> Optional[Json]:
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

    def _bft_pending_block_json_by_hash(self, block_hash: str) -> Optional[Json]:
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

    def _resolve_pending_block_identity(self, *, block_id: str = "", block_hash: str = "") -> Tuple[str, Optional[Json]]:
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
        if not isinstance(payload, dict):
            return False
        if not self._bft_payload_phase_is_cache_compatible(payload):
            return False
        local_epoch = self._current_validator_epoch()
        local_set_hash = self._current_validator_set_hash() if int(local_epoch) > 0 else ""
        payload_epoch = _safe_int(payload.get("validator_epoch"), 0)
        payload_set_hash = str(payload.get("validator_set_hash") or "").strip()
        if int(local_epoch) > 0 and int(payload_epoch) > 0 and int(payload_epoch) != int(local_epoch):
            return False
        if local_set_hash and payload_set_hash and payload_set_hash != local_set_hash:
            return False
        return True

    def _prune_pending_bft_artifacts(self) -> bool:
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
            if self._is_conflicted_block_id(sbid) or self._has_local_block(sbid) or not self._bft_pending_artifact_matches_current_epoch(qcj):
                self._remove_pending_missing_qc(block_id=sbid)
                changed = True
                continue
            if finalized_block_id and sbid != finalized_block_id and not is_descendant(speculative, candidate=sbid, ancestor=finalized_block_id):
                self._remove_pending_missing_qc(block_id=sbid)
                changed = True

        for bid in self._ordered_pending_block_ids():
            sbid = str(bid or "").strip()
            blk = self._bft_pending_block_json(sbid)
            if not sbid or not isinstance(blk, dict):
                self._drop_pending_candidate_artifacts(sbid)
                changed = True
                continue
            if self._has_local_block(sbid) or not self._bft_pending_artifact_matches_current_epoch(blk):
                self._drop_pending_candidate_artifacts(sbid)
                changed = True
                continue
            height = self._block_height_hint(blk)
            if height > 0 and height <= local_height and sbid != str(self.state.get("tip") or "").strip():
                self._drop_pending_candidate_artifacts(sbid)
                changed = True
                continue
            if finalized_block_id and not self._bft_block_is_applyable_finalized_descendant(blk, finalized_block_id):
                self._drop_pending_candidate_artifacts(sbid)
                changed = True

        return changed

    def _bft_block_is_applyable_finalized_descendant(self, block: Json, finalized_block_id: str) -> bool:
        bid = str(block.get("block_id") or "").strip()
        fin = str(finalized_block_id or "").strip()
        if not bid or not fin:
            return False
        if bid == fin:
            return True
        return is_descendant(self._bft_speculative_blocks_map(), candidate=bid, ancestor=fin)

    def _bft_parent_ready_for_apply(self, block: Json) -> bool:
        parent_id = str(block.get("prev_block_id") or "").strip()
        height = self._block_height_hint(block)
        if height <= 1:
            return True
        if not parent_id:
            return False
        return parent_id == str(self.state.get("tip") or "").strip()

    def bft_try_apply_pending_remote_blocks(self) -> List[ExecutorMeta]:
        """Attempt deterministic catch-up replay for pending BFT blocks.

        In production, only blocks on the currently finalized path are durably
        replayed. In non-production modes we preserve the historic testnet/dev
        catch-up behavior and allow contiguous QC-backed replay from the local
        tip even before a later QC advances finalization.
        """
        results: List[ExecutorMeta] = []
        self._prune_pending_bft_artifacts()
        if _mode() == "prod" and not self._bft_phase_allows_artifact_processing():
            return results
        finalized_block_id = str(self._bft.finalized_block_id or "").strip()
        allow_qc_replay = _mode() != "prod"
        if not finalized_block_id and not allow_qc_replay:
            return results

        total_pending = len(self._pending_remote_blocks) + len(self._pending_candidates) + len(self._pending_missing_qcs)
        max_rounds = max(1, total_pending + 1)
        rounds = 0
        while rounds < max_rounds:
            rounds += 1
            progress = False
            candidates: List[Tuple[int, str, Json]] = []

            for bid in self._ordered_pending_block_ids():
                sbid = str(bid or "").strip()
                if not sbid:
                    continue
                if self._has_local_block(sbid):
                    self._drop_pending_candidate_artifacts(sbid)
                    progress = True
                    break
                blk = self._bft_pending_block_json(sbid)
                if not isinstance(blk, dict):
                    continue
                if finalized_block_id:
                    if not self._bft_block_is_applyable_finalized_descendant(blk, finalized_block_id):
                        continue
                else:
                    qcj = self._pending_missing_qc_json(block_id=sbid, block_hash=_block_hash_from_any(blk))
                    if not (allow_qc_replay and isinstance(qcj, dict)):
                        continue
                candidates.append((self._block_height_hint(blk), sbid, blk))

            if progress:
                continue

            candidates.sort(key=lambda item: (int(item[0]), _block_hash_from_any(item[2]), item[1]))
            for _height, bid, blk in candidates:
                if not self._bft_parent_ready_for_apply(blk):
                    continue
                qcj = self._pending_missing_qc_json(block_id=bid, block_hash=_block_hash_from_any(blk))
                blk2 = dict(blk)
                if isinstance(qcj, dict):
                    blk2["qc"] = dict(qcj)
                meta = self.apply_block(blk2)
                if meta is None or not bool(getattr(meta, "ok", False)):
                    continue
                self._drop_pending_candidate_artifacts(bid)
                results.append(meta)
                progress = True
                break
            if not progress:
                break
        return results

    def _committed_chain_recent_timestamps_ms(self, *, limit: int = 11) -> List[int]:
        try:
            blocks_map = self.state.get("blocks")
            if not isinstance(blocks_map, dict):
                return []
            cur = str(self.state.get("tip") or "").strip()
            out: List[int] = []
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

    def bft_diagnostics(self) -> Json:
        pending_pruned = self._prune_pending_bft_artifacts()
        pending_remote_blocks = self._ordered_pending_block_ids()
        pending_remote_block_hashes = [_block_hash_from_any(self._bft_pending_block_json(bid) or {}) for bid in pending_remote_blocks if _block_hash_from_any(self._bft_pending_block_json(bid) or {})]
        pending_block_identity_descriptors = []
        for bid in pending_remote_blocks:
            blk = self._bft_pending_block_json(bid) or {}
            if not isinstance(blk, dict):
                continue
            pending_block_identity_descriptors.append({
                "block_id": str(bid or "").strip(),
                "block_hash": _block_hash_from_any(blk),
                "height": int(self._block_height_hint(blk) or 0),
            })
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
        pending_fetch_request_hashes = [str(d.get("block_hash") or "").strip() for d in pending_fetch_request_descriptors if isinstance(d, dict) and str(d.get("block_hash") or "").strip()]
        pending_candidates = [bid for bid in pending_remote_blocks if bid in self._pending_candidates]
        pending_candidate_block_hashes = [_block_hash_from_any(self._bft_pending_block_json(bid) or {}) for bid in pending_candidates if _block_hash_from_any(self._bft_pending_block_json(bid) or {})]
        quarantined_remote_blocks = [str(bid or "").strip() for bid in list(self._quarantined_remote_blocks.keys()) if str(bid or "").strip()]
        quarantined_remote_block_hashes = [_block_hash_from_any(self._quarantined_remote_blocks.get(bid) or {}) for bid in quarantined_remote_blocks if _block_hash_from_any(self._quarantined_remote_blocks.get(bid) or {})]
        conflicted_block_ids = list(self._conflicted_block_ids.keys())
        conflicted_block_hashes = list(self._conflicted_block_hashes.keys())
        finalized_block_id = str(self._bft.finalized_block_id or "")
        tip = str(self.state.get("tip") or "").strip()
        tip_height = _safe_int(self.state.get("height"), 0)
        finalized_height = _safe_int((self.state.get("finalized") or {}).get("height") if isinstance(self.state.get("finalized"), dict) else 0, 0)
        tip_ts_ms = _safe_int(self.state.get("tip_ts_ms") or self.state.get("last_block_ts_ms"), 0)
        median_time_past_ms = int(self.committed_chain_median_time_past_ms())
        chain_time_floor_ms = int(max(tip_ts_ms, median_time_past_ms))
        proposed_next_ts_ms = max(1, int(chain_time_floor_ms) + 1)
        now_ms = _now_ms()
        clock_skew_ahead_ms = max(0, int(tip_ts_ms) - int(now_ms)) if tip_ts_ms > 0 else 0
        clock_skew_warning = bool(clock_skew_ahead_ms >= int(CLOCK_SKEW_WARN_MS)) if tip_ts_ms > 0 else False

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
            stall_reason = "waiting_for_finalized_descendant_apply" if finalized_block_id else "waiting_for_finalization"
        elif _mode() == "prod" and finalized_block_id and tip and finalized_block_id != tip:
            stall_reason = "tip_not_finalized_yet"

        return {
            "view": int(self._bft.view),
            "high_qc_id": str(self._bft.high_qc.block_id if self._bft.high_qc is not None else ""),
            "locked_qc_id": str(self._bft.locked_qc.block_id if self._bft.locked_qc is not None else ""),
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
            "protocol_profile_hash": str(((self.state.get("meta") or {}) if isinstance(self.state.get("meta"), dict) else {}).get("production_consensus_profile_hash") or ""),
            "schema_version": str(((self.state.get("meta") or {}) if isinstance(self.state.get("meta"), dict) else {}).get("schema_version") or ""),
            "tx_index_hash": str(((self.state.get("meta") or {}) if isinstance(self.state.get("meta"), dict) else {}).get("tx_index_hash") or ""),
            "reputation_scale": int(_safe_int((((self.state.get("meta") or {}) if isinstance(self.state.get("meta"), dict) else {}).get("reputation_scale")), REPUTATION_SCALE)),
            "max_block_future_drift_ms": int(_safe_int((((self.state.get("meta") or {}) if isinstance(self.state.get("meta"), dict) else {}).get("max_block_future_drift_ms")), MAX_BLOCK_FUTURE_DRIFT_MS)),
            "max_block_time_advance_ms": int(MAX_BLOCK_TIME_ADVANCE_MS),
            "clock_skew_warn_ms": int(_safe_int((((self.state.get("meta") or {}) if isinstance(self.state.get("meta"), dict) else {}).get("clock_skew_warn_ms")), CLOCK_SKEW_WARN_MS)),
            "startup_clock_sanity_required": bool((((self.state.get("meta") or {}) if isinstance(self.state.get("meta"), dict) else {}).get("startup_clock_sanity_required", PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required))),
            "startup_clock_hard_fail_ms": int(_safe_int((((self.state.get("meta") or {}) if isinstance(self.state.get("meta"), dict) else {}).get("startup_clock_hard_fail_ms")), STARTUP_CLOCK_HARD_FAIL_MS)),
            "clock_warning": (((self.state.get("meta") or {}) if isinstance(self.state.get("meta"), dict) else {}).get("clock_warning") if isinstance((((self.state.get("meta") or {}) if isinstance(self.state.get("meta"), dict) else {}).get("clock_warning")), dict) else None),
            "validator_signing_enabled": bool(self.validator_signing_enabled()),
            "observer_mode": bool(self.observer_mode()),
            "signing_block_reason": str(self._signing_block_reason or ""),
            "last_shutdown_clean": bool((((self.state.get("meta") or {}) if isinstance(self.state.get("meta"), dict) else {}).get("last_shutdown_clean", True))),
            "recent_rejection_summary": self.bft_recent_rejection_summary(limit=25),
            "journal_tail": self._bft_journal.read_tail(limit=25),
        }

    def bft_cache_remote_block(self, block_json: Json) -> bool:
        """Cache a fetched remote block for deterministic replay.

        Returns True when the block is locally compatible and stored (or already
        present locally), else False.
        """
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
        qc_any = blk.get("qc") if isinstance(blk.get("qc"), dict) else blk.get("justify_qc") if isinstance(blk.get("justify_qc"), dict) else None
        if isinstance(qc_any, dict):
            verified_qc = self.bft_verify_qc_json(qc_any)
            if verified_qc is None:
                return False
            self._put_pending_missing_qc(verified_qc.to_json())
        _bounded_put(self._pending_remote_blocks, bid, blk, cap=self._max_pending_remote_blocks)
        self._persist_pending_bft_artifact(kind="pending_remote_block", block_id=bid, payload=dict(blk))
        self._index_pending_remote_block(blk)
        self.bft_try_apply_pending_remote_blocks()
        return True

    def bft_pending_fetch_request_descriptors(self) -> List[Json]:
        wants: "OrderedDict[str, Json]" = OrderedDict()

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
            if self._has_local_block(parent_id) or self._bft_pending_block_json(parent_id) is not None:
                continue
            header = blk.get("header") if isinstance(blk.get("header"), dict) else {}
            expected_hash = str(header.get("prev_block_hash") or "").strip()
            wants[parent_id] = {
                "block_id": parent_id,
                "block_hash": expected_hash,
                "reason": "missing_parent",
                "child_block_id": sbid,
            }

        out: List[Json] = []
        for bid, desc in list(wants.items()):
            sbid = str(bid or "").strip()
            if not sbid:
                continue
            d = dict(desc) if isinstance(desc, dict) else {"block_id": sbid}
            d["block_id"] = sbid
            out.append(d)
        return out

    def _resolve_fetch_request_descriptor(self, desc: Json) -> Optional[Json]:
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

    def bft_resolved_pending_fetch_request_descriptors(self) -> List[Json]:
        out: List[Json] = []
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

    def bft_pending_fetch_requests(self) -> List[str]:
        return [str(d.get("block_id") or "").strip() for d in self.bft_resolved_pending_fetch_request_descriptors() if isinstance(d, dict) and str(d.get("block_id") or "").strip()]


    def bft_resolve_fetch_request_descriptor(self, desc: Json) -> Optional[Json]:
        out = self._resolve_fetch_request_descriptor(desc)
        if isinstance(out, dict):
            out = dict(out)
            out.pop("requested_block_id", None)
        return out

    def bft_recent_rejection_summary(self, *, limit: int = 25) -> Json:
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
            summary = dict(payload.get("summary") or item.get("summary") or {}) if isinstance(payload.get("summary") or item.get("summary"), dict) else {}
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
        return {"items": items, "count": len(items), "by_reason": by_reason, "by_message_type": by_message_type, "latest": latest or {}}

    def bft_current_view(self) -> int:
        return int(self._bft.view)

    def bft_set_view(self, view: int) -> None:
        self._bft.view = int(view)
        self._persist_bft_state()

    def _prune_bft_liveness_caches_for_current_epoch(self) -> None:
        local_epoch = int(self._current_validator_epoch())
        local_set_hash = str(self._current_validator_set_hash() or "").strip() if local_epoch > 0 else ""
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
                elif local_set_hash and str(getattr(tc, "validator_set_hash", "") or "").strip() not in {"", local_set_hash}:
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
        self._bft_record_event("bft_state_persisted", view=int(self._bft.view), finalized_block_id=str(self._bft.finalized_block_id or ""))

    def bft_verify_qc_json(self, qcj: Json) -> Optional[QuorumCert]:
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
        self._bft_record_event("bft_qc_observed", block_id=str(qc.block_id), view=int(qc.view), parent_id=str(qc.parent_id))
        return True

    def _bft_best_justify_qc_json(self) -> Optional[Json]:
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

    def bft_leader_propose(self, *, max_txs: int = 1000) -> Optional[Json]:
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

        blk, st2, applied_ids, invalid_ids, err = self.build_block_candidate(max_txs=max_txs, allow_empty=True)
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
            blk["proposer_sig"] = sign_ed25519(message=msg, privkey=proposer_privkey, encoding="hex")

        if bid:
            self._persist_bft_state()
            _bounded_put(self._pending_candidates, bid, (blk, st2, applied_ids, invalid_ids), cap=self._max_pending_candidates)
            self._persist_pending_bft_artifact(kind="pending_candidate", block_id=bid, payload=dict(blk))
            self._index_pending_candidate(blk)
        return blk

    def bft_handle_vote(self, vote_json: Json) -> Optional[QuorumCert]:
        if not isinstance(vote_json, dict):
            return None
        if str(vote_json.get("t") or "") != "VOTE":
            return None
        if not self._bft_phase_allows_artifact_processing():
            return None
        if not self._bft_payload_phase_matches_current_security_model(vote_json):
            return None
        if not self._bft_epoch_binding_matches(vote_json):
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

    def bft_commit_if_ready(self, qc: QuorumCert) -> Optional[ExecutorMeta]:
        validators = self._active_validators()
        vpub = self._validator_pubkeys()
        if not verify_qc(qc=qc, validators=validators, validator_pubkeys=vpub):
            return None

        bid = str(qc.block_id)
        self._put_pending_missing_qc(qc.to_json())

        metas = self.bft_try_apply_pending_remote_blocks()
        if metas:
            return metas[-1]
        self._persist_bft_state()
        return None

    def bft_make_vote_for_block(self, *, view: int, block_id: str, block_hash: str, parent_id: str) -> Optional[Json]:
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

    def bft_make_timeout(self, *, view: int) -> Optional[Json]:
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
        self._bft_record_event("bft_timeout_emitted", view=int(view), high_qc_id=high_qc_id, timeout_ms=int(self._bft.pacemaker_timeout_ms()))
        self._bft_enqueue_outbound("timeout", tjson)
        return tjson

    def bft_handle_timeout(self, timeout_json: Json) -> Optional[int]:
        if not isinstance(timeout_json, dict):
            return None
        if str(timeout_json.get("t") or "") != "TIMEOUT":
            return None
        if not self._bft_phase_allows_artifact_processing():
            return None
        if not self._bft_payload_phase_matches_current_security_model(timeout_json):
            return None
        if not self._bft_epoch_binding_matches(timeout_json):
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
        new_view = self._bft.accept_timeout(timeout_json=tmo.to_json(), validators=validators, vpub=vpub)
        if new_view is not None:
            self._persist_bft_state()
            return int(new_view)

        self._persist_bft_state()
        return None

    def bft_timeout_check(self) -> Optional[Json]:
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

    # ----------------------------
    # Block + history APIs
    # ----------------------------

    def get_block_by_id(self, block_id: str) -> Optional[Json]:
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

    def get_block_by_height(self, height: int) -> Optional[Json]:
        with self._db.connection() as con:
            row = con.execute("SELECT block_json FROM blocks WHERE height=? LIMIT 1;", (int(height),)).fetchone()
            if row is None:
                return None
            blk = json.loads(str(row["block_json"]))
            if isinstance(blk, dict):
                blk, bh = ensure_block_hash(blk)
                self._cache_known_block_hash(str(blk.get("block_id") or ""), str(bh))
            return blk

    def get_latest_block(self) -> Optional[Json]:
        with self._db.connection() as con:
            row = con.execute("SELECT block_json FROM blocks ORDER BY height DESC LIMIT 1;").fetchone()
            if row is None:
                return None
            blk = json.loads(str(row["block_json"]))
            if isinstance(blk, dict):
                blk, bh = ensure_block_hash(blk)
                self._cache_known_block_hash(str(blk.get("block_id") or ""), str(bh))
            return blk

    def _schema_version(self) -> str:
        return str(getattr(self, "_schema_version_cached", "") or os.environ.get("WEALL_SCHEMA_VERSION") or "1").strip() or "1"

    def build_state_sync_trusted_anchor(self) -> Json:
        return build_snapshot_anchor(self.state)

    def _state_sync_service(self) -> StateSyncService:
        return StateSyncService(
            chain_id=self.chain_id,
            schema_version=self._schema_version(),
            tx_index_hash=self._tx_index_hash,
            state_provider=lambda: dict(self.state),
            block_provider=self.get_block_by_height,
        )

    def apply_state_sync_response(
        self,
        resp: StateSyncResponseMsg,
        *,
        trusted_anchor: Optional[Json] = None,
        allow_snapshot_bootstrap: bool = False,
    ) -> List[ExecutorMeta]:
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
            raise ExecutorError(f"state_sync_remote_error:{str(resp.reason or 'unknown')}" )

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

        metas: List[ExecutorMeta] = []
        local_height = int(self.state.get("height") or 0)
        pending: List[Tuple[int, str, Json]] = []

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

        return metas

    def request_and_apply_state_sync(
        self,
        net_node: Any,
        peer_id: str,
        *,
        trusted_anchor: Json,
        timeout_ms: Optional[int] = None,
        pump: Optional[Any] = None,
        sleep_ms: int = 10,
    ) -> List[ExecutorMeta]:
        """Request delta state sync from a peer in bounded rounds until the trusted anchor is reached.

        Expects the transport node to implement request_state_sync(peer_id, req, ...).
        """
        if not hasattr(net_node, "request_state_sync"):
            raise ExecutorError("state_sync_transport_missing_request_state_sync")

        target_height = _safe_int((trusted_anchor or {}).get("height"), 0)
        finalized_target_height = _safe_int((trusted_anchor or {}).get("finalized_height"), 0)
        enforce_finalized_anchor = bool(getattr(self._state_sync_service(), "enforce_finalized_anchor", False))
        if enforce_finalized_anchor and finalized_target_height > 0:
            target_height = min(target_height or finalized_target_height, finalized_target_height)
        local_height = int(self.state.get("height") or 0)
        if target_height <= local_height:
            return []

        max_delta_blocks = max(1, _env_int("WEALL_SYNC_MAX_DELTA_BLOCKS", 128))
        max_rounds = max(1, _env_int("WEALL_SYNC_MAX_ROUNDS", max(4, ((target_height - local_height + max_delta_blocks - 1) // max_delta_blocks) + 2)))
        all_metas: List[ExecutorMeta] = []
        rounds = 0

        while int(self.state.get("height") or 0) < target_height:
            rounds += 1
            if rounds > max_rounds:
                raise ExecutorError("state_sync_max_rounds_exceeded")

            from_height = int(self.state.get("height") or 0)
            to_height = min(target_height, from_height + max_delta_blocks)
            corr_id = hashlib.sha256(
                f"{self.chain_id}:{self.node_id}:{peer_id}:{from_height}:{to_height}:{target_height}:{_now_ms()}".encode("utf-8")
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

            metas = self.apply_state_sync_response(resp, trusted_anchor=trusted_anchor)
            new_height = int(self.state.get("height") or 0)
            if new_height <= from_height:
                raise ExecutorError("state_sync_no_progress")
            all_metas.extend(metas)

        final_anchor = build_snapshot_anchor(self.state)
        if enforce_finalized_anchor and finalized_target_height > 0:
            if int(final_anchor.get("finalized_height") or 0) != finalized_target_height or str(final_anchor.get("finalized_block_id") or "") != str((trusted_anchor or {}).get("finalized_block_id") or ""):
                raise ExecutorError("state_sync_final_anchor_mismatch")
        elif str(final_anchor.get("tip_hash") or "") != str((trusted_anchor or {}).get("tip_hash") or "") or str(final_anchor.get("state_root") or "") != str((trusted_anchor or {}).get("state_root") or ""):
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
        setattr(self, "_last_db_prune_ms", now)

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
                    inc_counter("db_prune_deleted_blocks_total", int(res.get("deleted_blocks") or 0))
                    inc_counter("db_prune_deleted_bft_candidates_total", int(res.get("deleted_bft_candidates") or 0))
                except Exception:
                    pass
        except Exception:
            inc_counter("db_prune_errors_total", 1)
            return

    # ----------------------------
    # Compatibility / orchestration hooks
    # ----------------------------

    @classmethod
    def from_env(cls) -> "WeAllExecutor":
        cfg = load_chain_config()
        return cls(
            db_path=cfg.db_path,
            node_id=cfg.node_id,
            chain_id=cfg.chain_id,
            tx_index_path=cfg.tx_index_path,
        )

def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return int(default)
    try:
        return int(str(raw).strip())
    except Exception:
        if _mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}")
        return int(default)

