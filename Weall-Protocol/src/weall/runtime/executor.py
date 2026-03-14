from __future__ import annotations

import copy
from collections import OrderedDict
import json
import os
import time
import hashlib
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
    canonical_timeout_message,
    canonical_vote_message,
    normalize_validators,
    qc_from_json,
    verify_qc,
)
from weall.runtime.block_admission import admit_block_txs
from weall.runtime.block_hash import compute_receipts_root, ensure_block_hash, make_block_header
from weall.runtime.vrf_sig import make_vrf_record, verify_vrf_record
from weall.runtime.state_hash import compute_state_root
from weall.runtime.chain_config import load_chain_config
from weall.runtime.domain_apply import ApplyError, apply_tx_atomic_meta
from weall.runtime.mempool import PersistentMempool, compute_tx_id
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs
from weall.runtime.poh.tier3_scheduler import schedule_poh_tier3_system_txs
from weall.runtime.sqlite_db import SqliteDB, SqliteLedgerStore, _canon_json
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


# Timestamp policy for produced blocks.
MAX_BLOCK_FUTURE_DRIFT_MS = 2 * 60 * 1000  # 2 minutes


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

        self._db = SqliteDB(path=self.db_path)
        self._db.init_schema()

        self._ledger_store = SqliteLedgerStore(db=self._db)
        self._mempool = PersistentMempool(db=self._db)
        self._att_pool = PersistentAttestationPool(db=self._db)

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

        # Fail-closed if on-disk DB invariants do not match the snapshot.
        self._check_db_consistency_fail_closed()

        # Fail-closed on chain_id mismatch once state is present.
        st_chain_id = str(self.state.get("chain_id") or "").strip()
        if st_chain_id and st_chain_id != self.chain_id:
            raise ExecutorError(
                f"chain_id mismatch: db={st_chain_id!r} executor={self.chain_id!r}. Refuse to start."
            )

        # Ensure chain_id is set in state if missing.
        if not st_chain_id:
            self.state["chain_id"] = self.chain_id
            self._ledger_store.write(self.state)

        # Back-compat / migration: ensure tip fields exist.
        self.state.setdefault("tip_hash", "")
        self.state.setdefault("tip_ts_ms", 0)
        self.state.setdefault("blocks", {})  # minimal ancestry map: block_id -> {height, prev_block_id}
        self.state.setdefault("finalized", {"height": 0, "block_id": ""})  # legacy finality placeholder

        # Canon tx index.
        self.tx_index: TxIndex = TxIndex.load_from_file(self.tx_index_path)

        # Stable hash of the canonical tx index file (used by /readyz and clients to detect mismatches).
        try:
            _b = Path(self.tx_index_path).read_bytes()
            self._tx_index_hash = hashlib.sha256(_b).hexdigest()
        except Exception:
            # Fail-closed elsewhere if tx index can't be read; keep best-effort hash empty here.
            self._tx_index_hash = ""

        # BFT engine (HotStuff)
        self._bft = HotStuffBFT(chain_id=self.chain_id)
        self._bft.load_from_state(self.state)

        # In-memory cache for candidate blocks awaiting QC (leader side)
        # block_id -> (block_dict, state_after_apply, applied_ids, invalid_ids)
        # Strict mode: these caches are hard-capped to prevent memory DoS.
        self._max_pending_candidates: int = _safe_int(os.environ.get("WEALL_MAX_PENDING_CANDIDATES"), 128)
        self._pending_candidates: "OrderedDict[str, Tuple[Json, Json, List[str], List[str]]]" = OrderedDict()

        # In-memory cache for remote proposals we may need to commit once a QC arrives
        # block_id -> block_dict
        # Strict mode: hard-cap to prevent unbounded growth from untrusted peers.
        self._max_pending_remote_blocks: int = _safe_int(os.environ.get("WEALL_MAX_PENDING_REMOTE_BLOCKS"), 256)
        self._pending_remote_blocks: "OrderedDict[str, Json]" = OrderedDict()

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

    def _initial_state(self) -> Json:
        # IMPORTANT: this must include the core consensus/authorization subtrees.
        # Many tests and admission/gate logic assume these keys exist.
        return {
            "chain_id": self.chain_id,
            "created_ms": _now_ms(),

            # Monotonic chain time (ts_ms) tracked by the executor.
            # Initialized at genesis so session-gated logic can behave deterministically.
            "time": 0,

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

        try:
            bootstrap_rep = float(os.environ.get("WEALL_GENESIS_BOOTSTRAP_REPUTATION") or 1.0)
        except Exception:
            bootstrap_rep = 1.0
        if bootstrap_rep < 0.0:
            bootstrap_rep = 0.0

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
                "balance": 0,
                "keys": {"by_id": {}},
                "devices": {"by_id": {}},
                "recovery": {"config": None, "proposals": {}},
                "session_keys": {},
            }
            accounts[acct] = a

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
        a["reputation"] = max(float(a.get("reputation") or 0.0), float(bootstrap_rep))
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

        wall_now = _now_ms()
        last_ts = _safe_int(self.state.get("tip_ts_ms"), 0)

        ts_ms = int(force_ts_ms) if force_ts_ms is not None else (wall_now if wall_now >= last_ts else last_ts)
        if ts_ms > wall_now + MAX_BLOCK_FUTURE_DRIFT_MS:
            return None, None, [], [], "invalid_block_ts:future_drift"

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
        ok, block_reject, per_tx = admit_block_txs(env_objs, ledger_for_block, self.tx_index)
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

        # Phase: schedule PoH system txs (best-effort)
        try:
            schedule_poh_tier2_system_txs(working, next_height=next_height)
            schedule_poh_tier3_system_txs(working, next_height=next_height)
        except Exception:
            pass

        # Phase: system emitter post
        try:
            sys_post = system_tx_emitter(working, self.tx_index, next_height=next_height, phase="post")
            for env in sys_post:
                _apply_system_env(env)
        except Exception:
            pass

        if not applied_envs and not bool(allow_empty):
            return None, None, [], invalid_ids, "no_applicable"

        new_height = next_height
        block_id = f"{new_height}:{ts_ms}:{len(applied_envs)}"

        # Update ancestry + tip fields before computing roots.
        blocks_map = working.get("blocks")
        if not isinstance(blocks_map, dict):
            blocks_map = {}
            working["blocks"] = blocks_map
        blocks_map[str(block_id)] = {"height": int(new_height), "prev_block_id": str(tip)}

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
        require_vrf = _env_bool("WEALL_REQUIRE_VRF", False)
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

        receipts_root = compute_receipts_root(receipts=receipts)

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
        except Exception:
            pass

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
            except Exception:
                pass

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
                    time.sleep(float(sleep_ms) / 1000.0)

                # TEST-ONLY fail hook: simulate an exception after the block row is inserted
                # but before mempool cleanup + ledger_state write.
                if os.environ.get("WEALL_TEST_FAIL_AFTER_BLOCK_INSERT", "").strip().lower() in {"1", "true", "yes"}:
                    raise RuntimeError("test_fail_after_block_insert")

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

            self.state = new_state
            self._bft.load_from_state(self.state)

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

        header = block2.get("header")
        if not isinstance(header, dict):
            return ExecutorMeta(ok=False, error="bad_block:missing_header", height=0, block_id="")

        if str(header.get("chain_id") or "").strip() != self.chain_id:
            return ExecutorMeta(ok=False, error="bad_block:chain_id_mismatch", height=0, block_id="")

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
            try:
                schedule_poh_tier2_system_txs(working, next_height=next_height)
                schedule_poh_tier3_system_txs(working, next_height=next_height)
            except Exception:
                return

        def _run_system_emitter_side_effects(phase: str) -> None:
            try:
                # We discard envelopes; the block already contains the tx list.
                _ = system_tx_emitter(working, self.tx_index, next_height=next_height, phase=str(phase), proposer="")
            except Exception:
                return

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
        _run_poh_schedulers()
        _run_system_emitter_side_effects("pre")

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
        ok, block_reject, per_tx = admit_block_txs(env_objs, ledger_for_block, self.tx_index)
        if (not ok) and block_reject is not None:
            return ExecutorMeta(ok=False, error=f"bad_block:block_reject:{block_reject.code}", height=0, block_id="")

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
                        _run_poh_schedulers()
                        _run_system_emitter_side_effects("post")
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
            _run_poh_schedulers()
            _run_system_emitter_side_effects("post")

        # Update ancestry + tip fields and time exactly as the leader should have.
        block_id = str(block2.get("block_id") or "").strip()
        if not block_id:
            # Back-compat: accept derived id
            block_id = f"{height}:{ts_ms}:{len(applied_ids)}"

        blocks_map = working.get("blocks")
        if not isinstance(blocks_map, dict):
            blocks_map = {}
            working["blocks"] = blocks_map
        blocks_map[str(block_id)] = {"height": int(height), "prev_block_id": str(self.state.get("tip") or "")}

        working["height"] = int(height)
        working["tip"] = str(block_id)
        working["time"] = int(int(ts_ms) // 1000)

        # Verify commitments
        receipts_root = compute_receipts_root(receipts=receipts)
        have_rr = str(header.get("receipts_root") or "").strip()
        if have_rr and receipts_root != have_rr:
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
            if _env_bool("WEALL_REQUIRE_VRF", False):
                return ExecutorMeta(ok=False, error="bad_block:vrf:missing", height=0, block_id="")

        state_root = compute_state_root(working)
        have_sr = str(header.get("state_root") or "").strip()
        if have_sr and state_root != have_sr:
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

    def bft_on_proposal(self, proposal: Json) -> Optional[Json]:
        """Handle a leader proposal.

        Returns a vote JSON if we should vote, else None.
        """
        if not isinstance(proposal, dict):
            return None

        # Basic sanity and cache for later commit.
        try:
            proposal2, _ = ensure_block_hash(proposal)
        except Exception:
            return None

        bid = str(proposal2.get("block_id") or "").strip()
        if bid:
            _bounded_put(self._pending_remote_blocks, bid, proposal2, cap=self._max_pending_remote_blocks)

        # Optional auto-vote (default off so unit tests remain deterministic).
        if not _env_bool("WEALL_AUTOVOTE", False):
            return None

        try:
            view = int(proposal2.get("view") or proposal2.get("bft_view") or 0)
        except Exception:
            view = 0

        parent_id = str(proposal2.get("prev_block_id") or "").strip()
        if not parent_id:
            parent_id = str(self.state.get("tip") or "").strip()

        return self.bft_make_vote_for_block(view=view, block_id=bid, parent_id=parent_id)

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

        # Leader path: commit candidate if we have full state.
        meta = self.bft_commit_if_ready(qc)
        if meta is not None:
            return meta

        # Follower path: if we have the block, replay+commit it.
        blk = self._pending_remote_blocks.get(bid)
        if blk is None:
            return None

        blk2 = dict(blk)
        blk2["qc"] = qc.to_json()
        meta2 = self.apply_block(blk2)
        try:
            del self._pending_remote_blocks[bid]
        except Exception:
            pass
        return meta2

    def bft_on_timeout(self, timeoutj: Json) -> Optional[Json]:
        """Handle a timeout and return a QC JSON if one was formed."""
        qc = self.bft_handle_timeout(timeoutj)
        return qc.to_json() if qc is not None else None

    def bft_drive_timeouts(self, now_ms: int) -> list[Json]:
        """Return any timeout messages we should broadcast."""
        if not _env_bool("WEALL_AUTOTIMEOUT", False):
            return []
        try:
            # If we believe we're not the leader and haven't seen progress, emit a timeout.
            # HotStuffBFT itself doesn't know wall clock; this is a minimal adapter.
            view = int(self._bft.view)
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

    def bft_current_view(self) -> int:
        return int(self._bft.view)

    def bft_set_view(self, view: int) -> None:
        self._bft.view = int(view)
        self._persist_bft_state()

    def _persist_bft_state(self) -> None:
        self.state["bft"] = self._bft.export_state()
        self._ledger_store.write(self.state)

    def bft_verify_qc_json(self, qcj: Json) -> Optional[QuorumCert]:
        qc = qc_from_json(qcj)
        if qc is None:
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
        blocks_map = self.state.get("blocks")
        if not isinstance(blocks_map, dict):
            blocks_map = {}
        self._bft.observe_qc(blocks=blocks_map, qc=qc)
        self._persist_bft_state()
        return True

    def bft_leader_propose(self, *, max_txs: int = 1000) -> Optional[Json]:
        blk, st2, applied_ids, invalid_ids, err = self.build_block_candidate(max_txs=max_txs, allow_empty=True)
        if err and err != "empty":
            return None
        if blk is None or st2 is None:
            return None

        if self._bft.high_qc is not None:
            blk["justify_qc"] = self._bft.high_qc.to_json()

        bid = str(blk.get("block_id") or "")
        if bid:
            _bounded_put(self._pending_candidates, bid, (blk, st2, applied_ids, invalid_ids), cap=self._max_pending_candidates)
        return blk

    def bft_handle_vote(self, vote_json: Json) -> Optional[QuorumCert]:
        if not isinstance(vote_json, dict):
            return None
        if str(vote_json.get("t") or "") != "VOTE":
            return None

        validators = self._active_validators()
        vpub = self._validator_pubkeys()

        vote = BftVote(
            chain_id=str(vote_json.get("chain_id") or self.chain_id).strip(),
            view=int(vote_json.get("view") or 0),
            block_id=str(vote_json.get("block_id") or "").strip(),
            parent_id=str(vote_json.get("parent_id") or "").strip(),
            signer=str(vote_json.get("signer") or "").strip(),
            pubkey=str(vote_json.get("pubkey") or "").strip(),
            sig=str(vote_json.get("sig") or "").strip(),
        )

        # NOTE: HotStuffBFT validates signatures + threshold internally.
        # Use the engine's canonical accept_vote API.
        qc = self._bft.accept_vote(vote_json=vote.to_json(), validators=validators, vpub=vpub)
        if qc is None:
            return None

        blocks_map = self.state.get("blocks")
        if not isinstance(blocks_map, dict):
            blocks_map = {}
        self._bft.observe_qc(blocks=blocks_map, qc=qc)
        self._persist_bft_state()
        return qc

    def bft_commit_if_ready(self, qc: QuorumCert) -> Optional[ExecutorMeta]:
        validators = self._active_validators()
        vpub = self._validator_pubkeys()
        if not verify_qc(qc=qc, validators=validators, validator_pubkeys=vpub):
            return None

        bid = str(qc.block_id)
        tup = self._pending_candidates.get(bid)
        if tup is None:
            return None
        blk, st2, applied_ids, invalid_ids = tup

        blk2 = dict(blk)
        blk2["qc"] = qc.to_json()

        meta = self.commit_block_candidate(block=blk2, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids)

        try:
            del self._pending_candidates[bid]
        except Exception:
            pass

        self._bft.load_from_state(self.state)
        self._persist_bft_state()
        return meta

    def bft_make_vote_for_block(self, *, view: int, block_id: str, parent_id: str) -> Optional[Json]:
        signer = (os.environ.get("WEALL_VALIDATOR_ACCOUNT") or self.node_id or "").strip()
        pubkey = (os.environ.get("WEALL_NODE_PUBKEY") or "").strip()
        privkey = (os.environ.get("WEALL_NODE_PRIVKEY") or "").strip()
        if not signer or not pubkey or not privkey:
            return None

        msg = canonical_vote_message(
            chain_id=self.chain_id,
            view=int(view),
            block_id=str(block_id),
            parent_id=str(parent_id),
            signer=signer,
        )
        sig = sign_ed25519(message=msg, privkey=privkey, encoding="hex")

        vote = BftVote(
            chain_id=self.chain_id,
            view=int(view),
            block_id=str(block_id),
            parent_id=str(parent_id),
            signer=signer,
            pubkey=pubkey,
            sig=sig,
        )
        return vote.to_json()

    def bft_make_timeout(self, *, view: int) -> Optional[Json]:
        signer = (os.environ.get("WEALL_VALIDATOR_ACCOUNT") or self.node_id or "").strip()
        pubkey = (os.environ.get("WEALL_NODE_PUBKEY") or "").strip()
        privkey = (os.environ.get("WEALL_NODE_PRIVKEY") or "").strip()
        if not signer or not pubkey or not privkey:
            return None

        high_qc_id = ""
        if self._bft.high_qc is not None:
            high_qc_id = str(self._bft.high_qc.block_id)

        msg = canonical_timeout_message(chain_id=self.chain_id, view=int(view), high_qc_id=high_qc_id, signer=signer)
        sig = sign_ed25519(message=msg, privkey=privkey, encoding="hex")
        tmo = BftTimeout(
            chain_id=self.chain_id,
            view=int(view),
            high_qc_id=high_qc_id,
            signer=signer,
            pubkey=pubkey,
            sig=sig,
        )
        return tmo.to_json()

    def bft_handle_timeout(self, timeout_json: Json) -> Optional[int]:
        if not isinstance(timeout_json, dict):
            return None
        if str(timeout_json.get("t") or "") != "TIMEOUT":
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
        timeout_ms = 10_000
        now = _now_ms()
        if (now - int(self._bft.last_progress_ms)) < timeout_ms:
            return None
        view = int(self._bft.view)
        tmo = self.bft_make_timeout(view=view)
        if not isinstance(tmo, dict):
            return None
        self.bft_handle_timeout(tmo)
        return tmo

    # ----------------------------
    # Block + history APIs
    # ----------------------------

    def get_block_by_height(self, height: int) -> Optional[Json]:
        with self._db.connection() as con:
            row = con.execute("SELECT block_json FROM blocks WHERE height=? LIMIT 1;", (int(height),)).fetchone()
            if row is None:
                return None
            blk = json.loads(str(row["block_json"]))
            if isinstance(blk, dict):
                blk, _ = ensure_block_hash(blk)
            return blk

    def get_latest_block(self) -> Optional[Json]:
        with self._db.connection() as con:
            row = con.execute("SELECT block_json FROM blocks ORDER BY height DESC LIMIT 1;").fetchone()
            if row is None:
                return None
            blk = json.loads(str(row["block_json"]))
            if isinstance(blk, dict):
                blk, _ = ensure_block_hash(blk)
            return blk

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
