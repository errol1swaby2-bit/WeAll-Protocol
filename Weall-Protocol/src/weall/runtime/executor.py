from __future__ import annotations

import copy
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from weall.crypto.sig import sign_ed25519
from weall.ledger.state import LedgerView
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
from weall.runtime.block_hash import ensure_block_hash, make_block_header
from weall.runtime.chain_config import load_chain_config
from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.mempool import PersistentMempool
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs
from weall.runtime.poh.tier3_scheduler import schedule_poh_tier3_system_txs
from weall.runtime.sqlite_db import SqliteDB, SqliteLedgerStore, _canon_json
from weall.runtime.system_tx_engine import prune_emitted_system_queue, system_tx_emitter
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_id import compute_tx_id_from_dict
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

        # Load or initialize state.
        if self._ledger_store.exists():
            self.state = self._ledger_store.read()
        else:
            self.state = self._initial_state()
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

        # BFT engine (HotStuff)
        self._bft = HotStuffBFT(chain_id=self.chain_id)
        self._bft.load_from_state(self.state)

        # In-memory cache for candidate blocks awaiting QC (leader side)
        # block_id -> (block_dict, state_after_apply, applied_ids, invalid_ids)
        self._pending_candidates: Dict[str, Tuple[Json, Json, List[str], List[str]]] = {}

    def _initial_state(self) -> Json:
        return {
            "chain_id": self.chain_id,
            "height": 0,
            "tip": "",
            "tip_hash": "",
            "tip_ts_ms": 0,
            "blocks": {},
            "finalized": {"height": 0, "block_id": ""},
            "created_ms": _now_ms(),
        }

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

    def read_state(self) -> Json:
        return self.state

    # ----------------------------
    # Tx + att submission
    # ----------------------------

    def submit_tx(self, env: Json) -> Json:
        if not isinstance(env, dict):
            return {"ok": False, "error": "bad_env:not_object"}

        ledger = LedgerView.from_ledger(self.state)
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

        next_height = int(height) + 1

        def _apply_system_env(env: TxEnvelope) -> None:
            try:
                meta = apply_tx(working, env)
            except ApplyError:
                j = env.to_json()
                tx_id2 = compute_tx_id_from_dict(self.chain_id, j)
                invalid_ids.append(tx_id2)
                return
            if meta is None:
                return

            j = env.to_json()
            tx_id2 = compute_tx_id_from_dict(self.chain_id, j)
            j["tx_id"] = tx_id2
            applied_envs.append(j)
            applied_ids.append(tx_id2)

        try:
            schedule_poh_tier2_system_txs(working, next_height=next_height)
            schedule_poh_tier3_system_txs(working, next_height=next_height)
        except Exception:
            pass

        try:
            sys_pre = system_tx_emitter(working, self.tx_index, next_height=next_height, phase="pre")
            for env in sys_pre:
                _apply_system_env(env)
        except Exception:
            pass

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

        ledger_for_block = LedgerView.from_ledger(working)
        ok, block_reject, per_tx = admit_block_txs(env_objs, ledger_for_block, self.tx_index)
        if (not ok) and block_reject is not None:
            return None, None, [], [], f"block_reject:{block_reject.code}:{block_reject.reason}"

        for env, env_obj, tx_id, rej in zip(txs, env_objs, tx_ids, per_tx, strict=False):
            if not tx_id:
                invalid_ids.append(tx_id)
                continue

            if rej is not None:
                invalid_ids.append(tx_id)
                continue

            applied_ok = False
            try:
                meta = apply_tx(working, env)
                applied_ok = meta is not None
            except ApplyError:
                applied_ok = False

            try:
                if not bool(getattr(env_obj, "system", False)):
                    acct = working.get("accounts", {}).get(str(env_obj.signer))
                    if isinstance(acct, dict):
                        acct["nonce"] = int(env_obj.nonce)
            except Exception:
                pass

            applied_envs.append(env)
            applied_ids.append(tx_id)

            if not applied_ok:
                invalid_ids.append(tx_id)

        try:
            schedule_poh_tier2_system_txs(working, next_height=next_height)
            schedule_poh_tier3_system_txs(working, next_height=next_height)
        except Exception:
            pass

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

        header = make_block_header(
            chain_id=self.chain_id,
            height=new_height,
            prev_block_hash=tip_hash,
            block_ts_ms=ts_ms,
            tx_ids=applied_ids,
        )
        block = {
            "block_id": block_id,
            "height": new_height,
            "prev_block_id": tip,
            "prev_block_hash": tip_hash,
            "block_ts_ms": ts_ms,
            "header": header,
            "txs": applied_envs,
        }

        blocks_map = working.get("blocks")
        if not isinstance(blocks_map, dict):
            blocks_map = {}
            working["blocks"] = blocks_map
        blocks_map[str(block_id)] = {"height": int(new_height), "prev_block_id": str(tip)}

        working["height"] = int(new_height)
        working["tip"] = str(block_id)

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

                for tx_id in ids:
                    con.execute("DELETE FROM mempool WHERE tx_id=?;", (tx_id,))

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
            self._pending_candidates[bid] = (blk, st2, applied_ids, invalid_ids)
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

        qc = self._bft.add_vote(vote=vote, validators=validators, validator_pubkeys=vpub)
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
        ok = self._bft.add_timeout(timeout=tmo, validators=validators, validator_pubkeys=vpub)
        if not ok:
            return None

        if self._bft.should_advance_view(view=int(tmo.view), validators=validators):
            self._bft.view = int(tmo.view) + 1
            self._bft.last_progress_ms = _now_ms()
            self._persist_bft_state()
            return int(self._bft.view)

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
