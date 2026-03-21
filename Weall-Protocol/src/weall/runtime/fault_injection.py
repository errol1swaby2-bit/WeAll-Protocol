from __future__ import annotations

import multiprocessing as mp
import os
import tempfile
import threading
import time
from collections.abc import Mapping, MutableMapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from weall.crypto.sig import sign_ed25519
from weall.runtime.bft_hotstuff import (
    BftVote,
    canonical_proposal_message,
    canonical_timeout_message,
    canonical_vote_message,
    leader_for_view,
    quorum_threshold,
)
from weall.runtime.executor import WeAllExecutor
from weall.runtime.sqlite_db import SqliteDB

Json = dict[str, Any]


@dataclass(frozen=True)
class FaultInjectionSummary:
    chain_id: str
    rounds_requested: int
    rounds_built: int
    validator_ids: list[str]
    restart_events: int
    partitioned_deliveries: int
    delayed_child_first_events: int
    healed_partition_events: int
    epoch_bump_events: int
    stale_qc_replay_attempts: int
    stale_qc_replay_rejections: int
    stalled_delivery_events: int
    rejoin_catchup_events: int
    forced_clock_skew_events: int
    forced_clock_skew_warnings: int
    leader_height: int
    leader_tip: str
    follower_heights: dict[str, int]
    follower_tips: dict[str, str]
    follower_diagnostics: dict[str, Json]
    converged: bool

    def to_json(self) -> Json:
        return asdict(self)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _default_tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _mk_keypair_hex() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pk_b.hex(), sk_b.hex()


def _seed_validator_set(
    ex: WeAllExecutor, *, validators: Sequence[str], pub: Mapping[str, str], epoch: int = 1
) -> None:
    st = ex.read_state()
    st.setdefault("roles", {})
    st["roles"].setdefault("validators", {})
    st["roles"]["validators"]["active_set"] = list(validators)
    st.setdefault("consensus", {})
    st["consensus"].setdefault("validators", {})
    st["consensus"]["validators"].setdefault("registry", {})
    st["consensus"].setdefault("epochs", {})
    st["consensus"]["epochs"]["current"] = int(epoch)
    st["consensus"].setdefault("validator_set", {})
    st["consensus"]["validator_set"]["active_set"] = list(validators)
    st["consensus"].setdefault("epoch_history", [])
    st["consensus"]["validator_set"]["epoch"] = int(epoch)
    for v in validators:
        st["consensus"]["validators"]["registry"].setdefault(v, {})
        st["consensus"]["validators"]["registry"][v]["pubkey"] = str(pub[v])
    ex.state = st
    ex._ledger_store.write(ex.state)
    st = ex.read_state()
    st["consensus"]["validator_set"]["set_hash"] = ex._current_validator_set_hash()
    ex.state = st
    ex._ledger_store.write(ex.state)


def _advance_validator_epoch(
    executors: Mapping[str, WeAllExecutor],
    *,
    validators: Sequence[str],
    pub: Mapping[str, str],
    new_epoch: int,
) -> None:
    for ex in executors.values():
        _seed_validator_set(ex, validators=validators, pub=pub, epoch=new_epoch)
        ex._persist_bft_state()


def _make_qc(
    *,
    chain_id: str,
    validators: Sequence[str],
    vpub: Mapping[str, str],
    vpriv: Mapping[str, str],
    block_id: str,
    block_hash: str,
    parent_id: str,
    view: int,
    validator_epoch: int,
    validator_set_hash: str,
) -> Json:
    votes: list[Json] = []
    signer_count = quorum_threshold(len(validators))
    for signer in list(validators)[:signer_count]:
        msg = canonical_vote_message(
            chain_id=chain_id,
            view=view,
            block_id=block_id,
            block_hash=block_hash,
            parent_id=parent_id,
            signer=signer,
            validator_epoch=validator_epoch,
            validator_set_hash=validator_set_hash,
        )
        sig = sign_ed25519(message=msg, privkey=str(vpriv[signer]), encoding="hex")
        votes.append(
            BftVote(
                chain_id=chain_id,
                view=view,
                block_id=block_id,
                block_hash=block_hash,
                parent_id=parent_id,
                signer=signer,
                pubkey=str(vpub[signer]),
                sig=sig,
                validator_epoch=validator_epoch,
                validator_set_hash=validator_set_hash,
            ).to_json()
        )
    return {
        "t": "QC",
        "chain_id": str(chain_id),
        "view": int(view),
        "block_id": str(block_id),
        "block_hash": str(block_hash),
        "parent_id": str(parent_id),
        "votes": votes,
        "validator_epoch": int(validator_epoch),
        "validator_set_hash": str(validator_set_hash),
    }


def _build_committed_block(ex: WeAllExecutor, *, force_ts_ms: int) -> Json:
    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0, allow_empty=True, force_ts_ms=force_ts_ms
    )
    if err:
        raise RuntimeError(f"build_block_candidate failed: {err}")
    if not isinstance(blk, dict) or not isinstance(st2, dict):
        raise RuntimeError("build_block_candidate returned malformed result")
    meta = ex.commit_block_candidate(
        block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids
    )
    if meta.ok is not True:
        raise RuntimeError(f"commit_block_candidate failed: {meta.error}")
    return blk


def _proposal_payload(*, validators: Sequence[str], view: int, block: Json) -> Json:
    proposer = leader_for_view(list(validators), int(view))
    return {"view": int(view), "proposer": str(proposer), "block": dict(block)}


class _EnvPatch:
    def __init__(self, updates: Mapping[str, str]) -> None:
        self._updates = {str(k): str(v) for k, v in updates.items()}
        self._prev: dict[str, str | None] = {}

    def __enter__(self) -> None:
        for k, v in self._updates.items():
            self._prev[k] = os.environ.get(k)
            os.environ[k] = v

    def __exit__(self, exc_type, exc, tb) -> None:
        for k, old in self._prev.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


def run_bft_fault_injection_soak(
    *,
    work_dir: str | None = None,
    rounds: int = 18,
    validator_count: int = 4,
    partition_target: str | None = None,
    partition_rounds: Sequence[int] = (5, 6, 7),
    stall_target: str | None = None,
    stall_rounds: Sequence[int] = (),
    delay_target: str | None = None,
    delay_child_first_every: int = 4,
    restart_target: str | None = None,
    restart_every: int = 6,
    epoch_bump_rounds: Sequence[int] = (),
    stale_qc_replay_target: str | None = None,
    clock_skew_target: str | None = None,
    clock_skew_rounds: Sequence[int] = (),
    clock_skew_ahead_ms: int = 120_000,
    chain_id: str = "bft-soak",
    validator_epoch: int = 3,
    tx_index_path: str | None = None,
) -> FaultInjectionSummary:
    rounds_n = max(1, int(rounds))
    n_validators = max(4, int(validator_count))
    validators = [f"v{i}" for i in range(1, n_validators + 1)]
    partition_target_s = str(partition_target or validators[-1])
    stall_target_s = str(stall_target or validators[-1])
    delay_target_s = str(delay_target or validators[-2])
    restart_target_s = str(restart_target or validators[-1])
    stale_qc_replay_target_s = str(stale_qc_replay_target or validators[1])
    clock_skew_target_s = str(clock_skew_target or validators[-1])
    part_rounds = {int(x) for x in partition_rounds}
    stall_rounds_set = {int(x) for x in stall_rounds}
    epoch_rounds = {int(x) for x in epoch_bump_rounds}
    clock_skew_rounds_set = {int(x) for x in clock_skew_rounds}
    tx_index = str(tx_index_path or _default_tx_index_path())

    if (
        partition_target_s not in validators
        or delay_target_s not in validators
        or restart_target_s not in validators
        or stale_qc_replay_target_s not in validators
        or stall_target_s not in validators
        or clock_skew_target_s not in validators
    ):
        raise ValueError("targets must be members of the validator set")

    base_dir_obj = (
        tempfile.TemporaryDirectory(prefix="weall-bft-soak-") if work_dir is None else None
    )
    base_dir = Path(work_dir or base_dir_obj.name)
    base_dir.mkdir(parents=True, exist_ok=True)

    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    executors: dict[str, WeAllExecutor] = {}
    db_paths: dict[str, str] = {v: str(base_dir / f"{v}.db") for v in validators}

    with _EnvPatch({"WEALL_MODE": "testnet", "WEALL_BFT_ENABLED": "1"}):
        for v in validators:
            ex = WeAllExecutor(
                db_path=db_paths[v], node_id=v, chain_id=chain_id, tx_index_path=tx_index
            )
            _seed_validator_set(ex, validators=validators, pub=vpub, epoch=validator_epoch)
            executors[v] = ex

        leader_id = validators[0]
        leader = executors[leader_id]
        current_epoch = int(validator_epoch)
        vset_hash = leader._current_validator_set_hash()

        partition_backlog: dict[str, list[Json]] = {v: [] for v in validators}
        delayed_parent: dict[str, Json | None] = {v: None for v in validators}
        restart_events = 0
        partitioned_deliveries = 0
        delayed_child_first_events = 0
        healed_partition_events = 0
        epoch_bump_events = 0
        stale_qc_replay_attempts = 0
        stale_qc_replay_rejections = 0
        stalled_delivery_events = 0
        rejoin_catchup_events = 0
        forced_clock_skew_events = 0
        forced_clock_skew_warnings = 0

        def _force_clock_skew(node_id: str, *, reference_ts_ms: int) -> None:
            nonlocal forced_clock_skew_events, forced_clock_skew_warnings
            ex = executors[node_id]
            st = ex.read_state()
            st["_fault_prev_tip_ts_ms"] = int(st.get("tip_ts_ms") or 0)
            st["tip_ts_ms"] = int(time.time() * 1000) + max(1, int(clock_skew_ahead_ms))
            ex.state = st
            ex._ledger_store.write(ex.state)
            forced_clock_skew_events += 1
            diag = ex.bft_diagnostics()
            if bool(diag.get("clock_skew_warning", False)):
                forced_clock_skew_warnings += 1

        def _clear_clock_skew(node_id: str, *, reference_ts_ms: int) -> None:
            ex = executors[node_id]
            st = ex.read_state()
            prev_tip_ts_ms = int(st.pop("_fault_prev_tip_ts_ms", st.get("tip_ts_ms") or 0) or 0)
            # Restore to the prior committed chain time, never to the current round's
            # block timestamp, because that would make the incoming block appear to be
            # at or before the current chain-time floor and stall catch-up.
            st["tip_ts_ms"] = int(max(0, prev_tip_ts_ms))
            ex.state = st
            ex._ledger_store.write(ex.state)

        def _deliver(node_id: str, blk: Json, view: int) -> None:
            ex = executors[node_id]
            ex.bft_on_proposal(_proposal_payload(validators=validators, view=view, block=blk))

        for view in range(1, rounds_n + 1):
            leader = executors[leader_id]
            blk = dict(_build_committed_block(leader, force_ts_ms=int(view * 1000)))
            qc = _make_qc(
                chain_id=chain_id,
                validators=validators,
                vpub=vpub,
                vpriv=vpriv,
                block_id=str(blk["block_id"]),
                block_hash=str(blk.get("block_hash") or ""),
                parent_id=str(blk.get("prev_block_id") or ""),
                view=view,
                validator_epoch=current_epoch,
                validator_set_hash=vset_hash,
            )
            blk["qc"] = qc
            blk["validator_epoch"] = int(current_epoch)
            blk["validator_set_hash"] = str(vset_hash)

            for node_id in validators[1:]:
                ref_ts_ms = int(blk.get("block_ts_ms") or view * 1000)
                if node_id == clock_skew_target_s and view in clock_skew_rounds_set:
                    _force_clock_skew(node_id, reference_ts_ms=ref_ts_ms)
                    _clear_clock_skew(node_id, reference_ts_ms=ref_ts_ms)

                if node_id == partition_target_s and view in part_rounds:
                    partition_backlog[node_id].append(dict(blk))
                    partitioned_deliveries += 1
                    continue

                if node_id == stall_target_s and view in stall_rounds_set:
                    stalled_delivery_events += 1
                    partition_backlog[node_id].append(dict(blk))
                    continue

                if node_id == partition_target_s and partition_backlog[node_id]:
                    _deliver(node_id, blk, view)
                    rejoin_catchup_events += 1
                    for old_index, old_blk in enumerate(list(partition_backlog[node_id]), start=1):
                        old_view = max(1, view - len(partition_backlog[node_id]) - 1 + old_index)
                        _deliver(node_id, old_blk, old_view)
                        healed_partition_events += 1
                    partition_backlog[node_id].clear()
                    _clear_clock_skew(node_id, reference_ts_ms=ref_ts_ms)
                    continue

                if node_id == stall_target_s and partition_backlog[node_id]:
                    _deliver(node_id, blk, view)
                    rejoin_catchup_events += 1
                    for old_index, old_blk in enumerate(list(partition_backlog[node_id]), start=1):
                        old_view = max(1, view - len(partition_backlog[node_id]) - 1 + old_index)
                        _deliver(node_id, old_blk, old_view)
                        healed_partition_events += 1
                    partition_backlog[node_id].clear()
                    _clear_clock_skew(node_id, reference_ts_ms=ref_ts_ms)
                    continue

                if node_id == delay_target_s:
                    pending_parent = delayed_parent[node_id]
                    if (
                        pending_parent is None
                        and delay_child_first_every > 0
                        and view % int(delay_child_first_every) == 1
                        and view < rounds_n
                    ):
                        delayed_parent[node_id] = dict(blk)
                        continue
                    if pending_parent is not None:
                        _deliver(node_id, blk, view)
                        parent_view = max(1, view - 1)
                        _deliver(node_id, pending_parent, parent_view)
                        delayed_parent[node_id] = None
                        delayed_child_first_events += 1
                        if node_id == clock_skew_target_s and view in clock_skew_rounds_set:
                            _clear_clock_skew(node_id, reference_ts_ms=ref_ts_ms)
                        continue

                _deliver(node_id, blk, view)
                if node_id == clock_skew_target_s and view in clock_skew_rounds_set:
                    _clear_clock_skew(node_id, reference_ts_ms=ref_ts_ms)

            if restart_every > 0 and view % int(restart_every) == 0:
                ex_old = executors[restart_target_s]
                persisted_height = int(ex_old.state.get("height") or 0)
                if hasattr(ex_old, "mark_clean_shutdown"):
                    ex_old.mark_clean_shutdown()
                ex_new = WeAllExecutor(
                    db_path=db_paths[restart_target_s],
                    node_id=restart_target_s,
                    chain_id=chain_id,
                    tx_index_path=tx_index,
                )
                executors[restart_target_s] = ex_new
                restart_events += 1
                if int(ex_new.state.get("height") or 0) < persisted_height:
                    raise RuntimeError("restart regression detected in soak harness")

            if view in epoch_rounds:
                stale_qc = dict(qc)
                current_epoch += 1
                _advance_validator_epoch(
                    executors, validators=validators, pub=vpub, new_epoch=current_epoch
                )
                epoch_bump_events += 1
                leader = executors[leader_id]
                vset_hash = leader._current_validator_set_hash()
                stale_qc_replay_attempts += 1
                accepted = executors[stale_qc_replay_target_s].bft_handle_qc(stale_qc)
                if accepted is not True:
                    stale_qc_replay_rejections += 1

        for node_id, pending_parent in list(delayed_parent.items()):
            if pending_parent is not None:
                _deliver(node_id, pending_parent, rounds_n)
                delayed_parent[node_id] = None
        for node_id, backlog in list(partition_backlog.items()):
            if backlog:
                rejoin_catchup_events += 1
                for old_blk in backlog:
                    _deliver(node_id, old_blk, rounds_n)
                    healed_partition_events += 1
                partition_backlog[node_id].clear()
                _clear_clock_skew(node_id, reference_ts_ms=int(rounds_n * 1000))

        leader = executors[leader_id]
        leader_height = int(leader.state.get("height") or 0)
        leader_tip = str(leader.state.get("tip") or "")
        follower_heights: dict[str, int] = {}
        follower_tips: dict[str, str] = {}
        follower_diagnostics: dict[str, Json] = {}
        converged = True
        for node_id in validators[1:]:
            ex = executors[node_id]
            follower_heights[node_id] = int(ex.state.get("height") or 0)
            follower_tips[node_id] = str(ex.state.get("tip") or "")
            follower_diagnostics[node_id] = ex.bft_diagnostics()
            if follower_heights[node_id] != leader_height or follower_tips[node_id] != leader_tip:
                converged = False

    if base_dir_obj is not None:
        base_dir_obj.cleanup()

    return FaultInjectionSummary(
        chain_id=chain_id,
        rounds_requested=rounds_n,
        rounds_built=leader_height,
        validator_ids=list(validators),
        restart_events=restart_events,
        partitioned_deliveries=partitioned_deliveries,
        delayed_child_first_events=delayed_child_first_events,
        healed_partition_events=healed_partition_events,
        epoch_bump_events=epoch_bump_events,
        stale_qc_replay_attempts=stale_qc_replay_attempts,
        stale_qc_replay_rejections=stale_qc_replay_rejections,
        stalled_delivery_events=stalled_delivery_events,
        rejoin_catchup_events=rejoin_catchup_events,
        forced_clock_skew_events=forced_clock_skew_events,
        forced_clock_skew_warnings=forced_clock_skew_warnings,
        leader_height=leader_height,
        leader_tip=leader_tip,
        follower_heights=follower_heights,
        follower_tips=follower_tips,
        follower_diagnostics=follower_diagnostics,
        converged=converged,
    )


@dataclass(frozen=True)
class CrossProcessSqlitePressureSummary:
    db_path: str
    process_count: int
    writes_per_process: int
    tx_hold_ms: int
    attempts: int
    successes: int
    operational_errors: int
    other_errors: int
    final_counter: int
    duration_ms: int
    ok: bool

    def to_json(self) -> Json:
        return asdict(self)


@dataclass(frozen=True)
class TimeoutEpochStormSummary:
    chain_id: str
    validator_ids: list[str]
    duplicate_timeouts: int
    stale_timeout_rejections: int
    epoch_replay_attempts: int
    epoch_replay_rejections: int
    restarts: int
    final_view: int
    highest_tc_view: int
    ok: bool

    def to_json(self) -> Json:
        return asdict(self)


@dataclass(frozen=True)
class Priority2SoakSummary:
    bft: Json
    consensus_resilience_matrix: Json
    sqlite_writer_pressure: Json
    sqlite_writer_pressure_cross_process: Json
    timeout_epoch_storm: Json
    mempool_spam: Json
    ok: bool

    def to_json(self) -> Json:
        return asdict(self)


@dataclass(frozen=True)
class SqliteWriterPressureSummary:
    db_path: str
    worker_count: int
    writes_per_worker: int
    tx_hold_ms: int
    attempts: int
    successes: int
    operational_errors: int
    other_errors: int
    maintenance_ticks: int
    final_counter: int
    duration_ms: int
    ok: bool

    def to_json(self) -> Json:
        return asdict(self)


@dataclass(frozen=True)
class MempoolSpamSummary:
    db_path: str
    chain_id: str
    worker_count: int
    txs_per_worker: int
    duplicate_every: int
    attempts: int
    accepted: int
    unique_tx_ids: int
    duplicate_accepts: int
    rejected: int
    blocks_produced: int
    committed_tx_count: int
    final_mempool_size: int
    final_height: int
    duration_ms: int
    ok: bool

    def to_json(self) -> Json:
        return asdict(self)


def run_sqlite_writer_pressure_soak(
    *,
    work_dir: str | None = None,
    worker_count: int = 4,
    writes_per_worker: int = 24,
    tx_hold_ms: int = 2,
    checkpoint_interval_ms: int = 10,
) -> SqliteWriterPressureSummary:
    base_dir_obj = None
    if work_dir:
        base_dir = Path(work_dir).resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
    else:
        base_dir_obj = tempfile.TemporaryDirectory(prefix="weall-sqlite-pressure-")
        base_dir = Path(base_dir_obj.name)
    db_path = str(base_dir / "writer_pressure.sqlite")
    db = SqliteDB(path=db_path)
    db.init_schema()
    with db.write_tx() as con:
        con.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('writer_pressure_counter', '0');"
        )

    lock = threading.Lock()
    stop_event = threading.Event()
    counters: MutableMapping[str, int] = {
        "attempts": 0,
        "successes": 0,
        "operational_errors": 0,
        "other_errors": 0,
        "maintenance_ticks": 0,
    }

    def _maintenance() -> None:
        interval_s = max(0.001, int(checkpoint_interval_ms) / 1000.0)
        while not stop_event.is_set():
            try:
                db.wal_checkpoint(mode="PASSIVE")
            finally:
                with lock:
                    counters["maintenance_ticks"] += 1
            stop_event.wait(interval_s)

    def _worker(worker_idx: int) -> None:
        for _ in range(max(1, int(writes_per_worker))):
            with lock:
                counters["attempts"] += 1
            try:
                with db.write_tx() as con:
                    row = con.execute(
                        "SELECT value FROM meta WHERE key='writer_pressure_counter' LIMIT 1;"
                    ).fetchone()
                    cur = int(row[0]) if row is not None and row[0] is not None else 0
                    if int(tx_hold_ms) > 0:
                        time.sleep(int(tx_hold_ms) / 1000.0)
                    con.execute(
                        "INSERT OR REPLACE INTO meta(key, value) VALUES('writer_pressure_counter', ?);",
                        (str(cur + 1),),
                    )
                with lock:
                    counters["successes"] += 1
            except Exception as e:
                with lock:
                    if "locked" in str(e).lower():
                        counters["operational_errors"] += 1
                    else:
                        counters["other_errors"] += 1

    started = _now_ms()
    maint = threading.Thread(target=_maintenance, daemon=True)
    maint.start()
    try:
        with ThreadPoolExecutor(max_workers=max(1, int(worker_count))) as pool:
            futures = [pool.submit(_worker, idx) for idx in range(max(1, int(worker_count)))]
            for fut in futures:
                fut.result()
    finally:
        stop_event.set()
        maint.join(timeout=1.0)

    with db.connection() as con:
        row = con.execute(
            "SELECT value FROM meta WHERE key='writer_pressure_counter' LIMIT 1;"
        ).fetchone()
        final_counter = int(row[0]) if row is not None and row[0] is not None else 0

    duration_ms = _now_ms() - started
    successes = int(counters["successes"])
    summary = SqliteWriterPressureSummary(
        db_path=db_path,
        worker_count=max(1, int(worker_count)),
        writes_per_worker=max(1, int(writes_per_worker)),
        tx_hold_ms=max(0, int(tx_hold_ms)),
        attempts=int(counters["attempts"]),
        successes=successes,
        operational_errors=int(counters["operational_errors"]),
        other_errors=int(counters["other_errors"]),
        maintenance_ticks=int(counters["maintenance_ticks"]),
        final_counter=final_counter,
        duration_ms=duration_ms,
        ok=(
            final_counter == successes
            and int(counters["operational_errors"]) == 0
            and int(counters["other_errors"]) == 0
        ),
    )
    if base_dir_obj is not None:
        base_dir_obj.cleanup()
    return summary


def run_mempool_spam_stress(
    *,
    work_dir: str | None = None,
    chain_id: str = "mempool-spam",
    worker_count: int = 4,
    txs_per_worker: int = 30,
    duplicate_every: int = 7,
    block_batch_size: int = 25,
    tx_index_path: str | None = None,
) -> MempoolSpamSummary:
    base_dir_obj = None
    if work_dir:
        base_dir = Path(work_dir).resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
    else:
        base_dir_obj = tempfile.TemporaryDirectory(prefix="weall-mempool-spam-")
        base_dir = Path(base_dir_obj.name)
    tx_index = str(tx_index_path or _default_tx_index_path())
    db_path = str(base_dir / "mempool_spam.sqlite")
    ex = WeAllExecutor(
        db_path=db_path, node_id="spam-node", chain_id=chain_id, tx_index_path=tx_index
    )

    results_lock = threading.Lock()
    seen_tx_ids: set[str] = set()
    counters: MutableMapping[str, int] = {
        "attempts": 0,
        "accepted": 0,
        "duplicate_accepts": 0,
        "rejected": 0,
    }

    def _submit_one(env: Json) -> None:
        nonlocal seen_tx_ids
        with results_lock:
            counters["attempts"] += 1
        res = ex.submit_tx(env)
        if bool(res.get("ok")):
            tx_id = str(res.get("tx_id") or env.get("tx_id") or "")
            with results_lock:
                counters["accepted"] += 1
                if tx_id in seen_tx_ids:
                    counters["duplicate_accepts"] += 1
                elif tx_id:
                    seen_tx_ids.add(tx_id)
        else:
            with results_lock:
                counters["rejected"] += 1

    def _worker(worker_idx: int) -> None:
        for nonce in range(1, max(1, int(txs_per_worker)) + 1):
            signer = f"@spam{worker_idx:02d}_{nonce:04d}"
            env: Json = {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": signer,
                "nonce": 1,
                "payload": {"pubkey": f"k:{signer}"},
            }
            _submit_one(dict(env))
            dup_every = max(0, int(duplicate_every))
            if dup_every > 0 and nonce % dup_every == 0:
                _submit_one(dict(env))

    started = _now_ms()
    with ThreadPoolExecutor(max_workers=max(1, int(worker_count))) as pool:
        futures = [pool.submit(_worker, idx) for idx in range(max(1, int(worker_count)))]
        for fut in futures:
            fut.result()

    blocks_produced = 0
    guard_rounds = max(8, (max(1, int(worker_count)) * max(1, int(txs_per_worker))))
    while ex._mempool.size() > 0 and blocks_produced < guard_rounds:
        meta = ex.produce_block(max_txs=max(1, int(block_batch_size)))
        if not bool(getattr(meta, "ok", False)):
            raise RuntimeError(
                f"mempool spam block production failed: {getattr(meta, 'error', '')}"
            )
        if int(getattr(meta, "height", 0) or 0) > 0:
            blocks_produced += 1

    final_mempool_size = ex._mempool.size()
    with ex._db.connection() as con:
        row = con.execute(
            "SELECT COUNT(1) AS n FROM tx_index WHERE tx_type='ACCOUNT_REGISTER' AND tx_id LIKE 'tx:%';"
        ).fetchone()
        committed_tx_count = int(row["n"]) if row is not None else 0

    unique_tx_ids = len(seen_tx_ids)
    duration_ms = _now_ms() - started
    summary = MempoolSpamSummary(
        db_path=db_path,
        chain_id=chain_id,
        worker_count=max(1, int(worker_count)),
        txs_per_worker=max(1, int(txs_per_worker)),
        duplicate_every=max(0, int(duplicate_every)),
        attempts=int(counters["attempts"]),
        accepted=int(counters["accepted"]),
        unique_tx_ids=unique_tx_ids,
        duplicate_accepts=int(counters["duplicate_accepts"]),
        rejected=int(counters["rejected"]),
        blocks_produced=blocks_produced,
        committed_tx_count=committed_tx_count,
        final_mempool_size=final_mempool_size,
        final_height=int(ex.state.get("height") or 0),
        duration_ms=duration_ms,
        ok=(final_mempool_size == 0 and committed_tx_count == unique_tx_ids),
    )
    if base_dir_obj is not None:
        base_dir_obj.cleanup()
    return summary


@dataclass(frozen=True)
class HeavySoakSummary:
    bft: Json
    sqlite_writer_pressure: Json
    mempool_spam: Json
    ok: bool

    def to_json(self) -> Json:
        return asdict(self)


def run_priority1_heavy_soak(
    *,
    work_dir: str | None = None,
    chain_id_prefix: str = "priority1-heavy",
    tx_index_path: str | None = None,
) -> HeavySoakSummary:
    base_dir_obj = None
    if work_dir:
        base_dir = Path(work_dir).resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
    else:
        base_dir_obj = tempfile.TemporaryDirectory(prefix="weall-priority1-heavy-")
        base_dir = Path(base_dir_obj.name)
    tx_index = str(tx_index_path or _default_tx_index_path())
    bft = run_bft_fault_injection_soak(
        work_dir=str(base_dir / "bft"),
        rounds=15,
        validator_count=4,
        partition_rounds=(3, 4),
        stall_target="v4",
        stall_rounds=(6, 7, 8),
        delay_child_first_every=3,
        restart_target="v4",
        restart_every=4,
        epoch_bump_rounds=(9, 12),
        stale_qc_replay_target="v2",
        chain_id=f"{chain_id_prefix}-bft",
        tx_index_path=tx_index,
    )
    writer = run_sqlite_writer_pressure_soak(
        work_dir=str(base_dir / "sqlite"),
        worker_count=4,
        writes_per_worker=20,
        tx_hold_ms=2,
        checkpoint_interval_ms=10,
    )
    mempool = run_mempool_spam_stress(
        work_dir=str(base_dir / "mempool"),
        chain_id=f"{chain_id_prefix}-mempool",
        worker_count=4,
        txs_per_worker=24,
        duplicate_every=6,
        block_batch_size=20,
        tx_index_path=tx_index,
    )
    summary = HeavySoakSummary(
        bft=bft.to_json(),
        sqlite_writer_pressure=writer.to_json(),
        mempool_spam=mempool.to_json(),
        ok=bool(bft.converged and writer.ok and mempool.ok),
    )
    if base_dir_obj is not None:
        base_dir_obj.cleanup()
    return summary


def _sqlite_pressure_worker_process(
    db_path: str, writes_per_process: int, tx_hold_ms: int, queue: Any
) -> None:
    db = SqliteDB(path=db_path)
    attempts = 0
    successes = 0
    operational_errors = 0
    other_errors = 0
    for _ in range(max(1, int(writes_per_process))):
        attempts += 1
        try:
            with db.write_tx() as con:
                row = con.execute(
                    "SELECT value FROM meta WHERE key='writer_pressure_counter' LIMIT 1;"
                ).fetchone()
                cur = int(row[0]) if row is not None and row[0] is not None else 0
                if int(tx_hold_ms) > 0:
                    time.sleep(int(tx_hold_ms) / 1000.0)
                con.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('writer_pressure_counter', ?);",
                    (str(cur + 1),),
                )
            successes += 1
        except Exception as e:
            if "locked" in str(e).lower():
                operational_errors += 1
            else:
                other_errors += 1
    queue.put(
        {
            "attempts": attempts,
            "successes": successes,
            "operational_errors": operational_errors,
            "other_errors": other_errors,
        }
    )


def run_sqlite_writer_pressure_cross_process_soak(
    *,
    work_dir: str | None = None,
    process_count: int = 3,
    writes_per_process: int = 12,
    tx_hold_ms: int = 2,
) -> CrossProcessSqlitePressureSummary:
    base_dir_obj = None
    if work_dir:
        base_dir = Path(work_dir).resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
    else:
        base_dir_obj = tempfile.TemporaryDirectory(prefix="weall-sqlite-pressure-proc-")
        base_dir = Path(base_dir_obj.name)
    db_path = str(base_dir / "writer_pressure_cross_process.sqlite")
    db = SqliteDB(path=db_path)
    db.init_schema()
    with db.write_tx() as con:
        con.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('writer_pressure_counter', '0');"
        )

    started = _now_ms()
    ctx = mp.get_context("spawn")
    queue = ctx.Queue()
    procs = []
    for _ in range(max(1, int(process_count))):
        proc = ctx.Process(
            target=_sqlite_pressure_worker_process,
            args=(db_path, max(1, int(writes_per_process)), max(0, int(tx_hold_ms)), queue),
        )
        proc.start()
        procs.append(proc)

    totals = {"attempts": 0, "successes": 0, "operational_errors": 0, "other_errors": 0}
    for _ in procs:
        payload = queue.get()
        for k in totals:
            totals[k] += int(payload.get(k) or 0)
    for proc in procs:
        proc.join(timeout=30.0)
        if proc.exitcode not in {0, None}:
            totals["other_errors"] += 1

    with db.connection() as con:
        row = con.execute(
            "SELECT value FROM meta WHERE key='writer_pressure_counter' LIMIT 1;"
        ).fetchone()
        final_counter = int(row[0]) if row is not None and row[0] is not None else 0

    duration_ms = _now_ms() - started
    summary = CrossProcessSqlitePressureSummary(
        db_path=db_path,
        process_count=max(1, int(process_count)),
        writes_per_process=max(1, int(writes_per_process)),
        tx_hold_ms=max(0, int(tx_hold_ms)),
        attempts=int(totals["attempts"]),
        successes=int(totals["successes"]),
        operational_errors=int(totals["operational_errors"]),
        other_errors=int(totals["other_errors"]),
        final_counter=final_counter,
        duration_ms=duration_ms,
        ok=(
            final_counter == int(totals["successes"])
            and int(totals["operational_errors"]) == 0
            and int(totals["other_errors"]) == 0
        ),
    )
    if base_dir_obj is not None:
        base_dir_obj.cleanup()
    return summary


def run_timeout_epoch_storm_soak(
    *,
    work_dir: str | None = None,
    chain_id: str = "timeout-epoch-storm",
    validator_count: int = 4,
    starting_epoch: int = 3,
    restart_after_view: int = 1,
    tx_index_path: str | None = None,
) -> TimeoutEpochStormSummary:
    base_dir_obj = None
    if work_dir:
        base_dir = Path(work_dir).resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
    else:
        base_dir_obj = tempfile.TemporaryDirectory(prefix="weall-timeout-epoch-storm-")
        base_dir = Path(base_dir_obj.name)
    tx_index = str(tx_index_path or _default_tx_index_path())
    validators = [f"v{i}" for i in range(1, max(4, int(validator_count)) + 1)]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    def _signed_timeout(
        *, signer: str, view: int, high_qc_id: str, validator_epoch: int, validator_set_hash: str
    ) -> Json:
        msg = canonical_timeout_message(
            chain_id=chain_id,
            view=int(view),
            high_qc_id=str(high_qc_id),
            signer=str(signer),
            validator_epoch=int(validator_epoch),
            validator_set_hash=str(validator_set_hash),
        )
        return {
            "t": "TIMEOUT",
            "chain_id": str(chain_id),
            "view": int(view),
            "high_qc_id": str(high_qc_id),
            "signer": str(signer),
            "pubkey": str(vpub[signer]),
            "sig": sign_ed25519(message=msg, privkey=str(vpriv[signer]), encoding="hex"),
            "validator_epoch": int(validator_epoch),
            "validator_set_hash": str(validator_set_hash),
        }

    db_path = str(base_dir / "timeout_epoch_storm.sqlite")
    ex = WeAllExecutor(db_path=db_path, node_id="@v4", chain_id=chain_id, tx_index_path=tx_index)
    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=int(starting_epoch))
    current_epoch = int(starting_epoch)
    set_hash = ex._current_validator_set_hash()
    threshold_signers = list(validators)[:3]
    duplicate_timeouts = 0
    stale_timeout_rejections = 0
    epoch_replay_attempts = 0
    epoch_replay_rejections = 0
    restarts = 0

    for view in range(0, 3):
        for signer in threshold_signers:
            accepted = ex.bft_handle_timeout(
                _signed_timeout(
                    signer=signer,
                    view=view,
                    high_qc_id="genesis" if view == 0 else f"qc-{view}",
                    validator_epoch=current_epoch,
                    validator_set_hash=set_hash,
                )
            )
            if signer == threshold_signers[0]:
                dup = ex.bft_handle_timeout(
                    _signed_timeout(
                        signer=signer,
                        view=view,
                        high_qc_id="genesis" if view == 0 else f"qc-{view}",
                        validator_epoch=current_epoch,
                        validator_set_hash=set_hash,
                    )
                )
                duplicate_timeouts += 1
                if dup is not None:
                    raise RuntimeError("duplicate timeout unexpectedly accepted")
            if view > 0:
                stale = ex.bft_handle_timeout(
                    _signed_timeout(
                        signer=signer,
                        view=view - 1,
                        high_qc_id=f"qc-{max(0, view - 1)}",
                        validator_epoch=current_epoch,
                        validator_set_hash=set_hash,
                    )
                )
                if stale is None:
                    stale_timeout_rejections += 1
            if accepted is not None and not isinstance(accepted, (int, dict)):
                raise RuntimeError("unexpected timeout acceptance payload")

        if int(ex.bft_current_view()) != view + 1:
            raise RuntimeError("timeout storm failed to advance view")

        if view == int(restart_after_view):
            if hasattr(ex, "mark_clean_shutdown"):
                ex.mark_clean_shutdown()
            ex = WeAllExecutor(
                db_path=db_path, node_id="@v4", chain_id=chain_id, tx_index_path=tx_index
            )
            _seed_validator_set(ex, validators=validators, pub=vpub, epoch=current_epoch)
            restarts += 1
            if int(ex.bft_current_view()) != view + 1:
                raise RuntimeError("restart lost timeout-driven view advancement")

        if view == 1:
            old_epoch = current_epoch
            old_set_hash = set_hash
            current_epoch += 1
            _advance_validator_epoch(
                {"v4": ex}, validators=validators, pub=vpub, new_epoch=current_epoch
            )
            set_hash = ex._current_validator_set_hash()
            epoch_replay_attempts += 1
            replay = ex.bft_handle_timeout(
                _signed_timeout(
                    signer="v1",
                    view=view + 1,
                    high_qc_id=f"qc-{view + 1}",
                    validator_epoch=old_epoch,
                    validator_set_hash=old_set_hash,
                )
            )
            if replay is None:
                epoch_replay_rejections += 1

    tc = ex._bft.best_timeout_certificate()
    highest_tc_view = int(tc.view) if tc is not None else -1
    final_view = int(ex.bft_current_view())
    summary = TimeoutEpochStormSummary(
        chain_id=str(chain_id),
        validator_ids=list(validators),
        duplicate_timeouts=duplicate_timeouts,
        stale_timeout_rejections=stale_timeout_rejections,
        epoch_replay_attempts=epoch_replay_attempts,
        epoch_replay_rejections=epoch_replay_rejections,
        restarts=restarts,
        final_view=final_view,
        highest_tc_view=highest_tc_view,
        ok=(
            final_view >= 3
            and highest_tc_view >= 2
            and stale_timeout_rejections >= len(threshold_signers) * 2
            and epoch_replay_rejections == epoch_replay_attempts
        ),
    )
    if base_dir_obj is not None:
        base_dir_obj.cleanup()
    return summary


def run_priority2_adversarial_soak(
    *,
    work_dir: str | None = None,
    chain_id_prefix: str = "priority2-adversarial",
    tx_index_path: str | None = None,
) -> Priority2SoakSummary:
    base_dir_obj = None
    if work_dir:
        base_dir = Path(work_dir).resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
    else:
        base_dir_obj = tempfile.TemporaryDirectory(prefix="weall-priority2-adversarial-")
        base_dir = Path(base_dir_obj.name)
    tx_index = str(tx_index_path or _default_tx_index_path())
    bft = run_bft_fault_injection_soak(
        work_dir=str(base_dir / "bft"),
        rounds=18,
        validator_count=4,
        partition_rounds=(4, 5, 6),
        stall_target="v4",
        stall_rounds=(7, 8, 9),
        delay_child_first_every=2,
        restart_target="v4",
        restart_every=3,
        epoch_bump_rounds=(10, 14),
        stale_qc_replay_target="v2",
        clock_skew_target="v4",
        clock_skew_rounds=(8, 15),
        chain_id=f"{chain_id_prefix}-bft",
        tx_index_path=tx_index,
    )
    matrix = run_consensus_resilience_matrix(
        work_dir=str(base_dir / "consensus-resilience-matrix"),
        chain_id_prefix=f"{chain_id_prefix}-matrix",
        tx_index_path=tx_index,
    )
    writer = run_sqlite_writer_pressure_soak(
        work_dir=str(base_dir / "sqlite-threaded"),
        worker_count=5,
        writes_per_worker=24,
        tx_hold_ms=3,
        checkpoint_interval_ms=8,
    )
    writer_proc = run_sqlite_writer_pressure_cross_process_soak(
        work_dir=str(base_dir / "sqlite-process"),
        process_count=3,
        writes_per_process=14,
        tx_hold_ms=3,
    )
    timeout_epoch = run_timeout_epoch_storm_soak(
        work_dir=str(base_dir / "timeout-epoch"),
        chain_id=f"{chain_id_prefix}-timeout",
        validator_count=4,
        starting_epoch=3,
        restart_after_view=1,
        tx_index_path=tx_index,
    )
    mempool = run_mempool_spam_stress(
        work_dir=str(base_dir / "mempool"),
        chain_id=f"{chain_id_prefix}-mempool",
        worker_count=5,
        txs_per_worker=24,
        duplicate_every=5,
        block_batch_size=18,
        tx_index_path=tx_index,
    )
    summary = Priority2SoakSummary(
        bft=bft.to_json(),
        consensus_resilience_matrix=matrix.to_json(),
        sqlite_writer_pressure=writer.to_json(),
        sqlite_writer_pressure_cross_process=writer_proc.to_json(),
        timeout_epoch_storm=timeout_epoch.to_json(),
        mempool_spam=mempool.to_json(),
        ok=bool(
            bft.converged
            and matrix.ok
            and writer.ok
            and writer_proc.ok
            and timeout_epoch.ok
            and mempool.ok
        ),
    )
    if base_dir_obj is not None:
        base_dir_obj.cleanup()
    return summary


@dataclass(frozen=True)
class ConsensusResilienceMatrixSummary:
    scenarios: dict[str, Json]
    ok: bool

    def to_json(self) -> Json:
        return asdict(self)


def _seed_validator_set_full(
    ex: WeAllExecutor, *, validators: Sequence[str], pub: Mapping[str, str], epoch: int = 1
) -> None:
    st = ex.read_state()
    st.setdefault("roles", {})
    st["roles"].setdefault("validators", {})
    st["roles"]["validators"]["active_set"] = list(validators)
    st.setdefault("validators", {})
    st["validators"].setdefault("registry", {})
    st.setdefault("consensus", {})
    st["consensus"].setdefault("validators", {})
    st["consensus"]["validators"].setdefault("registry", {})
    st["consensus"].setdefault("epochs", {})
    st["consensus"]["epochs"]["current"] = int(epoch)
    st["consensus"].setdefault("validator_set", {})
    st["consensus"]["validator_set"]["active_set"] = list(validators)
    st["consensus"]["validator_set"]["epoch"] = int(epoch)
    for v in validators:
        st["consensus"]["validators"]["registry"].setdefault(v, {})
        st["consensus"]["validators"]["registry"][v]["pubkey"] = str(pub[v])
        st["validators"]["registry"].setdefault(v, {})
        st["validators"]["registry"][v]["pubkey"] = str(pub[v])
    ex.state = st
    ex._ledger_store.write(ex.state)
    st = ex.read_state()
    st["consensus"]["validator_set"]["set_hash"] = ex._current_validator_set_hash()
    ex.state = st
    ex._ledger_store.write(ex.state)


def run_consensus_resilience_matrix(
    *,
    work_dir: str | None = None,
    chain_id_prefix: str = "consensus-resilience",
    tx_index_path: str | None = None,
) -> ConsensusResilienceMatrixSummary:
    base_dir_obj = None
    if work_dir:
        base_dir = Path(work_dir).resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
    else:
        base_dir_obj = tempfile.TemporaryDirectory(prefix="weall-consensus-resilience-")
        base_dir = Path(base_dir_obj.name)
    tx_index = str(tx_index_path or _default_tx_index_path())

    scenarios: dict[str, Json] = {}

    validators = ["v1", "v2", "v3", "v4"]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    def _validator_env(node_id: str) -> _EnvPatch:
        return _EnvPatch(
            {
                "WEALL_MODE": "prod",
                "WEALL_BFT_ENABLED": "1",
                "WEALL_VALIDATOR_ACCOUNT": str(node_id),
                "WEALL_NODE_PUBKEY": str(vpub[node_id]),
                "WEALL_NODE_PRIVKEY": str(vpriv[node_id]),
                "WEALL_AUTOVOTE": "1",
            }
        )

    def _mk_executor(db_path: Path, node_id: str, chain_id: str) -> WeAllExecutor:
        with _validator_env(node_id):
            ex = WeAllExecutor(
                db_path=str(db_path), node_id=node_id, chain_id=chain_id, tx_index_path=tx_index
            )
        _seed_validator_set_full(ex, validators=validators, pub=vpub, epoch=7)
        ex.bft_set_view(1)
        return ex

    # Scenario 1: locally persisted proposal/vote state survives restart and can be replayed.
    replay_chain_id = f"{chain_id_prefix}-proposal-replay"
    replay_dir = base_dir / "proposal_replay_after_restart"
    replay_dir.mkdir(parents=True, exist_ok=True)
    replay_validator = "v2"
    with _EnvPatch(
        {
            "WEALL_MODE": "testnet",
            "WEALL_BFT_ENABLED": "1",
            "WEALL_SIGVERIFY": "0",
            "WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "1",
            "WEALL_AUTOVOTE": "1",
            "WEALL_VALIDATOR_ACCOUNT": replay_validator,
            "WEALL_NODE_PUBKEY": str(vpub[replay_validator]),
            "WEALL_NODE_PRIVKEY": str(vpriv[replay_validator]),
        }
    ):
        replay_ex = WeAllExecutor(
            db_path=str(replay_dir / f"{replay_validator}.db"),
            node_id=replay_validator,
            chain_id=replay_chain_id,
            tx_index_path=tx_index,
        )
        _seed_validator_set_full(replay_ex, validators=validators, pub=vpub, epoch=7)
        replay_ex.bft_set_view(1)
        replay_proposal = replay_ex.bft_leader_propose(max_txs=0)
        if not isinstance(replay_proposal, dict):
            raise RuntimeError("proposal replay scenario failed to produce proposal")
        first_vote = replay_ex.bft_on_proposal(dict(replay_proposal))
        if not isinstance(first_vote, dict):
            raise RuntimeError("proposal replay scenario failed to produce initial vote")
        if hasattr(replay_ex, "mark_clean_shutdown"):
            replay_ex.mark_clean_shutdown()
        replay_ex2 = WeAllExecutor(
            db_path=str(replay_dir / f"{replay_validator}.db"),
            node_id=replay_validator,
            chain_id=replay_chain_id,
            tx_index_path=tx_index,
        )
        _seed_validator_set_full(replay_ex2, validators=validators, pub=vpub, epoch=7)
        replayed_vote = replay_ex2.bft_on_proposal(dict(replay_proposal))
    scenarios["proposal_replay_after_restart"] = {
        "ok": isinstance(replayed_vote, dict),
        "restart_events": 1,
        "initial_vote": isinstance(first_vote, dict),
        "replayed_vote": isinstance(replayed_vote, dict),
        "last_voted_view": int((replay_ex2.state.get("bft") or {}).get("last_voted_view") or 0),
        "last_voted_block_id": str(
            (replay_ex2.state.get("bft") or {}).get("last_voted_block_id") or ""
        ),
    }

    # Scenario 2: forged non-leader conflicting proposal is rejected while canonical leader proposal is accepted.
    conflict_chain_id = f"{chain_id_prefix}-conflict-reject"
    conflict_dir = base_dir / "conflicting_nonleader_proposal_rejected"
    conflict_dir.mkdir(parents=True, exist_ok=True)
    canonical_leader = str(leader_for_view(validators, 1))
    follower_id = "v3" if canonical_leader != "v3" else "v4"
    leader = WeAllExecutor(
        db_path=str(conflict_dir / f"{canonical_leader}.db"),
        node_id=canonical_leader,
        chain_id=conflict_chain_id,
        tx_index_path=tx_index,
    )
    follower = WeAllExecutor(
        db_path=str(conflict_dir / f"{follower_id}.db"),
        node_id=follower_id,
        chain_id=conflict_chain_id,
        tx_index_path=tx_index,
    )
    _seed_validator_set_full(leader, validators=validators, pub=vpub, epoch=7)
    _seed_validator_set_full(follower, validators=validators, pub=vpub, epoch=7)
    leader.bft_set_view(1)
    follower._validate_remote_proposal_for_vote = lambda block: False
    with _EnvPatch(
        {
            "WEALL_SIGVERIFY": "1",
            "WEALL_VALIDATOR_ACCOUNT": canonical_leader,
            "WEALL_NODE_PUBKEY": str(vpub[canonical_leader]),
            "WEALL_NODE_PRIVKEY": str(vpriv[canonical_leader]),
        }
    ):
        valid_proposal = leader.bft_leader_propose(max_txs=0)
    if not isinstance(valid_proposal, dict):
        raise RuntimeError("conflict scenario failed to produce canonical leader proposal")
    accepted_vote = follower.bft_on_proposal(dict(valid_proposal))
    accepted_diag = follower.bft_diagnostics()
    forged = dict(valid_proposal)
    forged["proposer"] = "v2"
    forged["proposer_pubkey"] = str(vpub["v2"])
    forged["proposer_sig"] = sign_ed25519(
        message=canonical_proposal_message(
            chain_id=str(forged.get("chain_id") or conflict_chain_id),
            view=int(forged.get("view") or 0),
            block_id=str(forged.get("block_id") or ""),
            block_hash=str(forged.get("block_hash") or ""),
            parent_id=str(forged.get("prev_block_id") or ""),
            proposer="v2",
            validator_epoch=int(forged.get("validator_epoch") or 0),
            validator_set_hash=str(forged.get("validator_set_hash") or ""),
            justify_qc_id=str(
                (
                    (forged.get("justify_qc") or {})
                    if isinstance(forged.get("justify_qc"), dict)
                    else {}
                ).get("block_id")
                or ""
            ),
        ),
        privkey=str(vpriv["v2"]),
        encoding="hex",
    )
    before = follower.bft_diagnostics()
    rejected_vote = follower.bft_on_proposal(dict(forged))
    after = follower.bft_diagnostics()
    valid_promoted = int(accepted_diag.get("pending_remote_blocks_count") or 0) >= 1
    scenarios["conflicting_nonleader_proposal_rejected"] = {
        "ok": bool(valid_promoted and rejected_vote is None),
        "accepted_vote": isinstance(accepted_vote, dict),
        "valid_promoted": bool(valid_promoted),
        "forged_rejected": rejected_vote is None,
        "pending_remote_blocks_count": int(after.get("pending_remote_blocks_count") or 0),
        "pending_candidates_count": int(after.get("pending_candidates_count") or 0),
        "rejection_count_delta": int(after.get("recent_rejection_summary", {}).get("count") or 0)
        - int(before.get("recent_rejection_summary", {}).get("count") or 0),
    }

    # Scenario 3: a delayed QC that arrives only after the view has turned over still
    # unlocks the next canonical leader proposal and clears missing-QC quarantine.
    turnover_chain_id = f"{chain_id_prefix}-delayed-qc-turnover"
    turnover_dir = base_dir / "delayed_qc_after_leader_turnover"
    turnover_dir.mkdir(parents=True, exist_ok=True)
    leader_view_1 = str(leader_for_view(validators, 1))
    leader_view_2 = str(leader_for_view(validators, 2))
    target_follower = "v4" if "v4" not in {leader_view_1, leader_view_2} else "v3"

    def _turnover_env(node_id: str) -> _EnvPatch:
        return _EnvPatch(
            {
                "WEALL_MODE": "testnet",
                "WEALL_BFT_ENABLED": "1",
                "WEALL_SIGVERIFY": "0",
                "WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "1",
                "WEALL_AUTOVOTE": "1",
                "WEALL_VALIDATOR_ACCOUNT": str(node_id),
                "WEALL_NODE_PUBKEY": str(vpub[node_id]),
                "WEALL_NODE_PRIVKEY": str(vpriv[node_id]),
            }
        )

    def _mk_turnover_executor(db_path: Path, node_id: str) -> WeAllExecutor:
        with _turnover_env(node_id):
            ex = WeAllExecutor(
                db_path=str(db_path),
                node_id=node_id,
                chain_id=turnover_chain_id,
                tx_index_path=tx_index,
            )
        _seed_validator_set_full(ex, validators=validators, pub=vpub, epoch=7)
        ex.bft_set_view(1)
        return ex

    leader1 = _mk_turnover_executor(turnover_dir / f"{leader_view_1}.db", leader_view_1)
    leader2 = _mk_turnover_executor(turnover_dir / f"{leader_view_2}.db", leader_view_2)
    follower = _mk_turnover_executor(turnover_dir / f"{target_follower}.db", target_follower)
    with _turnover_env(leader_view_1):
        proposal_v1 = leader1.bft_leader_propose(max_txs=0)
    if not isinstance(proposal_v1, dict):
        raise RuntimeError("delayed-qc turnover scenario failed to produce first leader proposal")
    with _turnover_env(target_follower):
        first_vote = follower.bft_on_proposal(dict(proposal_v1))
    parent_id_v1 = str(proposal_v1.get("prev_block_id") or follower.state.get("tip") or "")
    qc_view_1 = _make_qc(
        chain_id=turnover_chain_id,
        validators=validators,
        vpub=vpub,
        vpriv=vpriv,
        block_id=str(proposal_v1.get("block_id") or ""),
        block_hash=str(proposal_v1.get("block_hash") or ""),
        parent_id=parent_id_v1,
        view=1,
        validator_epoch=7,
        validator_set_hash=str(leader1._current_validator_set_hash() or ""),
    )
    with _turnover_env(target_follower):
        follower.bft_set_view(2)
        before_qc_diag = follower.bft_diagnostics()
        follower.bft_on_qc(dict(qc_view_1))
        after_qc_diag = follower.bft_diagnostics()
    with _turnover_env(leader_view_2):
        leader2.bft_on_proposal(dict(proposal_v1))
        leader2.bft_on_qc(dict(qc_view_1))
        proposal_v2 = leader2.bft_leader_propose(max_txs=0)
    if not isinstance(proposal_v2, dict):
        raise RuntimeError("delayed-qc turnover scenario failed to produce second leader proposal")
    with _turnover_env(target_follower):
        second_vote = follower.bft_on_proposal(dict(proposal_v2))
        after_turnover_diag = follower.bft_diagnostics()
    scenarios["delayed_qc_after_leader_turnover"] = {
        "ok": bool(
            isinstance(first_vote, dict)
            and follower.bft_verify_qc_json(qc_view_1) is not None
            and isinstance(second_vote, dict)
        ),
        "initial_vote": isinstance(first_vote, dict),
        "delayed_qc_applied": str(after_qc_diag.get("high_qc_id") or "")
        == str(qc_view_1.get("block_id") or ""),
        "view_after_turnover": int(after_turnover_diag.get("view") or 0),
        "high_qc_block_id": str(after_turnover_diag.get("high_qc_id") or ""),
        "second_leader_vote": isinstance(second_vote, dict),
        "pending_missing_qc_before": int(before_qc_diag.get("pending_missing_qcs_count") or 0),
        "pending_missing_qc_after": int(after_turnover_diag.get("pending_missing_qcs_count") or 0),
        "pending_remote_blocks_after": int(
            after_turnover_diag.get("pending_remote_blocks_count") or 0
        ),
    }

    # Scenario 4: delayed child-first + partition heal + restart under load still converges.
    convergence = run_bft_fault_injection_soak(
        work_dir=str(base_dir / "partition_heal_restart_under_load"),
        rounds=14,
        validator_count=4,
        partition_rounds=(3, 4),
        stall_target="v4",
        stall_rounds=(6, 7, 8),
        delay_child_first_every=3,
        restart_target="v4",
        restart_every=4,
        epoch_bump_rounds=(9,),
        stale_qc_replay_target="v2",
        chain_id=f"{chain_id_prefix}-partition-heal",
        tx_index_path=tx_index,
    )
    scenarios["partition_heal_restart_under_load"] = convergence.to_json()
    scenarios["partition_heal_restart_under_load"]["ok"] = bool(convergence.converged)

    # Scenario 5: a validator that repeatedly misses canonical proposals/QCs across
    # multiple leader turnovers and validator-epoch boundaries must still rejoin to
    # the canonical tip after restart without accepting stale cross-epoch certificates.
    epoch_boundary = run_bft_fault_injection_soak(
        work_dir=str(base_dir / "epoch_boundary_rejoin_turnover_cycles"),
        rounds=20,
        validator_count=4,
        partition_target="v4",
        partition_rounds=(4, 5, 10, 11),
        stall_target="v4",
        stall_rounds=(6, 12),
        delay_target="v3",
        delay_child_first_every=3,
        restart_target="v4",
        restart_every=2,
        epoch_bump_rounds=(8, 14, 18),
        stale_qc_replay_target="v2",
        chain_id=f"{chain_id_prefix}-epoch-boundary-rejoin",
        tx_index_path=tx_index,
    )
    epoch_boundary_payload = epoch_boundary.to_json()
    epoch_boundary_payload["ok"] = bool(
        epoch_boundary.converged
        and int(epoch_boundary.restart_events) >= 10
        and int(epoch_boundary.epoch_bump_events) == 3
        and int(epoch_boundary.stale_qc_replay_rejections)
        == int(epoch_boundary.stale_qc_replay_attempts)
        and int(epoch_boundary.healed_partition_events) >= 6
        and int(epoch_boundary.rejoin_catchup_events) >= 2
    )
    scenarios["epoch_boundary_rejoin_turnover_cycles"] = epoch_boundary_payload

    summary = ConsensusResilienceMatrixSummary(
        scenarios=scenarios,
        ok=all(bool(payload.get("ok", False)) for payload in scenarios.values()),
    )
    if base_dir_obj is not None:
        base_dir_obj.cleanup()
    return summary


__all__ = [
    "FaultInjectionSummary",
    "CrossProcessSqlitePressureSummary",
    "TimeoutEpochStormSummary",
    "Priority2SoakSummary",
    "SqliteWriterPressureSummary",
    "MempoolSpamSummary",
    "HeavySoakSummary",
    "ConsensusResilienceMatrixSummary",
    "run_bft_fault_injection_soak",
    "run_sqlite_writer_pressure_soak",
    "run_sqlite_writer_pressure_cross_process_soak",
    "run_mempool_spam_stress",
    "run_timeout_epoch_storm_soak",
    "run_priority1_heavy_soak",
    "run_priority2_adversarial_soak",
    "run_consensus_resilience_matrix",
]
