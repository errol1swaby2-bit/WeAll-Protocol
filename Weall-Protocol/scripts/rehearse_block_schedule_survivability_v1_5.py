#!/usr/bin/env python3
from __future__ import annotations

"""Measure WeAll block-schedule survivability on real runtime paths.

This harness intentionally exercises ``WeAllExecutor.submit_tx`` -> persistent
mempool -> ``build_block_candidate`` -> ``commit_block_candidate`` -> follower
``apply_block``.  It does not change consensus semantics and it does not make
helper execution authoritative.  Helper timings are reported when the runtime
fast path is enabled; otherwise they are reported as zero/unmeasured.
"""

import argparse
import copy
import json
import os
import statistics
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

Json = dict[str, Any]

DEFAULT_TARGET_BLOCK_MS = 20_000
PROFILE_DEFAULTS: dict[str, dict[str, int]] = {
    "light": {"users": 10, "blocks": 4, "max_txs_per_block": 40, "txs_per_block_feed": 55},
    "active": {"users": 75, "blocks": 6, "max_txs_per_block": 160, "txs_per_block_feed": 220},
    "adversarial": {"users": 50, "blocks": 5, "max_txs_per_block": 120, "txs_per_block_feed": 180},
    "network": {"users": 25, "blocks": 5, "max_txs_per_block": 80, "txs_per_block_feed": 110},
}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _ms(ns: int) -> float:
    return round(float(ns) / 1_000_000.0, 3)


class PhaseProbe:
    def __init__(self) -> None:
        self.values: dict[str, int] = {}

    def add(self, key: str, ns: int) -> None:
        self.values[key] = int(self.values.get(key, 0)) + int(ns)

    @contextmanager
    def timed(self, key: str):
        start = time.perf_counter_ns()
        try:
            yield
        finally:
            self.add(key, time.perf_counter_ns() - start)

    def ms(self, key: str) -> float:
        return _ms(int(self.values.get(key, 0)))

    def reset(self) -> None:
        self.values.clear()


@contextmanager
def _patched_block_builder_timing(executor: Any, probe: PhaseProbe):
    """Patch dependency-injection seams to time the exact leader code path.

    The runtime already routes extracted block-builder dependencies through
    ``RuntimeContext.from_executor``.  This context manager wraps those callables
    for measurement only and restores them immediately after one block attempt.
    """

    import weall.runtime.block_builder as block_builder
    import weall.runtime.runtime_context as runtime_context

    old_compute_state_root = block_builder.compute_state_root
    old_admit_block_txs = block_builder.admit_block_txs
    old_runtime_context_from_executor = block_builder.RuntimeContext.from_executor
    old_helper_meta = getattr(executor, "_build_helper_execution_metadata", None)

    def timed_compute_state_root(*args: Any, **kwargs: Any) -> Any:
        with probe.timed("state_root_time_ns"):
            return old_compute_state_root(*args, **kwargs)

    def timed_admit_block_txs(*args: Any, **kwargs: Any) -> Any:
        with probe.timed("block_admission_time_ns"):
            return old_admit_block_txs(*args, **kwargs)

    def timed_from_executor(ex: Any) -> Any:
        ctx = old_runtime_context_from_executor(ex)
        old_apply = ctx.tx_execution_set.apply_tx_atomic_meta

        def timed_apply(*args: Any, **kwargs: Any) -> Any:
            with probe.timed("execution_time_ns"):
                return old_apply(*args, **kwargs)

        tx_set = replace(ctx.tx_execution_set, apply_tx_atomic_meta=timed_apply)
        return replace(ctx, tx_execution_set=tx_set)

    def timed_helper_meta(*args: Any, **kwargs: Any) -> Any:
        if old_helper_meta is None:
            return {}
        with probe.timed("helper_planning_time_ns"):
            return old_helper_meta(*args, **kwargs)

    block_builder.compute_state_root = timed_compute_state_root
    block_builder.admit_block_txs = timed_admit_block_txs
    block_builder.RuntimeContext.from_executor = staticmethod(timed_from_executor)
    # Keep runtime_context patched too for extracted callers that import it directly.
    runtime_context.RuntimeContext.from_executor = staticmethod(timed_from_executor)
    if old_helper_meta is not None:
        setattr(executor, "_build_helper_execution_metadata", timed_helper_meta)
    try:
        yield
    finally:
        block_builder.compute_state_root = old_compute_state_root
        block_builder.admit_block_txs = old_admit_block_txs
        block_builder.RuntimeContext.from_executor = old_runtime_context_from_executor
        runtime_context.RuntimeContext.from_executor = old_runtime_context_from_executor
        if old_helper_meta is not None:
            setattr(executor, "_build_helper_execution_metadata", old_helper_meta)


def _make_executor(db_path: str, *, node_id: str, chain_id: str, helper_fast_path: bool = False) -> Any:
    from weall.runtime.executor import WeAllExecutor

    os.environ.setdefault("WEALL_MODE", "dev")
    os.environ.setdefault("WEALL_UNSAFE_DEV", "1")
    os.environ.setdefault("WEALL_SQLITE_ALLOW_NON_WAL", "1")
    os.environ.setdefault("WEALL_MEMPOOL_SELECTION_POLICY", "canonical")
    os.environ.setdefault("WEALL_DISABLE_BLOCK_PRODUCER", "1")
    os.environ.setdefault("WEALL_BLOCK_INTERVAL_MS", str(DEFAULT_TARGET_BLOCK_MS))
    os.environ.setdefault("WEALL_PRODUCER_INTERVAL_MS", str(DEFAULT_TARGET_BLOCK_MS))
    if helper_fast_path:
        os.environ.setdefault("WEALL_HELPER_EXECUTION_FAST_PATH", "1")
    else:
        os.environ.setdefault("WEALL_HELPER_EXECUTION_FAST_PATH", "0")

    return WeAllExecutor(
        db_path=db_path,
        node_id=node_id,
        chain_id=chain_id,
        tx_index_path=str(REPO_ROOT / "generated" / "tx_index.json"),
    )


def _account(account_id: str, nonce: int = 1) -> Json:
    return {
        "banned": False,
        "devices": {"by_id": {}},
        "keys": {"by_id": {}},
        "locked": False,
        "nonce": int(nonce),
        "poh_tier": 2,
        "recovery": {"config": None, "proposals": {}},
        "reputation": 10,
        "reputation_milli": 10_000,
        "session_keys": {},
    }


def _seed_state(executor: Any, users: list[str]) -> Json:
    st = executor.read_state()
    st["chain_id"] = str(getattr(executor, "chain_id", "block-schedule-survivability"))
    st["height"] = int(st.get("height") or 0)
    accounts = dict(st.get("accounts") or {})
    for user in users:
        accounts[user] = _account(user, nonce=1)
    accounts.setdefault("SYSTEM", {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False})
    st["accounts"] = accounts
    content = dict(st.get("content") or {})
    content.setdefault("posts", {})["seed-post"] = {
        "id": "seed-post",
        "post_id": "seed-post",
        "author": users[0],
        "body": "seed post for load rehearsal",
        "visibility": "public",
        "deleted": False,
        "locked": False,
        "labels": [],
    }
    content.setdefault("comments", {})
    content.setdefault("media", {})
    content.setdefault("reactions", {})
    content.setdefault("flags", {})
    st["content"] = content
    st.setdefault("groups_by_id", {})["seed-group"] = {
        "group_id": "seed-group",
        "created_by": users[0],
        "charter": "Seed public group for block cadence load.",
        "meta": {"visibility": "public", "read_visibility": "public", "public_only": True},
        "members": {users[0]: {"account": users[0], "role": "creator"}},
        "permissions": {"read": "public", "post": "members", "comment": "members", "vote": "members"},
        "signers": [users[0]],
        "threshold": 1,
        "moderators": [],
        "emissaries": [],
        "public_only": True,
        "read_visibility": "public",
        "visibility": "public",
    }
    st.setdefault("proposals", {})["seed-prop"] = {
        "proposal_id": "seed-prop",
        "creator": users[0],
        "title": "Seed poll",
        "body": "Seed poll for block cadence load.",
        "stage": "poll",
        "rules": {"start_stage": "poll", "auto_progress_enabled": False},
        "actions": [],
        "poll_votes": {},
        "votes": {},
        "eligible_validator_ids": [],
        "eligible_validator_count": 0,
        "required_votes": 0,
        "electorate_source": "",
        "comments": [],
        "versions": [],
        "current_version": 1,
        "updated_at_height": int(st.get("height") or 0),
    }
    # Dispute vote validity is expensive and requires explicit juror assignment;
    # seed a standing dispute so adversarial valid load can include juror actions.
    st.setdefault("disputes_by_id", {})["seed-dispute"] = {
        "dispute_id": "seed-dispute",
        "target_type": "content",
        "target_id": "seed-post",
        "opened_by": users[0],
        "reason": "seed",
        "stage": "review",
        "resolved": False,
        "jurors": {users[1] if len(users) > 1 else users[0]: {"status": "accepted", "accepted_at_height": 0}},
        "votes": {},
        "created_at_height": 0,
        "deadline_height": 10_000_000,
    }
    roles = dict(st.get("roles") or {})
    roles.setdefault("validators", {"active_set": users[: min(4, len(users))]})
    roles.setdefault("jurors", {"active_set": users[: min(12, len(users))]})
    st["roles"] = roles
    executor._ledger_store.write_state_snapshot(st)  # type: ignore[attr-defined]
    try:
        executor.state = copy.deepcopy(st)
    except Exception:
        pass
    return st


def _clone_seed_to_follower(follower: Any, state: Json) -> None:
    follower._ledger_store.write_state_snapshot(copy.deepcopy(state))  # type: ignore[attr-defined]
    try:
        follower.state = copy.deepcopy(state)
    except Exception:
        pass


def _tx(tx_type: str, signer: str, nonce: int, payload: Json) -> Json:
    return {"tx_type": tx_type, "signer": signer, "nonce": int(nonce), "payload": payload}


def _next_nonce(next_nonces: dict[str, int], signer: str) -> int:
    nonce = int(next_nonces.get(signer, 2))
    next_nonces[signer] = nonce + 1
    return nonce


def _valid_payload_for(kind: str, signer: str, nonce: int, i: int, users: list[str], profile: str) -> Json:
    target = users[(users.index(signer) + 1) % len(users)] if signer in users and len(users) > 1 else users[0]
    if kind == "PROFILE_UPDATE":
        return {"display_name": f"User {signer} {i}", "bio": f"block cadence profile update {i}"}
    if kind == "CONTENT_POST_CREATE":
        return {"post_id": f"post:{signer}:{nonce}", "body": f"public load post {i} by {signer}", "visibility": "public", "tags": ["load", profile], "media": []}
    if kind == "CONTENT_COMMENT_CREATE":
        return {"comment_id": f"comment:{signer}:{nonce}", "post_id": "seed-post", "body": f"public load comment {i}"}
    if kind == "CONTENT_REACTION_SET":
        return {"target_id": "seed-post", "reaction": "like" if i % 2 == 0 else "support"}
    if kind == "FOLLOW_SET":
        return {"target": target, "active": True}
    if kind == "GROUP_CREATE":
        return {"group_id": f"g:{signer.strip('@').replace(':', '-')}-{nonce}", "charter": f"Public load group {i}"}
    if kind == "GROUP_MEMBERSHIP_REQUEST":
        return {"group_id": "seed-group"}
    if kind == "GOV_PROPOSAL_CREATE":
        return {"proposal_id": f"prop:{signer.strip('@')}:{nonce}", "title": f"Load proposal {i}", "body": "Measured public governance load.", "rules": {"start_stage": "poll", "auto_progress_enabled": False}, "actions": []}
    if kind == "GOV_PROPOSAL_COMMENT":
        return {"proposal_id": "seed-prop", "body": f"governance comment {i}"}
    if kind == "GOV_VOTE_CAST":
        return {"proposal_id": "seed-prop", "vote": "yes" if i % 3 else "abstain"}
    if kind == "DISPUTE_OPEN":
        return {"dispute_id": f"dispute:{signer.strip('@')}:{nonce}", "target_type": "content", "target_id": "seed-post", "reason": f"valid stress dispute {i}"}
    if kind == "CONTENT_FLAG":
        return {"flag_id": f"flag:{signer.strip('@')}:{nonce}", "target_id": "seed-post", "reason": "stress flag"}
    return {"note": f"unsupported generator kind {kind}"}


def _profile_mix(profile: str) -> list[str]:
    if profile == "light":
        return [
            "PROFILE_UPDATE",
            "CONTENT_POST_CREATE",
            "CONTENT_COMMENT_CREATE",
            "CONTENT_REACTION_SET",
            "FOLLOW_SET",
        ]
    if profile == "active":
        return [
            "CONTENT_POST_CREATE",
            "CONTENT_COMMENT_CREATE",
            "CONTENT_REACTION_SET",
            "FOLLOW_SET",
            "GROUP_CREATE",
            "GROUP_MEMBERSHIP_REQUEST",
            "GOV_PROPOSAL_CREATE",
            "GOV_PROPOSAL_COMMENT",
            "GOV_VOTE_CAST",
            "CONTENT_FLAG",
        ]
    if profile == "adversarial":
        return [
            "DISPUTE_OPEN",
            "CONTENT_FLAG",
            "GOV_PROPOSAL_CREATE",
            "GROUP_CREATE",
            "CONTENT_COMMENT_CREATE",
            "CONTENT_REACTION_SET",
            "GOV_VOTE_CAST",
            "GROUP_MEMBERSHIP_REQUEST",
        ]
    return [
        "CONTENT_POST_CREATE",
        "CONTENT_COMMENT_CREATE",
        "CONTENT_REACTION_SET",
        "GROUP_MEMBERSHIP_REQUEST",
        "GOV_VOTE_CAST",
    ]


def _submit_profile_load(executor: Any, *, profile: str, users: list[str], next_nonces: dict[str, int], count: int) -> Json:
    mix = _profile_mix(profile)
    admitted = 0
    rejected = 0
    rejected_by_code: dict[str, int] = {}
    submitted_by_type: dict[str, int] = {}
    accepted_by_type: dict[str, int] = {}
    malformed_submitted = 0
    malformed_rejected = 0
    for i in range(int(count)):
        if profile == "adversarial" and i % 17 == 0:
            malformed_submitted += 1
            bad = {"tx_type": "CONTENT_POST_CREATE", "signer": "", "nonce": -1, "payload": {"body": "bad"}}
            result = executor.submit_tx(bad, ingress="local_fixture")
            if not result.get("ok"):
                malformed_rejected += 1
                code = str(result.get("error") or result.get("reason") or "rejected")
                rejected_by_code[code] = int(rejected_by_code.get(code, 0)) + 1
            continue
        signer = users[i % len(users)]
        kind = mix[i % len(mix)]
        nonce = _next_nonce(next_nonces, signer)
        payload = _valid_payload_for(kind, signer, nonce, i, users, profile)
        submitted_by_type[kind] = int(submitted_by_type.get(kind, 0)) + 1
        result = executor.submit_tx(_tx(kind, signer, nonce, payload), ingress="local_fixture")
        if result.get("ok"):
            admitted += 1
            accepted_by_type[kind] = int(accepted_by_type.get(kind, 0)) + 1
        else:
            rejected += 1
            code = str(result.get("error") or result.get("reason") or "rejected")
            rejected_by_code[code] = int(rejected_by_code.get(code, 0)) + 1
    return {
        "admitted": admitted,
        "rejected": rejected,
        "rejected_by_code": rejected_by_code,
        "submitted_by_type": submitted_by_type,
        "accepted_by_type": accepted_by_type,
        "malformed_submitted": malformed_submitted,
        "malformed_rejected": malformed_rejected,
    }


def _mempool_size(executor: Any) -> int:
    mp = getattr(executor, "_mempool", None) or getattr(executor, "mempool", None)
    if mp is None:
        return 0
    fn = getattr(mp, "size", None)
    if callable(fn):
        return int(fn())
    return 0


def _selected_type_counts(executor: Any, *, max_txs: int) -> dict[str, int]:
    st = executor.read_state()
    candidate_height = int(st.get("height") or 0) + 1
    mp = getattr(executor, "_mempool", None) or getattr(executor, "mempool", None)
    if mp is None:
        return {}
    try:
        policy = mp.selection_policy()
        rows = mp.fetch_for_block(limit=int(max_txs), policy=policy, candidate_height=candidate_height)
    except TypeError:
        rows = mp.fetch_for_block(limit=int(max_txs))
    except Exception:
        return {}
    out: dict[str, int] = {}
    for tx in rows:
        t = str(tx.get("tx_type") or "UNKNOWN")
        out[t] = int(out.get(t, 0)) + 1
    return out


def _state_root(state: Json) -> str:
    from weall.runtime.state_hash import compute_state_root

    return str(compute_state_root(state))


def _produce_measured_block(executor: Any, *, max_txs: int, target_block_ms: int) -> Json:
    probe = PhaseProbe()
    backlog_before = _mempool_size(executor)
    candidate_type_counts = _selected_type_counts(executor, max_txs=max_txs)
    start = time.perf_counter_ns()
    with _patched_block_builder_timing(executor, probe):
        candidate_start = time.perf_counter_ns()
        block, new_state, applied_ids, invalid_ids, err = executor.build_block_candidate(max_txs=int(max_txs), allow_empty=False)
        candidate_ns = time.perf_counter_ns() - candidate_start
    if block is None:
        return {
            "ok": False,
            "error": str(err or "no_block_candidate"),
            "mempool_backlog_before": backlog_before,
            "mempool_backlog_after": _mempool_size(executor),
            "total_block_production_time_ms": _ms(time.perf_counter_ns() - start),
        }
    commit_start = time.perf_counter_ns()
    meta = executor.commit_block_candidate(block=block, new_state=new_state, applied_ids=applied_ids, invalid_ids=invalid_ids)
    persistence_ns = time.perf_counter_ns() - commit_start
    total_ns = time.perf_counter_ns() - start
    included_types: dict[str, int] = {}
    for tx in block.get("txs") if isinstance(block.get("txs"), list) else []:
        if not isinstance(tx, dict):
            continue
        t = str(tx.get("tx_type") or "UNKNOWN")
        included_types[t] = int(included_types.get(t, 0)) + 1
    receipts = block.get("receipts") if isinstance(block.get("receipts"), list) else []
    return {
        "ok": bool(getattr(meta, "ok", False)),
        "error": str(getattr(meta, "error", "") or ""),
        "height": int(block.get("height") or 0),
        "block_id": str(block.get("block_id") or ""),
        "txs_included": len(block.get("txs") if isinstance(block.get("txs"), list) else []),
        "receipts_emitted": len(receipts),
        "tx_types_selected_before_block": candidate_type_counts,
        "tx_types_included": included_types,
        "mempool_backlog_before": backlog_before,
        "mempool_backlog_after": _mempool_size(executor),
        "proposal_construction_time_ms": max(
            0.0,
            round(_ms(candidate_ns) - probe.ms("block_admission_time_ns") - probe.ms("execution_time_ns") - probe.ms("state_root_time_ns") - probe.ms("helper_planning_time_ns"), 3),
        ),
        "candidate_total_time_ms": _ms(candidate_ns),
        "block_admission_time_ms": probe.ms("block_admission_time_ns"),
        "execution_time_ms": probe.ms("execution_time_ns"),
        "helper_planning_time_ms": probe.ms("helper_planning_time_ns"),
        "helper_execution_time_ms": 0.0,
        "deterministic_merge_time_ms": 0.0,
        "state_root_time_ms": probe.ms("state_root_time_ns"),
        "persistence_time_ms": _ms(persistence_ns),
        "gossip_commit_time_ms": None,
        "total_block_production_time_ms": _ms(total_ns),
        "target_block_interval_ms": int(target_block_ms),
        "target_exceeded": _ms(total_ns) > float(target_block_ms),
        "state_root": _state_root(new_state),
        "unmeasured_fields": ["real_network_gossip_latency", "remote_helper_execution_latency"],
    }


def _apply_to_follower(follower: Any, block: Json) -> Json:
    start = time.perf_counter_ns()
    try:
        meta = follower.apply_block(block)
        ok = bool(getattr(meta, "ok", False))
        err = str(getattr(meta, "error", "") or "")
    except Exception as exc:
        ok = False
        err = str(exc)
    return {
        "ok": ok,
        "error": err,
        "apply_time_ms": _ms(time.perf_counter_ns() - start),
        "height": int(follower.read_state().get("height") or 0),
        "state_root": _state_root(follower.read_state()),
    }


def _summary(blocks: list[Json]) -> Json:
    totals = [float(b.get("total_block_production_time_ms") or 0.0) for b in blocks if b.get("ok")]
    if not totals:
        return {"count": 0}
    ordered = sorted(totals)
    def percentile(p: float) -> float:
        if len(ordered) == 1:
            return ordered[0]
        k = (len(ordered) - 1) * p
        f = int(k)
        c = min(f + 1, len(ordered) - 1)
        if f == c:
            return ordered[f]
        return ordered[f] + (ordered[c] - ordered[f]) * (k - f)
    return {
        "count": len(totals),
        "avg_ms": round(statistics.mean(totals), 3),
        "max_ms": round(max(totals), 3),
        "p95_ms": round(percentile(0.95), 3),
        "p99_ms": round(percentile(0.99), 3),
        "target_exceeded_count": sum(1 for b in blocks if b.get("target_exceeded")),
    }


def run_profile(profile: str, *, users_n: int, blocks_n: int, max_txs_per_block: int, txs_per_block_feed: int, target_block_ms: int, helper_fast_path: bool, restart_during_load: bool) -> Json:
    tempdir = tempfile.mkdtemp(prefix=f"weall-block-schedule-{profile}-")
    chain_id = f"block-schedule-survivability-{profile}"
    users = [f"@load{i:03d}" for i in range(max(3, int(users_n)))]
    leader = _make_executor(str(Path(tempdir) / "leader.db"), node_id="@leader", chain_id=chain_id, helper_fast_path=helper_fast_path)
    follower = _make_executor(str(Path(tempdir) / "follower.db"), node_id="@follower", chain_id=chain_id, helper_fast_path=False)
    slow_observer = _make_executor(str(Path(tempdir) / "slow-observer.db"), node_id="@slow-observer", chain_id=chain_id, helper_fast_path=False)
    seed = _seed_state(leader, users)
    _clone_seed_to_follower(follower, seed)
    _clone_seed_to_follower(slow_observer, seed)
    next_nonces = {u: 2 for u in users}
    blocks: list[Json] = []
    follower_results: list[Json] = []
    slow_queue: list[Json] = []
    restart_result: Json = {}
    aggregate_submit = {"admitted": 0, "rejected": 0, "malformed_submitted": 0, "malformed_rejected": 0, "rejected_by_code": {}, "accepted_by_type": {}}

    for block_i in range(int(blocks_n)):
        submit_result = _submit_profile_load(
            leader,
            profile=profile,
            users=users,
            next_nonces=next_nonces,
            count=int(txs_per_block_feed),
        )
        aggregate_submit["admitted"] += int(submit_result.get("admitted") or 0)
        aggregate_submit["rejected"] += int(submit_result.get("rejected") or 0)
        aggregate_submit["malformed_submitted"] += int(submit_result.get("malformed_submitted") or 0)
        aggregate_submit["malformed_rejected"] += int(submit_result.get("malformed_rejected") or 0)
        for k, v in dict(submit_result.get("rejected_by_code") or {}).items():
            aggregate_submit["rejected_by_code"][k] = int(aggregate_submit["rejected_by_code"].get(k, 0)) + int(v)
        for k, v in dict(submit_result.get("accepted_by_type") or {}).items():
            aggregate_submit["accepted_by_type"][k] = int(aggregate_submit["accepted_by_type"].get(k, 0)) + int(v)

        measured = _produce_measured_block(leader, max_txs=max_txs_per_block, target_block_ms=target_block_ms)
        measured["block_index"] = block_i
        measured["txs_admitted_this_round"] = int(submit_result.get("admitted") or 0)
        measured["txs_rejected_this_round"] = int(submit_result.get("rejected") or 0)
        measured["rejected_by_code_this_round"] = submit_result.get("rejected_by_code") or {}
        blocks.append(measured)
        if not measured.get("ok"):
            continue
        block_obj = leader.read_state().get("blocks", {}).get(str(measured.get("height")))
        if not isinstance(block_obj, dict):
            # The executor keeps the produced block in the return path only. Fall back to DB rows.
            import sqlite3
            con = sqlite3.connect(str(Path(tempdir) / "leader.db"))
            con.row_factory = sqlite3.Row
            row = con.execute("SELECT block_json FROM blocks WHERE height=?", (int(measured.get("height") or 0),)).fetchone()
            con.close()
            block_obj = json.loads(row["block_json"]) if row else {}
        fr = _apply_to_follower(follower, block_obj)
        follower_results.append(fr)
        slow_queue.append(block_obj)
        if len(slow_queue) >= 2:
            _apply_to_follower(slow_observer, slow_queue.pop(0))

        if restart_during_load and block_i == int(blocks_n) // 2:
            before = {"height": int(leader.read_state().get("height") or 0), "state_root": _state_root(leader.read_state())}
            leader = _make_executor(str(Path(tempdir) / "leader.db"), node_id="@leader", chain_id=chain_id, helper_fast_path=helper_fast_path)
            after = {"height": int(leader.read_state().get("height") or 0), "state_root": _state_root(leader.read_state())}
            restart_result = {"performed": True, "before": before, "after": after, "same_state_root": before["state_root"] == after["state_root"]}

    for block_obj in slow_queue:
        _apply_to_follower(slow_observer, block_obj)
    leader_root = _state_root(leader.read_state())
    follower_root = _state_root(follower.read_state())
    slow_root = _state_root(slow_observer.read_state())
    return {
        "profile": profile,
        "chain_id": chain_id,
        "tempdir": tempdir,
        "users": len(users),
        "blocks_requested": int(blocks_n),
        "max_txs_per_block": int(max_txs_per_block),
        "txs_per_block_feed": int(txs_per_block_feed),
        "target_block_interval_ms": int(target_block_ms),
        "helper_fast_path_requested": bool(helper_fast_path),
        "aggregate_submit": aggregate_submit,
        "block_measurements": blocks,
        "latency_summary": _summary(blocks),
        "follower_apply_results": follower_results,
        "convergence": {
            "leader_height": int(leader.read_state().get("height") or 0),
            "follower_height": int(follower.read_state().get("height") or 0),
            "slow_observer_height": int(slow_observer.read_state().get("height") or 0),
            "leader_state_root": leader_root,
            "follower_state_root": follower_root,
            "slow_observer_state_root": slow_root,
            "all_nodes_converged": leader_root == follower_root == slow_root,
        },
        "restart_during_load": restart_result or {"performed": False},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["light", "active", "adversarial", "network", "all"], default="light")
    parser.add_argument("--users", type=int, default=0)
    parser.add_argument("--blocks", type=int, default=0)
    parser.add_argument("--max-txs-per-block", type=int, default=0)
    parser.add_argument("--txs-per-block-feed", type=int, default=0)
    parser.add_argument("--target-block-ms", type=int, default=DEFAULT_TARGET_BLOCK_MS)
    parser.add_argument("--helper-fast-path", action="store_true")
    parser.add_argument("--restart-during-load", action="store_true", default=True)
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    profiles = ["light", "active", "adversarial", "network"] if args.profile == "all" else [args.profile]
    results = []
    for profile in profiles:
        defaults = PROFILE_DEFAULTS[profile]
        results.append(
            run_profile(
                profile,
                users_n=args.users or defaults["users"],
                blocks_n=args.blocks or defaults["blocks"],
                max_txs_per_block=args.max_txs_per_block or defaults["max_txs_per_block"],
                txs_per_block_feed=args.txs_per_block_feed or defaults["txs_per_block_feed"],
                target_block_ms=args.target_block_ms,
                helper_fast_path=args.helper_fast_path,
                restart_during_load=bool(args.restart_during_load),
            )
        )
    artifact: Json = {
        "artifact": "block_schedule_survivability_rehearsal_evidence_v1_5",
        "generated_at_ms": _now_ms(),
        "repo_root": str(REPO_ROOT),
        "budget_artifact": "specs/block_schedule_survivability_budget_v1_5.json",
        "profiles": results,
    }
    out = Path(args.out) if args.out else REPO_ROOT / "rehearsal-evidence" / f"block_schedule_survivability_{_now_ms()}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")
    print(str(out))
    # A non-zero exit is reserved for harness/runtime failure. Cadence misses are evidence.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
