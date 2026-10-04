#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ANCESTRY = ROOT / "src/weall/runtime/ancestry.py"
BUILDER = ROOT / "src/weall/runtime/block_builder.py"
REPLAY = ROOT / "src/weall/runtime/block_replay.py"
TESTS = ROOT / "tests/test_p0_10_bounded_ancestry.py"
BENCH = ROOT / "scripts/rehearse_p0_10_bounded_ancestry.py"
LEDGER = ROOT.parent / "docs/audit/WeAll-A01-A20-P0-Closure-Status-20260930.md"

ANCESTRY_TEXT = '''from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

Json = dict[str, Any]

# Keep the consensus-visible ancestry horizon aligned with the executor's
# existing durable block-retention default. Durable block bodies remain a
# separate SQLite/history concern; this constant bounds only root-visible
# ancestry metadata carried in every consensus state snapshot.
CONSENSUS_ANCESTRY_WINDOW = 10_000
CONSENSUS_ANCESTRY_CHECKPOINT_VERSION = 1
_CHECKPOINT_DOMAIN = "weall.consensus-ancestry-checkpoint.v1"
_CHECKPOINT_SEED = hashlib.sha256(_CHECKPOINT_DOMAIN.encode("utf-8")).hexdigest()


class AncestryCompactionError(RuntimeError):
    """Raised when bounded ancestry cannot advance without losing safety truth."""


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _i(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _s(value: Any) -> str:
    return str(value or "").strip()


def _record_height(record: Any) -> int:
    return _i(record.get("height"), 0) if isinstance(record, dict) else 0


def _protected_ancestry_ids(state: Json) -> set[str]:
    """Return live block identities that pruning must never silently discard.

    The bounded window is permitted to forget old finalized history only after
    current consensus safety has moved forward. If finality/lock/QC lag exceeds
    the window, block construction/replay fails closed instead of growing state
    without bound or deleting the anchor needed to prove branch safety.
    """

    out: set[str] = set()

    tip = _s(state.get("tip"))
    if tip:
        out.add(tip)

    finalized = state.get("finalized")
    if isinstance(finalized, dict):
        bid = _s(finalized.get("block_id"))
        if bid:
            out.add(bid)

    bft = state.get("bft")
    if isinstance(bft, dict):
        bid = _s(bft.get("finalized_block_id"))
        if bid:
            out.add(bid)
        for key in ("high_qc", "locked_qc"):
            qc = bft.get(key)
            if isinstance(qc, dict):
                qbid = _s(qc.get("block_id"))
                if qbid:
                    out.add(qbid)

    return out


def _checkpoint_advance(checkpoint: Json, *, block_id: str, record: Json) -> Json:
    previous = _s(checkpoint.get("commitment")) or _CHECKPOINT_SEED
    count = max(0, _i(checkpoint.get("pruned_count"), 0)) + 1
    material = {
        "domain": _CHECKPOINT_DOMAIN,
        "version": int(CONSENSUS_ANCESTRY_CHECKPOINT_VERSION),
        "sequence": int(count),
        "previous_commitment": previous,
        "block_id": str(block_id),
        "record": dict(record),
    }
    commitment = hashlib.sha256(_canon(material).encode("utf-8")).hexdigest()
    return {
        "version": int(CONSENSUS_ANCESTRY_CHECKPOINT_VERSION),
        "commitment": commitment,
        "pruned_count": int(count),
        "through_height": int(_record_height(record)),
        "through_block_id": str(block_id),
    }


def _initial_checkpoint() -> Json:
    return {
        "version": int(CONSENSUS_ANCESTRY_CHECKPOINT_VERSION),
        "commitment": _CHECKPOINT_SEED,
        "pruned_count": 0,
        "through_height": 0,
        "through_block_id": "",
    }


def _validate_existing_meta(meta: Json, *, limit: int) -> tuple[list[str], int, Json]:
    if _i(meta.get("version"), 0) != int(CONSENSUS_ANCESTRY_CHECKPOINT_VERSION):
        raise AncestryCompactionError("unsupported_consensus_ancestry_version")
    if _i(meta.get("window_limit"), 0) != int(limit):
        raise AncestryCompactionError("consensus_ancestry_window_mismatch")

    ring = meta.get("active_ring")
    if not isinstance(ring, list) or len(ring) != int(limit):
        raise AncestryCompactionError("consensus_ancestry_ring_invalid")
    if any(not _s(item) for item in ring):
        raise AncestryCompactionError("consensus_ancestry_ring_contains_empty_id")

    head = _i(meta.get("ring_head"), -1)
    if head < 0 or head >= int(limit):
        raise AncestryCompactionError("consensus_ancestry_ring_head_invalid")

    checkpoint = meta.get("checkpoint")
    if not isinstance(checkpoint, dict):
        raise AncestryCompactionError("consensus_ancestry_checkpoint_missing")
    if _i(checkpoint.get("version"), 0) != int(CONSENSUS_ANCESTRY_CHECKPOINT_VERSION):
        raise AncestryCompactionError("consensus_ancestry_checkpoint_version_invalid")
    commitment = _s(checkpoint.get("commitment"))
    if len(commitment) != 64:
        raise AncestryCompactionError("consensus_ancestry_checkpoint_commitment_invalid")
    try:
        int(commitment, 16)
    except Exception as exc:
        raise AncestryCompactionError(
            "consensus_ancestry_checkpoint_commitment_invalid"
        ) from exc

    return [str(x) for x in ring], int(head), dict(checkpoint)


def compact_consensus_ancestry(state: Json, *, limit: int | None = None) -> Json:
    """Bound ``state['blocks']`` and commit pruned ancestry into a hash chain.

    Normal steady-state operation is O(1) with respect to chain age. The first
    compaction of a legacy/pre-patch state performs a one-time deterministic
    sort of the existing ancestry map, then records a fixed-size circular order
    ring. Thereafter each appended canonical block replaces exactly one oldest
    ring slot and advances a constant-size rolling checkpoint.

    The helper intentionally mutates only after all safety checks for the next
    prune step have passed. A stale finalized/highQC/lockedQC anchor therefore
    fails closed without partially rewriting consensus state.
    """

    if not isinstance(state, dict):
        raise AncestryCompactionError("consensus_state_not_dict")

    window = int(CONSENSUS_ANCESTRY_WINDOW if limit is None else limit)
    if window < 3:
        raise AncestryCompactionError("consensus_ancestry_window_too_small")

    blocks = state.get("blocks")
    if not isinstance(blocks, dict):
        raise AncestryCompactionError("consensus_blocks_not_dict")
    if len(blocks) <= window:
        return state

    protected = _protected_ancestry_ids(state)
    root_meta = state.get("meta")
    existing_meta = root_meta.get("consensus_ancestry") if isinstance(root_meta, dict) else None

    # Fast steady-state path: once compaction has started, canonical execution
    # adds exactly one new tip before calling this helper. The fixed-size ring
    # makes the next prune identity available without scanning/sorting history.
    if isinstance(existing_meta, dict) and len(blocks) == window + 1:
        ring, head, checkpoint = _validate_existing_meta(existing_meta, limit=window)
        old_id = _s(ring[head])
        new_tip = _s(state.get("tip"))
        if not old_id or old_id not in blocks:
            raise AncestryCompactionError("consensus_ancestry_oldest_record_missing")
        if not new_tip or new_tip not in blocks:
            raise AncestryCompactionError("consensus_ancestry_new_tip_missing")
        if new_tip == old_id:
            raise AncestryCompactionError("consensus_ancestry_tip_reuses_oldest_slot")
        if old_id in protected:
            raise AncestryCompactionError(
                f"consensus_ancestry_safety_anchor_outside_window:{old_id}"
            )
        old_record = blocks.get(old_id)
        if not isinstance(old_record, dict):
            raise AncestryCompactionError("consensus_ancestry_oldest_record_invalid")

        next_checkpoint = _checkpoint_advance(
            checkpoint,
            block_id=old_id,
            record=dict(old_record),
        )

        # All failure-prone validation/hash work is complete. Apply the bounded
        # mutation as one deterministic state transition.
        del blocks[old_id]
        ring[head] = new_tip
        existing_meta["active_ring"] = ring
        existing_meta["ring_head"] = int((head + 1) % window)
        existing_meta["checkpoint"] = next_checkpoint
        existing_meta["active_count"] = int(window)
        return state

    # One-time migration/recovery path. Ordering is explicit and independent of
    # dict insertion order so restart/JSON round-trips cannot change the root.
    ordered: list[tuple[int, str, Json]] = []
    for raw_id, raw_record in blocks.items():
        bid = _s(raw_id)
        if not bid or not isinstance(raw_record, dict):
            raise AncestryCompactionError("consensus_ancestry_record_invalid")
        ordered.append((_record_height(raw_record), bid, dict(raw_record)))
    ordered.sort(key=lambda row: (int(row[0]), str(row[1])))

    excess = len(ordered) - window
    if excess <= 0:
        return state
    to_prune = ordered[:excess]
    for _height, bid, _record in to_prune:
        if bid in protected:
            raise AncestryCompactionError(
                f"consensus_ancestry_safety_anchor_outside_window:{bid}"
            )

    checkpoint = _initial_checkpoint()
    if isinstance(existing_meta, dict):
        _ring, _head, checkpoint = _validate_existing_meta(existing_meta, limit=window)

    next_checkpoint = dict(checkpoint)
    for _height, bid, record in to_prune:
        next_checkpoint = _checkpoint_advance(
            next_checkpoint,
            block_id=bid,
            record=record,
        )

    remaining = ordered[excess:]
    ring = [bid for _height, bid, _record in remaining]
    if len(ring) != window:
        raise AncestryCompactionError("consensus_ancestry_rebuild_size_mismatch")

    # Apply after complete validation.
    for _height, bid, _record in to_prune:
        del blocks[bid]
    if not isinstance(root_meta, dict):
        root_meta = {}
        state["meta"] = root_meta
    root_meta["consensus_ancestry"] = {
        "version": int(CONSENSUS_ANCESTRY_CHECKPOINT_VERSION),
        "window_limit": int(window),
        "active_count": int(window),
        "active_ring": ring,
        "ring_head": 0,
        "checkpoint": next_checkpoint,
    }
    return state


def walk_ancestry(
    records: dict[str, Any],
    *,
    candidate: str,
    ancestor: str,
    parent_of: Callable[[Any], str],
) -> bool:
    """Return True iff ``candidate`` descends from ``ancestor``.

    This helper is consensus-critical and intentionally avoids arbitrary hop
    limits. A fixed traversal cap can cause honest nodes to disagree once the
    live chain grows past that bound. Instead we terminate only when:
      - the ancestor is reached,
      - the lineage ends,
      - a record is missing, or
      - a cycle is detected in corrupted state.

    The caller supplies ``parent_of`` so the same logic can be reused across
    block maps with slightly different record shapes. Production compaction
    retains every live safety anchor inside the bounded map, so callers never
    need to treat a checkpoint hash as if it were a full ancestry record.
    """

    cand = str(candidate).strip()
    anc = str(ancestor).strip()
    if not cand or not anc:
        return False
    if cand == anc:
        return True

    cur = cand
    seen: set[str] = set()
    while cur:
        if cur in seen:
            return False
        seen.add(cur)
        rec = records.get(cur)
        if not isinstance(rec, dict):
            return False
        parent = str(parent_of(rec)).strip()
        if not parent:
            return False
        if parent == anc:
            return True
        cur = parent
    return False
'''

TEST_TEXT = '''from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.state_sync import StateSyncService
from weall.runtime import ancestry
from weall.runtime.ancestry import AncestryCompactionError, compact_consensus_ancestry
from weall.runtime.fork_choice import choose_head
from weall.runtime.executor import WeAllExecutor


def _chain(count: int) -> dict:
    state: dict = {"height": 0, "tip": "", "blocks": {}}
    parent = ""
    for height in range(1, count + 1):
        bid = f"b{height}"
        state["blocks"][bid] = {
            "height": height,
            "prev_block_id": parent,
            "block_ts_ms": height * 20_000,
        }
        state["height"] = height
        state["tip"] = bid
        parent = bid
    return state


def test_a15_f001_compaction_bounds_root_visible_ancestry_and_commits_history() -> None:
    state = _chain(7)
    compact_consensus_ancestry(state, limit=3)

    assert list(state["blocks"]) == ["b5", "b6", "b7"]
    meta = state["meta"]["consensus_ancestry"]
    assert meta["window_limit"] == 3
    assert meta["active_count"] == 3
    assert meta["active_ring"] == ["b5", "b6", "b7"]
    assert meta["ring_head"] == 0
    checkpoint = meta["checkpoint"]
    assert checkpoint["pruned_count"] == 4
    assert checkpoint["through_height"] == 4
    assert checkpoint["through_block_id"] == "b4"
    assert len(checkpoint["commitment"]) == 64


def test_a15_f001_compaction_is_deterministic_across_insertion_order() -> None:
    left = _chain(8)
    right = _chain(8)
    right["blocks"] = dict(reversed(list(right["blocks"].items())))

    compact_consensus_ancestry(left, limit=3)
    compact_consensus_ancestry(right, limit=3)

    assert left == right


def test_a15_f001_checkpoint_continues_identically_after_json_restart() -> None:
    uninterrupted = _chain(8)
    compact_consensus_ancestry(uninterrupted, limit=3)

    staged = _chain(7)
    compact_consensus_ancestry(staged, limit=3)
    restarted = json.loads(json.dumps(staged, sort_keys=True))
    restarted["blocks"]["b8"] = {
        "height": 8,
        "prev_block_id": "b7",
        "block_ts_ms": 160_000,
    }
    restarted["height"] = 8
    restarted["tip"] = "b8"
    compact_consensus_ancestry(restarted, limit=3)

    assert restarted == uninterrupted


def test_a15_f001_pruning_fails_closed_before_losing_finalized_anchor() -> None:
    state = _chain(5)
    state["finalized"] = {"height": 1, "block_id": "b1"}
    before = json.loads(json.dumps(state, sort_keys=True))

    with pytest.raises(AncestryCompactionError, match="safety_anchor_outside_window:b1"):
        compact_consensus_ancestry(state, limit=3)

    assert state == before


def test_a15_f001_fork_choice_remains_valid_inside_compacted_finality_window() -> None:
    state = _chain(8)
    state["finalized"] = {"height": 6, "block_id": "b6"}
    compact_consensus_ancestry(state, limit=3)

    assert choose_head(state) == "b8"


def test_a15_f001_state_sync_snapshot_verifies_with_compacted_checkpoint() -> None:
    state = _chain(8)
    compact_consensus_ancestry(state, limit=3)
    svc = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: state,
    )
    req = StateSyncRequestMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_REQUEST,
            chain_id="test",
            schema_version="1",
            tx_index_hash="deadbeef",
            corr_id="a15-f001",
        ),
        mode="snapshot",
        from_height=0,
        to_height=None,
        selector=None,
    )

    response = svc.handle_request(req)
    assert response.ok is True
    assert response.snapshot is not None
    assert len(response.snapshot["blocks"]) == 3
    assert response.snapshot["meta"]["consensus_ancestry"]["checkpoint"]["pruned_count"] == 5
    svc.verify_response(response)


def _canon_path() -> str:
    return str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")


def _executor(tmp_path: Path, node_id: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{node_id}.sqlite"),
        node_id=node_id,
        chain_id="a15-f001-chain",
        tx_index_path=_canon_path(),
    )


def test_a15_f001_leader_follower_roots_match_across_compaction_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    monkeypatch.setattr(ancestry, "CONSENSUS_ANCESTRY_WINDOW", 3)

    leader = _executor(tmp_path, "leader")
    follower = _executor(tmp_path, "follower")

    for _ in range(6):
        meta = leader.produce_block(max_txs=0, allow_empty=True)
        assert meta.ok is True, meta.error
        block = leader.get_latest_block()
        assert isinstance(block, dict)
        applied = follower.apply_block(block)
        assert applied.ok is True, applied.error

    assert leader.state["height"] == follower.state["height"] == 6
    assert leader.state["tip"] == follower.state["tip"]
    assert leader.state["blocks"] == follower.state["blocks"]
    assert leader.state["meta"]["consensus_ancestry"] == follower.state["meta"]["consensus_ancestry"]
    assert len(leader.state["blocks"]) == 3
'''

BENCH_TEXT = '''#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import resource
import time
from pathlib import Path

from weall.runtime.ancestry import CONSENSUS_ANCESTRY_WINDOW, compact_consensus_ancestry


def _state_bytes(state: dict) -> int:
    return len(json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _rss_kib() -> int:
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def _write_svg(path: Path, samples: list[dict]) -> None:
    width, height = 900, 420
    pad = 60
    max_n = max(int(s["blocks_processed"]) for s in samples)
    max_elapsed = max(float(s["elapsed_seconds"]) for s in samples) or 1.0
    max_bytes = max(int(s["consensus_state_bytes"]) for s in samples) or 1

    def x(n: int) -> float:
        return pad + (width - 2 * pad) * (n / max_n)

    def y_time(v: float) -> float:
        return height - pad - (height - 2 * pad) * (v / max_elapsed)

    def y_size(v: int) -> float:
        return height - pad - (height - 2 * pad) * (v / max_bytes)

    time_points = " ".join(f"{x(int(s['blocks_processed'])):.1f},{y_time(float(s['elapsed_seconds'])):.1f}" for s in samples)
    size_points = " ".join(f"{x(int(s['blocks_processed'])):.1f},{y_size(int(s['consensus_state_bytes'])):.1f}" for s in samples)
    labels = []
    for s in samples:
        px = x(int(s["blocks_processed"]))
        labels.append(f'<text x="{px:.1f}" y="{height - 25}" font-size="12" text-anchor="middle">{int(s["blocks_processed"]):,}</text>')
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<rect width="100%" height="100%" fill="white"/>
<text x="{width/2}" y="28" font-size="18" text-anchor="middle">A15-F001 bounded ancestry synthetic stress</text>
<line x1="{pad}" y1="{height-pad}" x2="{width-pad}" y2="{height-pad}" stroke="black"/>
<line x1="{pad}" y1="{pad}" x2="{pad}" y2="{height-pad}" stroke="black"/>
<polyline points="{time_points}" fill="none" stroke="#1f77b4" stroke-width="3"/>
<polyline points="{size_points}" fill="none" stroke="#d62728" stroke-width="3" stroke-dasharray="8,5"/>
<text x="{pad+10}" y="{pad+15}" font-size="13" fill="#1f77b4">cumulative wall time (normalized)</text>
<text x="{pad+10}" y="{pad+34}" font-size="13" fill="#d62728">consensus-state bytes (normalized)</text>
{''.join(labels)}
<text x="{width/2}" y="{height-5}" font-size="12" text-anchor="middle">blocks processed</text>
</svg>\n'''
    path.write_text(svg, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="artifacts/p0-10/a15-f001-bounded-ancestry-benchmark.json")
    parser.add_argument("--svg", default="artifacts/p0-10/a15-f001-bounded-ancestry-benchmark.svg")
    parser.add_argument("--max-blocks", type=int, default=2_000_000)
    args = parser.parse_args()

    milestones = [100_000, 1_000_000, int(args.max_blocks)]
    milestones = sorted(set(n for n in milestones if n > 0))
    state: dict = {"height": 0, "tip": "", "blocks": {}}
    started = time.perf_counter()
    samples: list[dict] = []
    parent = ""

    for height in range(1, milestones[-1] + 1):
        bid = f"b{height:016x}"
        state["blocks"][bid] = {
            "height": height,
            "prev_block_id": parent,
            "block_ts_ms": height * 20_000,
        }
        state["height"] = height
        state["tip"] = bid
        compact_consensus_ancestry(state)
        parent = bid

        if height in milestones:
            ancestry_meta = state.get("meta", {}).get("consensus_ancestry", {})
            checkpoint = ancestry_meta.get("checkpoint", {})
            samples.append(
                {
                    "blocks_processed": int(height),
                    "root_visible_block_records": int(len(state["blocks"])),
                    "window_limit": int(CONSENSUS_ANCESTRY_WINDOW),
                    "checkpoint_pruned_count": int(checkpoint.get("pruned_count") or 0),
                    "consensus_state_bytes": int(_state_bytes(state)),
                    "elapsed_seconds": round(time.perf_counter() - started, 6),
                    "max_rss_kib": int(_rss_kib()),
                }
            )

    assert len(state["blocks"]) <= CONSENSUS_ANCESTRY_WINDOW
    checkpoint = state["meta"]["consensus_ancestry"]["checkpoint"]
    assert int(checkpoint["pruned_count"]) == milestones[-1] - CONSENSUS_ANCESTRY_WINDOW

    payload = {
        "schema": "weall.p0-10.a15-f001.bounded-ancestry-benchmark.v1",
        "window_limit": int(CONSENSUS_ANCESTRY_WINDOW),
        "samples": samples,
        "final_checkpoint_commitment": str(checkpoint["commitment"]),
        "bounded": True,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    svg = Path(args.svg)
    svg.parent.mkdir(parents=True, exist_ok=True)
    _write_svg(svg, samples)
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"expected exactly one replacement in {path}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> int:
    ANCESTRY.write_text(ANCESTRY_TEXT, encoding="utf-8")

    replace_once(
        BUILDER,
        "from weall.net.wire_limits import MAX_BFT_BLOCK_BYTES\n",
        "from weall.net.wire_limits import MAX_BFT_BLOCK_BYTES\n"
        "from weall.runtime.ancestry import AncestryCompactionError, compact_consensus_ancestry\n",
    )
    replace_once(
        BUILDER,
        '''    blocks_map[str(block_id)] = {
        "height": int(new_height),
        "prev_block_id": str(tip),
        "block_ts_ms": int(ts_ms),
    }

    working["height"] = int(new_height)
    working["tip"] = str(block_id)
''',
        '''    blocks_map[str(block_id)] = {
        "height": int(new_height),
        "prev_block_id": str(tip),
        "block_ts_ms": int(ts_ms),
    }

    working["height"] = int(new_height)
    working["tip"] = str(block_id)
    try:
        compact_consensus_ancestry(working)
    except AncestryCompactionError as exc:
        return None, None, [], invalid_ids, f"ancestry_compaction_failed:{exc}"
''',
    )

    replay_text = REPLAY.read_text(encoding="utf-8")
    import_anchor = "from weall.runtime.bft_finality_bridge import schedule_bft_finality_receipt\n"
    if import_anchor not in replay_text:
        raise SystemExit("block_replay import anchor not found")
    replay_text = replay_text.replace(
        import_anchor,
        "from weall.runtime.ancestry import AncestryCompactionError, compact_consensus_ancestry\n"
        + import_anchor,
        1,
    )
    old_replay = '''    blocks_map[str(block_id)] = {
        "height": int(height),
        "prev_block_id": str(self.state.get("tip") or ""),
        "block_ts_ms": int(ts_ms),
    }

    working["height"] = int(height)
    working["tip"] = str(block_id)
'''
    new_replay = '''    blocks_map[str(block_id)] = {
        "height": int(height),
        "prev_block_id": str(self.state.get("tip") or ""),
        "block_ts_ms": int(ts_ms),
    }

    working["height"] = int(height)
    working["tip"] = str(block_id)
    try:
        compact_consensus_ancestry(working)
    except AncestryCompactionError as exc:
        return ExecutorMeta(
            ok=False,
            error=f"bad_block:ancestry_compaction_failed:{exc}",
            height=0,
            block_id=str(block_id),
        )
'''
    if replay_text.count(old_replay) != 1:
        raise SystemExit("block_replay ancestry insertion anchor not found exactly once")
    REPLAY.write_text(replay_text.replace(old_replay, new_replay, 1), encoding="utf-8")

    TESTS.write_text(TEST_TEXT, encoding="utf-8")
    BENCH.write_text(BENCH_TEXT, encoding="utf-8")

    ledger = LEDGER.read_text(encoding="utf-8")
    old_row = "| P0-10 Bounded production state / state sync / permanent account state | A15-F001..F003 | DESIGN + IMPLEMENTATION BLOCKER | Requires bounded ancestry commitment/history architecture, finite authenticated state-sync work/response envelope, and protocol-level permanent-state scarcity/identity bootstrap policy. |"
    new_row = "| P0-10 Bounded production state / state sync / permanent account state | A15-F001..F003 | PARTIAL | A15-F001 patched/evidence-pending: consensus-visible block ancestry is bounded to the existing 10,000-block retention horizon, pruned history advances a deterministic rolling checkpoint commitment, and finality/highQC/lockedQC anchors fail closed rather than being silently discarded. A15-F002 state-sync amplification and A15-F003 permanent Tier-0 account cardinality remain open. |"
    if ledger.count(old_row) != 1:
        raise SystemExit("P0-10 ledger row anchor not found exactly once")
    LEDGER.write_text(ledger.replace(old_row, new_row, 1), encoding="utf-8")

    print("P0-10 A15-F001 bounded ancestry repair staged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
