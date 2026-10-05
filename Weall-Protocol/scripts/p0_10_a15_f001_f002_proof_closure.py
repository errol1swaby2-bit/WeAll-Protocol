#!/usr/bin/env python3
from __future__ import annotations

import copy
import csv
import hashlib
import json
import os
import resource
import statistics
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any

BASE_SHA = "279546caddc6b766c883cee7e00750639495d699"
BRANCH = "p0-03-production-closure-staging-20261001"
ROOT = Path(os.environ.get("GITHUB_WORKSPACE") or Path.cwd()).resolve()
PROTO = ROOT / "Weall-Protocol"
WEB = ROOT / "web"
EVIDENCE = Path("/tmp/p0-10-evidence")
CONTROL_SCRIPT = PROTO / "scripts" / "p0_10_a15_f001_f002_proof_closure.py"
CONTROL_WORKFLOW = ROOT / ".github" / "workflows" / "p0-10-a15-f001-f002-proof-closure.yml"


def run(*args: str, cwd: Path = PROTO, env: dict[str, str] | None = None) -> None:
    cmd = [str(x) for x in args]
    print("+", " ".join(cmd), flush=True)
    merged = os.environ.copy()
    if env:
        merged.update(env)
    subprocess.run(cmd, cwd=str(cwd), env=merged, check=True)


def output(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.check_output([str(x) for x in args], cwd=str(cwd), text=True).strip()


def patch_tests() -> None:
    f001 = PROTO / "tests" / "test_p0_10_a15_f001_bounded_block_history.py"
    text = f001.read_text(encoding="utf-8")
    marker = "def test_compacted_history_preserves_fork_choice_finality_and_state_sync"
    if marker not in text:
        import_anchor = "import pytest\n\n"
        imports = (
            "import pytest\n\n"
            "from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader\n"
            "from weall.net.state_sync import StateSyncService, build_snapshot_anchor\n"
            "from weall.runtime.bft_hotstuff import HotStuffBFT, qc_from_json\n"
            "from weall.runtime.fork_choice import choose_head\n\n"
        )
        if text.count(import_anchor) != 1:
            raise SystemExit("f001_import_anchor_not_unique")
        text = text.replace(import_anchor, imports, 1)
        text += textwrap.dedent(
            '''


def test_compacted_history_preserves_fork_choice_finality_and_state_sync(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    state = _chain_state(8, max_records=4, finalized_height=5)
    compact_bounded_block_history_in_place(state)

    assert list(state["blocks"].keys()) == ["b5", "b6", "b7", "b8"]
    assert state[BLOCK_HISTORY_CHECKPOINT_KEY]["through_height"] == 4

    def _qc(view: int, block_id: str, parent_id: str) -> dict:
        return {
            "t": "QC",
            "chain_id": "p0-10-history-test",
            "view": view,
            "block_id": block_id,
            "block_hash": f"h:{block_id}",
            "parent_id": parent_id,
            "votes": [],
        }

    state["bft"] = {
        "finalized_block_id": "b5",
        "high_qc": _qc(8, "b8", "b7"),
    }
    state["block_attestations"] = {}
    assert choose_head(state) == "b8"

    hotstuff = HotStuffBFT(chain_id="p0-10-history-test")
    hotstuff.finalized_block_id = "b5"
    hotstuff.finalized_view = 5
    hotstuff.locked_qc = qc_from_json(_qc(6, "b6", "b5"))
    finalized = hotstuff.observe_qc(
        blocks=state["blocks"],
        qc=qc_from_json(_qc(8, "b8", "b7")),
    )
    assert finalized == "b6"
    assert hotstuff.finalized_block_id == "b6"

    sync_state = copy.deepcopy(state)
    sync_state.pop("bft", None)
    trusted = build_snapshot_anchor(sync_state)
    selector = {
        "trusted_anchor": {
            "height": trusted["height"],
            "state_root": trusted["state_root"],
            "finalized_height": trusted["finalized_height"],
            "finalized_block_id": trusted["finalized_block_id"],
        }
    }
    service = StateSyncService(
        chain_id="p0-10-history-test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: sync_state,
        require_trusted_anchor=True,
    )
    request = StateSyncRequestMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_REQUEST,
            chain_id="p0-10-history-test",
            schema_version="1",
            tx_index_hash="deadbeef",
            corr_id="compacted-history",
        ),
        mode="snapshot",
        selector=selector,
        from_height=0,
        to_height=None,
    )
    response = service.handle_request(request)
    assert response.ok is True, response.reason
    assert isinstance(response.snapshot, dict)
    assert len(response.snapshot["blocks"]) == 4
    assert response.snapshot[BLOCK_HISTORY_CHECKPOINT_KEY] == state[BLOCK_HISTORY_CHECKPOINT_KEY]
    service.verify_response(response, trusted_anchor=selector["trusted_anchor"])
'''
        )
        f001.write_text(text, encoding="utf-8")

    f002 = PROTO / "tests" / "test_p0_10_a15_f002_state_sync_resource_bounds.py"
    text = f002.read_text(encoding="utf-8")
    marker = "def test_state_sync_result_drain_is_bounded_per_tick"
    if marker not in text:
        text += textwrap.dedent(
            '''


def test_state_sync_result_drain_is_bounded_per_tick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_NET_SYNC_WORK_MAX", "2")
    monkeypatch.setenv("WEALL_NET_SYNC_WORK_PER_PEER_MAX", "2")
    monkeypatch.setenv("WEALL_NET_SYNC_RESULTS_PER_TICK", "1")

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: {"height": 0, "accounts": {}},
    )
    node = NetNode(cfg=_cfg(), sync_service=service, transport=InMemoryTransport())
    peer = _established(node, "peer-a")

    assert peer.router.handle_message(_request("drain-1")) is None
    assert peer.router.handle_message(_request("drain-2")) is None

    deadline = time.monotonic() + 2.0
    before = node.sync_work_debug()
    while time.monotonic() < deadline:
        before = node.sync_work_debug()
        if before["completed_waiting"] == 2:
            break
        time.sleep(0.01)

    assert before["outstanding"] == 2
    assert before["completed_waiting"] == 2
    node.tick(max_packets=0)
    after_one = node.sync_work_debug()
    assert after_one["completed_waiting"] == 1
    assert after_one["outstanding"] == 1
    node.tick(max_packets=0)
    after_two = node.sync_work_debug()
    assert after_two["completed_waiting"] == 0
    assert after_two["outstanding"] == 0
    node.close()
'''
        )
        f002.write_text(text, encoding="utf-8")


def _steady_state(height: int, limit: int = 10_000) -> dict[str, Any]:
    through = max(0, int(height) - int(limit))
    blocks: dict[str, dict[str, Any]] = {}
    previous = f"b{through}" if through else ""
    for h in range(through + 1, int(height) + 1):
        block_id = f"b{h}"
        blocks[block_id] = {
            "height": h,
            "prev_block_id": previous,
            "block_ts_ms": h * 1_000,
        }
        previous = block_id
    state: dict[str, Any] = {
        "height": int(height),
        "tip": f"b{height}",
        "blocks": blocks,
        "accounts": {},
        "meta": {"consensus_block_history_max_records": int(limit)},
        "finalized": {"height": int(height) - 2, "block_id": f"b{int(height) - 2}"},
    }
    if through:
        state["block_history_checkpoint"] = {
            "version": 1,
            "records_committed": int(through),
            "through_height": int(through),
            "through_block_id": f"b{through}",
            "root": hashlib.sha256(f"checkpoint:{through}".encode()).hexdigest(),
        }
    return state


def f001_height_benchmark(height: int) -> dict[str, Any]:
    sys.path.insert(0, str(PROTO / "src"))
    from weall.runtime.block_history import compact_bounded_block_history_in_place
    from weall.runtime.state_hash import compute_state_root

    state = _steady_state(int(height))
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    started = time.perf_counter()
    candidate = copy.deepcopy(state)
    deepcopy_ms = (time.perf_counter() - started) * 1_000.0

    started = time.perf_counter()
    root = compute_state_root(state)
    state_root_ms = (time.perf_counter() - started) * 1_000.0

    started = time.perf_counter()
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    serialize_ms = (time.perf_counter() - started) * 1_000.0

    with tempfile.NamedTemporaryFile(prefix="weall-p0-10-history-", suffix=".json", delete=False) as fh:
        path = Path(fh.name)
        started = time.perf_counter()
        fh.write(encoded)
        fh.flush()
        os.fsync(fh.fileno())
        write_ms = (time.perf_counter() - started) * 1_000.0
    try:
        started = time.perf_counter()
        restarted = json.loads(path.read_text(encoding="utf-8"))
        restart_ms = (time.perf_counter() - started) * 1_000.0
    finally:
        path.unlink(missing_ok=True)

    started = time.perf_counter()
    replay_root = compute_state_root(restarted)
    replay_root_ms = (time.perf_counter() - started) * 1_000.0
    if replay_root != root:
        raise SystemExit(f"f001_replay_root_mismatch:{height}")

    next_state = candidate
    next_height = int(height) + 1
    next_state["blocks"][f"b{next_height}"] = {
        "height": next_height,
        "prev_block_id": f"b{height}",
        "block_ts_ms": next_height * 1_000,
    }
    next_state["height"] = next_height
    next_state["tip"] = f"b{next_height}"
    next_state["finalized"] = {"height": int(height) - 1, "block_id": f"b{int(height) - 1}"}
    started = time.perf_counter()
    removed = compact_bounded_block_history_in_place(next_state)
    per_block_compaction_ms = (time.perf_counter() - started) * 1_000.0
    if removed != 1 or len(next_state.get("blocks") or {}) != 10_000:
        raise SystemExit(f"f001_compaction_bound_failed:{height}")

    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {
        "height": int(height),
        "live_block_records": len(state["blocks"]),
        "checkpoint_records_committed": int(state["block_history_checkpoint"]["records_committed"]),
        "state_bytes": len(encoded),
        "deepcopy_ms": round(deepcopy_ms, 3),
        "state_root_ms": round(state_root_ms, 3),
        "serialize_ms": round(serialize_ms, 3),
        "commit_write_fsync_ms": round(write_ms, 3),
        "restart_parse_ms": round(restart_ms, 3),
        "replay_root_ms": round(replay_root_ms, 3),
        "per_block_compaction_ms": round(per_block_compaction_ms, 3),
        "peak_rss_kib": int(max(rss_before, rss_after)),
        "state_root": root,
        "replay_root": replay_root,
    }


def f002_scale_benchmark(megabytes: int) -> dict[str, Any]:
    os.environ["WEALL_MODE"] = "prod"
    sys.path.insert(0, str(PROTO / "src"))
    from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
    from weall.net.state_sync import DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES, StateSyncService

    target = int(megabytes) * 1024 * 1024
    blob = "x" * target
    state = {"height": 0, "accounts": {}, "stress_blob": blob}
    provider_calls = 0

    def provider() -> dict[str, Any]:
        nonlocal provider_calls
        provider_calls += 1
        return state

    service = StateSyncService(
        chain_id="p0-10-sync-scale",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=provider,
        require_trusted_anchor=True,
    )
    request = StateSyncRequestMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_REQUEST,
            chain_id="p0-10-sync-scale",
            schema_version="1",
            tx_index_hash="deadbeef",
            corr_id=f"scale-{megabytes}",
        ),
        mode="snapshot",
        selector={"trusted_anchor": {"height": 0}},
        from_height=0,
        to_height=None,
    )
    started = time.perf_counter()
    response = service.handle_request(request)
    elapsed_ms = (time.perf_counter() - started) * 1_000.0
    if response.ok or response.reason != "snapshot_too_large":
        raise SystemExit(f"f002_scale_cap_failed:{megabytes}:{response.reason}")
    return {
        "requested_state_mib": int(megabytes),
        "payload_bytes": int(target),
        "provider_calls": int(provider_calls),
        "service_ms": round(elapsed_ms, 3),
        "response_ok": bool(response.ok),
        "response_reason": str(response.reason),
        "response_cap_bytes": int(DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES),
        "peak_rss_kib": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
    }


def f002_concurrency_benchmark() -> dict[str, Any]:
    os.environ["WEALL_MODE"] = "test"
    os.environ["WEALL_NET_SYNC_WORK_MAX"] = "4"
    os.environ["WEALL_NET_SYNC_WORK_PER_PEER_MAX"] = "2"
    os.environ["WEALL_NET_SYNC_RESULTS_PER_TICK"] = "1"
    sys.path.insert(0, str(PROTO / "src"))
    import threading
    from weall.net.messages import BftVoteMsg, MsgType, StateSyncRequestMsg, WireHeader
    from weall.net.node import NetConfig, NetNode
    from weall.net.state_sync import StateSyncService
    from weall.net.transport_memory import InMemoryTransport

    started = threading.Event()
    release = threading.Event()
    vote_count = 0

    def provider() -> dict[str, Any]:
        started.set()
        if not release.wait(10.0):
            raise RuntimeError("benchmark_release_timeout")
        return {"height": 0, "accounts": {}}

    def on_vote(_peer: str, _msg: Any) -> None:
        nonlocal vote_count
        vote_count += 1

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=provider,
    )
    node = NetNode(
        cfg=NetConfig(chain_id="test", schema_version="1", tx_index_hash="deadbeef", peer_id="bench"),
        sync_service=service,
        transport=InMemoryTransport(),
        on_bft_vote=on_vote,
    )

    peers = []
    for i in range(6):
        peer_id = f"peer-{i}"
        rec = node._ensure_peer(peer_id)
        rec.router.handshake.status = "ESTABLISHED"
        rec.router.handshake.session_id = f"session-{i}"
        peers.append(rec)

    accepted = 0
    busy = 0
    for i, rec in enumerate(peers):
        req = StateSyncRequestMsg(
            header=WireHeader(
                type=MsgType.STATE_SYNC_REQUEST,
                chain_id="test",
                schema_version="1",
                tx_index_hash="deadbeef",
                corr_id=f"sync-{i}",
            ),
            mode="snapshot",
            selector=None,
            from_height=0,
            to_height=None,
        )
        result = rec.router.handle_message(req)
        if result is None:
            accepted += 1
        elif getattr(result, "reason", "") == "sync_busy":
            busy += 1
        else:
            raise SystemExit(f"unexpected_sync_admission:{getattr(result, 'reason', None)}")

    if not started.wait(2.0):
        raise SystemExit("sync_worker_did_not_start")
    debug = node.sync_work_debug()
    if accepted != 4 or busy != 2 or int(debug["outstanding"]) != 4:
        raise SystemExit(f"sync_budget_mismatch:{accepted}:{busy}:{debug}")

    latencies: list[float] = []
    vote = BftVoteMsg(
        header=WireHeader(
            type=MsgType.BFT_VOTE,
            chain_id="test",
            schema_version="1",
            tx_index_hash="deadbeef",
            corr_id="vote-bench",
        ),
        view=1,
        vote={"block_id": "b1"},
    )
    for _ in range(500):
        t0 = time.perf_counter()
        peers[0].router.handle_message(vote)
        latencies.append((time.perf_counter() - t0) * 1_000.0)

    release.set()
    deadline = time.monotonic() + 10.0
    max_completed = 0
    while time.monotonic() < deadline and node.sync_work_debug()["outstanding"]:
        debug = node.sync_work_debug()
        max_completed = max(max_completed, int(debug["completed_waiting"]))
        node.tick(max_packets=0)
        time.sleep(0.002)
    final_debug = node.sync_work_debug()
    node.close()
    if int(final_debug["outstanding"]) != 0:
        raise SystemExit(f"sync_work_did_not_drain:{final_debug}")

    ordered = sorted(latencies)
    return {
        "global_capacity": 4,
        "per_peer_capacity": 2,
        "accepted_requests": accepted,
        "busy_rejections": busy,
        "max_completed_waiting": max_completed,
        "results_per_tick": 1,
        "bft_votes_routed": vote_count,
        "bft_route_ms_median": round(statistics.median(ordered), 6),
        "bft_route_ms_p95": round(ordered[int(len(ordered) * 0.95) - 1], 6),
        "bft_route_ms_max": round(max(ordered), 6),
        "final_outstanding": int(final_debug["outstanding"]),
    }


def write_f001_svg(rows: list[dict[str, Any]]) -> None:
    width, height = 960, 540
    margin = 70
    metrics = [
        ("state_bytes", "State bytes"),
        ("state_root_ms", "State-root ms"),
        ("per_block_compaction_ms", "Per-block compaction ms"),
    ]
    panels = []
    for idx, (key, label) in enumerate(metrics):
        x0 = margin + idx * 300
        y0 = 80
        w = 240
        h = 360
        values = [float(row[key]) for row in rows]
        vmax = max(values) or 1.0
        points = []
        for j, value in enumerate(values):
            x = x0 + (j / max(1, len(values) - 1)) * w
            y = y0 + h - (value / vmax) * h
            points.append(f"{x:.1f},{y:.1f}")
        panels.append(
            f'<text x="{x0}" y="45" font-size="16">{label}</text>'
            f'<line x1="{x0}" y1="{y0+h}" x2="{x0+w}" y2="{y0+h}" stroke="black"/>'
            f'<line x1="{x0}" y1="{y0}" x2="{x0}" y2="{y0+h}" stroke="black"/>'
            f'<polyline points="{" ".join(points)}" fill="none" stroke="black" stroke-width="2"/>'
        )
        for j, row in enumerate(rows):
            x = x0 + (j / max(1, len(rows) - 1)) * w
            panels.append(
                f'<text x="{x-22:.1f}" y="{y0+h+22}" font-size="11">{int(row["height"]):,}</text>'
            )
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">'
        '<rect width="100%" height="100%" fill="white"/>'
        '<text x="70" y="510" font-size="13">Synthetic steady-state height (10,000 live ancestry records + rolling checkpoint)</text>'
        + "".join(panels)
        + "</svg>\n"
    )
    (EVIDENCE / "a15-f001-long-height.svg").write_text(svg, encoding="utf-8")


def run_benchmarks() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    script = Path("/tmp/p0_10_f001_f002_proof_closure.py")
    f001_rows: list[dict[str, Any]] = []
    for height in (100_000, 1_000_000, 5_000_000):
        raw = subprocess.check_output(
            [sys.executable, str(script), "--f001-height", str(height)],
            cwd=str(PROTO),
            env={**os.environ, "GITHUB_WORKSPACE": str(ROOT)},
            text=True,
        )
        f001_rows.append(json.loads(raw))
    (EVIDENCE / "a15-f001-long-height.json").write_text(
        json.dumps({"schema": "weall.a15_f001.long_height_evidence.v1", "rows": f001_rows}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with (EVIDENCE / "a15-f001-long-height.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(f001_rows[0].keys()))
        writer.writeheader()
        writer.writerows(f001_rows)
    write_f001_svg(f001_rows)

    f002_rows: list[dict[str, Any]] = []
    for size in (10, 100, 500):
        raw = subprocess.check_output(
            [sys.executable, str(script), "--f002-scale", str(size)],
            cwd=str(PROTO),
            env={**os.environ, "GITHUB_WORKSPACE": str(ROOT)},
            text=True,
        )
        f002_rows.append(json.loads(raw))
    (EVIDENCE / "a15-f002-state-sync-scale.json").write_text(
        json.dumps({"schema": "weall.a15_f002.state_sync_scale_evidence.v1", "rows": f002_rows}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    concurrency = f002_concurrency_benchmark()
    (EVIDENCE / "a15-f002-concurrency.json").write_text(
        json.dumps({"schema": "weall.a15_f002.concurrency_evidence.v1", **concurrency}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return f001_rows, f002_rows, concurrency


def patch_status(f001: list[dict[str, Any]], f002: list[dict[str, Any]], concurrency: dict[str, Any]) -> None:
    path = ROOT / "docs" / "audit" / "WeAll-A01-A20-P0-Closure-Status-20260930.md"
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    replaced = False
    for i, line in enumerate(lines):
        if line.startswith("| P0-10 Bounded production state / state sync / permanent account state |"):
            lines[i] = (
                "| P0-10 Bounded production state / state sync / permanent account state | A15-F001..F003 | CLOSED — PATCHED AND PROVEN | "
                "A15-F001 bounds root-visible live ancestry to a consensus-committed ceiling with a rolling checkpoint commitment; restart, proposer/follower equality, fork-choice/HotStuff finality and state-sync verification cross the compaction boundary. Synthetic steady-state evidence at 100k/1M/5M heights retains exactly 10,000 live ancestry records while measuring state size, deepcopy, state-root/replay-root, durable serialization/write, restart parse, RSS and per-block compaction. A15-F002 uses finite wire-derived response caps, cheap trusted-anchor/range preflight before state materialization, and a global/per-peer bounded off-loop worker with bounded result drain; 10/100/500 MiB synthetic state requests remain response-capped, concurrent accepted work is globally bounded, excess requests fail `sync_busy`, and BFT routing remains independently serviceable under saturated sync work. A15-F003 remains closed by finite nonzero identity-bound registration work without claiming human uniqueness or a lifetime account cap. |"
            )
            replaced = True
            break
    if not replaced:
        raise SystemExit("p0_10_status_row_not_found")
    text = "\n".join(lines) + "\n"
    text = text.replace(
        "These exact-head passes prove the current source/evidence tree; they do not override the still-open P0-06 and A15-F001/A15-F002 design/implementation blockers.",
        "These exact-head passes prove the current source/evidence tree. P0-10 A15-F001/F002 are now closed by the bounded-history/state-sync architecture plus the dedicated long-height/large-state proof run; P0-06 remains the only open P0 track.",
    )
    old_order = (
        "1. Complete P0-10 A15-F001 bounded consensus-visible ancestry/history and A15-F002 finite authenticated state-sync work/response architecture with adversarial stress evidence.\n"
        "2. Adjudicate P0-06 A08/A20 together so global human uniqueness and reviewer anti-grinding share one coherent protocol trust model.\n"
        "3. After those remaining runtime/design tracks close, capture the final closure SHA/tree, regenerate final same-tree public evidence, and require all four normal exact-head gates plus the P0 assurance gate to remain green."
    )
    new_order = (
        "1. Adjudicate P0-06 A08/A20 together so global human uniqueness and reviewer anti-grinding share one coherent protocol trust model.\n"
        "2. After P0-06 closes, capture the final closure SHA/tree, regenerate final same-tree public evidence, and require all four normal exact-head gates plus the P0 assurance gate to remain green."
    )
    if old_order not in text:
        raise SystemExit("next_implementation_order_anchor_missing")
    text = text.replace(old_order, new_order, 1)

    run_id = str(os.environ.get("GITHUB_RUN_ID") or "local")
    evidence_section = textwrap.dedent(
        f'''

## P0-10 A15-F001/F002 dedicated closure evidence

Dedicated closure workflow run: `{run_id}`.

A15-F001 synthetic steady-state heights were exercised at 100,000 / 1,000,000 / 5,000,000 while retaining the protocol ceiling of 10,000 live ancestry records plus a constant-size rolling checkpoint. The run measured candidate deepcopy, state-root and replay-root equality, canonical serialization/write, restart parse, RSS, and one-block compaction at each height. The largest measured state-root time was `{max(float(r['state_root_ms']) for r in f001):.3f} ms`; the largest encoded bounded state was `{max(int(r['state_bytes']) for r in f001):,}` bytes. These are CI-host synthetic measurements, not validator-hardware throughput claims.

A15-F002 exercised synthetic 10 / 100 / 500 MiB state snapshots. Every oversized request was rejected as `snapshot_too_large` under the finite wire-derived response cap; the 500 MiB case completed in `{float(f002[-1]['service_ms']):.3f} ms` with peak process RSS `{int(f002[-1]['peak_rss_kib']):,} KiB` on the CI host. A saturated worker admitted `{int(concurrency['accepted_requests'])}` requests at the global work cap, rejected `{int(concurrency['busy_rejections'])}` excess requests as `sync_busy`, drained at one result per tick, and routed `{int(concurrency['bft_votes_routed'])}` BFT vote messages with measured max callback latency `{float(concurrency['bft_route_ms_max']):.6f} ms`. These are bounded stress measurements, not network throughput claims.

The workflow artifact contains the machine-readable JSON/CSV evidence and the long-height SVG plot. Closure remains contingent on the workflow-free exact tree passing the normal Backend CI, Reviewer Readiness, Web CI and Secrets Guard gates.
'''
    )
    insertion = "\n## Additional CI blockers discovered during closure\n"
    if "## P0-10 A15-F001/F002 dedicated closure evidence" not in text:
        if insertion not in text:
            raise SystemExit("status_evidence_insertion_anchor_missing")
        text = text.replace(insertion, evidence_section + insertion, 1)
    path.write_text(text, encoding="utf-8")


def validate_and_commit() -> None:
    run("ruff", "check", "--fix", "tests/test_p0_10_a15_f001_bounded_block_history.py", "tests/test_p0_10_a15_f002_state_sync_resource_bounds.py")
    run("ruff", "format", "tests/test_p0_10_a15_f001_bounded_block_history.py", "tests/test_p0_10_a15_f002_state_sync_resource_bounds.py")
    run("ruff", "check", "tests/test_p0_10_a15_f001_bounded_block_history.py", "tests/test_p0_10_a15_f002_state_sync_resource_bounds.py")

    run(
        "pytest", "-q",
        "tests/test_p0_10_a15_f001_bounded_block_history.py",
        "tests/test_p0_10_a15_f002_state_sync_resource_bounds.py",
        "tests/test_priority0_long_chain_ancestry_unbounded.py",
        "tests/test_executor_state_sync.py",
        "tests/test_executor_state_sync_progress.py",
        "tests/test_executor_state_sync_progress_rejection.py",
    )

    f001, f002, concurrency = run_benchmarks()
    patch_status(f001, f002, concurrency)

    run("python", "scripts/gen_public_beta_blocker_report_v1_5.py")
    run("python", "scripts/gen_release_evidence_manifest_v1_5.py")
    run("python", "scripts/gen_current_verified_claims.py")
    run("python", "scripts/compile_v2_spec.py")

    run("pip-audit", "-r", "requirements.lock")
    run("pip-audit", "-r", "requirements-dev.lock")
    run("python", "-m", "tooling.canon_lint")
    run("python", "scripts/check_generated.py")
    run("python", "scripts/compile_v2_spec.py", "--check", env={"PYTHONPATH": "src"})
    run("python", "scripts/check_v15_public_readiness_artifacts.py", env={"PYTHONDONTWRITEBYTECODE": "1"})
    run("python", "scripts/check_public_claim_freshness.py")
    run("python", "scripts/gen_current_verified_claims.py", "--check")
    run("python", "tests/p0_assurance.py", "gate", "--report", "artifacts/p0-assurance/p0_assurance_report.json", "--timeout-seconds", "120")

    run("npm", "ci", cwd=WEB)
    run("npm", "run", "dependency-audit", cwd=WEB)
    run("npm", "run", "typecheck", cwd=WEB)
    run("npm", "run", "test:account-custody-crypto-source", cwd=WEB)
    run("npm", "run", "build", cwd=WEB)

    run("pytest", "-q")

    run("git", "diff", "--check", cwd=ROOT)
    changed = set(output("git", "diff", "--name-only", BASE_SHA, cwd=ROOT).splitlines())
    controls = {
        ".github/workflows/p0-10-a15-f001-f002-proof-closure.yml",
        "Weall-Protocol/scripts/p0_10_a15_f001_f002_proof_closure.py",
    }
    if changed & controls:
        raise SystemExit(f"temporary_controls_survived:{sorted(changed & controls)}")
    required = {
        "Weall-Protocol/tests/test_p0_10_a15_f001_bounded_block_history.py",
        "Weall-Protocol/tests/test_p0_10_a15_f002_state_sync_resource_bounds.py",
        "docs/audit/WeAll-A01-A20-P0-Closure-Status-20260930.md",
        "Weall-Protocol/generated/current_verified_claims.json",
    }
    missing = sorted(required - changed)
    if missing:
        raise SystemExit(f"missing_required_closure_diff:{missing}")
    allowed_exact = {
        "Weall-Protocol/tests/test_p0_10_a15_f001_bounded_block_history.py",
        "Weall-Protocol/tests/test_p0_10_a15_f002_state_sync_resource_bounds.py",
        "docs/audit/WeAll-A01-A20-P0-Closure-Status-20260930.md",
        "Weall-Protocol/docs/CURRENT_VERIFIED_CLAIMS.md",
        "Weall-Protocol/generated/current_verified_claims.json",
        "Weall-Protocol/generated/public_beta_blocker_report_v1_5.json",
        "Weall-Protocol/generated/release_evidence_manifest_v1_5.json",
        "Weall-Protocol/artifacts/p0-assurance/p0_assurance_report.json",
        "web/src/generated/protocolStatus.ts",
    }
    unexpected = sorted(
        path for path in changed
        if path not in allowed_exact and not path.startswith("Weall-Protocol/generated/v2/")
    )
    if unexpected:
        raise SystemExit(f"unexpected_p0_10_diff:{unexpected}")

    run("git", "config", "user.name", "github-actions[bot]", cwd=ROOT)
    run("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com", cwd=ROOT)
    run("git", "add", "-A", cwd=ROOT)
    run("git", "commit", "-m", "test: prove A15-F001/F002 bounded resource closure", cwd=ROOT)
    source_commit = output("git", "rev-parse", "HEAD", cwd=ROOT)
    source_tree = output("git", "rev-parse", "HEAD^{tree}", cwd=ROOT)

    run("python", "scripts/check_v2_spec_clean_checkout.py")
    run("python", "scripts/check_v15_public_readiness_artifacts.py", env={"PYTHONDONTWRITEBYTECODE": "1"})
    run("git", "push", "origin", f"HEAD:{BRANCH}", cwd=ROOT)
    (EVIDENCE / "exact-head.txt").write_text(
        f"source_commit={source_commit}\nsource_tree={source_tree}\nworkflow_run_id={os.environ.get('GITHUB_RUN_ID', '')}\n",
        encoding="utf-8",
    )
    print(f"P0-10 source commit: {source_commit}")
    print(f"P0-10 source tree:   {source_tree}")


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--f001-height":
        print(json.dumps(f001_height_benchmark(int(sys.argv[2])), sort_keys=True))
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "--f002-scale":
        print(json.dumps(f002_scale_benchmark(int(sys.argv[2])), sort_keys=True))
        return 0

    if output("git", "merge-base", BASE_SHA, "HEAD", cwd=ROOT) != BASE_SHA:
        raise SystemExit("closure_base_not_ancestor")
    patch_tests()
    CONTROL_SCRIPT.unlink(missing_ok=True)
    CONTROL_WORKFLOW.unlink(missing_ok=True)
    validate_and_commit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
