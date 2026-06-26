from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.api.routes_public_parts.content import _feed_cursor_pack, _feed_rank_score, _sort_feed_items

ROOT = Path(__file__).resolve().parents[1]


class _FakeExecutor:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state


def _client(state: dict[str, Any]) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    return TestClient(app, raise_server_exceptions=False)


def _run_json(script: str) -> dict[str, Any]:
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / script), "--json"], cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return json.loads(proc.stdout)


def test_validator_rehearsal_uses_process_model_and_preserves_boundaries() -> None:
    out = _run_json("rehearse_real_validator_network_v1_5.py")
    assert out["ok"] is True
    assert out["process_model"] == "multiprocessing_queue_local_processes"
    assert out["public_validator_enabled"] is False
    assert out["minority_partition_result"] == "finality_threshold_not_met"
    assert out["rejoin_root_matches_reference"] is True
    assert len(set(out["roots_after_restart"])) == 1


def test_fresh_node_replay_uses_durable_blocks_and_rejects_corruption() -> None:
    out = _run_json("rehearse_fresh_node_replay_sync_v1_5.py")
    assert out["ok"] is True
    assert out["durable_block_store_used"] is True
    assert out["snapshot_used"] is False
    assert out["corrupt_block_rejected"] is True
    assert out["source_state_root"] == out["fresh_state_root"] == out["interrupted_resume_root"]


def test_full_lifecycle_exercises_real_runtime_domains() -> None:
    out = _run_json("rehearse_v15_full_lifecycle.py")
    assert out["ok"] is True
    journey = out["journey"]
    assert journey["post_id"] == "post:lifecycle:1"
    assert journey["dispute_id"] == "d-life"
    assert journey["final_enforcement_count"] >= 1
    assert journey["storage_retrieval_confirmed"] is True
    assert journey["economics_locked_rejection"] is True
    assert journey["protocol_upgrade_record_only"] is True
    assert out["locked_boundaries"] == {"public_validators": False, "live_economics": False, "automatic_upgrades": False, "production_helpers": False}


def test_ranked_feed_cursor_uses_score_nonce_id_and_does_not_skip_new_quiet_posts() -> None:
    state = {
        "content": {
            "posts": {
                "old-popular": {"post_id": "old-popular", "author": "@a", "body": "old", "visibility": "public", "created_nonce": 10, "reactions": {"like": 10}},
                "new-quiet": {"post_id": "new-quiet", "author": "@a", "body": "new", "visibility": "public", "created_nonce": 20, "reactions": {}},
                "middle": {"post_id": "middle", "author": "@a", "body": "middle", "visibility": "public", "created_nonce": 15, "reactions": {"like": 1}},
            },
            "comments": {},
            "reactions": {},
            "media": {},
        }
    }
    with _client(state) as client:
        first = client.get("/v1/feed?rank=engagement&limit=1")
        assert first.status_code == 200, first.text
        body = first.json()
        assert body["items"][0]["post_id"] == "old-popular"
        assert body["ranking"]["cursor_model"] == "rank_score_nonce_id"
        second = client.get(f"/v1/feed?rank=engagement&limit=5&cursor={body['next_cursor']}")
        assert second.status_code == 200, second.text
        ids = [item["post_id"] for item in second.json()["items"]]
        assert ids == ["middle", "new-quiet"]


def test_recency_cursor_remains_legacy_compatible() -> None:
    item = {"post_id": "post-1", "id": "post-1", "created_at_nonce": 42, "feed_rank_score": 42}
    cursor = _feed_cursor_pack(mode="recency", obj=item)
    assert "|" not in cursor
    state = {"content": {"posts": {"post-1": {"post_id": "post-1", "author": "@a", "body": "one", "visibility": "public", "created_nonce": 42}}, "comments": {}, "reactions": {}, "media": {}}}
    with _client(state) as client:
        res = client.get("/v1/feed?limit=1")
        assert res.status_code == 200
        assert res.json()["ranking"]["cursor_model"] == "legacy_nonce_id"


def test_sort_key_matches_cursor_model_for_ranked_modes() -> None:
    items = [
        {"post_id": "old-popular", "created_at_nonce": 10, "reaction_total": 5, "comment_total": 2},
        {"post_id": "new-quiet", "created_at_nonce": 20, "reaction_total": 0, "comment_total": 0},
    ]
    ranked = []
    for item in items:
        obj = dict(item)
        obj["feed_rank_score"] = _feed_rank_score(obj, mode="engagement")
        ranked.append(obj)
    assert [x["post_id"] for x in _sort_feed_items(ranked, mode="engagement")] == ["old-popular", "new-quiet"]


def test_sensitive_route_metadata_is_explicit_and_generated_artifact_is_fresh() -> None:
    metadata = json.loads((ROOT / "specs" / "api_contracts" / "v1_5_route_metadata.json").read_text())
    routes = metadata["routes"]
    for route in [
        "GET /v1/session/me",
        "GET /v1/dev/bootstrap-secret",
        "GET /v1/poh/async/case/{case_id}",
        "GET /v1/poh/tier2/case/{case_id}",
        "GET /v1/poh/live/session/{session_id}/webrtc/signals",
        "GET /v1/net/relay/fetch",
        "GET /v1/observer/edge/status",
        "GET /v1/feed",
    ]:
        assert route in routes
        assert "static_generator_heuristic" not in json.dumps(routes[route])

    proc = subprocess.run([sys.executable, "scripts/gen_api_contract_map.py", "--check"], cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_proof_artifact_is_fresh() -> None:
    proc = subprocess.run([sys.executable, "scripts/gen_b523_b527_completion_proof_v1_5.py", "--check"], cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    artifact = json.loads((ROOT / "generated" / "b523_b527_completion_proof_v1_5.json").read_text())
    assert artifact["ok"] is True
    assert artifact["feed_ranking"]["complete_for_deterministic_public_pagination"] is True
    assert artifact["feed_ranking"]["complete_for_recommendation_discovery"] is False
