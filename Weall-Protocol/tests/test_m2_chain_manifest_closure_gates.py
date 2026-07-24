from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.status import router as status_router
from weall.runtime.executor import WeAllExecutor

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent


def test_controlled_devnet_manifest_generator_is_current() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/gen_controlled_devnet_chain_manifest.py", "--check"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_state_root_comparison_fails_closed_on_chain_manifest_status() -> None:
    text = (ROOT / "scripts" / "devnet_compare_state_roots.sh").read_text(encoding="utf-8")
    assert 'manifest.get("ok") is not True' in text
    assert 'manifest.get("tx_index_hash_matches") is not True' in text
    assert "chain_manifest_mode_not_controlled_devnet" in text
    assert "OK: node chain manifests are valid and current" in text


def test_cross_node_live_runner_invokes_fail_closed_manifest_comparison() -> None:
    text = (ROOT / "scripts" / "devnet_run_cross_node_convergence_live.sh").read_text(
        encoding="utf-8"
    )
    probe = text.index("devnet_cross_node_convergence.sh")
    compare = text.index("devnet_compare_state_roots.sh", probe)
    complete = text.index("OK: live controlled-devnet cross-node convergence probe passed")
    assert probe < compare < complete


def test_m2_convergence_gates_require_valid_manifest_marker() -> None:
    for rel in (
        "scripts/run_m2_restart_replay_gate.sh",
        "scripts/run_m2_two_node_state_root_gate.sh",
        "scripts/run_m2_observer_catchup_gate.sh",
    ):
        text = (PROJECT_ROOT / rel).read_text(encoding="utf-8")
        assert 'grep -q "OK: node chain manifests are valid and current"' in text


def test_fresh_joiner_does_not_treat_provisional_state_as_manifest_genesis(
    tmp_path: Path, monkeypatch
) -> None:
    manifest_path = ROOT / "configs" / "chains" / "weall-controlled-devnet.json"
    tx_index_path = ROOT / "generated" / "tx_index.json"

    monkeypatch.setenv("WEALL_MODE", "controlled_devnet")
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(manifest_path))
    monkeypatch.setenv("WEALL_REQUIRE_CHAIN_MANIFEST", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "0")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "joiner.db"),
        node_id="@devnet-joiner",
        chain_id="weall-controlled-devnet",
        tx_index_path=str(tx_index_path),
    )
    app = FastAPI()
    app.include_router(status_router, prefix="/v1")
    app.state.executor = ex

    body = TestClient(app).get("/v1/chain/identity").json()

    assert body["height"] == 0
    assert body["chain_manifest"]["ok"] is True
    assert "chain_manifest_genesis_state_root_mismatch" not in body["chain_manifest"]["issues"]
    assert body["state_root"]
    assert body["state_root"] != body["chain_manifest"]["genesis_state_root"]
