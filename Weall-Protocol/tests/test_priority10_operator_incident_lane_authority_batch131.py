from __future__ import annotations

from pathlib import Path

from weall.runtime.chain_config import load_chain_config
from weall.runtime.executor import WeAllExecutor
from weall.runtime.operator_incident_lane import (
    build_operator_incident_lane,
    build_operator_incident_lane_summary,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, chain_id: str) -> WeAllExecutor:
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    return WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@validator",
        chain_id=chain_id,
        tx_index_path=tx_index_path,
    )


def _cfg_for(tmp_path: Path, chain_id: str):
    cfg = load_chain_config()
    return cfg.__class__(
        **{
            **cfg.__dict__,
            "db_path": str(tmp_path / "node.db"),
            "tx_index_path": str(_repo_root() / "generated" / "tx_index.json"),
            "chain_id": chain_id,
            "node_id": "@validator",
        }
    )


def test_operator_incident_lane_summary_carries_authority_contract_batch131(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    _make_executor(tmp_path, chain_id="incident-lane-authority")
    lane = build_operator_incident_lane(
        cfg=_cfg_for(tmp_path, chain_id="incident-lane-authority"),
        db_path=tmp_path / "node.db",
        tx_index_path=_repo_root() / "generated" / "tx_index.json",
        remote_forensics=None,
        peer_reports=[],
    )

    summary = build_operator_incident_lane_summary(lane)
    contract = summary["authority_contract"]
    assert contract["contract_source"] == "runtime"
    assert contract["requested_state"] == "production_service"
    assert contract["validator_requested"] is True
    assert summary["severity"] in {"ok", "warning", "critical"}
