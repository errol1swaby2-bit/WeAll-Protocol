from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app

ROOT = Path(__file__).resolve().parents[1]
BUILD_GENESIS = ROOT / "scripts" / "build_production_genesis_manifest.py"
ASSERT_GENESIS = ROOT / "scripts" / "assert_production_genesis_artifacts.py"
CONGRUITY = ROOT / "scripts" / "audit_frontend_backend_congruity.py"
DOCKERFILE = ROOT / "Dockerfile"


class _FakePool:
    def size(self) -> int:
        return 0


class _ObserverExecutor:
    def __init__(self) -> None:
        self.node_id = "observer-node-1"
        self.mempool = _FakePool()
        self.attestation_pool = _FakePool()
        self.block_loop_running = False
        self.block_loop_unhealthy = False
        self.block_loop_last_error = ""
        self.block_loop_consecutive_failures = 0
        self._schema_version_cached = "1"

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": "weall-prod-test",
            "height": 0,
            "tip": "",
            "meta": {
                "schema_version": "1",
                "tx_index_hash": "txhash",
                "observer_mode": True,
                "validator_signing_enabled": False,
                "signing_block_reason": "observer_mode",
            },
            "roles": {"validators": {"active_set": ["@genesis"]}},
            "validators": {"registry": {}},
            "consensus": {
                "epochs": {"current": 0},
                "validator_set": {
                    "epoch": 0,
                    "set_hash": "genesis-hash",
                    "active_set": ["@genesis"],
                    "pending": {},
                },
            },
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def tx_index_hash(self) -> str:
        return "txhash"

    def validator_signing_enabled(self) -> bool:
        return False

    def _effective_signing_block_reason(self) -> str:
        return "observer_mode"

    def _current_validator_epoch(self) -> int:
        return 0

    def _current_validator_set_hash(self) -> str:
        return "genesis-hash"


def test_build_and_assert_production_genesis_artifacts_batch323(tmp_path: Path) -> None:
    genesis = tmp_path / "genesis.ledger.prod.json"
    manifest = tmp_path / "weall-genesis.json"
    founding_pubkey = "a" * 64
    authority_pubkey = "b" * 64

    built = subprocess.run(
        [
            sys.executable,
            str(BUILD_GENESIS),
            "--chain-id",
            "weall-prod-batch323",
            "--founding-account",
            "@founder-batch323",
            "--founding-pubkey",
            founding_pubkey,
            "--authority-pubkey",
            authority_pubkey,
            "--genesis-time",
            "1900000000",
            "--genesis-out",
            str(genesis),
            "--manifest-out",
            str(manifest),
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert built.returncode == 0, built.stderr + built.stdout

    checked = subprocess.run(
        [
            sys.executable,
            str(ASSERT_GENESIS),
            "--manifest",
            str(manifest),
            "--genesis",
            str(genesis),
            "--tx-index",
            str(ROOT / "generated" / "tx_index.json"),
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert checked.returncode == 0, checked.stderr + checked.stdout
    report = json.loads(checked.stdout.split("\nok:", 1)[0])
    assert report["ok"] is True
    assert report["manifest_chain_id"] == "weall-prod-batch323"
    assert report["genesis_chain_id"] == "weall-prod-batch323"


def test_assert_production_genesis_rejects_template_placeholders_batch323(tmp_path: Path) -> None:
    genesis = tmp_path / "genesis.ledger.prod.json"
    manifest = tmp_path / "weall-genesis.json"
    genesis.write_text(
        json.dumps(
            {
                "chain_id": "weall-prod",
                "time": 0,
                "accounts": {"SYSTEM": {}, "FOUNDING_NODE_ID": {"keys": {"PUT_FOUNDING_PUBKEY_HEX_HERE": {}}}},
                "params": {
                    "genesis_time": 0,
                    "economic_unlock_time": 0,
                    "economics_enabled": False,
                    "bootstrap_founder_account": "FOUNDING_NODE_ID",
                    "bootstrap_allowlist": {"FOUNDING_NODE_ID": {"pubkey": "PUT_FOUNDING_PUBKEY_HEX_HERE"}},
                    "poh_bootstrap_mode": "allowlist",
                    "poh_bootstrap_auto_lock_rule": "active_validators>=BFT_MIN_VALIDATORS",
                },
            }
        ),
        encoding="utf-8",
    )
    manifest.write_text(
        json.dumps(
            {
                "chain_id": "weall-prod",
                "mode": "prod",
                "profile": "production_service",
                "schema_version": "1",
                "tx_index_hash": "REPLACE_WITH_TX_INDEX_HASH",
                "genesis_hash": "REPLACE_WITH_GENESIS_HASH",
                "genesis_state_root": "REPLACE_WITH_STATE_ROOT",
                "protocol_profile_hash": "",
                "trusted_authority_pubkeys": ["REPLACE_WITH_PRODUCTION_AUTHORITY_PUBKEY_HEX"],
                "authority": {},
            }
        ),
        encoding="utf-8",
    )

    checked = subprocess.run(
        [
            sys.executable,
            str(ASSERT_GENESIS),
            "--manifest",
            str(manifest),
            "--genesis",
            str(genesis),
            "--tx-index",
            str(ROOT / "generated" / "tx_index.json"),
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert checked.returncode == 2
    report = json.loads(checked.stdout)
    codes = {item["code"] for item in report["issues"]}
    assert "manifest_tx_index_hash_unpinned" in codes
    assert "manifest_protocol_profile_hash_unpinned" in codes
    assert "manifest_trusted_authority_pubkey_unpinned" in codes
    assert "genesis_bootstrap_founder_account_unpinned" in codes


def test_operator_status_reports_observer_mode_and_no_local_signing_batch323(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "observer_onboarding")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    app = create_app(boot_runtime=False)
    app.state.executor = _ObserverExecutor()
    client = TestClient(app)

    body = client.get("/v1/status/operator").json()

    assert body["mode"] == "observer"
    assert body["operator"]["signing_enabled_locally"] is False
    assert body["operator"]["signing_allowed_by_consensus_state"] is False
    assert body["operator"]["signing_block_reason"] == "observer_mode"


def test_dockerfile_default_uses_production_runner_batch323() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert 'CMD ["sh", "-c", "/app/scripts/run_node.sh"]' in text
    assert "--workers ${GUNICORN_WORKERS:-2}" not in text


def test_frontend_backend_congruity_script_supports_exported_layout_batch323() -> None:
    result = subprocess.run(
        [sys.executable, str(CONGRUITY)],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "WeAll-Protocol/web" in result.stdout
    assert "PASS" in result.stdout
