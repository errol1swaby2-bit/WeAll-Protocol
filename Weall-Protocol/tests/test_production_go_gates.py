from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.crypto.pq_mldsa import MLDSA65_PUBLIC_KEY_BYTES
from weall.runtime.commitments import canonical_json_sha256
from weall.runtime.state_hash import compute_state_root
from weall.testing.sigtools import deterministic_mldsa_keypair

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


def test_build_and_assert_production_genesis_artifacts(tmp_path: Path) -> None:
    genesis = tmp_path / "genesis.ledger.prod.json"
    manifest = tmp_path / "weall-genesis.json"
    founding_pubkey, _seed = deterministic_mldsa_keypair(label="test-production-go-gates")
    assert len(founding_pubkey) == MLDSA65_PUBLIC_KEY_BYTES * 2
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
        capture_output=True,
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
        capture_output=True,
        check=False,
    )
    assert checked.returncode == 0, checked.stderr + checked.stdout
    report = json.loads(checked.stdout.split("\nok:", 1)[0])
    assert report["ok"] is True
    assert report["manifest_chain_id"] == "weall-prod-batch323"
    assert report["genesis_chain_id"] == "weall-prod-batch323"

    # Rehashing a locally tampered ledger must not make a shortened signer
    # identity acceptable as a full post-quantum validator key.
    original_genesis = json.loads(genesis.read_text(encoding="utf-8"))
    original_manifest = json.loads(manifest.read_text(encoding="utf-8"))
    founder_id = "@founder-batch323"
    for mode, expected_code in (
        ("allowlist", "genesis_bootstrap_allowlist_pubkey_invalid"),
        ("account_key", "genesis_founder_key_invalid"),
    ):
        mutated_genesis = copy.deepcopy(original_genesis)
        if mode == "allowlist":
            mutated_genesis["params"]["bootstrap_allowlist"][founder_id]["pubkey"] = "a" * 64
        else:
            by_id = mutated_genesis["accounts"][founder_id]["keys"]["by_id"]
            first_key = next(iter(by_id))
            by_id[first_key]["pubkey"] = "a" * 64
        mutated_manifest = copy.deepcopy(original_manifest)
        mutated_manifest["genesis_hash"] = canonical_json_sha256(mutated_genesis)
        mutated_manifest["genesis_state_root"] = compute_state_root(mutated_genesis)
        genesis.write_text(json.dumps(mutated_genesis), encoding="utf-8")
        manifest.write_text(json.dumps(mutated_manifest), encoding="utf-8")
        rejected = subprocess.run(
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
            capture_output=True,
            check=False,
        )
        assert rejected.returncode == 2, rejected.stderr + rejected.stdout
        codes = {row["code"] for row in json.loads(rejected.stdout)["issues"]}
        assert expected_code in codes


def test_assert_production_genesis_rejects_template_placeholders(tmp_path: Path) -> None:
    genesis = tmp_path / "genesis.ledger.prod.json"
    manifest = tmp_path / "weall-genesis.json"
    genesis.write_text(
        json.dumps(
            {
                "chain_id": "weall-prod",
                "time": 0,
                "accounts": {
                    "SYSTEM": {},
                    "FOUNDING_NODE_ID": {"keys": {"PUT_FOUNDING_PUBKEY_HEX_HERE": {}}},
                },
                "params": {
                    "genesis_time": 0,
                    "economic_unlock_time": 0,
                    "economics_enabled": False,
                    "bootstrap_founder_account": "FOUNDING_NODE_ID",
                    "bootstrap_allowlist": {
                        "FOUNDING_NODE_ID": {"pubkey": "PUT_FOUNDING_PUBKEY_HEX_HERE"}
                    },
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
        capture_output=True,
        check=False,
    )
    assert checked.returncode == 2
    report = json.loads(checked.stdout)
    codes = {item["code"] for item in report["issues"]}
    assert "manifest_tx_index_hash_unpinned" in codes
    assert "manifest_protocol_profile_hash_unpinned" in codes
    assert "manifest_trusted_authority_pubkey_unpinned" in codes
    assert "genesis_bootstrap_founder_account_unpinned" in codes


def test_operator_status_reports_observer_mode_and_no_local_signing(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_DB_PATH", str(tmp_path / "operator-go-gate.db"))
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


def test_dockerfile_default_uses_production_runner() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert 'CMD ["sh", "-c", "/app/scripts/run_node.sh"]' in text
    assert "--workers ${GUNICORN_WORKERS:-2}" not in text


def test_frontend_backend_congruity_script_supports_exported_layout() -> None:
    result = subprocess.run(
        [sys.executable, str(CONGRUITY)],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout

    expected_repo = ROOT.parent.resolve()
    expected_frontend = (expected_repo / "web").resolve()
    expected_backend = ROOT.resolve()

    assert f"Repo root: {expected_repo}" in result.stdout
    assert f"Frontend:  {expected_frontend}" in result.stdout
    assert f"Backend:   {expected_backend}" in result.stdout
    assert "PASS" in result.stdout
