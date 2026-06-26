from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "scripts" / "build_external_observer_bundle.py"
VERIFY = ROOT / "scripts" / "verify_node_operator_onboarding_bundle.py"
SMOKE = ROOT / "scripts" / "external_observer_onboarding_smoke.sh"
LIVE_GATE = ROOT / "scripts" / "external_observer_live_gate.sh"
REHEARSAL = ROOT / "scripts" / "rehearse_external_observer_two_machine.sh"
CONTROLLED_MANIFEST = ROOT / "configs" / "chains" / "weall-controlled-devnet.json"


def test_controlled_devnet_manifest_exists_for_external_observer_rehearsal() -> None:
    manifest = json.loads(CONTROLLED_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["chain_id"] == "weall-controlled-devnet"
    assert manifest["mode"] == "controlled_devnet"
    assert manifest["profile"] == "controlled_devnet_service"
    assert manifest["authority"]["expected_profile"] == "controlled_devnet_rehearsal"
    assert manifest["authority"]["lan_http_allowed_for_rehearsal"] is True
    assert manifest["authority"]["authority_snapshot_required"] is False
    assert manifest["authority"]["signed_snapshot_required"] is False
    assert manifest["tx_index_hash"]
    assert manifest["protocol_profile_hash"]


def test_controlled_devnet_bundle_allows_private_http_only_with_explicit_rehearsal_flag(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "controlled-observer-bundle.json"
    built = subprocess.run(
        [
            sys.executable,
            str(BUILD),
            "--manifest",
            str(CONTROLLED_MANIFEST),
            "--genesis-api-base",
            "http://10.131.107.82:8000",
            "--out",
            str(bundle),
            "--generated-at-ms",
            "1900000000000",
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert built.returncode == 0, built.stderr + built.stdout

    data = json.loads(bundle.read_text(encoding="utf-8"))
    assert data["profile"] == "controlled_devnet_rehearsal"
    assert data["chain"]["chain_id"] == "weall-controlled-devnet"
    assert data["chain"]["manifest_path_hint"].endswith("weall-controlled-devnet.json")
    assert data["authority"]["profile"] == "controlled_devnet_rehearsal"
    assert data["authority"]["authority_url"] == "http://10.131.107.82:8000"
    assert data["recommended_commands"]["verify_bundle"].startswith("WEALL_ALLOW_LAN_GENESIS_API=1")

    env = os.environ.copy()
    env.pop("WEALL_ALLOW_LAN_GENESIS_API", None)
    denied = subprocess.run(
        [sys.executable, str(VERIFY), "--bundle", str(bundle), "--manifest", str(CONTROLLED_MANIFEST), "--json"],
        cwd=str(ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert denied.returncode != 0
    denied_report = json.loads(denied.stdout)
    assert "rehearsal_lan_authority_url_requires_WEALL_ALLOW_LAN_GENESIS_API=1" in denied_report["issues"]

    env["WEALL_ALLOW_LAN_GENESIS_API"] = "1"
    allowed = subprocess.run(
        [sys.executable, str(VERIFY), "--bundle", str(bundle), "--manifest", str(CONTROLLED_MANIFEST), "--json"],
        cwd=str(ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert allowed.returncode == 0, allowed.stderr + allowed.stdout
    allowed_report = json.loads(allowed.stdout)
    assert allowed_report["ok"] is True
    assert allowed_report["issues"] == []

    shell = subprocess.run(
        [sys.executable, str(VERIFY), "--bundle", str(bundle), "--manifest", str(CONTROLLED_MANIFEST), "--emit-shell-env"],
        cwd=str(ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert shell.returncode == 0, shell.stderr + shell.stdout
    assert "export WEALL_MODE=controlled_devnet" in shell.stdout
    assert "export WEALL_AUTHORITY_PROFILE=controlled_devnet_rehearsal" in shell.stdout


def test_production_bundle_still_rejects_plain_http_authority(tmp_path: Path) -> None:
    manifest = tmp_path / "prod-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "authority": {
                    "authority_snapshot_required": True,
                    "expected_profile": "production",
                    "signed_snapshot_required": True,
                },
                "authority_snapshot_version": 1,
                "chain_id": "weall-prod-batch351",
                "genesis_hash": "1" * 64,
                "genesis_state_root": "2" * 64,
                "mode": "prod",
                "profile": "production_service",
                "protocol_profile_hash": "3" * 64,
                "schema_version": "1",
                "trusted_authority_pubkeys": ["b" * 64],
                "tx_index_hash": "4" * 64,
                "version": 1,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    bundle = tmp_path / "prod-http-bundle.json"
    built = subprocess.run(
        [
            sys.executable,
            str(BUILD),
            "--manifest",
            str(manifest),
            "--genesis-api-base",
            "http://10.131.107.82:8000",
            "--out",
            str(bundle),
            "--generated-at-ms",
            "1900000000000",
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert built.returncode == 0, built.stderr + built.stdout
    result = subprocess.run(
        [sys.executable, str(VERIFY), "--bundle", str(bundle), "--manifest", str(manifest), "--json"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode != 0
    report = json.loads(result.stdout)
    assert "production_authority_url_must_be_https" in report["issues"]


def test_observer_scripts_resolve_manifest_from_bundle_hint() -> None:
    for script in (SMOKE, LIVE_GATE, REHEARSAL):
        text = script.read_text(encoding="utf-8")
        assert "manifest_path_hint" in text
        assert "WEALL_BUNDLE_MANIFEST_PATH_PY" in text
        assert "configs' / 'chains' / 'weall-genesis.json" in text

    smoke = SMOKE.read_text(encoding="utf-8")
    assert "prod_chain_manifest_check.sh" in smoke
    assert "non-production observer rehearsal manifest is pinned and matches local tx index" in smoke

