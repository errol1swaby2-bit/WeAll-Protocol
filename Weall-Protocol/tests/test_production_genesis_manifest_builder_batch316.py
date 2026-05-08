from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_production_genesis_manifest.py"


def _write_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}, sort_keys=True), encoding="utf-8")


def test_production_genesis_manifest_builder_rejects_placeholder_pubkeys_batch316(tmp_path: Path) -> None:
    tx_index = tmp_path / "tx_index.json"
    _write_tx_index(tx_index)
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--founding-account",
            "founder",
            "--founding-pubkey",
            "PUT_FOUNDING_PUBKEY_HEX_HERE",
            "--authority-pubkey",
            "a" * 64,
            "--tx-index",
            str(tx_index),
            "--genesis-out",
            str(tmp_path / "genesis.json"),
            "--manifest-out",
            str(tmp_path / "manifest.json"),
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode != 0
    assert "placeholder_value:founding_pubkey" in (result.stderr + result.stdout)


def test_production_genesis_manifest_builder_pins_lock_and_manifest_batch316(tmp_path: Path) -> None:
    tx_index = tmp_path / "tx_index.json"
    _write_tx_index(tx_index)
    genesis = tmp_path / "genesis.json"
    manifest = tmp_path / "manifest.json"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--chain-id",
            "weall-prod-test",
            "--founding-account",
            "founder",
            "--founding-pubkey",
            "a" * 64,
            "--authority-pubkey",
            "b" * 64,
            "--tx-index",
            str(tx_index),
            "--genesis-out",
            str(genesis),
            "--manifest-out",
            str(manifest),
            "--genesis-time",
            "1900000000",
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    g = json.loads(genesis.read_text(encoding="utf-8"))
    m = json.loads(manifest.read_text(encoding="utf-8"))
    assert g["chain_id"] == "weall-prod-test"
    assert g["params"]["economics_enabled"] is False
    assert g["params"]["economic_unlock_time"] == 1900000000 + 90 * 24 * 60 * 60
    assert g["params"]["poh_bootstrap_mode"] == "allowlist"
    assert g["params"]["poh_bootstrap_auto_lock_rule"] == "active_validators>=BFT_MIN_VALIDATORS"
    assert "PUT_FOUNDING" not in genesis.read_text(encoding="utf-8")
    assert m["protocol_profile_hash"]
    assert m["trusted_authority_pubkeys"] == ["b" * 64]
    assert len(m["genesis_hash"]) == 64
    assert len(m["genesis_state_root"]) == 64
