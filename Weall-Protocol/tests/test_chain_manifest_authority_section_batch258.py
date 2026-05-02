from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build_node_operator_onboarding_bundle.py"
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verify_node_operator_onboarding_bundle.py"


def _load_build_module():
    spec = importlib.util.spec_from_file_location(
        "build_node_operator_onboarding_bundle",
        BUILD_SCRIPT,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_chain_manifests_use_authority_section_not_oracle_section() -> None:
    for relative in (
        "configs/chains/weall-genesis.json",
        "configs/chains/weall-demo.json",
    ):
        manifest = json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))
        assert "authority" in manifest
        assert "oracle" not in manifest


def test_manifest_authority_reader_accepts_legacy_section_read_only() -> None:
    mod = _load_build_module()

    modern = {"authority": {"profile": "production"}, "oracle": {"profile": "legacy"}}
    legacy = {"oracle": {"profile": "legacy"}}

    assert mod._manifest_authority(modern)["profile"] == "production"
    assert mod._manifest_authority(legacy)["profile"] == "legacy"


def test_bundle_builder_emits_authority_only(tmp_path: Path) -> None:
    manifest = REPO_ROOT / "configs" / "chains" / "weall-genesis.json"
    out = tmp_path / "bundle.json"

    subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "--manifest",
            str(manifest),
            "--out",
            str(out),
            "--authority-url",
            "https://authority.example",
            "--profile",
            "production",
        ],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert "authority" in bundle
    assert "oracle" not in bundle


def test_verifier_accepts_legacy_authority_section_read_only(tmp_path: Path) -> None:
    legacy_bundle = {
        "type": "weall_node_operator_onboarding_bundle",
        "version": 1,
        "profile": "development",
        "chain": {
            "chain_id": "weall-test",
            "genesis_hash": "g",
            "genesis_state_root": "s",
            "tx_index_hash": "t",
            "schema_version": "1",
        },
        "oracle": {
            "profile": "development",
            "url": "http://legacy-authority.example",
            "trusted_authority_pubkeys": ["legacy-authority-pubkey"],
        },
    }
    bundle_path = tmp_path / "legacy-bundle.json"
    bundle_path.write_text(json.dumps(legacy_bundle), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT), "--bundle", str(bundle_path), "--json"],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    result = json.loads(proc.stdout)
    assert result["ok"] is True
    assert result["legacy_authority_section_used"] is True
