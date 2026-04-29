from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_batch246_preflight_scripts_exist_and_parse_shell() -> None:
    scripts = [
        "scripts/prod_oracle_env_check.sh",
        "scripts/prod_oracle_smoke.sh",
        "scripts/prod_node_preflight.sh",
        "scripts/demo_full_oracle_preflight.sh",
    ]
    for script in scripts:
        path = ROOT / script
        assert path.exists(), script
        proc = subprocess.run(["bash", "-n", str(path)], cwd=ROOT, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr


def test_batch246_production_oracle_env_check_passes_non_strict_static_config() -> None:
    proc = subprocess.run(
        ["bash", "scripts/prod_oracle_env_check.sh"],
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    body = json.loads(proc.stdout)
    assert body["ok"] is True
    assert body["chain_id"] == "weall-prod"
    assert body["genesis_hash"]
    assert body["tx_index_hash"]
    assert "trusted_authority_pubkeys_still_placeholder" in body["warnings"]


def test_batch246_prod_node_preflight_rejects_oracle_service_secrets() -> None:
    proc = subprocess.run(
        ["bash", "scripts/prod_node_preflight.sh"],
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": str(ROOT / "src"),
            "WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY": "should-not-be-on-a-node",
        },
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "authority snapshot signer private key must not be present" in proc.stderr


def test_batch246_demo_preflight_pins_demo_profile_and_manifest() -> None:
    source = _read("scripts/demo_full_oracle_preflight.sh")
    assert 'export WEALL_MODE="demo"' in source
    assert 'export WEALL_RUNTIME_PROFILE="seeded_demo"' in source
    assert 'export WEALL_ORACLE_PROFILE="demo"' in source
    assert 'configs/chains/weall-demo.json' in source

    manifest = json.loads((ROOT / "configs/chains/weall-demo.json").read_text(encoding="utf-8"))
    assert manifest["chain_id"] == "weall-demo"
    assert manifest["mode"] == "demo"
    assert manifest["oracle"]["expected_profile"] == "demo"


def test_batch246_prod_scripts_keep_node_operators_separate_from_oracle_operators() -> None:
    node_preflight = _read("scripts/prod_node_preflight.sh")
    env_check = _read("scripts/prod_oracle_env_check.sh")
    smoke = _read("scripts/prod_oracle_smoke.sh")

    assert "authority snapshot signer private key must not be present" in node_preflight
    assert "prod_chain_manifest_check.sh" in node_preflight
    assert "prod_node_operator_oracle_preflight.sh" in node_preflight

    assert "secret_must_not_be_plain_var" in env_check
    assert "WEALL_TRUSTED_AUTHORITY_PUBKEYS" in env_check
    assert "production_var_mismatch" in env_check

    assert "/healthz" in smoke
    assert "profile_not_production" in smoke
    assert "healthz_may_expose_sensitive_label" in smoke
