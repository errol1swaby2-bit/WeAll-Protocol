import json
import os
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_cmd(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False, **kwargs)


def _build_bundle(tmp_path: Path) -> Path:
    out = tmp_path / "node-operator-bundle.json"
    proc = run_cmd([
        sys.executable,
        "scripts/build_node_operator_onboarding_bundle.py",
        "--manifest",
        "configs/chains/weall-genesis.json",
        "--out",
        str(out),
        "--oracle-url",
        "https://oracle.example.invalid",
        "--authority-url",
        "https://node.example.invalid",
        "--authority-pubkeys",
        "aa" * 32,
        "--generated-at-ms",
        "1234567890",
    ])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out


def test_batch248_installs_public_bundle_env_file(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    out = tmp_path / "operator.env"
    proc = run_cmd([
        sys.executable,
        "scripts/install_node_operator_onboarding_bundle.py",
        "--bundle",
        str(bundle),
        "--manifest",
        "configs/chains/weall-genesis.json",
        "--out",
        str(out),
        "--print-source-command",
    ])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"source '{out}'" in proc.stdout
    body = out.read_text(encoding="utf-8")
    assert "export WEALL_CHAIN_ID=weall-prod" in body
    assert "export WEALL_EXPECTED_GENESIS_HASH=" in body
    assert "export WEALL_POH_EMAIL_ORACLE_URL=https://oracle.example.invalid" in body
    assert "export WEALL_CHAIN_AUTHORITY_URL=https://node.example.invalid" in body
    assert "WEALL_SMTP_PASSWORD" not in body
    assert "WEALL_EMAIL_ORACLE_PRIVATE_KEY" not in body
    assert "WEALL_NODE_PRIVKEY=" not in body
    assert "WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY" not in body
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_batch248_install_refuses_oracle_service_secrets_in_environment(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    out = tmp_path / "operator.env"
    env = dict(os.environ)
    env["WEALL_EMAIL_ORACLE_PRIVATE_KEY"] = "oracle-private-key-should-not-be-on-node"
    proc = run_cmd([
        sys.executable,
        "scripts/install_node_operator_onboarding_bundle.py",
        "--bundle",
        str(bundle),
        "--manifest",
        "configs/chains/weall-genesis.json",
        "--out",
        str(out),
    ], env=env)
    assert proc.returncode == 1
    assert "oracle_service_or_authority_secret_present:WEALL_EMAIL_ORACLE_PRIVATE_KEY" in proc.stderr
    assert not out.exists()


def test_batch248_install_refuses_overwrite_without_force(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    out = tmp_path / "operator.env"
    out.write_text("existing\n", encoding="utf-8")
    proc = run_cmd([
        sys.executable,
        "scripts/install_node_operator_onboarding_bundle.py",
        "--bundle",
        str(bundle),
        "--manifest",
        "configs/chains/weall-genesis.json",
        "--out",
        str(out),
    ])
    assert proc.returncode == 1
    assert "output_exists" in proc.stderr
    assert out.read_text(encoding="utf-8") == "existing\n"


def test_batch248_shell_wrapper_exists_and_parses() -> None:
    script = ROOT / "scripts/prod_node_operator_install_bundle.sh"
    assert script.exists()
    proc = run_cmd(["bash", "-n", str(script)])
    assert proc.returncode == 0, proc.stderr


def test_batch248_onboarding_doc_exists_and_states_secret_boundary() -> None:
    doc = ROOT / "docs" / "NODE_OPERATOR_ONBOARDING.md"
    assert doc.exists()
    body = doc.read_text(encoding="utf-8")
    assert "normal node operator" in body.lower()
    assert "PoH email oracle" in body
    assert "authority snapshot signer" in body
    assert "chain state" in body
