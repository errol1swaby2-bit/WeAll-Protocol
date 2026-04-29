import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_cmd(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False, **kwargs)


def test_batch247_build_and_verify_public_onboarding_bundle(tmp_path: Path) -> None:
    out = tmp_path / "node-operator-bundle.json"
    build = run_cmd([
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
        "ab" * 32,
        "--generated-at-ms",
        "1234567890",
    ])
    assert build.returncode == 0, build.stdout + build.stderr
    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert bundle["type"] == "weall_node_operator_onboarding_bundle"
    assert bundle["chain"]["chain_id"] == "weall-prod"
    assert bundle["oracle"]["profile"] == "production"
    assert "WEALL_SMTP_PASSWORD" in bundle["secret_boundary"]["prohibited_environment_variables"]
    serialized = json.dumps(bundle).lower()
    assert "weall_smtp_password" in serialized
    assert "weall_email_oracle_private_key" in serialized
    assert "weall_node_privkey\":" not in serialized

    verify = run_cmd([
        sys.executable,
        "scripts/verify_node_operator_onboarding_bundle.py",
        "--bundle",
        str(out),
        "--manifest",
        "configs/chains/weall-genesis.json",
        "--json",
    ])
    assert verify.returncode == 0, verify.stdout + verify.stderr
    result = json.loads(verify.stdout)
    assert result["ok"] is True
    assert result["trusted_authority_pubkeys_count"] == 1


def test_batch247_verify_rejects_placeholder_authority_for_production(tmp_path: Path) -> None:
    out = tmp_path / "node-operator-bundle.json"
    build = run_cmd([
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
        "--generated-at-ms",
        "1234567890",
    ])
    assert build.returncode == 0, build.stdout + build.stderr
    verify = run_cmd([
        sys.executable,
        "scripts/verify_node_operator_onboarding_bundle.py",
        "--bundle",
        str(out),
        "--manifest",
        "configs/chains/weall-genesis.json",
        "--json",
    ])
    assert verify.returncode == 1
    result = json.loads(verify.stdout)
    assert "placeholder_trusted_authority_pubkey" in result["issues"]


def test_batch247_emit_shell_env_exports_public_anchors_only(tmp_path: Path) -> None:
    out = tmp_path / "node-operator-bundle.json"
    subprocess.run([
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
        "cd" * 32,
    ], cwd=ROOT, check=True)
    proc = run_cmd([
        sys.executable,
        "scripts/verify_node_operator_onboarding_bundle.py",
        "--bundle",
        str(out),
        "--manifest",
        "configs/chains/weall-genesis.json",
        "--emit-shell-env",
    ])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "export WEALL_CHAIN_ID=weall-prod" in proc.stdout
    assert "export WEALL_POH_EMAIL_ORACLE_URL=https://oracle.example.invalid" in proc.stdout
    assert "WEALL_SMTP_PASSWORD" not in proc.stdout
    assert "PRIVKEY" not in proc.stdout


def test_batch247_shell_wrapper_exists_and_parses() -> None:
    script = ROOT / "scripts/prod_node_operator_from_bundle_preflight.sh"
    assert script.exists()
    proc = run_cmd(["bash", "-n", str(script)])
    assert proc.returncode == 0, proc.stderr
