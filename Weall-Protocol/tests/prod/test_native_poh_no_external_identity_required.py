from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_native_poh_onboarding_canon_has_no_email_or_external_identity_txs() -> None:
    tx_index = (ROOT / "generated" / "tx_index.json").read_text(encoding="utf-8")
    lowered = tx_index.lower()
    for forbidden in ("email", "smtp", "named-host-provider", "captcha", "oauth", "kyc"):
        assert forbidden not in lowered
    assert "POH_ASYNC_REQUEST_OPEN" in tx_index
    assert "POH_ASYNC_EVIDENCE_DECLARE" in tx_index
    assert "POH_ASYNC_EVIDENCE_BIND" in tx_index
    assert "POH_LIVE_REQUEST_OPEN" in tx_index


def test_production_preflight_does_not_require_external_identity_env() -> None:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "WEALL_MODE": "prod",
        "WEALL_CHAIN_MANIFEST_PATH": str(ROOT / "configs" / "chains" / "weall-genesis.json"),
        "WEALL_OBSERVER_MODE": "1",
        "WEALL_VALIDATOR_SIGNING_ENABLED": "0",
        "WEALL_BFT_ENABLED": "0",
        "WEALL_SERVICE_ROLES": "",
    }
    result = subprocess.run(
        ["bash", "scripts/prod_node_preflight.sh"],
        cwd=str(ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert result.returncode == 0, result.stdout
    assert "production node preflight passed" in result.stdout
    assert "external identity-provider secrets are absent" in result.stdout


def test_production_preflight_rejects_external_identity_provider_secrets() -> None:
    cases = {
        "WEALL_NAMED_HOSTING_PROVIDER_API_TOKEN": "named hosting-provider token",
        "WEALL_DNS_API_TOKEN": "DNS provider token",
        "WEALL_OAUTH_CLIENT_SECRET": "OAuth secret",
        "WEALL_KYC_PROVIDER_SECRET": "KYC provider secret",
        "WEALL_CAPTCHA_SECRET": "CAPTCHA secret",
        "WEALL_" + "SM" + "TP_PASSWORD": "SMTP password",
    }
    for key, expected in cases.items():
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "WEALL_MODE": "prod",
            "WEALL_CHAIN_MANIFEST_PATH": str(ROOT / "configs" / "chains" / "weall-genesis.json"),
            "WEALL_OBSERVER_MODE": "1",
            "WEALL_VALIDATOR_SIGNING_ENABLED": "0",
            "WEALL_BFT_ENABLED": "0",
            "WEALL_SERVICE_ROLES": "",
            key: "not-required",
        }
        result = subprocess.run(
            ["bash", "scripts/prod_node_preflight.sh"],
            cwd=str(ROOT),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        assert result.returncode != 0, key
        assert expected in result.stdout
