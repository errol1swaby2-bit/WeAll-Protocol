from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from nacl.signing import SigningKey, VerifyKey

ROOT = Path(__file__).resolve().parents[1]


def _signing_material(headers: dict[str, str], *, method: str, path: str) -> bytes:
    return "\n".join(
        [
            "weall-email-oracle-v1",
            method,
            path,
            headers["x-weall-oracle-chain-id"],
            headers["x-weall-oracle-genesis-hash"],
            headers["x-weall-oracle-timestamp"],
            headers["x-weall-oracle-nonce"],
            headers["x-weall-oracle-body-sha256"],
            headers["x-weall-oracle-account"],
            headers["x-weall-oracle-pubkey"],
            "",
        ]
    ).encode("utf-8")


def test_prod_oracle_request_signer_emits_chain_bound_headers() -> None:
    sk = SigningKey(bytes.fromhex("11" * 32))
    body = '{"account_id":"@alice","operator_account_id":"@operator","email":"alice@example.com","chain_id":"weall-prod"}'
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/prod_oracle_request_signer.py",
            "--path",
            "/start",
            "--body",
            body,
            "--account",
            "@operator",
            "--pubkey",
            sk.verify_key.encode().hex(),
            "--privkey",
            sk.encode().hex(),
            "--chain-id",
            "weall-prod",
            "--genesis-hash",
            "aa" * 32,
            "--nonce",
            "nonce-1",
            "--timestamp-ms",
            "1234567890",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(proc.stdout)
    headers = payload["headers"]
    assert headers["x-weall-oracle-chain-id"] == "weall-prod"
    assert headers["x-weall-oracle-genesis-hash"] == "aa" * 32
    assert headers["x-weall-oracle-nonce"] == "nonce-1"
    VerifyKey(bytes.fromhex(headers["x-weall-oracle-pubkey"])).verify(
        _signing_material(headers, method="POST", path="/start"),
        bytes.fromhex(headers["x-weall-oracle-signature"]),
    )


def test_prod_oracle_authority_snapshot_check_accepts_signed_fixture(tmp_path: Path) -> None:
    from weall.poh.oracle_authority_snapshot import sign_authority_snapshot

    sk = SigningKey(bytes.fromhex("22" * 32))
    node_sk = SigningKey(bytes.fromhex("33" * 32))
    now = int(time.time() * 1000)
    snapshot = sign_authority_snapshot(
        {
            "ok": True,
            "version": 1,
            "type": "weall_email_oracle_authority_snapshot",
            "chain_id": "weall-prod",
            "genesis_hash": "aa" * 32,
            "height": 10,
            "block_hash": "bb" * 32,
            "state_root": "cc" * 32,
            "tx_index_hash": "dd" * 32,
            "schema_version": "1",
            "validator_epoch": 0,
            "validator_set_hash": "ee" * 32,
            "generated_at_ms": now,
            "expires_at_ms": now + 60000,
            "registry": {
                "@operator": {
                    "eligible": True,
                    "status": "active",
                    "poh_tier": 2,
                    "active_node_operator": True,
                    "reputation_units": 1,
                    "locked": False,
                    "banned": False,
                    "pubkeys": [node_sk.verify_key.encode().hex()],
                    "reasons": [
                        "active_node_operator",
                        "live_verified_human",
                        "positive_reputation",
                        "account_unlocked",
                        "account_not_banned",
                        "active_account_key",
                    ],
                }
            },
            "authorized_accounts": ["@operator"],
            "authorized_pubkeys": [node_sk.verify_key.encode().hex()],
        },
        signer="@authority",
        pubkey=sk.verify_key.encode().hex(),
        privkey_hex=sk.encode().hex(),
    )
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/prod_oracle_authority_snapshot_check.py",
            "--snapshot-file",
            str(path),
            "--expected-chain-id",
            "weall-prod",
            "--expected-genesis-hash",
            "aa" * 32,
            "--expected-tx-index-hash",
            "dd" * 32,
            "--trusted-pubkeys",
            sk.verify_key.encode().hex(),
            "--operator-account",
            "@operator",
            "--node-pubkey",
            node_sk.verify_key.encode().hex(),
            "--json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    result = json.loads(proc.stdout)
    assert result["ok"] is True
    assert result["signature_ok"] is True


def test_node_operator_preflight_script_does_not_require_oracle_service_secrets() -> None:
    script = (ROOT / "scripts/prod_poh_email_oracle_operator_preflight.sh").read_text(encoding="utf-8")
    assert "WEALL_EMAIL_ORACLE_PRIVATE_KEY" in script or "oracle-service" in script
    assert "authority-signer private keys" in script
    assert "provider-cli" not in script


def test_prod_oracle_tooling_shell_syntax() -> None:
    subprocess.run(["bash", "-n", "scripts/prod_oracle_authority_snapshot_check.sh"], cwd=ROOT, check=True)
    subprocess.run(["bash", "-n", "scripts/prod_poh_email_oracle_operator_preflight.sh"], cwd=ROOT, check=True)
