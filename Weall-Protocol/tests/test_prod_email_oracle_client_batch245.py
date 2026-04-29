from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _clean_env() -> dict[str, str]:
    env = dict(os.environ)
    for name in (
        "WEALL_SMTP_PASSWORD",
        "WEALL_EMAIL_ORACLE_PRIVATE_KEY",
        "WEALL_EMAIL_ORACLE_PRIVATE_KEY_FILE",
        "WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY",
        "WEALL_ORACLE_AUTHORITY_PRIVKEY",
    ):
        env.pop(name, None)
    return env


def test_prod_email_oracle_client_start_posts_to_weall_api_and_redacts_stdout() -> None:
    captured: dict[str, Any] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            captured["path"] = self.path
            captured["body"] = json.loads(body)
            response = json.dumps(
                {
                    "ok": True,
                    "request_id": "challenge-1",
                    "expires_ms": 900000,
                    "security_phrase": "blue-river-7421",
                    "official_sender": "verify@poh.weall.org",
                    "email_masked": "a***@example.com",
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    env = _clean_env()
    url = f"http://127.0.0.1:{server.server_port}"
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/prod_email_oracle_client.py",
            "--api-base",
            url,
            "start",
            "--account",
            "@alice",
            "--email",
            "alice@example.com",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    thread.join(timeout=5)
    server.server_close()

    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["request_id"] == "challenge-1"
    assert captured["path"] == "/v1/poh/email/begin"
    assert captured["body"] == {"account": "@alice", "email": "alice@example.com"}


def test_prod_email_oracle_client_complete_posts_to_weall_api() -> None:
    captured: dict[str, Any] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            captured["path"] = self.path
            captured["body"] = json.loads(body)
            response = json.dumps({"ok": True, "tx": {"tx_type": "POH_EMAIL_ATTESTATION_SUBMIT"}}).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    env = _clean_env()
    url = f"http://127.0.0.1:{server.server_port}"
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/prod_email_oracle_client.py",
            "--api-base",
            url,
            "complete",
            "--account",
            "@alice",
            "--email",
            "alice@example.com",
            "--request-id",
            "challenge-1",
            "--code",
            "123456",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    thread.join(timeout=5)
    server.server_close()

    assert json.loads(proc.stdout)["ok"] is True
    assert captured["path"] == "/v1/poh/email/complete"
    assert captured["body"] == {
        "account": "@alice",
        "email": "alice@example.com",
        "request_id": "challenge-1",
        "code": "123456",
    }


def test_prod_email_oracle_client_wrappers_parse() -> None:
    client = (ROOT / "scripts/prod_email_oracle_client.py").read_text(encoding="utf-8")
    assert "/v1/poh/email/begin" in client
    assert "/v1/poh/email/complete" in client
    assert "provider-cli" not in client.lower()
    subprocess.run(["bash", "-n", "scripts/prod_email_oracle_start.sh"], cwd=ROOT, check=True)
    subprocess.run(["bash", "-n", "scripts/prod_email_oracle_verify.sh"], cwd=ROOT, check=True)
