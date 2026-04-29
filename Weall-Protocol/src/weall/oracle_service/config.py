from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from weall.oracle_service.transports.base import EmailTransport
from weall.oracle_service.transports.external_smtp import ExternalSMTPTransport
from weall.oracle_service.transports.mock import MockDevTransport
from weall.oracle_service.transports.stalwart_smtp import StalwartSMTPConfig, StalwartSMTPTransport


def _read_env_or_file(name: str) -> str:
    value = str(os.environ.get(name) or "").strip()
    if value:
        return value
    path = str(os.environ.get(f"{name}_FILE") or "").strip()
    if not path:
        return ""
    return Path(path).read_text(encoding="utf-8").strip()


@dataclass(frozen=True)
class OracleServiceConfig:
    email_transport: str
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    smtp_from: str
    oracle_id: str
    oracle_private_key: str
    oracle_public_key_id: str
    node_rpc_url: str
    challenge_db_path: str
    mock_outbox_path: str

    @classmethod
    def from_env(cls) -> "OracleServiceConfig":
        return cls(
            email_transport=str(os.environ.get("WEALL_EMAIL_TRANSPORT") or "mock").strip().lower(),
            smtp_host=str(os.environ.get("WEALL_SMTP_HOST") or os.environ.get("WEALL_EMAIL_HOST") or "").strip(),
            smtp_port=int(str(os.environ.get("WEALL_SMTP_PORT") or os.environ.get("WEALL_EMAIL_PORT") or "587").strip()),
            smtp_username=str(os.environ.get("WEALL_SMTP_USERNAME") or os.environ.get("WEALL_EMAIL_USER") or "").strip(),
            smtp_password=_read_env_or_file("WEALL_SMTP_PASSWORD") or _read_env_or_file("WEALL_EMAIL_PASS"),
            smtp_from=str(os.environ.get("WEALL_SMTP_FROM") or os.environ.get("WEALL_EMAIL_FROM") or "verify@poh.weall.org").strip(),
            oracle_id=str(os.environ.get("WEALL_EMAIL_ORACLE_ID") or "").strip(),
            oracle_private_key=_read_env_or_file("WEALL_EMAIL_ORACLE_PRIVATE_KEY"),
            oracle_public_key_id=str(os.environ.get("WEALL_EMAIL_ORACLE_PUBLIC_KEY_ID") or "").strip(),
            node_rpc_url=str(os.environ.get("WEALL_NODE_RPC_URL") or "http://127.0.0.1:8000").strip().rstrip("/"),
            challenge_db_path=str(os.environ.get("WEALL_POH_EMAIL_CHALLENGE_DB") or "data/poh_email_challenges.sqlite3").strip(),
            mock_outbox_path=str(os.environ.get("WEALL_MOCK_EMAIL_OUTBOX") or "data/poh_email_outbox.jsonl").strip(),
        )

    def validate_signing_config(self) -> None:
        if not self.oracle_id:
            raise ValueError("missing_email_oracle_id")
        if not self.oracle_private_key:
            raise ValueError("missing_email_oracle_private_key")

    def build_transport(self) -> EmailTransport:
        transport = self.email_transport
        if transport in {"mock", "dev_mock"}:
            return MockDevTransport(outbox_path=self.mock_outbox_path)
        if transport == "stalwart_smtp":
            return StalwartSMTPTransport(
                StalwartSMTPConfig(
                    host=self.smtp_host,
                    port=self.smtp_port,
                    username=self.smtp_username,
                    password=self.smtp_password,
                )
            )
        if transport in {"smtp", "external_smtp"}:
            return ExternalSMTPTransport(
                StalwartSMTPConfig(
                    host=self.smtp_host,
                    port=self.smtp_port,
                    username=self.smtp_username,
                    password=self.smtp_password,
                )
            )
        raise ValueError(f"unsupported_email_transport:{transport}")
