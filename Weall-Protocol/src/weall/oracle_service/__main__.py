from __future__ import annotations

"""Standalone WeAll PoH email oracle service entrypoint.

This service is intentionally outside consensus execution. It may use wall-clock,
random challenge generation, local challenge persistence, and SMTP transport, but
normal WeAll nodes only verify signed attestations against chain state.
"""

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from weall.poh.email_verification import EmailVerificationService, OracleCallerIdentity
from weall.runtime.poh.email_attestation import (
    build_unsigned_email_control_attestation_v1,
    domain_hash_for_attestation,
    email_hash_for_attestation,
    sign_email_control_attestation_v1,
)
from weall.oracle_service.config import OracleServiceConfig

Json = dict[str, Any]

app = FastAPI(title="WeAll PoH Email Oracle", version="1.0")


class EmailBeginRequest(BaseModel):
    account: str = Field(..., min_length=1, max_length=128)
    email: str = Field(..., min_length=3, max_length=320)
    chain_id: str = ""


class EmailCompleteRequest(BaseModel):
    account: str = Field(..., min_length=1, max_length=128)
    email: str = Field(..., min_length=3, max_length=320)
    code: str = Field(..., min_length=1, max_length=128)
    request_id: str = Field(..., min_length=1, max_length=256)
    chain_id: str = ""
    current_height: int = Field(default=0, ge=0)


def _cfg() -> OracleServiceConfig:
    return OracleServiceConfig.from_env()


def _service(cfg: OracleServiceConfig) -> EmailVerificationService:
    public_key = (os.environ.get("WEALL_EMAIL_ORACLE_PUBLIC_KEY") or cfg.oracle_public_key_id or "").strip().lower()
    return EmailVerificationService(
        secret=_hash_salt(),
        caller_identity=OracleCallerIdentity(
            operator_account=cfg.oracle_id,
            node_pubkey=public_key,
            node_privkey=cfg.oracle_private_key,
        ),
        transport=cfg.build_transport(),
        official_sender=cfg.smtp_from,
    )


def _ttl_heights() -> int:
    try:
        value = int(os.environ.get("WEALL_POH_EMAIL_TTL_HEIGHTS") or "60")
    except Exception:
        value = 60
    return max(1, value)


def _hash_salt() -> str:
    value = (os.environ.get("WEALL_POH_EMAIL_HASH_SALT") or "").strip()
    if value:
        return value
    if (os.environ.get("WEALL_MODE") or "").strip().lower() == "prod":
        raise RuntimeError("missing_email_hash_salt")
    return "weall-local-dev-email-secret"


def _default_manifest_path() -> Path:
    configured = (os.environ.get("WEALL_CHAIN_MANIFEST_PATH") or "").strip()
    if configured:
        return Path(configured)
    root = Path(__file__).resolve().parents[3]
    mode = (os.environ.get("WEALL_MODE") or "").strip().lower()
    if mode == "demo":
        return root / "configs" / "chains" / "weall-demo.json"
    return root / "configs" / "chains" / "weall-genesis.json"


def _manifest_health_fields() -> Json:
    path = _default_manifest_path()
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            manifest = {}
    except Exception:
        manifest = {}
    oracle = manifest.get("oracle") if isinstance(manifest.get("oracle"), dict) else {}
    profile = (os.environ.get("WEALL_ORACLE_PROFILE") or oracle.get("expected_profile") or manifest.get("mode") or "").strip()
    return {
        "profile": profile,
        "chain_id": str(manifest.get("chain_id") or ""),
        "expected_genesis_hash": str(manifest.get("genesis_hash") or ""),
        "expected_tx_index_hash": str(manifest.get("tx_index_hash") or ""),
    }


@app.get("/healthz")
def healthz() -> Json:
    cfg = _cfg()
    payload: Json = {"ok": True, "service": "weall-poh-email-oracle", "transport": cfg.email_transport}
    payload.update(_manifest_health_fields())
    return payload


@app.get("/readyz")
def readyz() -> Json:
    cfg = _cfg()
    cfg.validate_signing_config()
    transport = cfg.build_transport()
    transport.validate_config()
    return {"ok": True, "transport": cfg.email_transport, "oracle_id": cfg.oracle_id}


@app.post("/v1/poh/email/begin")
def begin(req: EmailBeginRequest) -> Json:
    cfg = _cfg()
    transport = cfg.build_transport()
    transport.validate_config()
    result = _service(cfg).begin(account=req.account, email=req.email, chain_id=req.chain_id)
    result["oracle_id"] = cfg.oracle_id
    return result


@app.post("/v1/poh/email/complete")
def complete(req: EmailCompleteRequest) -> Json:
    cfg = _cfg()
    cfg.validate_signing_config()
    svc = _service(cfg)
    result = svc.complete(
        account=req.account,
        email=req.email,
        code=req.code,
        request_id=req.request_id,
        chain_id=req.chain_id,
    )
    issued_at_height = int(req.current_height or 0)
    email_hash = email_hash_for_attestation(
        normalized_email=req.email,
        salt=_hash_salt(),
        account_id=req.account,
    )
    domain_hash = domain_hash_for_attestation(
        normalized_email=req.email,
        salt=_hash_salt(),
        account_id=req.account,
    )
    unsigned = build_unsigned_email_control_attestation_v1(
        chain_id=req.chain_id,
        account_id=req.account,
        email_hash=email_hash,
        domain_hash=domain_hash,
        challenge_id=req.request_id,
        issued_at_height=issued_at_height,
        expires_at_height=issued_at_height + _ttl_heights(),
        oracle_id=cfg.oracle_id,
    )
    attestation = sign_email_control_attestation_v1(
        unsigned,
        oracle_private_key=cfg.oracle_private_key,
    )
    return {
        "ok": True,
        "request_id": req.request_id,
        "completed": bool(result.get("completed", True)) if isinstance(result, dict) else True,
        "attestation": attestation,
        "security_phrase": str(result.get("security_phrase") or "") if isinstance(result, dict) else "",
    }


def main() -> None:
    import uvicorn

    host = os.environ.get("WEALL_EMAIL_ORACLE_HOST") or "0.0.0.0"
    port = int(os.environ.get("WEALL_EMAIL_ORACLE_PORT") or "8091")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
