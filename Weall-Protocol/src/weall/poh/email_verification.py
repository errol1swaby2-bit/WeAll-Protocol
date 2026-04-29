from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from weall.oracle_service.transports.base import EmailMessage, EmailSendResult, EmailTransport
from weall.oracle_service.transports.external_smtp import ExternalSMTPTransport
from weall.oracle_service.transports.mock import MockDevTransport
from weall.oracle_service.transports.stalwart_smtp import StalwartSMTPConfig, StalwartSMTPTransport

Json = dict[str, Any]


class OracleRequestError(RuntimeError):
    """Raised when the WeAll-hosted email oracle cannot process a request."""


@dataclass(frozen=True)
class OracleCallerIdentity:
    operator_account: str
    node_pubkey: str
    node_privkey: str


@dataclass(frozen=True)
class RelayCompletionToken:
    payload: Json
    signature: str

    @classmethod
    def from_response(cls, data: Json) -> "RelayCompletionToken | None":
        relay = data.get("relay_token")
        if not isinstance(relay, dict):
            return None
        payload = relay.get("payload")
        signature = relay.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            return None
        return cls(payload=payload, signature=signature)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _json_dumps(payload: Json) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_email(email: str) -> str:
    value = str(email or "").strip().lower()
    if "@" not in value or value.startswith("@") or value.endswith("@"):
        raise OracleRequestError("invalid_email")
    return value


def _mask_email(email: str) -> str:
    try:
        local, domain = email.split("@", 1)
    except ValueError:
        return "***"
    if not local:
        masked_local = "***"
    elif len(local) == 1:
        masked_local = f"{local}***"
    else:
        masked_local = f"{local[0]}***{local[-1]}"
    return f"{masked_local}@{domain}"


def _challenge_secret() -> str:
    secret = (os.environ.get("WEALL_POH_EMAIL_SECRET") or "").strip()
    if secret:
        return secret
    if (os.environ.get("WEALL_MODE") or "").strip().lower() == "prod":
        raise OracleRequestError("missing_email_secret")
    return "weall-local-dev-email-secret"


def _email_commitment(*, account: str, email: str, chain_id: str, secret: str | None = None) -> str:
    material = "\n".join(
        [
            "weall-poh-email-commitment-v1",
            str(chain_id or "").strip(),
            str(account or "").strip(),
            _normalize_email(email),
            secret if secret is not None else _challenge_secret(),
            "",
        ]
    )
    return _sha256_hex(material.encode("utf-8"))


def _code_hash(*, challenge_id: str, code: str, secret: str | None = None) -> str:
    material = "\n".join(
        [
            "weall-poh-email-code-v1",
            str(challenge_id or "").strip(),
            str(code or "").strip(),
            secret if secret is not None else _challenge_secret(),
            "",
        ]
    )
    return _sha256_hex(material.encode("utf-8"))


def _security_phrase() -> str:
    first = ["blue", "green", "silver", "quiet", "bright", "steady", "open", "calm"]
    second = ["river", "harbor", "signal", "garden", "anchor", "lantern", "summit", "meadow"]
    return f"{secrets.choice(first)}-{secrets.choice(second)}-{secrets.randbelow(9000) + 1000}"


def _verification_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _store_path() -> Path:
    configured = (os.environ.get("WEALL_POH_EMAIL_CHALLENGE_STORE") or "").strip()
    if configured:
        return Path(configured)
    return Path(os.getcwd()) / "data" / "poh_email_challenges.json"


def _outbox_path() -> Path:
    configured = (os.environ.get("WEALL_MOCK_EMAIL_OUTBOX") or "").strip()
    if configured:
        return Path(configured)
    return Path(os.getcwd()) / "data" / "poh_email_outbox.jsonl"


def _load_store() -> Json:
    path = _store_path()
    if not path.exists():
        return {"challenges": {}}
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"challenges": {}}
    if not isinstance(parsed, dict):
        return {"challenges": {}}
    challenges = parsed.get("challenges")
    if not isinstance(challenges, dict):
        parsed["challenges"] = {}
    return parsed


def _save_store(store: Json) -> None:
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(store, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _relay_token_message(payload: Json) -> bytes:
    return _json_dumps(payload).encode("utf-8")


def _read_env_or_file(name: str) -> str:
    value = (os.environ.get(name) or "").strip()
    if value:
        return value
    path = (os.environ.get(f"{name}_FILE") or "").strip()
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def _default_transport_from_env() -> EmailTransport:
    transport = (os.environ.get("WEALL_EMAIL_TRANSPORT") or "mock").strip().lower()
    if transport in {"mock", "dev_mock"}:
        return MockDevTransport(outbox_path=_outbox_path())

    if transport == "stalwart_smtp":
        return StalwartSMTPTransport(
            StalwartSMTPConfig(
                host=(os.environ.get("WEALL_SMTP_HOST") or os.environ.get("WEALL_EMAIL_HOST") or "").strip(),
                port=int((os.environ.get("WEALL_SMTP_PORT") or os.environ.get("WEALL_EMAIL_PORT") or "587").strip()),
                username=(os.environ.get("WEALL_SMTP_USERNAME") or os.environ.get("WEALL_EMAIL_USER") or "").strip(),
                password=_read_env_or_file("WEALL_SMTP_PASSWORD") or _read_env_or_file("WEALL_EMAIL_PASS"),
            )
        )

    if transport in {"smtp", "external_smtp"}:
        return ExternalSMTPTransport(
            StalwartSMTPConfig(
                host=(os.environ.get("WEALL_SMTP_HOST") or os.environ.get("WEALL_EMAIL_HOST") or "").strip(),
                port=int((os.environ.get("WEALL_SMTP_PORT") or os.environ.get("WEALL_EMAIL_PORT") or "587").strip()),
                username=(os.environ.get("WEALL_SMTP_USERNAME") or os.environ.get("WEALL_EMAIL_USER") or "").strip(),
                password=_read_env_or_file("WEALL_SMTP_PASSWORD") or _read_env_or_file("WEALL_EMAIL_PASS"),
            )
        )

    raise OracleRequestError(f"unsupported_email_transport:{transport}")


class EmailVerificationService:
    """WeAll-owned PoH email verification oracle.

    This service intentionally has no provider-specific runtime dependency. It
    owns challenge generation, local challenge persistence, email template
    creation, transport selection, completion verification, and relay-token
    signing. SMTP/Stalwart are only transport choices; they do not decide PoH.
    """

    def __init__(
        self,
        secret: str | None = None,
        ttl_ms: int | None = None,
        caller_identity: OracleCallerIdentity | None = None,
        email_verify_base_url: str | None = None,
        transport: EmailTransport | None = None,
        official_sender: str | None = None,
    ) -> None:
        _ = email_verify_base_url  # preserved for old constructor callers; ignored by design.
        self.secret = secret if secret is not None else _challenge_secret()
        self._transport = transport if transport is not None else _default_transport_from_env()
        self._official_sender = (
            official_sender
            or os.environ.get("WEALL_SMTP_FROM")
            or os.environ.get("WEALL_EMAIL_FROM")
            or "verify@poh.weall.org"
        ).strip()
        self.ttl_ms = int(ttl_ms) if ttl_ms is not None else int((os.environ.get("WEALL_POH_EMAIL_TTL_MS") or "900000").strip())
        self._mode = (os.environ.get("WEALL_MODE") or "").strip().lower()

        env_operator = (_read_env_or_file("WEALL_VALIDATOR_ACCOUNT") or _read_env_or_file("WEALL_NODE_ID")).strip()
        env_pubkey = _read_env_or_file("WEALL_NODE_PUBKEY").lower()
        env_privkey = _read_env_or_file("WEALL_NODE_PRIVKEY").lower()

        if caller_identity is None:
            caller_identity = OracleCallerIdentity(
                operator_account=env_operator,
                node_pubkey=env_pubkey,
                node_privkey=env_privkey,
            )

        self._caller_identity = caller_identity
        self._operator_account = caller_identity.operator_account.strip()
        self._node_pubkey = caller_identity.node_pubkey.strip().lower()
        self._node_privkey = caller_identity.node_privkey.strip().lower()

    @property
    def caller_identity(self) -> OracleCallerIdentity:
        return self._caller_identity

    def configured(self) -> bool:
        try:
            self._transport.validate_config()
        except Exception:
            return False
        return True

    def require_configured(self) -> None:
        if self.configured():
            return
        raise OracleRequestError("email_transport_not_configured")

    def _require_oracle_auth_material(self) -> None:
        if not self._operator_account:
            raise OracleRequestError("missing_oracle_operator_account")
        if not self._node_pubkey:
            raise OracleRequestError("missing_oracle_node_pubkey")
        if not self._node_privkey:
            raise OracleRequestError("missing_oracle_node_privkey")

    def _signing_key(self) -> SigningKey:
        self._require_oracle_auth_material()
        try:
            return SigningKey(bytes.fromhex(self._node_privkey))
        except Exception as exc:
            raise OracleRequestError("invalid_oracle_node_privkey") from exc

    def _send_verification_email(
        self,
        *,
        to_email: str,
        security_phrase: str,
        code: str,
        expires_at_ms: int,
    ) -> Json:
        _ = expires_at_ms
        subject = "Your WeAll PoH verification code"
        body = "\n".join(
            [
                "Your WeAll PoH verification phrase:",
                security_phrase,
                "",
                "Your verification code:",
                code,
                "",
                "This code expires soon.",
                "",
                "WeAll will never ask for your password, private key, seed phrase, wallet secret, or payment.",
                "Only trust this email if the phrase matches what is shown inside WeAll.",
                "",
            ]
        )
        sent: EmailSendResult = self._transport.send(
            EmailMessage(
                to_email=to_email,
                from_email=self._official_sender,
                subject=subject,
                body_text=body,
            )
        )
        return {"provider": sent.provider, "message_id": sent.message_id, "diagnostic": sent.diagnostic}

    def begin(
        self,
        *,
        account: str,
        email: str,
        chain_id: str | None = None,
        genesis_hash: str | None = None,
    ) -> Json:
        _ = genesis_hash
        self.require_configured()
        account_norm = str(account or "").strip()
        normalized_email = _normalize_email(email)
        chain_id_norm = str(chain_id or "").strip()
        challenge_id = f"poh_email_{uuid.uuid4().hex}"
        code = _verification_code()
        phrase = _security_phrase()
        issued_at_ms = _now_ms()
        expires_at_ms = issued_at_ms + int(self.ttl_ms)
        commitment = _email_commitment(account=account_norm, email=normalized_email, chain_id=chain_id_norm, secret=self.secret)

        store = _load_store()
        challenges = store.setdefault("challenges", {})
        challenges[challenge_id] = {
            "version": 1,
            "challenge_id": challenge_id,
            "account_id": account_norm,
            "chain_id": chain_id_norm,
            "email_commitment": commitment,
            "code_hash": _code_hash(challenge_id=challenge_id, code=code, secret=self.secret),
            "security_phrase": phrase,
            "issued_at_ms": issued_at_ms,
            "expires_at_ms": expires_at_ms,
            "attempts": 0,
            "completed": False,
        }
        _save_store(store)
        send_meta = self._send_verification_email(
            to_email=normalized_email,
            security_phrase=phrase,
            code=code,
            expires_at_ms=expires_at_ms,
        )

        result: Json = {
            "ok": True,
            "request_id": challenge_id,
            "challenge_id": challenge_id,
            "email_masked": _mask_email(normalized_email),
            "expires_ms": expires_at_ms,
            "expires_at_ms": expires_at_ms,
            "email_commitment": commitment,
            "security_phrase": phrase,
            "official_sender": self._official_sender,
            "provider": send_meta.get("provider"),
        }
        if os.environ.get("WEALL_POH_EMAIL_EXPOSE_DEV_CODE", "").strip() in {"1", "true", "yes"}:
            result["dev_code"] = code
        return result

    def complete(
        self,
        *,
        account: str,
        email: str,
        code: str,
        request_id: str | None = None,
        chain_id: str | None = None,
        genesis_hash: str | None = None,
    ) -> Json:
        _ = genesis_hash
        challenge_id = (request_id or "").strip()
        if not challenge_id:
            raise OracleRequestError("missing_request_id")
        account_norm = str(account or "").strip()
        email_norm = _normalize_email(email)
        chain_id_norm = str(chain_id or "").strip()

        store = _load_store()
        challenges = store.get("challenges") if isinstance(store.get("challenges"), dict) else {}
        record = challenges.get(challenge_id) if isinstance(challenges, dict) else None
        if not isinstance(record, dict):
            raise OracleRequestError("unknown_challenge")
        if bool(record.get("completed")):
            raise OracleRequestError("challenge_already_completed")
        if str(record.get("account_id") or "").strip() != account_norm:
            raise OracleRequestError("challenge_account_mismatch")
        if chain_id_norm and str(record.get("chain_id") or "").strip() != chain_id_norm:
            raise OracleRequestError("challenge_chain_mismatch")
        expected_commitment = _email_commitment(account=account_norm, email=email_norm, chain_id=str(record.get("chain_id") or chain_id_norm), secret=self.secret)
        if str(record.get("email_commitment") or "").strip() != expected_commitment:
            raise OracleRequestError("challenge_email_mismatch")
        now = _now_ms()
        if now > int(record.get("expires_at_ms") or 0):
            raise OracleRequestError("challenge_expired")
        attempts = int(record.get("attempts") or 0) + 1
        record["attempts"] = attempts
        if attempts > int(os.environ.get("WEALL_POH_EMAIL_MAX_ATTEMPTS") or "5"):
            _save_store(store)
            raise OracleRequestError("too_many_attempts")
        if str(record.get("code_hash") or "") != _code_hash(challenge_id=challenge_id, code=code, secret=self.secret):
            _save_store(store)
            raise OracleRequestError("invalid_code")

        self._require_oracle_auth_material()
        payload: Json = {
            "version": 1,
            "type": "email_challenge_completed",
            "chain_id": str(record.get("chain_id") or chain_id_norm),
            "challenge_id": challenge_id,
            "account_id": account_norm,
            "operator_account_id": self._operator_account,
            "email_commitment": str(record.get("email_commitment") or ""),
            "issued_at_ms": now,
            "expires_at_ms": now + int(self.ttl_ms),
            "relay_account_id": self._operator_account,
            "relay_pubkey": self._node_pubkey,
        }
        signature = self._signing_key().sign(_relay_token_message(payload)).signature.hex()
        relay_token = {"payload": payload, "signature": signature}
        record["completed"] = True
        record["completed_at_ms"] = now
        _save_store(store)
        return {
            "ok": True,
            "request_id": challenge_id,
            "challenge_id": challenge_id,
            "completed": True,
            "relay_token": relay_token,
            "email_commitment": str(record.get("email_commitment") or ""),
            "security_phrase": str(record.get("security_phrase") or ""),
        }

    def begin_legacy(
        self,
        *,
        account_id: str,
        email: str,
        chain_id: str | None = None,
        genesis_hash: str | None = None,
    ) -> Json:
        return self.begin(account=account_id, email=email, chain_id=chain_id, genesis_hash=genesis_hash)

    def verify_legacy(
        self,
        *,
        account_id: str,
        email: str,
        code: str,
        challenge_id: str,
        chain_id: str | None = None,
        genesis_hash: str | None = None,
    ) -> Json:
        return self.complete(
            account=account_id,
            email=email,
            code=code,
            request_id=challenge_id,
            chain_id=chain_id,
            genesis_hash=genesis_hash,
        )


_SERVICE_SINGLETON: EmailVerificationService | None = None


def get_email_verification_service() -> EmailVerificationService:
    global _SERVICE_SINGLETON
    if _SERVICE_SINGLETON is None:
        _SERVICE_SINGLETON = EmailVerificationService()
    return _SERVICE_SINGLETON
