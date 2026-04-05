from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any

from nacl.signing import SigningKey


Json = dict[str, Any]


class OracleRequestError(RuntimeError):
    """Raised when the external email oracle rejects or fails a request."""


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
    return json.dumps(payload, separators=(",", ":"), sort_keys=False)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_oracle_signature_material(
    *,
    method: str,
    path: str,
    ts_ms: int,
    nonce: str,
    body_sha256: str,
    operator_account: str,
    node_pubkey: str,
) -> bytes:
    material = "\n".join(
        [
            "weall-email-oracle-v1",
            method.strip().upper(),
            path.strip(),
            str(int(ts_ms)),
            nonce.strip(),
            body_sha256.strip().lower(),
            operator_account.strip(),
            node_pubkey.strip().lower(),
            "",
        ]
    )
    return material.encode("utf-8")


def _read_response_json(resp: Any) -> Json:
    raw = resp.read()
    if not raw:
        return {}
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise OracleRequestError("oracle_response_not_object")
    return parsed


def _post_json(
    url: str,
    payload: Json,
    *,
    timeout_s: int = 10,
    headers: dict[str, str] | None = None,
) -> Json:
    body_bytes = _json_dumps(payload).encode("utf-8")
    req_headers = {"accept": "application/json", "content-type": "application/json"}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return _read_response_json(resp)
    except urllib.error.HTTPError as exc:
        details: Any = None
        try:
            raw = exc.read()
            if raw:
                details = json.loads(raw.decode("utf-8"))
        except Exception:
            details = None
        raise OracleRequestError(f"oracle_http_error:{exc.code}:{url}:{details!r}") from exc
    except urllib.error.URLError as exc:
        raise OracleRequestError(f"oracle_transport_error:{url}:{exc}") from exc


class EmailVerificationService:
    """Oracle-backed email verification service."""

    def __init__(
        self,
        secret: str | None = None,
        ttl_ms: int | None = None,
        caller_identity: OracleCallerIdentity | None = None,
        email_verify_base_url: str | None = None,
    ) -> None:
        oracle = (email_verify_base_url or os.environ.get("WEALL_POH_EMAIL_ORACLE_URL") or "").strip().rstrip("/")
        self._oracle_base = oracle
        self._mode = (os.environ.get("WEALL_MODE") or "").strip().lower()

        self.secret = secret if secret is not None else (os.environ.get("WEALL_POH_EMAIL_SECRET") or "").strip()
        self.ttl_ms = int(ttl_ms) if ttl_ms is not None else int((os.environ.get("WEALL_POH_EMAIL_TTL_MS") or "900000").strip())

        env_operator = ((os.environ.get("WEALL_VALIDATOR_ACCOUNT") or "").strip() or (os.environ.get("WEALL_NODE_ID") or "").strip())
        env_pubkey = (os.environ.get("WEALL_NODE_PUBKEY") or "").strip().lower()
        env_privkey = (os.environ.get("WEALL_NODE_PRIVKEY") or "").strip().lower()

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
        return bool(self._oracle_base)

    def require_configured(self) -> None:
        if self.configured():
            return
        raise OracleRequestError("missing_email_oracle_url")

    def _require_oracle_auth_material(self) -> None:
        if not self._operator_account:
            raise OracleRequestError("missing_oracle_operator_account")
        if not self._node_pubkey:
            raise OracleRequestError("missing_oracle_node_pubkey")
        if not self._node_privkey:
            raise OracleRequestError("missing_oracle_node_privkey")

    def _signing_key(self) -> SigningKey:
        try:
            return SigningKey(bytes.fromhex(self._node_privkey))
        except Exception as exc:
            raise OracleRequestError("invalid_oracle_node_privkey") from exc

    def _oracle_headers(self, *, method: str, path: str, body_bytes: bytes) -> dict[str, str]:
        self._require_oracle_auth_material()

        ts_ms = _now_ms()
        nonce = str(uuid.uuid4())
        body_sha256 = _sha256_hex(body_bytes)
        material = _canonical_oracle_signature_material(
            method=method,
            path=path,
            ts_ms=ts_ms,
            nonce=nonce,
            body_sha256=body_sha256,
            operator_account=self._operator_account,
            node_pubkey=self._node_pubkey,
        )
        signature = self._signing_key().sign(material).signature.hex()

        return {
            "x-weall-oracle-account": self._operator_account,
            "x-weall-oracle-pubkey": self._node_pubkey,
            "x-weall-oracle-timestamp": str(ts_ms),
            "x-weall-oracle-nonce": nonce,
            "x-weall-oracle-body-sha256": body_sha256,
            "x-weall-oracle-signature": signature,
        }

    def _post_oracle(self, path: str, payload: Json, *, timeout_s: int = 10) -> Json:
        self.require_configured()
        raw_body = _json_dumps(payload).encode("utf-8")
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
            "user-agent": "WeAllNode/2026.03 (+https://weallprotocol.xyz)",
            **self._oracle_headers(method="POST", path=path, body_bytes=raw_body),
        }
        return _post_json(f"{self._oracle_base}{path}", payload, timeout_s=timeout_s, headers=headers)

    def begin(self, *, account: str, email: str, turnstile_token: str | None = None) -> Json:
        normalized_email = str(email or "").strip().lower()
        payload: Json = {
            "account_id": account,
            "operator_account_id": self._operator_account,
            "email": normalized_email,
        }
        if turnstile_token:
            payload["turnstile_token"] = turnstile_token

        data = self._post_oracle("/start", payload, timeout_s=10)
        if not data.get("ok", True):
            raise OracleRequestError(f"oracle_begin_rejected:{data!r}")

        challenge_id = str(data.get("challenge_id") or "").strip()
        if not challenge_id:
            raise OracleRequestError(f"oracle_begin_missing_challenge_id:{data!r}")

        return {
            "ok": True,
            "request_id": challenge_id,
            "challenge_id": challenge_id,
            "email_masked": data.get("email_masked"),
            "expires_ms": data.get("expires_ms") or data.get("expires_at_ms"),
            "expires_at_ms": data.get("expires_at_ms") or data.get("expires_ms"),
            "provider": data.get("provider"),
            "resend_id": data.get("resend_id"),
        }

    def complete(
        self,
        *,
        account: str,
        email: str,
        code: str,
        request_id: str | None = None,
        turnstile_token: str | None = None,
    ) -> Json:
        challenge_id = (request_id or "").strip()
        if not challenge_id:
            raise OracleRequestError("missing_request_id")

        payload: Json = {"challenge_id": challenge_id, "code": code}
        if turnstile_token:
            payload["turnstile_token"] = turnstile_token

        data = self._post_oracle("/verify", payload, timeout_s=10)
        if not data.get("ok", True):
            raise OracleRequestError(f"oracle_complete_rejected:{data!r}")

        relay_token = RelayCompletionToken.from_response(data)
        return {
            "ok": True,
            "request_id": challenge_id,
            "challenge_id": challenge_id,
            "completed": bool(data.get("completed", True)),
            "relay_token": {"payload": relay_token.payload, "signature": relay_token.signature} if relay_token else data.get("relay_token"),
        }

    def begin_legacy(self, *, account_id: str, email: str, turnstile_token: str | None = None) -> Json:
        return self.begin(account=account_id, email=email, turnstile_token=turnstile_token)

    def verify_legacy(
        self,
        *,
        account_id: str,
        email: str,
        code: str,
        challenge_id: str,
        turnstile_token: str | None = None,
    ) -> Json:
        return self.complete(
            account=account_id,
            email=email,
            code=code,
            request_id=challenge_id,
            turnstile_token=turnstile_token,
        )


_SERVICE_SINGLETON: EmailVerificationService | None = None


def get_email_verification_service() -> EmailVerificationService:
    global _SERVICE_SINGLETON
    if _SERVICE_SINGLETON is None:
        _SERVICE_SINGLETON = EmailVerificationService()
    return _SERVICE_SINGLETON
