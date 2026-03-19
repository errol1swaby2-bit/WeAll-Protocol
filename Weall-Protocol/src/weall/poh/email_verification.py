from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


def _now_ms() -> int:
    return int(time.time() * 1000)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _hmac_hex(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def _post_json(url: str, payload: dict[str, Any], timeout_s: int = 10) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read().decode("utf-8")
        if not raw:
            return {}
        return json.loads(raw)


def _normalize_email(email: str) -> str:
    return email.strip().lower()


@dataclass(frozen=True)
class BeginResult:
    request_id: str
    expires_ms: int


class EmailVerificationService:
    """Orchestrate PoH email verification via an external oracle.

    Flow:
      - begin(email, account) -> request_id + expiry
      - confirm(request_id, code, account, turnstile_token?) -> True/False

    begin(): calls email-oracle /start, then wraps expiry into a signed request_id
    binding (account, normalized_email, expires_ts_ms).

    confirm(): validates signed request_id, then calls email-oracle /verify.

    Environment:
      - WEALL_POH_EMAIL_ORACLE_URL (preferred)
      - WEALL_POH_EMAIL_ORACLE_BASE
      - WEALL_EMAIL_ORACLE_URL

    Back-compat:
      - __init__ supports both `secret=` and legacy `email_secret=`.
    """

    def __init__(
        self,
        *,
        ttl_ms: int,
        secret: str | None = None,
        email_secret: str | None = None,
        email_verify_base_url: str | None = None,
    ) -> None:
        s = str(secret or email_secret or "").strip()
        if not s:
            raise ValueError("missing_email_secret")

        self.secret = s
        self.ttl_ms = int(ttl_ms)

        if email_verify_base_url is None:
            import os

            email_verify_base_url = str(
                os.environ.get("WEALL_POH_EMAIL_ORACLE_URL")
                or os.environ.get("WEALL_POH_EMAIL_ORACLE_BASE")
                or os.environ.get("WEALL_EMAIL_ORACLE_URL")
                or ""
            ).strip()

        # e.g. http://localhost:8787
        self.email_verify_base_url: str = str(email_verify_base_url or "").strip()

    def _make_request_id(self, *, account: str, email_norm: str, expires_ts_ms: int) -> str:
        payload = {"a": account, "e": email_norm, "x": int(expires_ts_ms)}
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        sig = _hmac_hex(self.secret, raw)
        token = {"p": payload, "s": sig}
        token_raw = json.dumps(token, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return _b64url(token_raw)

    def _parse_request_id(self, request_id: str) -> dict[str, Any] | None:
        try:
            padded = request_id + "=" * (-len(request_id) % 4)
            raw = base64.urlsafe_b64decode(padded.encode("utf-8"))
            obj = json.loads(raw.decode("utf-8"))
            if not isinstance(obj, dict):
                return None
            if "p" not in obj or "s" not in obj:
                return None
            payload = obj["p"]
            sig = obj["s"]
            if not isinstance(payload, dict) or not isinstance(sig, str):
                return None
            raw_payload = json.dumps(payload, separators=(",", ":"), sort_keys=True)
            exp_sig = _hmac_hex(self.secret, raw_payload)
            if not hmac.compare_digest(sig, exp_sig):
                return None
            return payload
        except Exception:
            return None

    def begin(self, *, email: str, account: str, turnstile_token: str | None = None) -> BeginResult:
        email_norm = _normalize_email(email)
        oracle = self.email_verify_base_url.rstrip("/")
        if not oracle:
            raise RuntimeError("email_verify_base_url not configured")

        # Turnstile may be required by the oracle in prod (recommended).
        # We keep it optional for back-compat with existing deployments.
        turnstile_token = str(turnstile_token or "").strip()
        payload: dict[str, Any] = {"email": email_norm}
        if turnstile_token:
            payload["turnstile_token"] = turnstile_token

        data = _post_json(f"{oracle}/start", payload, timeout_s=10)

        expires_ts_ms = int(data.get("expires_ts_ms") or (_now_ms() + self.ttl_ms))
        local_expires = min(expires_ts_ms, _now_ms() + self.ttl_ms)

        request_id = self._make_request_id(
            account=account, email_norm=email_norm, expires_ts_ms=local_expires
        )
        return BeginResult(request_id=request_id, expires_ms=max(1, local_expires - _now_ms()))

    def confirm(
        self,
        *,
        request_id: str,
        code: str,
        account: str,
        turnstile_token: str | None = None,
    ) -> bool:
        payload = self._parse_request_id(request_id)
        if not payload:
            return False

        try:
            if payload.get("a") != account:
                return False
            email_norm = str(payload.get("e") or "")
            exp = int(payload.get("x") or 0)
            if not email_norm or exp <= 0:
                return False
            if _now_ms() > exp:
                return False
        except Exception:
            return False

        oracle = self.email_verify_base_url.rstrip("/")
        if not oracle:
            return False

        turnstile_token = str(turnstile_token or "").strip()

        try:
            data = _post_json(
                f"{oracle}/verify",
                {
                    "email": email_norm,
                    "code": str(code or "").strip(),
                    "turnstile_token": turnstile_token,
                },
                timeout_s=10,
            )
        except urllib.error.HTTPError:
            return False
        except urllib.error.URLError:
            return False
        except Exception:
            return False

        return bool(data.get("ok") is True)
