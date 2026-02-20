from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from weall.email.smtp_sender import send_email
from weall.runtime.sqlite_db import SqliteDB, _canon_json

Json = Dict[str, Any]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _post_json(url: str, payload: Dict[str, Any], *, timeout_s: int = 10) -> Dict[str, Any]:
    body = _canon_json(payload).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read()
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {"ok": False, "error": "bad_json_from_oracle"}


class EmailStartReq(BaseModel):
    account: str = Field(..., min_length=1)
    email: str = Field(..., min_length=3)
    pubkey: str = Field(..., min_length=16, description="Ed25519 pubkey (hex or base64)")


class EmailStartResp(BaseModel):
    ok: bool
    contact_hash: str
    expires_ts_ms: int


class EmailConfirmReq(BaseModel):
    account: str = Field(..., min_length=1)
    code: str = Field(..., min_length=4, max_length=12)
    pubkey: str = Field(..., min_length=16, description="Ed25519 pubkey (hex or base64)")
    sig: str = Field("", description="Signature for the parent tx")
    nonce: int = Field(0, ge=0, description="Nonce for the parent tx (must be next)")

    # Optional for backward compatibility; REQUIRED when WEALL_EMAIL_VERIFY_BASE_URL is set
    email: Optional[str] = Field(None, min_length=3)
    turnstile_token: Optional[str] = Field(None, min_length=10)


class EmailConfirmResp(BaseModel):
    ok: bool
    enqueued: bool
    parent_tx_id: str
    parent_tx_type: str


@dataclass
class EmailVerificationService:
    """Off-chain email verification state backed by SQLite.

    Table: poh_email_verifications(
        account PRIMARY KEY,
        contact_hash,
        pubkey,
        token_hash,
        created_ts_ms,
        expires_ts_ms,
        attempts,
        verified
    )

    Hardening:
      - Only hashed email is stored (contact_hash).
      - Only hashed code is stored (token_hash) in SMTP mode.
      - Attempts are incremented on every failed verify.
      - Conflicting updates to an account (pubkey mismatch / contact mismatch) are rejected.
    """

    db_path: str
    ttl_seconds: int = 15 * 60
    max_attempts: int = 5

    def __post_init__(self) -> None:
        self._db = SqliteDB(path=str(self.db_path))
        self._db.init_schema()

    def _oracle_base(self) -> str:
        return (os.environ.get("WEALL_EMAIL_VERIFY_BASE_URL") or "").strip().rstrip("/")

    def _get(self, account: str) -> Optional[Json]:
        with self._db.connection() as con:
            row = con.execute(
                """
                SELECT account, contact_hash, pubkey, token_hash, created_ts_ms, expires_ts_ms, attempts, verified
                FROM poh_email_verifications
                WHERE account=?
                LIMIT 1;
                """,
                (str(account),),
            ).fetchone()
            if row is None:
                return None
            return {
                "account": str(row["account"]),
                "contact_hash": str(row["contact_hash"]),
                "pubkey": str(row["pubkey"]),
                "token_hash": str(row["token_hash"]) if row["token_hash"] is not None else None,
                "created_ts_ms": int(row["created_ts_ms"]),
                "expires_ts_ms": int(row["expires_ts_ms"]),
                "attempts": int(row["attempts"]),
                "verified": bool(int(row["verified"]) or 0),
            }

    def _insert_or_verify(self, rec: Json) -> bool:
        """Insert if absent; otherwise require compatibility to update.

        Compatibility rules:
          - pubkey must match existing record
          - contact_hash must match existing record
        """
        account = str(rec.get("account") or "").strip()
        if not account:
            return False

        with self._db.write_tx() as con:
            # Insert if absent.
            con.execute(
                """
                INSERT OR IGNORE INTO poh_email_verifications(
                  account, contact_hash, pubkey, token_hash,
                  created_ts_ms, expires_ts_ms, attempts, verified
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    account,
                    str(rec.get("contact_hash")),
                    str(rec.get("pubkey")),
                    rec.get("token_hash"),
                    int(rec.get("created_ts_ms")),
                    int(rec.get("expires_ts_ms")),
                    int(rec.get("attempts")),
                    1 if bool(rec.get("verified")) else 0,
                ),
            )

            row = con.execute(
                """
                SELECT contact_hash, pubkey
                FROM poh_email_verifications
                WHERE account=?
                LIMIT 1;
                """,
                (account,),
            ).fetchone()
            if row is None:
                return False

            if str(row["pubkey"]) != str(rec.get("pubkey")):
                return False
            if str(row["contact_hash"]) != str(rec.get("contact_hash")):
                return False

            # Update mutable fields.
            con.execute(
                """
                UPDATE poh_email_verifications
                SET token_hash=?, created_ts_ms=?, expires_ts_ms=?, attempts=?, verified=?
                WHERE account=?;
                """,
                (
                    rec.get("token_hash"),
                    int(rec.get("created_ts_ms")),
                    int(rec.get("expires_ts_ms")),
                    int(rec.get("attempts")),
                    1 if bool(rec.get("verified")) else 0,
                    account,
                ),
            )

        return True

    def start(self, *, account: str, email: str, pubkey: str) -> Dict[str, Any]:
        account = account.strip()
        if not account:
            raise ValueError("account required")

        pubkey = pubkey.strip()
        if not pubkey:
            raise ValueError("pubkey required")

        norm_email = _normalize_email(email)
        if "@" not in norm_email or "." not in norm_email:
            raise ValueError("invalid email")

        contact_hash = _sha256_hex(norm_email)
        now = _now_ms()
        expires_fallback = now + int(self.ttl_seconds * 1000)

        oracle = self._oracle_base()
        use_oracle = bool(oracle)

        rec: Dict[str, Any] = {
            "account": account,
            "contact_hash": contact_hash,
            "pubkey": pubkey,
            "created_ts_ms": now,
            "expires_ts_ms": expires_fallback,
            "attempts": 0,
            "verified": False,
            "token_hash": None,
        }

        existing = self._get(account)
        if existing:
            # Fail-closed if someone tries to restart on the same account with different pubkey/email hash.
            if str(existing.get("pubkey")) != pubkey:
                return {"ok": False, "error": "pubkey_mismatch"}
            if str(existing.get("contact_hash")) != contact_hash:
                return {"ok": False, "error": "email_mismatch"}

        if use_oracle:
            try:
                data = _post_json(f"{oracle}/start", {"email": norm_email}, timeout_s=10)
            except Exception:
                return {"ok": False, "error": "oracle_unreachable"}

            if not (isinstance(data, dict) and data.get("ok") is True):
                return {"ok": False, "error": str(data.get("error") or "email_send_failed")}

            expires_ts_ms = int(data.get("expires_ts_ms") or 0) or expires_fallback
            rec["expires_ts_ms"] = expires_ts_ms

            ok = self._insert_or_verify(rec)
            if not ok:
                return {"ok": False, "error": "record_conflict"}

            return {"ok": True, "contact_hash": contact_hash, "expires_ts_ms": expires_ts_ms}

        # SMTP/local mode
        code = f"{secrets.randbelow(1_000_000):06d}"
        rec["token_hash"] = _sha256_hex(code)

        ok = self._insert_or_verify(rec)
        if not ok:
            return {"ok": False, "error": "record_conflict"}

        subject = "WeAll: Your verification code"
        body = (
            "Your WeAll verification code is:\n\n"
            f"{code}\n\n"
            f"This code expires in {self.ttl_seconds // 60} minutes.\n"
            "If you did not request this, you can ignore this email.\n"
        )
        send_email(to_email=norm_email, subject=subject, body_text=body)

        return {"ok": True, "contact_hash": contact_hash, "expires_ts_ms": int(rec["expires_ts_ms"])}

    def confirm(
        self,
        *,
        account: str,
        code: str,
        pubkey: str,
        email: Optional[str] = None,
        turnstile_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        account = account.strip()
        if not account:
            raise ValueError("account required")

        pubkey = pubkey.strip()
        if not pubkey:
            raise ValueError("pubkey required")

        code = (code or "").strip()
        if not code:
            raise ValueError("code required")

        rec = self._get(account)
        if not isinstance(rec, dict):
            return {"ok": False, "error": "not_started"}

        now = _now_ms()
        if int(rec.get("expires_ts_ms", 0)) <= int(now):
            return {"ok": False, "error": "expired"}

        if str(rec.get("pubkey") or "").strip() != pubkey:
            return {"ok": False, "error": "pubkey_mismatch"}

        attempts = int(rec.get("attempts", 0))
        if attempts >= int(self.max_attempts):
            return {"ok": False, "error": "attempts_exceeded"}

        oracle = self._oracle_base()
        use_oracle = bool(oracle)

        if use_oracle:
            if not email or not (turnstile_token and str(turnstile_token).strip()):
                return {"ok": False, "error": "oracle_requires_email_and_turnstile"}

            norm_email = _normalize_email(email)
            if _sha256_hex(norm_email) != str(rec.get("contact_hash") or ""):
                return {"ok": False, "error": "email_mismatch"}

            try:
                data = _post_json(
                    f"{oracle}/verify",
                    {"email": norm_email, "code": code, "turnstile_token": str(turnstile_token)},
                    timeout_s=10,
                )
            except Exception:
                # count attempt
                rec["attempts"] = attempts + 1
                self._insert_or_verify(rec)
                return {"ok": False, "error": "oracle_unreachable"}

            if not (isinstance(data, dict) and data.get("ok") is True):
                rec["attempts"] = attempts + 1
                self._insert_or_verify(rec)
                return {"ok": False, "error": str(data.get("error") or "invalid_code")}

            rec["verified"] = True
            ok = self._insert_or_verify(rec)
            return {"ok": bool(ok)}

        token_hash = str(rec.get("token_hash") or "").strip()
        if not token_hash:
            return {"ok": False, "error": "no_local_token"}

        if _sha256_hex(code) != token_hash:
            rec["attempts"] = attempts + 1
            self._insert_or_verify(rec)
            return {"ok": False, "error": "invalid_code"}

        rec["verified"] = True
        ok = self._insert_or_verify(rec)
        return {"ok": bool(ok)}
