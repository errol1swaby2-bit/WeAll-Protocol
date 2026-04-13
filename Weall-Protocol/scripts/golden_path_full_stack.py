#!/usr/bin/env python3
"""
Golden-path script for the WeAll protocol (full stack).

This script validates the real web-facing path:
  1) readiness checks
  2) ACCOUNT_REGISTER
  3) dev/testnet Tier-3 bootstrap grant
  4) ACCOUNT_SESSION_KEY_ISSUE
  5) /v1/media/upload with session headers
  6) CONTENT_MEDIA_DECLARE
  7) CONTENT_POST_CREATE referencing declared media
  8) public feed + account feed verification
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from weall.crypto.sig import sign_tx_envelope_dict

Json = dict[str, Any]


@dataclass(frozen=True)
class Cfg:
    api: str
    chain_id: str
    wait_apply_s: float
    poll_s: float
    media_name: str
    media_bytes: bytes
    post_body: str


def _env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    return v if v not in (None, "") else default


def _env_float(name: str, default: float) -> float:
    v = _env(name)
    if v is None:
        return float(default)
    try:
        return float(v)
    except ValueError as e:
        raise SystemExit(f"{name} must be a float, got: {v!r}") from e


def _cfg() -> Cfg:
    api = str(_env("WEALL_API", "http://127.0.0.1:8000")).rstrip("/")
    chain_id = str(_env("WEALL_CHAIN_ID", "weall-dev")).strip() or "weall-dev"
    wait_apply_s = _env_float("WEALL_WAIT_APPLY_S", 90.0)
    poll_s = max(0.2, _env_float("WEALL_POLL_S", 0.5))
    media_name = str(_env("WEALL_MEDIA_NAME", "golden-path.txt"))
    media_text = str(_env("WEALL_MEDIA_TEXT", "hello from golden path\n"))
    post_body = str(_env("WEALL_POST_BODY", f"golden path post {int(time.time())}"))
    return Cfg(
        api=api,
        chain_id=chain_id,
        wait_apply_s=wait_apply_s,
        poll_s=poll_s,
        media_name=media_name,
        media_bytes=media_text.encode("utf-8"),
        post_body=post_body,
    )


def _account_slug(value: str) -> str:
    raw = str(value or "demo").strip().lower()
    raw = raw[1:] if raw.startswith("@") else raw
    raw = re.sub(r"[^a-z0-9_]+", "-", raw)
    raw = raw.strip("-_") or "demo"
    return raw


def _choose_account_name() -> str:
    fixed = str(_env("WEALL_ACCOUNT", "")).strip()
    if fixed:
        return fixed if fixed.startswith("@") else f"@{fixed}"
    prefix = _account_slug(str(_env("WEALL_ACCOUNT_PREFIX", "demo")))
    return f"@{prefix}_{int(time.time())}_{uuid.uuid4().hex[:8]}"


class FlowError(RuntimeError):
    pass


def _write_demo_summary(
    account: str, post_body: str, media_name: str, extra: dict[str, Any]
) -> str:
    out_dir = Path(__file__).resolve().parent.parent / "generated"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "demo_bootstrap_result.json"
    payload: dict[str, Any] = {
        "account": account,
        "post_body": post_body,
        "media_name": media_name,
        **extra,
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(out_path)


def _http_json(
    method: str,
    url: str,
    body: Json | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
) -> tuple[int, Any]:
    data = None
    req_headers: dict[str, str] = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            txt = raw.decode("utf-8", errors="replace")
            ct = str(r.headers.get("content-type") or "")
            if "json" in ct:
                return r.status, json.loads(txt) if txt else {}
            try:
                return r.status, json.loads(txt) if txt else {}
            except Exception:
                return r.status, txt
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw) if raw else {}
        except Exception:
            parsed = {"raw": raw}
        return e.code, parsed
    except Exception as e:
        raise FlowError(f"HTTP {method} {url} failed: {type(e).__name__}: {e}") from e


def _http_bytes(
    method: str,
    url: str,
    data: bytes,
    headers: dict[str, str],
    timeout: float = 30.0,
) -> tuple[int, Any]:
    req_headers = {"Accept": "application/json", **headers}
    req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            txt = raw.decode("utf-8", errors="replace")
            ct = str(r.headers.get("content-type") or "")
            if "json" in ct:
                return r.status, json.loads(txt) if txt else {}
            try:
                return r.status, json.loads(txt) if txt else {}
            except Exception:
                return r.status, txt
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw) if raw else {}
        except Exception:
            parsed = {"raw": raw}
        return e.code, parsed
    except Exception as e:
        raise FlowError(f"HTTP {method} {url} failed: {type(e).__name__}: {e}") from e


def _get(cfg: Cfg, path: str, headers: dict[str, str] | None = None) -> Any:
    status, body = _http_json("GET", f"{cfg.api}{path}", headers=headers)
    if status >= 400:
        raise FlowError(f"GET {path} failed status={status} body={body}")
    return body


def _post(cfg: Cfg, path: str, payload: Json, headers: dict[str, str] | None = None) -> Any:
    status, body = _http_json("POST", f"{cfg.api}{path}", body=payload, headers=headers)
    if status >= 400:
        raise FlowError(f"POST {path} failed status={status} body={body}")
    return body


def _account_path(account: str) -> str:
    return f"/v1/accounts/{urllib.parse.quote(account, safe='')}"


def _account_state(cfg: Cfg, account: str) -> Json:
    body = _get(cfg, _account_path(account))
    state = body.get("state")
    return state if isinstance(state, dict) else {}


def _snapshot(cfg: Cfg) -> Json:
    body = _get(cfg, "/v1/state/snapshot")
    if not isinstance(body, dict):
        return {}
    state = body.get("state")
    return state if isinstance(state, dict) else {}


def _snapshot_account_exists(cfg: Cfg, account: str) -> bool:
    snap = _snapshot(cfg)
    accounts = snap.get("accounts")
    return (
        isinstance(accounts, dict)
        and account in accounts
        and isinstance(accounts.get(account), dict)
    )


def _account_registered(cfg: Cfg, account: str) -> bool:
    body = _get(cfg, f"{_account_path(account)}/registered")
    return bool(body.get("registered") is True)


def _next_nonce(cfg: Cfg, account: str) -> int:
    state = _account_state(cfg, account)
    try:
        return int(state.get("nonce") or 0) + 1
    except Exception:
        return 1


def _wait_account_exists(cfg: Cfg, account: str) -> Json:
    deadline = time.time() + cfg.wait_apply_s
    last_state: Json = {}
    last_exists = False

    while time.time() < deadline:
        last_state = _account_state(cfg, account)
        last_exists = _snapshot_account_exists(cfg, account)
        if last_exists:
            return last_state
        time.sleep(cfg.poll_s)

    raise FlowError(
        f"account was not materialized in snapshot within timeout: account={account} exists={last_exists} last={last_state}"
    )


def _wait_account(
    cfg: Cfg,
    account: str,
    *,
    nonce_at_least: int | None = None,
    tier_at_least: int | None = None,
) -> Json:
    deadline = time.time() + cfg.wait_apply_s
    last: Json = {}

    while time.time() < deadline:
        exists = _snapshot_account_exists(cfg, account)
        last = _account_state(cfg, account)

        if not exists:
            time.sleep(cfg.poll_s)
            continue

        nonce_ok = nonce_at_least is None or int(last.get("nonce") or 0) >= int(nonce_at_least)
        tier_ok = tier_at_least is None or int(
            last.get("poh_tier") or last.get("tier") or 0
        ) >= int(tier_at_least)

        if nonce_ok and tier_ok:
            return last

        time.sleep(cfg.poll_s)

    raise FlowError(
        f"account state did not reach requested threshold: account={account} last={last}"
    )


def _wait_registered(cfg: Cfg, account: str) -> Json:
    deadline = time.time() + cfg.wait_apply_s
    last: Json = {}

    while time.time() < deadline:
        last = _account_state(cfg, account)
        exists = _snapshot_account_exists(cfg, account)
        registered = _account_registered(cfg, account)
        tier = int(last.get("poh_tier") or last.get("tier") or 0)

        if exists and registered and tier >= 3:
            return last

        time.sleep(cfg.poll_s)

    raise FlowError(
        f"account did not become registered within timeout: account={account} last={last}"
    )


def _tx_status(cfg: Cfg, tx_id: str) -> Json:
    return _get(cfg, f"/v1/tx/status/{urllib.parse.quote(str(tx_id), safe='')}")


def _wait_tx_confirmed(cfg: Cfg, tx_id: str) -> Json:
    deadline = time.time() + cfg.wait_apply_s
    last: Json = {}
    while time.time() < deadline:
        last = _tx_status(cfg, tx_id)
        status = str(last.get("status") or "").strip().lower()
        if status == "confirmed":
            return last
        if status in {"failed", "rejected"}:
            raise FlowError(f"tx failed: tx_id={tx_id} body={last}")
        time.sleep(cfg.poll_s)
    raise FlowError(f"tx did not confirm within timeout: tx_id={tx_id} last={last}")


def _make_keypair() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    seed_bytes = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_hex = seed_bytes.hex()
    pub_hex = pub_bytes.hex()
    return priv_hex, pub_hex


def _submit_tx(cfg: Cfg, *, priv_hex: str, tx_type: str, signer: str, payload: Json) -> Json:
    env: Json = {
        "chain_id": cfg.chain_id,
        "tx_type": tx_type,
        "signer": signer,
        "nonce": _next_nonce(cfg, signer),
        "payload": payload,
        "parent": None,
    }
    signed = sign_tx_envelope_dict(tx=env, privkey=priv_hex, encoding="hex")
    body = _post(cfg, "/v1/tx/submit", signed)
    tx_id = str(body.get("tx_id") or "").strip()
    if not tx_id:
        raise FlowError(f"tx submit missing tx_id: {body}")
    return {"tx_id": tx_id, "submit": body}


def _issue_session(cfg: Cfg, *, account: str, priv_hex: str) -> str:
    session_key = f"sess-{uuid.uuid4().hex}"
    issued = _submit_tx(
        cfg,
        priv_hex=priv_hex,
        tx_type="ACCOUNT_SESSION_KEY_ISSUE",
        signer=account,
        payload={"session_key": session_key, "ttl_s": 3600},
    )
    _wait_tx_confirmed(cfg, issued["tx_id"])
    state = _wait_account(cfg, account, nonce_at_least=2)
    sessions = state.get("session_keys")
    if not isinstance(sessions, dict) or session_key not in sessions:
        raise FlowError(f"session key was not written on-chain: account={account} state={state}")
    return session_key


def _upload_media(cfg: Cfg, *, account: str, session_key: str) -> Json:
    boundary = f"----weall-{uuid.uuid4().hex}"
    payload = (
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{cfg.media_name}"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
        ).encode()
        + cfg.media_bytes
        + b"\r\n"
        + f"--{boundary}--\r\n".encode()
    )
    status, body = _http_bytes(
        "POST",
        f"{cfg.api}/v1/media/upload",
        payload,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-WeAll-Account": account,
            "X-WeAll-Session-Key": session_key,
        },
        timeout=60.0,
    )
    if status >= 400:
        raise FlowError(f"media upload failed status={status} body={body}")
    if not isinstance(body, dict) or body.get("ok") is not True:
        raise FlowError(f"media upload did not return ok=true: {body}")
    cid = str(body.get("cid") or body.get("upload_ref") or "").strip()
    if not cid:
        raise FlowError(f"media upload missing cid: {body}")
    return body


def _verify_feed(cfg: Cfg, *, account: str, post_id: str, body_text: str, media_id: str) -> None:
    deadline = time.time() + cfg.wait_apply_s
    last_public: Any = None
    last_account: Any = None
    account_path = f"{_account_path(account)}/feed"
    while time.time() < deadline:
        public_feed = _get(cfg, "/v1/feed")
        account_feed = _get(cfg, account_path)
        last_public = public_feed
        last_account = account_feed

        public_items = public_feed.get("items") if isinstance(public_feed, dict) else None
        account_items = account_feed.get("items") if isinstance(account_feed, dict) else None
        if isinstance(public_items, list) and isinstance(account_items, list):
            pub_hit = next(
                (x for x in public_items if str(x.get("post_id") or "") == post_id), None
            )
            acct_hit = next(
                (x for x in account_items if str(x.get("post_id") or "") == post_id), None
            )
            if pub_hit and acct_hit:
                pub_media = pub_hit.get("media") if isinstance(pub_hit.get("media"), list) else []
                acct_media = (
                    acct_hit.get("media") if isinstance(acct_hit.get("media"), list) else []
                )
                if (
                    pub_hit.get("body") == body_text
                    and media_id in pub_media
                    and media_id in acct_media
                ):
                    return
        time.sleep(cfg.poll_s)
    raise FlowError(
        f"post did not appear in feed/account feed as expected: post_id={post_id} last_public={last_public} last_account={last_account}"
    )


def main() -> int:
    cfg = _cfg()
    priv_hex, pub_hex = _make_keypair()
    account = _choose_account_name()

    print("=== FULL STACK GOLDEN PATH ===")
    print(f"API: {cfg.api}")
    print(f"CHAIN_ID: {cfg.chain_id}")
    print(f"ACCOUNT: {account}")
    if os.getenv("WEALL_ACCOUNT"):
        print("ACCOUNT MODE: fixed")
    else:
        print("ACCOUNT MODE: generated")
    print()

    _get(cfg, "/v1/status")
    _get(cfg, "/v1/readyz")
    _get(cfg, "/v1/feed")
    _get(cfg, "/v1/state/snapshot")

    print("[1] ACCOUNT_REGISTER")
    reg = _submit_tx(
        cfg,
        priv_hex=priv_hex,
        tx_type="ACCOUNT_REGISTER",
        signer=account,
        payload={"pubkey": pub_hex},
    )
    _wait_tx_confirmed(cfg, reg["tx_id"])
    _wait_account_exists(cfg, account)
    print(f"    confirmed tx_id={reg['tx_id']}")

    print("[2] POH_BOOTSTRAP_TIER3_GRANT")
    boot = _submit_tx(
        cfg,
        priv_hex=priv_hex,
        tx_type="POH_BOOTSTRAP_TIER3_GRANT",
        signer=account,
        payload={"account_id": account},
    )
    _wait_tx_confirmed(cfg, boot["tx_id"])
    state = _wait_registered(cfg, account)
    print(
        f"    confirmed tx_id={boot['tx_id']} poh_tier={state.get('poh_tier') or state.get('tier')}"
    )

    print("[3] ACCOUNT_SESSION_KEY_ISSUE")
    session_key = _issue_session(cfg, account=account, priv_hex=priv_hex)
    print("    session issued")

    print("[4] /v1/media/upload")
    upload = _upload_media(cfg, account=account, session_key=session_key)
    cid = str(upload.get("cid") or upload.get("upload_ref") or "").strip()
    print(f"    uploaded cid={cid}")

    media_id = f"media:{account}:{_next_nonce(cfg, account)}"
    print("[5] CONTENT_MEDIA_DECLARE")
    declared = _submit_tx(
        cfg,
        priv_hex=priv_hex,
        tx_type="CONTENT_MEDIA_DECLARE",
        signer=account,
        payload={
            "media_id": media_id,
            "cid": cid,
            "upload_ref": cid,
            "mime": "text/plain",
            "bytes": len(cfg.media_bytes),
            "name": cfg.media_name,
        },
    )
    _wait_tx_confirmed(cfg, declared["tx_id"])
    _wait_account(cfg, account, nonce_at_least=4)
    print(f"    confirmed tx_id={declared['tx_id']} media_id={media_id}")

    post_id = f"post:{account}:{_next_nonce(cfg, account)}"
    print("[6] CONTENT_POST_CREATE")
    post = _submit_tx(
        cfg,
        priv_hex=priv_hex,
        tx_type="CONTENT_POST_CREATE",
        signer=account,
        payload={
            "post_id": post_id,
            "body": cfg.post_body,
            "visibility": "public",
            "tags": ["golden-path", "e2e"],
            "media": [media_id],
        },
    )
    _wait_tx_confirmed(cfg, post["tx_id"])
    _wait_account(cfg, account, nonce_at_least=5)
    print(f"    confirmed tx_id={post['tx_id']} post_id={post_id}")

    print("[7] feed verification")
    _verify_feed(cfg, account=account, post_id=post_id, body_text=cfg.post_body, media_id=media_id)
    print("    public feed + account feed verified")

    summary_path = _write_demo_summary(
        account=account,
        post_body=cfg.post_body,
        media_name=cfg.media_name,
        extra={
            "api": cfg.api,
            "chain_id": cfg.chain_id,
            "feed_path": "/v1/feed",
            "account_feed_url": f"{cfg.api}/v1/accounts/{urllib.parse.quote(account, safe='')}/feed",
            "post_id": post_id,
            "media_id": media_id,
            "pubkey_hex": pub_hex,
            "secret_key_b64": base64.b64encode(bytes.fromhex(priv_hex) + bytes.fromhex(pub_hex)).decode("ascii"),
            "pubkey_b64": base64.b64encode(bytes.fromhex(pub_hex)).decode("ascii"),
            "session_key": session_key,
            "session_ttl_seconds": 3600,
        },
    )

    print()
    print(
        f"View account feed at: {cfg.api}/v1/accounts/{urllib.parse.quote(account, safe='')}/feed"
    )
    print(f"DEMO_ACCOUNT={account}")
    print(f"DEMO_POST_BODY={cfg.post_body}")
    print(f"DEMO_SUMMARY={summary_path}")
    print("✅ FULL STACK GOLDEN PATH PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
