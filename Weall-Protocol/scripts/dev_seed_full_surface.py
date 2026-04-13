#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from weall.crypto.sig import sign_tx_envelope_dict

Json = dict[str, Any]


@dataclass(frozen=True)
class Cfg:
    api: str
    chain_id: str
    account: str
    wait_apply_s: float
    poll_s: float
    bootstrap_manifest_path: Path
    fixture_post_body: str
    fixture_post_id: str


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    return value if value not in (None, "") else default


def _cfg() -> Cfg:
    api = str(_env("WEALL_API", "http://127.0.0.1:8000")).rstrip("/")
    chain_id = str(_env("WEALL_CHAIN_ID", "weall-dev")).strip() or "weall-dev"
    account = str(_env("WEALL_DEV_ACCOUNT", "@dev_tester")).strip() or "@dev_tester"
    if not account.startswith("@"):
        account = f"@{account}"
    wait_apply_s = float(_env("WEALL_WAIT_APPLY_S", "90") or "90")
    poll_s = max(0.2, float(_env("WEALL_POLL_S", "0.5") or "0.5"))
    manifest_path = Path(
        str(
            _env(
                "WEALL_DEV_BOOTSTRAP_MANIFEST_PATH",
                str(Path(__file__).resolve().parents[2] / "web" / "public" / "dev-bootstrap.json"),
            )
        )
    )
    fixture_post_body = str(_env("WEALL_DEV_FIXTURE_POST_BODY", "Dev full-surface bootstrap post")).strip()
    fixture_post_id = str(_env("WEALL_DEV_FIXTURE_POST_ID", f"post:{account}:fixture")).strip()
    return Cfg(
        api=api,
        chain_id=chain_id,
        account=account,
        wait_apply_s=wait_apply_s,
        poll_s=poll_s,
        bootstrap_manifest_path=manifest_path,
        fixture_post_body=fixture_post_body,
        fixture_post_id=fixture_post_id,
    )


def _seed_material() -> tuple[str, str, str]:
    seed = hashlib.sha256(b"weall-dev-full-surface-seed-v1").digest()
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_hex = seed.hex()
    pub_hex = pub.hex()
    secret_key_b64 = base64.b64encode(seed + pub).decode("ascii")
    return priv_hex, pub_hex, secret_key_b64


def _http_json(method: str, url: str, body: Json | None = None, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    payload = None
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=payload, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=30.0) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except Exception:
                parsed = {"raw": raw}
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw) if raw else {}
        except Exception:
            parsed = {"raw": raw}
        return exc.code, parsed


def _get(cfg: Cfg, path: str) -> Json:
    status, body = _http_json("GET", f"{cfg.api}{path}")
    if status >= 400:
        raise RuntimeError(f"GET {path} failed status={status} body={body}")
    return body if isinstance(body, dict) else {}


def _post(cfg: Cfg, path: str, payload: Json) -> Json:
    status, body = _http_json("POST", f"{cfg.api}{path}", body=payload)
    if status >= 400:
        raise RuntimeError(f"POST {path} failed status={status} body={body}")
    return body if isinstance(body, dict) else {}


def _account_path(account: str) -> str:
    return f"/v1/accounts/{urllib.parse.quote(account, safe='')}"


def _account_state(cfg: Cfg, account: str) -> Json:
    body = _get(cfg, _account_path(account))
    state = body.get("state")
    return state if isinstance(state, dict) else {}


def _snapshot_account_exists(cfg: Cfg, account: str) -> bool:
    body = _get(cfg, "/v1/state/snapshot")
    state = body.get("state") if isinstance(body, dict) else None
    accounts = state.get("accounts") if isinstance(state, dict) else None
    return isinstance(accounts, dict) and isinstance(accounts.get(account), dict)


def _next_nonce(cfg: Cfg, account: str) -> int:
    state = _account_state(cfg, account)
    try:
        return int(state.get("nonce") or 0) + 1
    except Exception:
        return 1


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
            raise RuntimeError(f"tx failed: {tx_id} body={last}")
        time.sleep(cfg.poll_s)
    raise RuntimeError(f"tx did not confirm in time: {tx_id} last={last}")


def _wait_account(cfg: Cfg, account: str, *, nonce_at_least: int | None = None, tier_at_least: int | None = None) -> Json:
    deadline = time.time() + cfg.wait_apply_s
    last: Json = {}
    while time.time() < deadline:
        if not _snapshot_account_exists(cfg, account):
            time.sleep(cfg.poll_s)
            continue
        last = _account_state(cfg, account)
        nonce_ok = nonce_at_least is None or int(last.get("nonce") or 0) >= nonce_at_least
        tier_ok = tier_at_least is None or int(last.get("poh_tier") or last.get("tier") or 0) >= tier_at_least
        if nonce_ok and tier_ok:
            return last
        time.sleep(cfg.poll_s)
    raise RuntimeError(f"account state did not reach threshold: account={account} last={last}")


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
        raise RuntimeError(f"tx submit missing tx_id: {body}")
    return {"tx_id": tx_id, "submit": body}


def _ensure_account_registered(cfg: Cfg, *, priv_hex: str, pub_hex: str) -> Json:
    state = _account_state(cfg, cfg.account)
    if _snapshot_account_exists(cfg, cfg.account):
        return state
    reg = _submit_tx(
        cfg,
        priv_hex=priv_hex,
        tx_type="ACCOUNT_REGISTER",
        signer=cfg.account,
        payload={"pubkey": pub_hex},
    )
    _wait_tx_confirmed(cfg, reg["tx_id"])
    return _wait_account(cfg, cfg.account, nonce_at_least=1)


def _ensure_tier3(cfg: Cfg, *, priv_hex: str) -> Json:
    state = _account_state(cfg, cfg.account)
    if int(state.get("poh_tier") or state.get("tier") or 0) >= 3:
        return state
    grant = _submit_tx(
        cfg,
        priv_hex=priv_hex,
        tx_type="POH_BOOTSTRAP_TIER3_GRANT",
        signer=cfg.account,
        payload={"account_id": cfg.account},
    )
    _wait_tx_confirmed(cfg, grant["tx_id"])
    return _wait_account(cfg, cfg.account, tier_at_least=3)


def _ensure_fixture_post(cfg: Cfg, *, priv_hex: str) -> None:
    feed = _get(cfg, f"{_account_path(cfg.account)}/feed")
    items = feed.get("items") if isinstance(feed, dict) else None
    if isinstance(items, list):
        for item in items:
            if str(item.get("post_id") or "") == cfg.fixture_post_id:
                return
    tx = _submit_tx(
        cfg,
        priv_hex=priv_hex,
        tx_type="CONTENT_POST_CREATE",
        signer=cfg.account,
        payload={
            "post_id": cfg.fixture_post_id,
            "body": cfg.fixture_post_body,
            "visibility": "public",
            "tags": ["dev", "full-surface", "bootstrap"],
            "media": [],
        },
    )
    _wait_tx_confirmed(cfg, tx["tx_id"])
    _wait_account(cfg, cfg.account, nonce_at_least=3)


def _write_manifest(cfg: Cfg, *, secret_key_b64: str, pub_hex: str) -> Path:
    manifest = {
        "profile": "dev_full_surface",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "account": cfg.account,
        "pubkeyB64": base64.b64encode(bytes.fromhex(pub_hex)).decode("ascii"),
        "secretKeyB64": secret_key_b64,
        "apiBase": cfg.api,
        "sessionTtlSeconds": 24 * 60 * 60,
        "note": "Local dev bootstrap profile. Not production authority.",
    }
    cfg.bootstrap_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.bootstrap_manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return cfg.bootstrap_manifest_path


def main() -> int:
    cfg = _cfg()
    priv_hex, pub_hex, secret_key_b64 = _seed_material()

    _get(cfg, "/v1/readyz")
    _ensure_account_registered(cfg, priv_hex=priv_hex, pub_hex=pub_hex)
    state = _ensure_tier3(cfg, priv_hex=priv_hex)
    _ensure_fixture_post(cfg, priv_hex=priv_hex)
    manifest_path = _write_manifest(cfg, secret_key_b64=secret_key_b64, pub_hex=pub_hex)

    summary = {
        "ok": True,
        "profile": "dev_full_surface",
        "account": cfg.account,
        "api": cfg.api,
        "chain_id": cfg.chain_id,
        "poh_tier": int(state.get("poh_tier") or state.get("tier") or 0),
        "manifest_path": str(manifest_path),
        "fixture_post_id": cfg.fixture_post_id,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
