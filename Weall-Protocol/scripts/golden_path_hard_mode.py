#!/usr/bin/env python3
"""
Hard-mode golden path for WeAll Protocol (dev/testnet).

Robust against nodes that:
  - report tx status only after commit (or return pending/unknown)
  - store account keys as either a list OR as {"by_id": {...}}

Flow:
  1) generate ed25519 keypair
  2) ACCOUNT_REGISTER (nonce=account.nonce+1)
  3) wait for account registration to apply (keys present)
  4) POH_BOOTSTRAP_TIER3_GRANT (dev-only; requires WEALL_POH_BOOTSTRAP_OPEN=1)
  5) verify tier>=3 then POST_CREATE

Run:
  PYTHONPATH=src python3 scripts/golden_path_hard_mode.py
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from nacl.signing import SigningKey

from weall.crypto.sig import sign_tx_envelope_dict

Json = dict[str, Any]


@dataclass(frozen=True)
class Cfg:
    api_base: str
    chain_id: str


def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v is not None and v != "" else default


def _http_json(
    method: str, url: str, body: Json | None = None, timeout_s: float = 10.0
) -> tuple[int, Json]:
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            raw = r.read().decode("utf-8", errors="replace")
            try:
                obj = json.loads(raw) if raw.strip() else {}
            except Exception:
                obj = {"raw": raw}
            return int(getattr(r, "status", 200)), obj
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            obj = json.loads(raw) if raw.strip() else {}
        except Exception:
            obj = {"raw": raw}
        return int(e.code), obj


def _get_account(cfg: Cfg, account: str) -> Json:
    url = f"{cfg.api_base}/v1/accounts/{urllib.parse.quote(account, safe='')}"
    status, body = _http_json("GET", url, None, timeout_s=10.0)
    if status != 200:
        raise RuntimeError(f"account_get failed status={status} body={body}")
    return body


def _account_state(body: Json) -> Json:
    st = body.get("state")
    return st if isinstance(st, dict) else {}


def _account_nonce(body: Json) -> int:
    st = _account_state(body)
    try:
        return int(st.get("nonce") or 0)
    except Exception:
        return 0


def _next_nonce(body: Json) -> int:
    return _account_nonce(body) + 1


def _poh_tier(body: Json) -> int:
    st = _account_state(body)
    try:
        return int(st.get("poh_tier") or 0)
    except Exception:
        return 0


def _has_any_keys(body: Json) -> bool:
    """
    Your current state uses:
      keys: { by_id: { k:...: {...} } }

    But older shapes may use:
      keys: [ {pubkey:...}, ... ]
    """
    st = _account_state(body)
    keys = st.get("keys")

    if isinstance(keys, list):
        return any(bool(k) for k in keys)

    if isinstance(keys, dict):
        by_id = keys.get("by_id")
        if isinstance(by_id, dict) and len(by_id) > 0:
            return True
        # Sometimes keys is already a {id: {...}} dict
        if len(keys) > 0 and "by_id" not in keys:
            return True

    return False


def _wait_for_registration_applied(
    cfg: Cfg, account: str, *, timeout_s: float = 90.0, poll_s: float = 0.5
) -> Json:
    deadline = time.time() + float(timeout_s)
    last = None
    while time.time() < deadline:
        body = _get_account(cfg, account)
        last = body
        if _has_any_keys(body):
            return body
        time.sleep(float(poll_s))
    raise RuntimeError(f"account registration not applied within timeout; last={last}")


def _wait_for_poh_tier(
    cfg: Cfg, account: str, *, want_tier: int, timeout_s: float = 90.0, poll_s: float = 0.5
) -> Json:
    deadline = time.time() + float(timeout_s)
    last = None
    while time.time() < deadline:
        body = _get_account(cfg, account)
        last = body
        if _poh_tier(body) >= int(want_tier):
            return body
        time.sleep(float(poll_s))
    raise RuntimeError(f"poh tier not reached; want={want_tier} last={last}")


def _submit_tx(
    cfg: Cfg, priv_hex: str, tx_type: str, signer: str, nonce: int, payload: Json
) -> Json:
    tx: Json = {
        "chain_id": cfg.chain_id,
        "tx_type": tx_type,
        "signer": signer,
        "nonce": int(nonce),
        "payload": payload,
    }
    signed = sign_tx_envelope_dict(tx=tx, privkey=priv_hex, encoding="hex")

    url = f"{cfg.api_base}/v1/tx/submit"
    status, body = _http_json("POST", url, signed, timeout_s=20.0)
    if status != 200:
        raise RuntimeError(f"tx_submit failed: http={status} body={body}")
    return body


def _tx_status(cfg: Cfg, tx_id: str) -> Json:
    url = f"{cfg.api_base}/v1/tx/status/{urllib.parse.quote(str(tx_id), safe='')}"
    status, body = _http_json("GET", url, None, timeout_s=10.0)
    if status != 200:
        raise RuntimeError(f"tx_status failed status={status} body={body}")
    return body


def _wait_tx_confirmed_best_effort(
    cfg: Cfg, tx_id: str, *, timeout_s: float = 10.0, poll_s: float = 0.5
) -> str:
    deadline = time.time() + float(timeout_s)
    last_status = "unknown"
    while time.time() < deadline:
        last = _tx_status(cfg, tx_id)
        st = str(last.get("status") or "").strip().lower()
        last_status = st or "unknown"
        if last_status in {"confirmed", "committed", "applied"}:
            return last_status
        time.sleep(float(poll_s))
    return last_status


def _gen_keypair() -> tuple[str, str]:
    sk = SigningKey.generate()
    pk = sk.verify_key
    return sk.encode().hex(), pk.encode().hex()


def main() -> int:
    cfg = Cfg(
        api_base=_env("WEALL_API", "http://127.0.0.1:8000").rstrip("/"),
        chain_id=_env("WEALL_CHAIN_ID", "dev"),
    )

    priv_hex, pub_hex = _gen_keypair()
    acct = f"@hard_{int(time.time())}_{os.getpid()}"

    print("=== HARD MODE GOLDEN PATH ===")
    print("API:", cfg.api_base)
    print("CHAIN_ID:", cfg.chain_id)
    print("ACCOUNT:", acct)
    print()

    acct_body = _get_account(cfg, acct)
    print(f"[0] preflight nonce={_account_nonce(acct_body)} next_nonce={_next_nonce(acct_body)}")
    print()

    print("[1] ACCOUNT_REGISTER")
    res = _submit_tx(
        cfg,
        priv_hex=priv_hex,
        tx_type="ACCOUNT_REGISTER",
        signer=acct,
        nonce=_next_nonce(acct_body),
        payload={"pubkey": pub_hex},
    )
    tx_id = str(res.get("tx_id") or "").strip()
    if tx_id:
        st = _wait_tx_confirmed_best_effort(cfg, tx_id, timeout_s=10.0, poll_s=0.5)
        print(f"     submitted tx_id={tx_id} (status_endpoint={st})")

    print("[1b] wait for account registration to apply (keys present)")
    acct_body = _wait_for_registration_applied(cfg, acct, timeout_s=90.0, poll_s=0.5)
    print(
        f"     applied; current_nonce={_account_nonce(acct_body)} next_nonce={_next_nonce(acct_body)}"
    )
    print()

    print(
        "[2] POH_BOOTSTRAP_TIER3_GRANT (optional; requires WEALL_POH_BOOTSTRAP_OPEN=1 server-side)"
    )
    try:
        res = _submit_tx(
            cfg,
            priv_hex=priv_hex,
            tx_type="POH_BOOTSTRAP_TIER3_GRANT",
            signer=acct,
            nonce=_next_nonce(acct_body),
            payload={"account_id": acct, "pubkey": pub_hex},
        )
        tx_id = str(res.get("tx_id") or "").strip()
        if tx_id:
            st = _wait_tx_confirmed_best_effort(cfg, tx_id, timeout_s=10.0, poll_s=0.5)
            print(f"     submitted tx_id={tx_id} (status_endpoint={st})")

        acct_body = _wait_for_poh_tier(cfg, acct, want_tier=3, timeout_s=90.0, poll_s=0.5)
        print(
            f"     bootstrap ok; poh_tier={_poh_tier(acct_body)} current_nonce={_account_nonce(acct_body)} next_nonce={_next_nonce(acct_body)}"
        )
    except Exception as e:
        print(f"     (skipped/failed bootstrap) {e}")

    print()

    print("[3] POST_CREATE")
    acct_body = _get_account(cfg, acct)
    tier_now = _poh_tier(acct_body)
    if tier_now < 3:
        raise RuntimeError(f"refusing_to_post_without_tier3 poh_tier={tier_now}")

    post_payload: Json = {
        "body": "hello from hard mode",
        "tags": ["hardmode"],
        "visibility": "public",
    }

    res = _submit_tx(
        cfg,
        priv_hex=priv_hex,
        tx_type="POST_CREATE",
        signer=acct,
        nonce=_next_nonce(acct_body),
        payload=post_payload,
    )
    print("     post submitted:", res)
    print()
    print("✅ DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
