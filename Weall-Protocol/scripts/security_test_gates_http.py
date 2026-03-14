#!/usr/bin/env python3
"""
HTTP Gate Bypass Security Tests (WeAll Protocol)

Purpose
-------
Prove that PoH tier gates are enforced server-side even if a client bypasses the web UI and
calls /v1/tx/submit directly.

How it works
------------
- Uses HTTP calls only.
- Reads test accounts and optional session keys from environment variables.
- Submits representative tx types and asserts:
  - tier < required is rejected with gate_denied (or equivalent)
  - tier >= required is accepted (ok:true)

Requirements / assumptions
-------------------------
- You have a node reachable at WEALL_BASE (default http://127.0.0.1:8000).
- You provide 3 test accounts with known PoH tiers in the node's ledger:
  - WEALL_ACCT_TIER0  (observer / no PoH)
  - WEALL_ACCT_TIER2
  - WEALL_ACCT_TIER3
- If your node requires auth headers for tx submission, provide:
  - WEALL_SESSION_KEY_TIER0 / _TIER2 / _TIER3  (session key values)
- For dev-mode unsigned tx acceptance, set:
  - WEALL_ALLOW_UNSIGNED_TXS=1 on the node
  (If you do NOT allow unsigned txs, you must run this with valid signing support.
   This script intentionally avoids embedding private keys.)

What it validates
-----------------
- Tier0 cannot: CONTENT_POST_CREATE, GOV_PROPOSAL_CREATE, GROUP_CREATE
- Tier2 can: GROUP_CREATE (but not GOV_PROPOSAL_CREATE)
- Tier3 can: GOV_PROPOSAL_CREATE and CONTENT_POST_CREATE

Exit codes
----------
- 0: all tests passed
- 2: at least one test failed
- 3: cannot reach node / node not ready

"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, List


Json = Dict[str, Any]


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if v is not None and str(v).strip() != "" else default


def http_json(
    method: str,
    url: str,
    body: Optional[Json] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
) -> Tuple[int, Json]:
    data = None
    h = {"Accept": "application/json"}
    if headers:
        h.update(headers)

    if body is not None:
        raw = json.dumps(body).encode("utf-8")
        data = raw
        h["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, method=method.upper(), headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = int(resp.status)
            b = resp.read()
            if not b:
                return status, {}
            return status, json.loads(b.decode("utf-8"))
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            j = json.loads(b.decode("utf-8")) if b else {}
        except Exception:
            j = {"raw": b.decode("utf-8", errors="replace")}
        return int(e.code), j
    except urllib.error.URLError as e:
        raise RuntimeError(f"connection_error: {e}") from e


def is_gate_denied(status: int, j: Json) -> bool:
    if status in (401, 403):
        return True
    if status in (400, 422):
        err = j.get("error") if isinstance(j, dict) else None
        if isinstance(err, dict):
            code = str(err.get("code") or "").lower()
            msg = str(err.get("message") or "").lower()
            if "gate" in code or "gate_denied" in code:
                return True
            if "gate:" in msg or "tier" in msg and "deny" in msg:
                return True
        # Some builds may return ok:false with message
        if j.get("ok") is False:
            msg = json.dumps(j).lower()
            if "gate" in msg and ("deny" in msg or "denied" in msg):
                return True
            if "gate:" in msg:
                return True
    return False


def is_ok(j: Json) -> bool:
    return bool(isinstance(j, dict) and j.get("ok") is True)


def mk_auth_headers(account: str, session_key: Optional[str]) -> Dict[str, str]:
    # Backend CORS explicitly allows X-WeAll-Account / X-WeAll-Session-Key in your builds.
    # If your node uses different headers, adjust here.
    h: Dict[str, str] = {}
    if account:
        h["X-WeAll-Account"] = account
    if session_key:
        h["X-WeAll-Session-Key"] = session_key
    return h


def submit_tx_shape_candidates(account: str, tx_type: str, payload: Json, parent: Optional[str]) -> List[Json]:
    """
    Try a few common request shapes for /v1/tx/submit so this script survives small contract changes.
    """
    tx = {"tx_type": tx_type, "payload": payload, "parent": parent}

    candidates: List[Json] = [
        # Shape A: { account, tx_type, payload, parent }
        {"account": account, "tx_type": tx_type, "payload": payload, "parent": parent},
        # Shape B: { account, tx: { tx_type, payload, parent } }
        {"account": account, "tx": tx},
        # Shape C: { tx: { ... }, account }
        {"tx": tx, "account": account},
        # Shape D: include empty sig field for dev unsigned mode
        {"account": account, "tx": tx, "sig": None},
        {"account": account, "tx_type": tx_type, "payload": payload, "parent": parent, "sig": None},
    ]
    return candidates


@dataclass(frozen=True)
class Actor:
    label: str
    account: str
    session_key: Optional[str]


@dataclass(frozen=True)
class Case:
    name: str
    actor: Actor
    tx_type: str
    payload: Json
    expect: str  # "allow" or "deny"


def wait_ready(base: str) -> None:
    # prefer /v1/readyz; fallback /v1/health
    for i in range(30):
        try:
            st, j = http_json("GET", f"{base}/v1/readyz", None, None, timeout=3.0)
            if st == 200:
                return
        except Exception:
            pass
        try:
            st, j = http_json("GET", f"{base}/v1/health", None, None, timeout=3.0)
            if st == 200:
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("node_not_ready")


def run_case(base: str, c: Case) -> Tuple[bool, str]:
    url = f"{base}/v1/tx/submit"
    headers = mk_auth_headers(c.actor.account, c.actor.session_key)

    last_status = None
    last_body: Json = {}
    for body in submit_tx_shape_candidates(c.actor.account, c.tx_type, c.payload, parent=None):
        status, resp = http_json("POST", url, body, headers=headers, timeout=10.0)
        last_status, last_body = status, resp

        # If schema mismatch (FastAPI 422 validation), try next shape
        if status == 422 and isinstance(resp, dict) and ("detail" in resp or "errors" in resp):
            continue

        if c.expect == "deny":
            if is_gate_denied(status, resp):
                return True, f"PASS deny ({c.actor.label}) {c.tx_type} -> {status}"
            # if not denied, might have been accepted or rejected for other reasons
            if is_ok(resp):
                return False, f"FAIL expected deny but got ok:true ({c.actor.label}) {c.tx_type}"
            # non-ok rejection but not recognized as gate; still a concern for this test
            return False, f"FAIL expected gate deny but got {status} {json.dumps(resp)[:300]}"
        else:
            # allow expected
            if is_ok(resp):
                return True, f"PASS allow ({c.actor.label}) {c.tx_type} -> ok:true"
            # Allow tests may fail if you require signing. That’s still useful signal.
            if is_gate_denied(status, resp):
                return False, f"FAIL expected allow but got gate denied ({c.actor.label}) {c.tx_type}: {status} {json.dumps(resp)[:250]}"
            return False, f"FAIL expected allow but got {status} {json.dumps(resp)[:300]}"

    # Exhausted shapes
    return False, f"FAIL could not submit tx: last={last_status} {json.dumps(last_body)[:300]}"


def main() -> int:
    base = env("WEALL_BASE", "http://127.0.0.1:8000").rstrip("/")

    a0 = env("WEALL_ACCT_TIER0")
    a2 = env("WEALL_ACCT_TIER2")
    a3 = env("WEALL_ACCT_TIER3")

    if not a0 or not a2 or not a3:
        print("❌ Missing required env vars:")
        print("   WEALL_ACCT_TIER0, WEALL_ACCT_TIER2, WEALL_ACCT_TIER3")
        print("")
        print("Tip: use the web UI or your existing tooling to create 3 accounts and upgrade them to desired PoH tiers,")
        print("then export those account ids here.")
        return 2

    actors = {
        "tier0": Actor("tier0", a0, env("WEALL_SESSION_KEY_TIER0")),
        "tier2": Actor("tier2", a2, env("WEALL_SESSION_KEY_TIER2")),
        "tier3": Actor("tier3", a3, env("WEALL_SESSION_KEY_TIER3")),
    }

    try:
        wait_ready(base)
    except Exception as e:
        print(f"❌ Node not reachable/ready at {base}: {e}")
        return 3

    # Minimal payloads — these should be sufficient to trigger admission gating before deep apply validation.
    # If your executor requires additional fields, the ALLOW cases may fail for validation (which is still useful),
    # but the DENY cases should still show gate_denied if admission gates are wired correctly.
    cases: List[Case] = [
        # Content posting should be Tier3+ in your current build
        Case(
            name="tier0_cannot_post",
            actor=actors["tier0"],
            tx_type="CONTENT_POST_CREATE",
            payload={"text": "gate_test_post", "visibility": "public"},
            expect="deny",
        ),
        Case(
            name="tier3_can_post",
            actor=actors["tier3"],
            tx_type="CONTENT_POST_CREATE",
            payload={"text": "gate_test_post", "visibility": "public"},
            expect="allow",
        ),
        # Governance should be Tier3+
        Case(
            name="tier2_cannot_gov_propose",
            actor=actors["tier2"],
            tx_type="GOV_PROPOSAL_CREATE",
            payload={"title": "gate_test", "body": "gate_test", "proposal_type": "PARAM_CHANGE"},
            expect="deny",
        ),
        Case(
            name="tier3_can_gov_propose",
            actor=actors["tier3"],
            tx_type="GOV_PROPOSAL_CREATE",
            payload={"title": "gate_test", "body": "gate_test", "proposal_type": "PARAM_CHANGE"},
            expect="allow",
        ),
        # Groups create should be Tier2+
        Case(
            name="tier0_cannot_create_group",
            actor=actors["tier0"],
            tx_type="GROUP_CREATE",
            payload={"group_id": "g:gate-test", "charter": {"name": "Gate Test", "description": "test"}},
            expect="deny",
        ),
        Case(
            name="tier2_can_create_group",
            actor=actors["tier2"],
            tx_type="GROUP_CREATE",
            payload={"group_id": "g:gate-test", "charter": {"name": "Gate Test", "description": "test"}},
            expect="allow",
        ),
    ]

    print(f"🔐 Gate bypass tests against: {base}")
    print("")

    passed = 0
    failed = 0
    for c in cases:
        ok, msg = run_case(base, c)
        print(msg)
        if ok:
            passed += 1
        else:
            failed += 1

    print("")
    print(f"Summary: {passed} passed, {failed} failed")

    # If allow-cases fail due to signing/validation, you’ll see failures.
    # That still means “not trivially bypassable”, but it doesn’t prove positive authorization.
    # For production we want both deny + allow working.
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
