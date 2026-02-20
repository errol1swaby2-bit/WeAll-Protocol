#!/usr/bin/env python3
"""
Patch domain_apply.py to support "account balance slashing on ban".

- Adds deterministic, integer-only helpers:
  - _ensure_fees_pending_reward(...)
  - _get_account_balance_int(...)
  - _set_account_balance_int(...)
  - _apply_pending_reward_credit(...)
  - _compute_slash_amount(...)
- Patches _apply_account_ban(...) to:
  - set banned = True (existing behavior)
  - optionally slash balance based on payload: slash_amount or slash_pct
  - credit slashed amount into fees.pending_reward
  - append to state["ban_slash_log"]

Run:
  python3 scripts/patch_account_ban_slash.py
  pytest -q
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_APPLY = REPO_ROOT / "src" / "weall" / "runtime" / "domain_apply.py"

HELPERS_BEGIN = "# BEGIN WEALL BAN SLASH HELPERS (AUTO-GENERATED)\n"
HELPERS_END = "# END WEALL BAN SLASH HELPERS (AUTO-GENERATED)\n"

HELPERS_BLOCK = r'''# BEGIN WEALL BAN SLASH HELPERS (AUTO-GENERATED)
# Deterministic, integer-only money helpers used for ban slashing.
# We keep behavior opt-in via payload fields to avoid surprising semantics.

def _ensure_fees_pending_reward(state: Json) -> Json:
    fees = state.get("fees")
    if not isinstance(fees, dict):
        fees = {}
        state["fees"] = fees
    if "pending_reward" not in fees or fees.get("pending_reward") is None:
        fees["pending_reward"] = 0
    # normalize to int if possible
    try:
        fees["pending_reward"] = int(float(fees.get("pending_reward") or 0))
    except Exception:
        fees["pending_reward"] = 0
    return fees


def _get_account_balance_int(state: Json, account_id: str) -> int:
    acct = _create_default_account(state, account_id)
    bal = acct.get("balance")
    if bal is None:
        acct["balance"] = 0
        return 0
    try:
        v = int(float(bal))
    except Exception:
        v = 0
    if v < 0:
        v = 0
    acct["balance"] = v
    return v


def _set_account_balance_int(state: Json, account_id: str, new_balance: int) -> None:
    if new_balance < 0:
        new_balance = 0
    acct = _create_default_account(state, account_id)
    acct["balance"] = int(new_balance)


def _apply_pending_reward_credit(state: Json, amount: int) -> None:
    if amount <= 0:
        return
    fees = _ensure_fees_pending_reward(state)
    fees["pending_reward"] = int(fees.get("pending_reward") or 0) + int(amount)


def _compute_slash_amount(*, current_balance: int, payload: Json) -> int:
    # Priority:
    # 1) slash_amount (exact)
    # 2) slash_pct (0..100)
    # Otherwise: 0 (no slash)
    if not isinstance(payload, dict):
        return 0

    if "slash_amount" in payload and payload.get("slash_amount") is not None:
        try:
            amt = int(float(payload.get("slash_amount") or 0))
        except Exception:
            amt = 0
        if amt < 0:
            amt = 0
        if amt > current_balance:
            amt = current_balance
        return amt

    if "slash_pct" in payload and payload.get("slash_pct") is not None:
        try:
            pct = float(payload.get("slash_pct") or 0)
        except Exception:
            pct = 0.0
        if pct < 0:
            pct = 0.0
        if pct > 100:
            pct = 100.0
        # floor by int conversion
        amt = int((current_balance * pct) / 100.0)
        if amt < 0:
            amt = 0
        if amt > current_balance:
            amt = current_balance
        return amt

    return 0

# END WEALL BAN SLASH HELPERS (AUTO-GENERATED)
'''


def _insert_helpers_if_missing(src: str) -> str:
    if HELPERS_BEGIN in src:
        return src

    # Insert helpers right after the ApplyError class (stable-ish anchor)
    m = re.search(r"\nclass ApplyError\([^)]*\):\n(?:[^\n]*\n)+?\n", src)
    if not m:
        # fallback: insert near top after imports
        m2 = re.search(r"\nfrom __future__ import annotations\n", src)
        if not m2:
            raise SystemExit("Could not find a safe insertion anchor for helper block.")
        pos = m2.end()
        return src[:pos] + "\n" + HELPERS_BLOCK + "\n" + src[pos:]

    pos = m.end()
    return src[:pos] + "\n" + HELPERS_BLOCK + "\n" + src[pos:]


def _patch_apply_account_ban(src: str) -> str:
    """
    Find def _apply_account_ban(...): and inject slashing logic just before its return.
    """
    # Capture function body
    func_pat = re.compile(
        r"(def _apply_account_ban\([^\)]*\)\s*->\s*[^\:]+:\n)(?P<body>(?:[ \t].*\n)+)",
        re.M,
    )
    m = func_pat.search(src)
    if not m:
        raise SystemExit("Could not find function: _apply_account_ban(...) in domain_apply.py")

    body = m.group("body")
    if "ban_slash_log" in body or "_compute_slash_amount" in body:
        # already patched
        return src

    # We want to inject near the end of the function, before the final return line.
    # Find the last 'return {' in the body (most of your apply fns end with a dict return).
    ret_idx = body.rfind("\n    return ")
    if ret_idx < 0:
        raise SystemExit("_apply_account_ban has no 'return' line to patch against.")

    before = body[:ret_idx]
    after = body[ret_idx:]

    injection = r'''
    # Optional balance slashing on ban (opt-in via payload).
    # If present, slashed value is routed into fees.pending_reward for next block reward.
    try:
        payload = _as_dict(env.payload)
    except Exception:
        payload = {}

    target = _as_str(payload.get("account_id") or env.signer).strip()
    if target:
        current = _get_account_balance_int(state, target)
        slash_amt = _compute_slash_amount(current_balance=current, payload=payload)
        if slash_amt > 0:
            _set_account_balance_int(state, target, current - slash_amt)
            _apply_pending_reward_credit(state, slash_amt)

            log = state.get("ban_slash_log")
            if not isinstance(log, list):
                log = []
            log.append(
                {
                    "at_nonce": int(env.nonce),
                    "account_id": target,
                    "slashed": int(slash_amt),
                    "reason": _as_str(payload.get("reason") or "").strip(),
                }
            )
            state["ban_slash_log"] = log
'''

    new_body = before + injection + after
    return src[: m.start("body")] + new_body + src[m.end("body") :]


def main() -> None:
    if not DOMAIN_APPLY.exists():
        raise SystemExit(f"domain_apply not found at {DOMAIN_APPLY}")

    src = DOMAIN_APPLY.read_text(encoding="utf-8")

    src = _insert_helpers_if_missing(src)
    src = _patch_apply_account_ban(src)

    DOMAIN_APPLY.write_text(src, encoding="utf-8")
    print(f"Patched: {DOMAIN_APPLY}")


if __name__ == "__main__":
    main()
