from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, Optional

from weall.runtime.errors import ApplyError
from weall.poh.operator_email_receipts import validate_operator_email_receipt

Json = Dict[str, Any]


def _as_str(v: Any) -> str:
    try:
        return str(v)
    except Exception:
        return ""


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _sha256_hex(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def _poh_root(state: Json) -> Json:
    poh = state.get("poh")
    if not isinstance(poh, dict):
        poh = {}
        state["poh"] = poh
    return poh


def _tier2_cases(state: Json) -> Json:
    poh = _poh_root(state)
    cases = poh.get("tier2_cases")
    if not isinstance(cases, dict):
        cases = {}
        poh["tier2_cases"] = cases
    return cases


def _tier3_cases(state: Json) -> Json:
    poh = _poh_root(state)
    cases = poh.get("tier3_cases")
    if not isinstance(cases, dict):
        cases = {}
        poh["tier3_cases"] = cases
    return cases


def _challenges(state: Json) -> Json:
    poh = _poh_root(state)
    challenges = poh.get("challenges")
    if not isinstance(challenges, dict):
        challenges = {}
        poh["challenges"] = challenges
    return challenges


def _poh_nfts_root(state: Json) -> Json:
    root = state.get("poh_nfts")
    if not isinstance(root, dict):
        root = {}
        state["poh_nfts"] = root

    by_id = root.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        root["by_id"] = by_id

    by_owner = root.get("by_owner")
    if not isinstance(by_owner, dict):
        by_owner = {}
        root["by_owner"] = by_owner

    return root


def _chain_id(state: Json) -> str:
    cid = _as_str(state.get("chain_id") or "").strip()
    if cid:
        return cid
    params = state.get("params")
    if isinstance(params, dict):
        cid = _as_str(params.get("chain_id") or "").strip()
        if cid:
            return cid
    return "weall"


def _deterministic_poh_token_id(*, state: Json, owner: str, tier: int, source_id: str) -> str:
    payload = f"{_chain_id(state)}|POH_GATE|{owner}|{int(tier)}|{source_id}".encode("utf-8")
    return _sha256_hex(payload)


def _mint_poh_nft(state: Json, *, owner: str, tier: int, source_id: str, ts_ms: int = 0) -> str:
    root = _poh_nfts_root(state)
    by_id = root["by_id"]
    by_owner = root["by_owner"]

    token_id = _deterministic_poh_token_id(state=state, owner=owner, tier=int(tier), source_id=source_id)

    if token_id in by_id:
        bucket = by_owner.get(owner)
        if not isinstance(bucket, dict):
            bucket = {}
            by_owner[owner] = bucket
        bucket[token_id] = True
        return token_id

    by_id[token_id] = {
        "token_id": token_id,
        "owner": owner,
        "tier": int(tier),
        "source_id": source_id,
        "minted_height": int(state.get("height") or 0),
        "minted_ts_ms": int(ts_ms),
    }

    bucket = by_owner.get(owner)
    if not isinstance(bucket, dict):
        bucket = {}
        by_owner[owner] = bucket
    bucket[token_id] = True

    return token_id


def _require_prod_no_auto_create(state: Json, account_id: str) -> None:
    mode = str(os.environ.get("WEALL_MODE") or "prod").strip().lower()
    if mode == "prod":
        accounts = state.get("accounts") or {}
        if account_id not in accounts:
            raise ApplyError("invalid_tx", "account_not_registered", {"account_id": account_id})


def _require_account_exists(state: Json, account_id: str, *, code: str = "invalid_tx", reason: str = "account_not_found") -> Json:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_tx", "accounts_missing", {})
    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        raise ApplyError(code, reason, {"account_id": account_id})
    return acct

def _truthy_env(name: str) -> bool:
    v = (os.environ.get(name) or "").strip().lower()
    return v in {"1", "true", "yes", "y", "on"}


def _mode() -> str:
    return (os.environ.get("WEALL_MODE") or "prod").strip().lower()


def _account_has_pubkey(acct: Json, pubkey: str) -> bool:
    """Return True if acct.keys contains pubkey in any supported schema shape."""
    if not pubkey:
        return False
    pk = str(pubkey).strip()
    if not pk:
        return False

    keys = acct.get("keys")
    # Shape A: { "<pubkey>": {...}, ... }
    if isinstance(keys, dict) and pk in keys:
        return True

    # Shape B: { "by_id": { "<kid>": {"pubkey": "<pubkey>", ...}, ... } }
    if isinstance(keys, dict):
        by_id = keys.get("by_id")
        if isinstance(by_id, dict):
            for _, rec in by_id.items():
                if isinstance(rec, dict) and str(rec.get("pubkey") or "").strip() == pk:
                    return True

    # Shape C: [ "<pubkey>", ... ]
    if isinstance(keys, list):
        for it in keys:
            if str(it or "").strip() == pk:
                return True

    return False



def _require_active_tier3(state: Json, account_id: str, *, case_id: str = "") -> Json:
    acct = _require_account_exists(state, account_id, code="invalid_tx", reason="juror_account_not_found")
    if bool(acct.get("banned", False)):
        raise ApplyError("invalid_tx", "juror_banned", {"case_id": case_id, "juror": account_id})
    if bool(acct.get("locked", False)):
        raise ApplyError("invalid_tx", "juror_locked", {"case_id": case_id, "juror": account_id})
    tier = _as_int(acct.get("poh_tier") or 0, 0)
    if tier < 3:
        raise ApplyError("invalid_tx", "juror_not_tier3", {"case_id": case_id, "juror": account_id, "tier": tier})
    return acct


def _get_env(env: Any, key: str, default: Any = None) -> Any:
    if isinstance(env, dict):
        return env.get(key, default)
    return getattr(env, key, default)


def _tx_type(env: Any) -> str:
    return _as_str(_get_env(env, "tx_type", "")).strip().upper()


def _signer(env: Any) -> str:
    return _as_str(_get_env(env, "signer", "")).strip()


def _payload(env: Any) -> Json:
    p = _get_env(env, "payload", None)
    return p if isinstance(p, dict) else {}


def _case_id(prefix: str, *, account_id: str, nonce: int) -> str:
    return f"{prefix}:{account_id}:{max(0, int(nonce))}"




def _email_receipts(state: Json) -> Json:
    poh = _poh_root(state)
    receipts = poh.get("email_receipts")
    if not isinstance(receipts, dict):
        receipts = {}
        poh["email_receipts"] = receipts
    return receipts


def apply_poh_email_receipt_submit(state: Json, env: Any) -> Json:
    p = _payload(env)
    account_id = _as_str(p.get("account_id") or _signer(env)).strip()
    receipt = p.get("receipt")

    if not account_id:
        raise ApplyError("invalid_tx", "missing_account_id", {})
    acct = _require_account_exists(state, account_id)
    ok, code, payload = validate_operator_email_receipt(state, subject_account_id=account_id, receipt=receipt if isinstance(receipt, dict) else {})
    if not ok or not isinstance(payload, dict):
        raise ApplyError("invalid_tx", code, {"account_id": account_id})

    receipts = _email_receipts(state)
    receipt_key = _as_str(payload.get('request_id') or '')
    if receipt_key in receipts:
        raise ApplyError("invalid_tx", "receipt_replayed", {"receipt_key": receipt_key})

    acct["poh_tier"] = max(_as_int(acct.get("poh_tier") or 0), 1)
    token_id = _mint_poh_nft(
        state,
        owner=account_id,
        tier=1,
        source_id=receipt_key,
        ts_ms=_as_int(payload.get("issued_at_ms") or 0),
    )

    receipts[receipt_key] = {
        "receipt_key": receipt_key,
        "account_id": account_id,
        "worker_account_id": _as_str(payload.get("worker_account_id") or ""),
        "worker_pubkey": _as_str(payload.get("worker_pubkey") or ""),
        "email_commitment": _as_str(payload.get("email_commitment") or ""),
        "request_id": _as_str(payload.get("request_id") or ""),
        "nonce": _as_str(payload.get("nonce") or ""),
        "issued_at_ms": _as_int(payload.get("issued_at_ms") or 0),
        "expires_at_ms": _as_int(payload.get("expires_at_ms") or 0),
        "poh_nft_token_id": token_id,
        "accepted_at_height": int(state.get("height") or 0),
    }

    return {
        "applied": "POH_EMAIL_RECEIPT_SUBMIT",
        "account_id": account_id,
        "receipt_key": receipt_key,
        "token_id": token_id,
    }

def apply_poh_tier_set(state: Json, tx: Json) -> None:
    payload = tx.get("payload") or {}
    account_id = str(payload.get("account_id") or "")
    tier = int(payload.get("tier") or 0)

    if not account_id:
        raise ApplyError("invalid_tx", "missing_account", {})

    _require_prod_no_auto_create(state, account_id)

    accounts = state.setdefault("accounts", {})
    acct = accounts.setdefault(account_id, {})
    acct["poh_tier"] = tier


def apply_poh_bootstrap_tier3_grant(state: Json, tx: Json) -> None:
    """Bootstrap a Tier3 PoH grant.

    Production policy:
      - restricted to params.bootstrap_allowlist entries
      - expires after params.bootstrap_expires_height

    Dev/testnet convenience (opt-in, explicit):
      - if WEALL_POH_BOOTSTRAP_OPEN=1 and WEALL_MODE!=prod
      - signer must equal payload.account_id (self-bootstrap only)
      - still requires the account to exist (must register first)
      - respects params.poh_bootstrap_max_height if set (>0)
    """

    payload = tx.get("payload") or {}
    account_id = str(payload.get("account_id") or "").strip()
    signer = str(tx.get("signer") or "").strip()
    nonce = int(tx.get("nonce") or 0)

    if not account_id:
        raise ApplyError("invalid_tx", "missing_account", {})

    current_height = int(state.get("height") or 0)
    params = state.get("params") or {}

    # Optional global ceiling for any bootstrap mechanism (dev or allowlist).
    max_h = int(params.get("poh_bootstrap_max_height") or 0)
    if max_h > 0 and current_height > max_h:
        raise ApplyError("forbidden", "bootstrap_expired", {"height": current_height, "expires_height": max_h})

    # --- Dev/testnet open bootstrap (explicit opt-in) ---
    if _truthy_env("WEALL_POH_BOOTSTRAP_OPEN") and _mode() in {"dev", "testnet"}:
        if signer != account_id:
            raise ApplyError("forbidden", "bootstrap_self_only", {"signer": signer, "account_id": account_id})

        accounts = state.get("accounts") or {}
        acct = accounts.get(account_id)
        if not isinstance(acct, dict):
            raise ApplyError("invalid_tx", "account_not_found", {"account_id": account_id})

        # If caller included a pubkey, ensure the account actually has it registered.
        expected_pubkey = str(payload.get("pubkey") or "").strip()
        if expected_pubkey and not _account_has_pubkey(acct, expected_pubkey):
            raise ApplyError("forbidden", "bootstrap_pubkey_mismatch", {"account_id": account_id})

        acct["poh_tier"] = 3
        # Keep account nonce monotonic (bootstrap is still a signer-authored tx).
        try:
            acct["nonce"] = max(int(acct.get("nonce") or 0), int(nonce))
        except Exception:
            acct["nonce"] = int(nonce)
        _mint_poh_nft(state, owner=account_id, tier=3, source_id="bootstrap_open", ts_ms=0)
        return

    # --- Production / allowlist bootstrap ---
    allowlist = params.get("bootstrap_allowlist") or {}
    expires_height = int(params.get("bootstrap_expires_height") or 0)

    if account_id not in allowlist:
        raise ApplyError("forbidden", "not_bootstrap_account", {"account_id": account_id})

    if current_height > expires_height:
        raise ApplyError("forbidden", "bootstrap_expired", {"height": current_height, "expires_height": expires_height})

    entry = allowlist.get(account_id) or {}
    expected_pubkey = str(entry.get("pubkey") or "").strip()

    accounts = state.get("accounts") or {}
    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        raise ApplyError("invalid_tx", "account_not_found", {"account_id": account_id})

    if expected_pubkey and not _account_has_pubkey(acct, expected_pubkey):
        raise ApplyError("forbidden", "bootstrap_pubkey_mismatch", {"account_id": account_id})

    acct["poh_tier"] = 3
    try:
        acct["nonce"] = max(int(acct.get("nonce") or 0), int(nonce))
    except Exception:
        acct["nonce"] = int(nonce)
    _mint_poh_nft(state, owner=account_id, tier=3, source_id="bootstrap", ts_ms=0)

def _challenge_id(*, account_id: str, nonce: int) -> str:
    return f"pohc:{account_id}:{max(0, int(nonce))}"


def apply_poh_challenge_open(state: Json, env: Any) -> Json:
    p = _payload(env)
    account_id = _as_str(p.get("account_id") or "").strip()
    reason = _as_str(p.get("reason") or "").strip()
    if not account_id:
        raise ApplyError("invalid_tx", "missing_account_id", {})

    cid = _challenge_id(account_id=account_id, nonce=_as_int(_get_env(env, "nonce", 0)))
    ch = {
        "challenge_id": cid,
        "account_id": account_id,
        "opened_by": _signer(env),
        "reason": reason,
        "status": "open",
    }

    challenges = _challenges(state)
    challenges[cid] = ch

    return {"applied": "POH_CHALLENGE_OPEN", "challenge_id": cid}


def apply_poh_challenge_resolve(state: Json, env: Any) -> Json:
    p = _payload(env)
    cid = _as_str(p.get("challenge_id") or "").strip()
    resolution = _as_str(p.get("resolution") or "").strip().lower()
    note = _as_str(p.get("note") or "").strip()

    if not cid:
        raise ApplyError("invalid_tx", "missing_challenge_id", {})
    if resolution not in ("dismissed", "upheld"):
        raise ApplyError("invalid_tx", "bad_resolution", {"resolution": resolution})

    challenges = _challenges(state)
    ch = challenges.get(cid)
    if not isinstance(ch, dict):
        raise ApplyError("not_found", "challenge_not_found", {"challenge_id": cid})

    ch["status"] = "resolved"
    ch["resolution"] = resolution
    if note:
        ch["note"] = note

    return {"applied": "POH_CHALLENGE_RESOLVE", "challenge_id": cid, "resolution": resolution}


def _tier2_defaults_from_state(state: Json) -> tuple[int, int, int, int]:
    params = state.get("params")
    params = params if isinstance(params, dict) else {}
    poh = params.get("poh")
    poh = poh if isinstance(poh, dict) else {}

    def _param_int(key: str, default: int, minimum: int) -> int:
        try:
            return max(minimum, int(poh.get(key)))
        except Exception:
            return int(default)

    n_jurors = _param_int("tier2_n_jurors", 25, 1)
    min_total = _param_int("tier2_min_total_reviews", 25, 1)
    pass_threshold = _param_int("tier2_pass_threshold", 20, 1)
    fail_max = _param_int("tier2_fail_max", 3, 0)
    return min_total, pass_threshold, fail_max, n_jurors


def apply_poh_tier2_request_open(state: Json, env: Any) -> Json:
    p = _payload(env)
    account_id = _as_str(p.get("account_id") or p.get("target") or "").strip()

    video_commitment = _as_str(p.get("video_commitment") or "").strip()
    video_cid = _as_str(p.get("video_cid") or "").strip()

    target_tier = _as_int(p.get("target_tier") or 2, 2)

    if not account_id:
        raise ApplyError("invalid_tx", "missing_account_id", {})

    _require_prod_no_auto_create(state, account_id)

    if target_tier == 3:
        case_id = _case_id("poh3", account_id=account_id, nonce=_as_int(_get_env(env, "nonce", 0)))
        cases3 = _tier3_cases(state)
        cases3[case_id] = {
            "case_id": case_id,
            "account_id": account_id,
            "requested_by": _signer(env),
            "status": "requested",
            "jurors": {},
        }
        return {"applied": "POH_TIER2_REQUEST_OPEN", "case_id": case_id, "target_tier": 3}

    if not video_commitment:
        if video_cid:
            video_commitment = _sha256_hex(video_cid.encode("utf-8"))
        else:
            raise ApplyError("invalid_tx", "missing_video_commitment", {})

    case_id = _case_id("poh2", account_id=account_id, nonce=_as_int(_get_env(env, "nonce", 0)))
    cases = _tier2_cases(state)

    cases[case_id] = {
        "case_id": case_id,
        "account_id": account_id,
        "requested_by": _signer(env),
        "video_commitment": video_commitment,
        "status": "open",
        "jurors": {},
    }

    return {"applied": "POH_TIER2_REQUEST_OPEN", "case_id": case_id}


def _get_tier2_case(state: Json, case_id: str) -> Json:
    cases = _tier2_cases(state)
    case = cases.get(case_id)
    if not isinstance(case, dict):
        raise ApplyError("not_found", "tier2_case_not_found", {"case_id": case_id})
    return case


def apply_poh_tier2_juror_assign(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    jurors = p.get("jurors")

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    if not isinstance(jurors, list) or not jurors:
        raise ApplyError("invalid_tx", "missing_jurors", {})
    if len(jurors) != len(set([_as_str(x) for x in jurors])):
        raise ApplyError("invalid_tx", "duplicate_jurors", {})

    min_total, pass_threshold, fail_max, n_jurors_default = _tier2_defaults_from_state(state)
    n_jurors = _as_int(p.get("n_jurors") or n_jurors_default, n_jurors_default)
    if n_jurors <= 0:
        n_jurors = n_jurors_default
    if len(jurors) != n_jurors:
        raise ApplyError("invalid_tx", "wrong_juror_count", {"need": n_jurors, "got": len(jurors)})

    case = _get_tier2_case(state, case_id)
    if _as_str(case.get("status") or "") not in ("open", "assigned"):
        raise ApplyError("invalid_tx", "case_not_open", {"case_id": case_id})

    jm: Json = {}
    for jid_any in jurors:
        jid = _as_str(jid_any).strip()
        if not jid:
            continue
        jm[jid] = {"verdict": None, "ts_ms": None}

    if len(jm) != n_jurors:
        raise ApplyError("invalid_tx", "bad_jurors", {"need": n_jurors})

    case["jurors"] = jm
    case["status"] = "assigned"
    case["min_total_reviews"] = int(p.get("min_total_reviews") or min_total)
    case["pass_threshold"] = int(p.get("pass_threshold") or pass_threshold)
    case["fail_max"] = int(p.get("fail_max") or fail_max)
    case["n_jurors"] = int(n_jurors)

    return {"applied": "POH_TIER2_JUROR_ASSIGN", "case_id": case_id}


def apply_poh_tier2_juror_accept(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})

    case = _get_tier2_case(state, case_id)
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})

    signer = _signer(env)
    if signer not in jm:
        raise ApplyError("forbidden", "juror_required", {"case_id": case_id})

    return {"applied": "POH_TIER2_JUROR_ACCEPT", "case_id": case_id}


def apply_poh_tier2_juror_decline(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})

    case = _get_tier2_case(state, case_id)
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})

    signer = _signer(env)
    if signer not in jm:
        raise ApplyError("forbidden", "juror_required", {"case_id": case_id})

    return {"applied": "POH_TIER2_JUROR_DECLINE", "case_id": case_id}


def apply_poh_tier2_review_submit(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    verdict = _as_str(p.get("verdict") or "").strip().lower()

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    if verdict not in ("pass", "fail"):
        raise ApplyError("invalid_tx", "bad_verdict", {"verdict": verdict})

    case = _get_tier2_case(state, case_id)
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})

    signer = _signer(env)
    jrec = jm.get(signer)
    if not isinstance(jrec, dict):
        raise ApplyError("forbidden", "juror_required", {"case_id": case_id})

    jrec["verdict"] = verdict
    jrec["ts_ms"] = _as_int(p.get("ts_ms") or 0)

    return {"applied": "POH_TIER2_REVIEW_SUBMIT", "case_id": case_id, "verdict": verdict}


def apply_poh_tier2_finalize(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})

    case = _get_tier2_case(state, case_id)
    status = _as_str(case.get("status") or "")
    if status in ("awarded", "finalized", "rejected"):
        tier = _as_int(case.get("tier_awarded") or 0)
        outcome = _as_str(case.get("outcome") or "")
        token_id = _as_str(case.get("poh_nft_token_id") or "").strip()
        return {"applied": "POH_TIER2_FINALIZE", "case_id": case_id, "outcome": outcome, "tier_awarded": tier, "token_id": token_id}

    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})

    min_total = int(case.get("min_total_reviews") or 0)
    pass_threshold = int(case.get("pass_threshold") or 0)
    fail_max = int(case.get("fail_max") or 0)

    total = 0
    passes = 0
    fails = 0
    for _jid, jrec_any in jm.items():
        jrec = jrec_any if isinstance(jrec_any, dict) else {}
        v = _as_str(jrec.get("verdict") or "").strip().lower()
        if v not in ("pass", "fail"):
            continue
        total += 1
        if v == "pass":
            passes += 1
        else:
            fails += 1

    if total < min_total:
        raise ApplyError("invalid_tx", "not_enough_reviews", {"need": min_total, "have": total})

    outcome = "pass" if passes >= pass_threshold and fails <= fail_max else "fail"
    tier_awarded = 2 if outcome == "pass" else 0

    token_id = ""
    if outcome == "pass":
        acct_id = _as_str(case.get("account_id") or "").strip()
        if acct_id:
            accounts = state.setdefault("accounts", {})
            acct = accounts.setdefault(acct_id, {})
            acct["poh_tier"] = max(_as_int(acct.get("poh_tier") or 0), 2)
            token_id = _mint_poh_nft(state, owner=acct_id, tier=2, source_id=case_id, ts_ms=_as_int(p.get("ts_ms") or 0))

    case["status"] = "awarded" if outcome == "pass" else "rejected"
    case["outcome"] = outcome
    case["tier_awarded"] = tier_awarded
    case["finalized_ts_ms"] = _as_int(p.get("ts_ms") or 0)
    if token_id:
        case["poh_nft_token_id"] = token_id

    return {"applied": "POH_TIER2_FINALIZE", "case_id": case_id, "outcome": outcome, "tier_awarded": tier_awarded, "token_id": token_id}


def apply_poh_tier2_receipt(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    receipt_id = _as_str(p.get("receipt_id") or "").strip()
    if case_id:
        try:
            case = _get_tier2_case(state, case_id)
            case["tier2_receipt_emitted"] = True
            if receipt_id:
                case["tier2_receipt_id"] = receipt_id
        except Exception:
            pass
    return {"applied": "POH_TIER2_RECEIPT", "case_id": case_id, "receipt_id": receipt_id}


def _get_tier3_case(state: Json, case_id: str) -> Json:
    cases = _tier3_cases(state)
    case = cases.get(case_id)
    if not isinstance(case, dict):
        raise ApplyError("not_found", "tier3_case_not_found", {"case_id": case_id})
    return case


def apply_poh_tier3_init(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    account_id = _as_str(p.get("account_id") or "").strip()
    session_commitment = _as_str(p.get("session_commitment") or "").strip()

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    if not account_id:
        raise ApplyError("invalid_tx", "missing_account_id", {})

    if not session_commitment:
        seed = f"{_chain_id(state)}|POH3_SESSION|{case_id}|{account_id}|{int(state.get('height') or 0)}".encode("utf-8")
        session_commitment = _sha256_hex(seed)

    cases = _tier3_cases(state)
    case = cases.get(case_id)
    if not isinstance(case, dict):
        case = {"case_id": case_id}
        cases[case_id] = case

    case.setdefault("account_id", account_id)
    case["status"] = "open"
    case.setdefault("jurors", {})
    case["init_ts_ms"] = _as_int(p.get("ts_ms") or 0)
    case["session_commitment"] = session_commitment

    return {"applied": "POH_TIER3_INIT", "case_id": case_id, "session_commitment": session_commitment}


def apply_poh_tier3_juror_assign(state: Json, env: Any) -> Json:
    """Assign Tier-3 jurors (3 interacting + 7 observing).

    Production hardening:
    - requires SYSTEM tx (env.system True)
    - exactly 10 unique juror ids
    - every juror must exist, not banned, not locked, and PoH tier >= 3
    - subject account (being verified) cannot be a juror
    """
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    jurors = p.get("jurors")

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    if not bool(_get_env(env, "system", False)):
        raise ApplyError("forbidden", "system_only", {"tx_type": "POH_TIER3_JUROR_ASSIGN"})
    if not isinstance(jurors, list) or len(jurors) != 10:
        raise ApplyError("invalid_tx", "bad_jurors", {"need": 10})

    case = _get_tier3_case(state, case_id)
    subject = _as_str(case.get("account_id") or "").strip()
    if not subject:
        raise ApplyError("invalid_tx", "missing_account_id", {"case_id": case_id})

    seen: set[str] = set()
    cleaned: list[str] = []
    for jid_any in jurors:
        jid = _as_str(jid_any).strip()
        if not jid:
            raise ApplyError("invalid_tx", "bad_juror_id", {"case_id": case_id})
        if jid in seen:
            raise ApplyError("invalid_tx", "duplicate_jurors", {"case_id": case_id})
        if jid == subject:
            raise ApplyError("invalid_tx", "subject_cannot_be_juror", {"case_id": case_id, "juror": jid})
        seen.add(jid)
        _require_active_tier3(state, jid, case_id=case_id)
        cleaned.append(jid)

    jm: Json = {}
    for i, jid in enumerate(cleaned):
        role = "interacting" if i < 3 else "observing"
        jm[jid] = {"role": role, "accepted": None, "attended": None, "verdict": None}

    case["jurors"] = jm
    case["status"] = "init"

    return {"applied": "POH_TIER3_JUROR_ASSIGN", "case_id": case_id}


def apply_poh_tier3_juror_accept(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})

    signer = _signer(env)
    _require_active_tier3(state, signer, case_id=case_id)

    case = _get_tier3_case(state, case_id)
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})

    if signer not in jm:
        raise ApplyError("forbidden", "juror_required", {"case_id": case_id})

    jrec = jm.get(signer)
    if not isinstance(jrec, dict):
        jrec = {}
        jm[signer] = jrec

    jrec["accepted"] = True
    jrec["accepted_ts_ms"] = _as_int(p.get("ts_ms") or 0)

    return {"applied": "POH_TIER3_JUROR_ACCEPT", "case_id": case_id}


def apply_poh_tier3_juror_decline(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})

    signer = _signer(env)
    _require_active_tier3(state, signer, case_id=case_id)

    case = _get_tier3_case(state, case_id)
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})

    if signer not in jm:
        raise ApplyError("forbidden", "juror_required", {"case_id": case_id})

    jrec = jm.get(signer)
    if not isinstance(jrec, dict):
        jrec = {}
        jm[signer] = jrec

    jrec["accepted"] = False
    jrec["declined_ts_ms"] = _as_int(p.get("ts_ms") or 0)

    return {"applied": "POH_TIER3_JUROR_DECLINE", "case_id": case_id}


def apply_poh_tier3_juror_replace(state: Json, env: Any) -> Json:
    """SYSTEM tx to replace a declined / no-show juror.

    Payload:
      - case_id
      - old_juror_id
      - new_juror_id

    Rules:
      - system-only
      - old juror must be assigned
      - new juror must be eligible Tier3+, not banned/locked, exist, not already assigned, not the subject
      - replacement keeps the role (interacting/observing) of the old juror
      - old juror record is marked replaced=True and attended defaults to False if not set
    """
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    old_id = _as_str(p.get("old_juror_id") or "").strip()
    new_id = _as_str(p.get("new_juror_id") or "").strip()

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    if not old_id:
        raise ApplyError("invalid_tx", "missing_old_juror_id", {})
    if not new_id:
        raise ApplyError("invalid_tx", "missing_new_juror_id", {})
    if old_id == new_id:
        raise ApplyError("invalid_tx", "same_juror_id", {})

    if not bool(_get_env(env, "system", False)):
        raise ApplyError("forbidden", "system_only", {"tx_type": "POH_TIER3_JUROR_REPLACE"})

    case = _get_tier3_case(state, case_id)
    subject = _as_str(case.get("account_id") or "").strip()
    if subject and new_id == subject:
        raise ApplyError("invalid_tx", "subject_cannot_be_juror", {"case_id": case_id, "juror": new_id})

    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})
    if old_id not in jm:
        raise ApplyError("invalid_tx", "juror_not_assigned", {"case_id": case_id, "juror_id": old_id})
    if new_id in jm:
        raise ApplyError("invalid_tx", "juror_already_assigned", {"case_id": case_id, "juror_id": new_id})

    old_rec_any = jm.get(old_id)
    old_rec = old_rec_any if isinstance(old_rec_any, dict) else {}

    if old_rec.get("accepted") is not False and old_rec.get("attended") is True:
        raise ApplyError("invalid_tx", "juror_not_replaceable", {"case_id": case_id, "juror": old_id})

    _require_active_tier3(state, new_id, case_id=case_id)

    role = _as_str(old_rec.get("role") or "").strip() or "observing"

    old_rec["replaced"] = True
    old_rec["replaced_by"] = new_id
    if old_rec.get("attended") is None:
        old_rec["attended"] = False
    jm[old_id] = old_rec

    jm[new_id] = {"role": role, "accepted": None, "attended": None, "verdict": None}

    case["status"] = _as_str(case.get("status") or "init")

    return {"applied": "POH_TIER3_JUROR_REPLACE", "case_id": case_id, "old_juror_id": old_id, "new_juror_id": new_id, "role": role}


def apply_poh_tier3_attendance_mark(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    juror_id = _as_str(p.get("juror_id") or "").strip()
    attended = p.get("attended")

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    if not juror_id:
        raise ApplyError("invalid_tx", "missing_juror_id", {})

    signer = _signer(env)
    if signer != juror_id:
        raise ApplyError("forbidden", "juror_signer_mismatch", {"case_id": case_id, "juror_id": juror_id, "signer": signer})

    _require_active_tier3(state, signer, case_id=case_id)

    case = _get_tier3_case(state, case_id)

    expected_sc = _as_str(case.get("session_commitment") or "").strip()
    sc = _as_str(p.get("session_commitment") or "").strip()
    if expected_sc and (not sc or sc != expected_sc):
        raise ApplyError("invalid_tx", "bad_session_commitment", {"case_id": case_id})

    jm = case.get("jurors")
    if not isinstance(jm, dict) or juror_id not in jm:
        raise ApplyError("invalid_tx", "juror_not_assigned", {"case_id": case_id, "juror_id": juror_id})
    jrec = jm.get(juror_id)
    if not isinstance(jrec, dict):
        jrec = {}
        jm[juror_id] = jrec

    if jrec.get("accepted") is not True:
        raise ApplyError("forbidden", "accept_required", {"case_id": case_id, "juror": juror_id})

    if attended is False:
        raise ApplyError("forbidden", "cannot_self_mark_absent", {"case_id": case_id, "juror": juror_id})

    jrec["attended"] = True
    jrec["attended_ts_ms"] = _as_int(p.get("ts_ms") or 0)

    return {"applied": "POH_TIER3_ATTENDANCE_MARK", "case_id": case_id, "juror_id": juror_id, "attended": True}


def apply_poh_tier3_verdict_submit(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    verdict = _as_str(p.get("verdict") or "").strip().lower()

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    if verdict not in ("pass", "fail"):
        raise ApplyError("invalid_tx", "bad_verdict", {"verdict": verdict})

    signer = _signer(env)
    _require_active_tier3(state, signer, case_id=case_id)

    case = _get_tier3_case(state, case_id)

    expected_sc = _as_str(case.get("session_commitment") or "").strip()
    sc = _as_str(p.get("session_commitment") or "").strip()
    if expected_sc and (not sc or sc != expected_sc):
        raise ApplyError("invalid_tx", "bad_session_commitment", {"case_id": case_id})

    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})

    jrec = jm.get(signer)
    if not isinstance(jrec, dict):
        raise ApplyError("forbidden", "juror_required", {"case_id": case_id})

    if _as_str(jrec.get("role") or "") != "interacting":
        raise ApplyError("forbidden", "interacting_juror_required", {"case_id": case_id})

    if jrec.get("accepted") is not True:
        raise ApplyError("forbidden", "accept_required", {"case_id": case_id, "juror": signer})

    if jrec.get("attended") is not True:
        raise ApplyError("forbidden", "attendance_required", {"case_id": case_id, "juror": signer})

    jrec["verdict"] = verdict
    jrec["verdict_ts_ms"] = _as_int(p.get("ts_ms") or 0)

    return {"applied": "POH_TIER3_VERDICT_SUBMIT", "case_id": case_id, "verdict": verdict}


def apply_poh_tier3_finalize(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})

    case = _get_tier3_case(state, case_id)
    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("awarded", "finalized", "rejected"):
        tier = _as_int(case.get("tier_awarded") or 0)
        outcome = _as_str(case.get("outcome") or "")
        token_id = _as_str(case.get("poh_nft_token_id") or "").strip()
        return {"applied": "POH_TIER3_FINALIZE", "case_id": case_id, "outcome": outcome, "tier_awarded": tier, "token_id": token_id}

    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_ready", {"case_id": case_id})

    # Replacements keep an audit trail (old juror record remains with replaced=True).
    # Finalization should consider only *active* (not replaced) jurors.
    active: Json = {}
    for jid, jrec_any in jm.items():
        jrec = jrec_any if isinstance(jrec_any, dict) else {}
        if bool(jrec.get("replaced", False)):
            continue
        active[jid] = jrec

    if len(active) != 10:
        raise ApplyError("invalid_tx", "jurors_not_ready", {"case_id": case_id})

    for _jid, jrec in active.items():
        if jrec.get("attended") is None:
            raise ApplyError("invalid_tx", "attendance_not_ready", {"case_id": case_id})

    passes = 0
    have = 0
    for _jid, jrec in active.items():
        if _as_str(jrec.get("role") or "") != "interacting":
            continue
        v = _as_str(jrec.get("verdict") or "").strip().lower()
        if v not in ("pass", "fail"):
            raise ApplyError("invalid_tx", "verdicts_not_ready", {"case_id": case_id})
        have += 1
        if v == "pass":
            passes += 1

    if have != 3:
        raise ApplyError("invalid_tx", "verdicts_not_ready", {"case_id": case_id})

    outcome = "pass" if passes >= 2 else "fail"
    tier_awarded = 3 if outcome == "pass" else 0

    token_id = ""
    if outcome == "pass":
        acct_id = _as_str(case.get("account_id") or "").strip()
        if acct_id:
            accounts = state.setdefault("accounts", {})
            acct = accounts.setdefault(acct_id, {})
            acct["poh_tier"] = max(_as_int(acct.get("poh_tier") or 0), 3)
            token_id = _mint_poh_nft(state, owner=acct_id, tier=3, source_id=case_id, ts_ms=_as_int(p.get("ts_ms") or 0))

    case["status"] = "awarded" if outcome == "pass" else "rejected"
    case["outcome"] = outcome
    case["tier_awarded"] = tier_awarded
    case["finalized_ts_ms"] = _as_int(p.get("ts_ms") or 0)
    if token_id:
        case["poh_nft_token_id"] = token_id

    return {"applied": "POH_TIER3_FINALIZE", "case_id": case_id, "outcome": outcome, "tier_awarded": tier_awarded, "token_id": token_id}


def apply_poh_tier3_receipt(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    receipt_id = _as_str(p.get("receipt_id") or "").strip()
    if case_id:
        try:
            case = _get_tier3_case(state, case_id)
            case["tier3_receipt_emitted"] = True
            if receipt_id:
                case["tier3_receipt_id"] = receipt_id
        except Exception:
            pass
    return {"applied": "POH_TIER3_RECEIPT", "case_id": case_id, "receipt_id": receipt_id}


def apply_poh(state: Json, env: Any) -> Optional[Json]:
    t = _tx_type(env)

    if t in {"POH_APPLICATION_SUBMIT", "POH_EVIDENCE_DECLARE", "POH_EVIDENCE_BIND"}:
        poh = _poh_root(state)
        poh.setdefault("applications", {})
        poh.setdefault("evidence", {})

        p = _payload(env)
        if t == "POH_APPLICATION_SUBMIT":
            account_id = _as_str(p.get("account_id") or _signer(env)).strip()
            app_id = _as_str(p.get("application_id") or "").strip() or _case_id(
                "pohapp", account_id=account_id, nonce=_as_int(_get_env(env, "nonce", 0))
            )
            poh["applications"][app_id] = {"application_id": app_id, "account_id": account_id, "payload": p}
            return {"applied": t, "application_id": app_id}

        if t == "POH_EVIDENCE_DECLARE":
            evidence_id = _as_str(p.get("evidence_id") or "").strip() or _as_str(p.get("cid") or p.get("video_cid") or "").strip()
            if not evidence_id:
                evidence_id = f"evi:{_signer(env)}:{_as_int(_get_env(env, 'nonce', 0))}"
            poh["evidence"][evidence_id] = {"evidence_id": evidence_id, "payload": p}
            return {"applied": t, "evidence_id": evidence_id}

        if t == "POH_EVIDENCE_BIND":
            bind_id = f"bind:{_signer(env)}:{_as_int(_get_env(env, 'nonce', 0))}"
            poh.setdefault("evidence_binds", {})
            poh["evidence_binds"][bind_id] = {"bind_id": bind_id, "payload": p}
            return {"applied": t, "bind_id": bind_id}

    if t == "POH_EMAIL_RECEIPT_SUBMIT":
        return apply_poh_email_receipt_submit(state, env)

    if t == "POH_TIER_SET":
        apply_poh_tier_set(state, {"payload": _payload(env)})
        return {"applied": "POH_TIER_SET"}

    if t == "POH_BOOTSTRAP_TIER3_GRANT":
        apply_poh_bootstrap_tier3_grant(
            state,
            {
                "payload": _payload(env),
                "signer": _signer(env),
                "nonce": _as_int(_get_env(env, "nonce", 0)),
            },
        )
        return {"applied": "POH_BOOTSTRAP_TIER3_GRANT"}

    if t == "POH_CHALLENGE_OPEN":
        return apply_poh_challenge_open(state, env)

    if t == "POH_CHALLENGE_RESOLVE":
        return apply_poh_challenge_resolve(state, env)

    if t == "POH_TIER2_REQUEST_OPEN":
        return apply_poh_tier2_request_open(state, env)

    if t == "POH_TIER2_JUROR_ASSIGN":
        return apply_poh_tier2_juror_assign(state, env)

    if t == "POH_TIER2_JUROR_ACCEPT":
        return apply_poh_tier2_juror_accept(state, env)

    if t == "POH_TIER2_JUROR_DECLINE":
        return apply_poh_tier2_juror_decline(state, env)

    if t == "POH_TIER2_REVIEW_SUBMIT":
        return apply_poh_tier2_review_submit(state, env)

    if t == "POH_TIER2_FINALIZE":
        return apply_poh_tier2_finalize(state, env)

    if t == "POH_TIER2_RECEIPT":
        return apply_poh_tier2_receipt(state, env)

    if t == "POH_TIER3_INIT":
        return apply_poh_tier3_init(state, env)

    if t == "POH_TIER3_JUROR_ASSIGN":
        return apply_poh_tier3_juror_assign(state, env)

    if t == "POH_TIER3_JUROR_ACCEPT":
        return apply_poh_tier3_juror_accept(state, env)

    if t == "POH_TIER3_JUROR_DECLINE":
        return apply_poh_tier3_juror_decline(state, env)

    if t == "POH_TIER3_JUROR_REPLACE":
        return apply_poh_tier3_juror_replace(state, env)

    if t == "POH_TIER3_ATTENDANCE_MARK":
        return apply_poh_tier3_attendance_mark(state, env)

    if t == "POH_TIER3_VERDICT_SUBMIT":
        return apply_poh_tier3_verdict_submit(state, env)

    if t == "POH_TIER3_FINALIZE":
        return apply_poh_tier3_finalize(state, env)

    if t == "POH_TIER3_RECEIPT":
        return apply_poh_tier3_receipt(state, env)

    return None
