from __future__ import annotations

import hashlib
import re
from typing import Any

from weall.runtime.bft_hotstuff import BFT_MIN_VALIDATORS, normalize_validators
from weall.runtime.bootstrap_audit import record_bootstrap_tier2_grant
from weall.runtime.errors import ApplyError
from weall.runtime.poh.live_quorum import (
    DEFAULT_LIVE_PASS_THRESHOLD_DENOMINATOR,
    DEFAULT_LIVE_PASS_THRESHOLD_NUMERATOR,
    MAX_LIVE_INTERACTING_JURORS,
    MAX_LIVE_JURORS,
    PRODUCTION_LIVE_APPROVAL_THRESHOLD,
    PRODUCTION_LIVE_MIN_PRESENT,
    PRODUCTION_LIVE_MIN_VERDICTS,
    PRODUCTION_LIVE_PANEL_SIZE,
    production_live_quorum_summary,
    live_active_reviewer_count,
    live_quorum_summary,
    normalize_live_threshold,
    required_live_passes,
)
from weall.runtime.poh.bootstrap_quorum import adaptive_bootstrap_review_policy
from weall.runtime.poh.state import (
    POH_STATUS_ACTIVE,
    require_valid_poh_tier,
    revoke_account_poh_status,
    set_account_poh_status,
    v2_poh_tier,
)

Json = dict[str, Any]

_COMMITMENT_RE = re.compile(
    r"^(?:[0-9a-f]{64}|sha256:[0-9a-f]{64}|[a-z][a-z0-9_-]{1,32}:[a-z0-9][a-z0-9:._/-]{0,191}|[a-z][a-z0-9_-]{1,63})$"
)


def _require_system_tx(env: Any, tx_type: str) -> None:
    """Require a scheduler/system-owned tx envelope for PoH lifecycle actions."""

    if not bool(_get_env(env, "system", False)):
        raise ApplyError("forbidden", "system_only", {"tx_type": str(tx_type or _tx_type(env) or "")})


def _validate_commitment_format(
    value: Any,
    *,
    field: str,
    case_id: str = "",
    required: bool = False,
) -> str:
    """Validate PoH commitment strings without requiring raw evidence on-chain.

    The protocol-preferred production format is a lowercase sha256 hex digest.
    Legacy/dev test prefixes such as ``commit:...`` and ``session:...`` remain
    accepted only as bounded commitment labels. Raw URLs, whitespace, data URLs,
    JSON-like blobs, and unbounded strings fail closed.
    """

    raw = _as_str(value).strip()
    if not raw:
        if required:
            raise ApplyError("invalid_tx", "bad_commitment_format", {"field": field, "case_id": case_id})
        return ""

    lowered = raw.lower()
    if lowered != raw:
        raise ApplyError("invalid_tx", "bad_commitment_format", {"field": field, "case_id": case_id})
    if any(ch.isspace() for ch in raw):
        raise ApplyError("invalid_tx", "bad_commitment_format", {"field": field, "case_id": case_id})
    if lowered.startswith(("http://", "https://", "ipfs://", "data:", "file:", "blob:")):
        raise ApplyError("invalid_tx", "bad_commitment_format", {"field": field, "case_id": case_id})
    if not _COMMITMENT_RE.fullmatch(raw):
        raise ApplyError("invalid_tx", "bad_commitment_format", {"field": field, "case_id": case_id})
    return raw


def _validate_ipfs_uri(value: Any, *, field: str, case_id: str = "") -> str:
    raw = _as_str(value).strip()
    if not raw:
        return ""
    if not raw.startswith("ipfs://"):
        raise ApplyError("invalid_tx", "bad_evidence_uri", {"field": field, "case_id": case_id})
    cid = raw.removeprefix("ipfs://").split("/", 1)[0].strip()
    if not cid:
        raise ApplyError("invalid_tx", "bad_evidence_uri", {"field": field, "case_id": case_id})
    return raw


def _as_str(v: Any) -> str:
    if v is None:
        return ""
    try:
        return str(v)
    except Exception:
        return ""


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _state_poh_param_int(state: Json, key: str, default: int) -> int:
    try:
        params = state.get("params")
        poh = params.get("poh") if isinstance(params, dict) else None
        if isinstance(poh, dict) and key in poh:
            return int(poh.get(key))
    except Exception:
        pass
    return int(default)


def _state_poh_param_str(state: Json, key: str, default: str = "") -> str:
    try:
        params = state.get("params")
        if isinstance(params, dict):
            poh = params.get("poh")
            if isinstance(poh, dict) and key in poh:
                return _as_str(poh.get(key)).strip().lower()
            if key in params:
                return _as_str(params.get(key)).strip().lower()
    except Exception:
        pass
    return str(default).strip().lower()


def _live_poh_policy_mode(state: Json) -> str:
    mode = (
        _state_poh_param_str(state, "live_poh_policy_mode")
        or _state_poh_param_str(state, "live_quorum_mode")
        or _state_poh_param_str(state, "poh_live_policy_mode")
    )
    if mode in {"production", "prod", "fixed", "constitutional"}:
        return "production"
    return "bootstrap"


def _live_poh_production_mode(state: Json) -> bool:
    return _live_poh_policy_mode(state) == "production"


def _apply_production_live_quorum_overlay(quorum: Json) -> Json:
    out = dict(quorum)
    out.update(production_live_quorum_summary())
    out["policy_locked"] = True
    return out


def _live_threshold_from_assignment(state: Json, payload: Json) -> tuple[int, int]:
    num = payload.get("pass_threshold_num")
    den = payload.get("pass_threshold_den")
    if num is None:
        num = _state_poh_param_int(
            state, "live_pass_threshold_num", DEFAULT_LIVE_PASS_THRESHOLD_NUMERATOR
        )
    if den is None:
        den = _state_poh_param_int(
            state, "live_pass_threshold_den", DEFAULT_LIVE_PASS_THRESHOLD_DENOMINATOR
        )
    return normalize_live_threshold(numerator=num, denominator=den)


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



def _evidence_commitment_index(state: Json) -> Json:
    """Global PoH evidence commitment index.

    The index is intentionally shared across legacy async/live evidence lanes so the
    same off-chain media commitment cannot be replayed to elevate multiple
    accounts or create independent cases. Appeals/retries should reference the
    original case instead of reusing the same commitment as a fresh proof.
    """

    poh = _poh_root(state)
    index = poh.get("evidence_commitment_index")
    if not isinstance(index, dict):
        index = {}
        poh["evidence_commitment_index"] = index
    return index


def _require_subject_signer(env: Any, account_id: str, *, reason: str = "subject_signer_mismatch") -> None:
    signer = _signer(env)
    if signer != account_id:
        raise ApplyError(
            "forbidden",
            reason,
            {"signer": signer, "account_id": account_id},
        )


def _require_account_min_tier(
    state: Json,
    account_id: str,
    *,
    min_tier: int,
    reason: str,
) -> Json:
    acct = _require_registered_account(state, account_id)
    if bool(acct.get("banned", False)):
        raise ApplyError("forbidden", "account_banned", {"account_id": account_id})
    if bool(acct.get("locked", False)):
        raise ApplyError("forbidden", "account_locked", {"account_id": account_id})
    tier = v2_poh_tier(acct.get("poh_tier") or 0)
    if tier < int(min_tier):
        raise ApplyError(
            "forbidden",
            reason,
            {"account_id": account_id, "tier": tier, "required_tier": int(min_tier)},
        )
    return acct



def _async_cases(state: Json) -> Json:
    poh = _poh_root(state)
    cases = poh.get("async_cases")
    if not isinstance(cases, dict):
        cases = {}
        poh["async_cases"] = cases
    return cases

def _live_cases(state: Json) -> Json:
    poh = _poh_root(state)
    cases = poh.get("live_cases")
    if not isinstance(cases, dict):
        cases = {}
        poh["live_cases"] = cases
    return cases


def _live_sessions(state: Json) -> Json:
    poh = _poh_root(state)
    sessions = poh.get("live_sessions")
    if not isinstance(sessions, dict):
        sessions = {}
        poh["live_sessions"] = sessions
    return sessions


def _live_session_participants(state: Json) -> Json:
    poh = _poh_root(state)
    participants = poh.get("live_session_participants")
    if not isinstance(participants, dict):
        participants = {}
        poh["live_session_participants"] = participants
    return participants


def _live_required_commitments_from_payload(payload: Json) -> Json:
    return {
        "session_commitment": _as_str(payload.get("session_commitment") or "").strip(),
        "room_commitment": _as_str(payload.get("room_commitment") or "").strip(),
        "prompt_commitment": _as_str(payload.get("prompt_commitment") or "").strip(),
        "device_pairing_commitment": _as_str(payload.get("device_pairing_commitment") or "").strip(),
    }


def _require_live_request_commitments(payload: Json) -> Json:
    commitments = _live_required_commitments_from_payload(payload)
    missing = [
        key
        for key in ("session_commitment", "room_commitment", "prompt_commitment")
        if not commitments.get(key)
    ]
    if missing:
        raise ApplyError(
            "invalid_tx",
            "missing_live_session_commitment",
            {"missing": missing},
        )
    for field in ("session_commitment", "room_commitment", "prompt_commitment", "device_pairing_commitment"):
        if commitments.get(field):
            commitments[field] = _validate_commitment_format(
                commitments[field], field=field, required=(field in ("session_commitment", "room_commitment", "prompt_commitment"))
            )
    return commitments


def _require_live_case_commitments(case: Json, *, case_id: str) -> Json:
    commitments = {
        "session_commitment": _as_str(case.get("session_commitment") or "").strip(),
        "room_commitment": _as_str(case.get("room_commitment") or "").strip(),
        "prompt_commitment": _as_str(case.get("prompt_commitment") or "").strip(),
        "device_pairing_commitment": _as_str(case.get("device_pairing_commitment") or "").strip(),
    }
    missing = [
        key
        for key in ("session_commitment", "room_commitment", "prompt_commitment")
        if not commitments.get(key)
    ]
    if missing:
        raise ApplyError(
            "invalid_state",
            "live_session_commitment_missing",
            {"case_id": case_id, "missing": missing},
        )
    for field in ("session_commitment", "room_commitment", "prompt_commitment", "device_pairing_commitment"):
        if commitments.get(field):
            commitments[field] = _validate_commitment_format(
                commitments[field], field=field, case_id=case_id, required=(field in ("session_commitment", "room_commitment", "prompt_commitment"))
            )
    return commitments


def _require_live_payload_session_matches(case: Json, payload: Json, *, case_id: str) -> str:
    commitments = _require_live_case_commitments(case, case_id=case_id)
    expected_sc = commitments["session_commitment"]
    supplied_sc = _as_str(payload.get("session_commitment") or "").strip()
    if not supplied_sc or supplied_sc != expected_sc:
        raise ApplyError(
            "invalid_tx",
            "bad_session_commitment",
            {"case_id": case_id},
        )
    return expected_sc


def _challenges(state: Json) -> Json:
    poh = _poh_root(state)
    challenges = poh.get("challenges")
    if not isinstance(challenges, dict):
        challenges = {}
        poh["challenges"] = challenges
    return challenges


def _reverification_root(state: Json) -> Json:
    poh = _poh_root(state)
    root = poh.get("reverification")
    if not isinstance(root, dict):
        root = {}
        poh["reverification"] = root
    by_account = root.get("by_account")
    if not isinstance(by_account, dict):
        by_account = {}
        root["by_account"] = by_account
    events = root.get("events")
    if not isinstance(events, list):
        events = []
        root["events"] = events
    return root


def _evidence_retention_root(state: Json) -> Json:
    poh = _poh_root(state)
    root = poh.get("evidence_retention")
    if not isinstance(root, dict):
        root = {"by_challenge": {}, "events": []}
        poh["evidence_retention"] = root
    by_challenge = root.get("by_challenge")
    if not isinstance(by_challenge, dict):
        by_challenge = {}
        root["by_challenge"] = by_challenge
    events = root.get("events")
    if not isinstance(events, list):
        events = []
        root["events"] = events
    return root


def _record_challenge_evidence_retention_policy(
    state: Json,
    *,
    challenge_id: str,
    account_id: str,
    status: str,
    reason: str,
    case_id: str = "",
) -> Json:
    """Record deterministic retention/remedy policy for PoH challenge evidence.

    This is protocol state, not a storage delete command.  It makes the evidence
    lifecycle explicit for private-testnet review: upheld challenges retain
    evidence until appeal/reverification/remedy is complete; dismissed
    challenges retain only minimal audit metadata unless another policy keeps
    the evidence alive.
    """

    root = _evidence_retention_root(state)
    by_challenge = root["by_challenge"]
    events = root["events"]
    height = int(state.get("height") or 0)
    status_norm = _as_str(status or "").strip() or "retained"
    rec: Json = {
        "challenge_id": challenge_id,
        "account_id": account_id,
        "case_id": case_id,
        "status": status_norm,
        "reason": reason,
        "updated_height": height,
        "deletion_eligible": status_norm in {"dismissed_minimal_retention", "remedy_completed_minimal_retention"},
        "appeal_remedy_available": status_norm in {"retain_until_reverification_or_appeal", "retain_until_remedy_complete"},
        "history": [],
    }
    prev = by_challenge.get(challenge_id)
    if isinstance(prev, dict) and isinstance(prev.get("history"), list):
        rec["history"] = list(prev.get("history") or [])
    event = {
        "event": "poh_challenge_evidence_retention_policy",
        "challenge_id": challenge_id,
        "account_id": account_id,
        "case_id": case_id,
        "status": status_norm,
        "height": height,
    }
    rec["history"].append(event)
    by_challenge[challenge_id] = rec
    events.append(event)
    return dict(rec)


def _record_reverification_required(
    state: Json,
    *,
    account_id: str,
    challenge_id: str,
    reason: str,
) -> Json:
    root = _reverification_root(state)
    by_account = root.get("by_account")
    assert isinstance(by_account, dict)
    events = root.get("events")
    assert isinstance(events, list)

    height = int(state.get("height") or 0)
    rec = by_account.get(account_id)
    existed = isinstance(rec, dict)
    if not existed:
        rec = {"account_id": account_id, "history": []}
    history = rec.get("history")
    if not isinstance(history, list):
        history = []
    event = {
        "event": "reverification_required",
        "account_id": account_id,
        "challenge_id": challenge_id,
        "reason": reason,
        "height": height,
    }
    history.append(event)
    rec["status"] = "required"
    rec["reason"] = reason
    rec["challenge_id"] = challenge_id
    rec["required_at_height"] = height
    rec["history"] = history
    by_account[account_id] = rec
    events.append(event)
    root["by_account"] = by_account
    root["events"] = events
    return dict(rec)



def _mark_reverification_completed(
    state: Json,
    *,
    account_id: str,
    case_id: str,
    height: int,
) -> Json:
    """Close a pending challenge-driven reverification after successful PoH proof.

    Batch 507 keeps the challenge consequence deterministic but adds the missing
    completion mechanic: once a revoked account completes a fresh native PoH
    verification, the prior reverification requirement is closed with an audit
    event.  This does not bypass review; it only records completion after the
    existing finalize path has already awarded active PoH status.
    """

    root = _reverification_root(state)
    by_account = root.get("by_account")
    assert isinstance(by_account, dict)
    events = root.get("events")
    assert isinstance(events, list)

    rec = by_account.get(account_id)
    if not isinstance(rec, dict):
        return {"applied": False, "reason": "no_reverification_required"}
    if _as_str(rec.get("status") or "").strip().lower() != "required":
        return {"applied": False, "reason": "reverification_not_required"}

    history = rec.get("history")
    if not isinstance(history, list):
        history = []
    event = {
        "event": "reverification_completed",
        "account_id": account_id,
        "case_id": case_id,
        "challenge_id": _as_str(rec.get("challenge_id") or "").strip(),
        "height": int(height),
    }
    history.append(event)
    rec["status"] = "completed"
    rec["completed_by_case_id"] = case_id
    rec["completed_at_height"] = int(height)
    rec["history"] = history
    by_account[account_id] = rec
    events.append(event)
    root["by_account"] = by_account
    root["events"] = events

    challenge_id = _as_str(rec.get("challenge_id") or "").strip()
    challenges = _challenges(state)
    ch = challenges.get(challenge_id) if challenge_id else None
    if isinstance(ch, dict):
        ch["post_challenge_reverification"] = {
            "status": "completed",
            "case_id": case_id,
            "height": int(height),
        }
        ch["status"] = "resolved_reverified"
        challenges[challenge_id] = ch
        _record_challenge_evidence_retention_policy(
            state,
            challenge_id=challenge_id,
            account_id=account_id,
            case_id=case_id,
            status="remedy_completed_minimal_retention",
            reason="reverification_completed",
        )

    return {"applied": True, "account_id": account_id, "case_id": case_id, "status": "completed", "challenge_id": challenge_id}

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
    payload = f"{_chain_id(state)}|POH_GATE|{owner}|{int(tier)}|{source_id}".encode()
    return _sha256_hex(payload)


def _mint_poh_nft(state: Json, *, owner: str, tier: int, source_id: str, ts_ms: int = 0) -> str:
    root = _poh_nfts_root(state)
    by_id = root["by_id"]
    by_owner = root["by_owner"]

    token_id = _deterministic_poh_token_id(
        state=state, owner=owner, tier=int(tier), source_id=source_id
    )

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


def _require_registered_account(
    state: Json,
    account_id: str,
    *,
    code: str = "invalid_tx",
    reason: str = "account_not_registered",
) -> Json:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_tx", "accounts_missing", {})
    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        raise ApplyError(code, reason, {"account_id": account_id})
    return acct


def _require_account_exists(
    state: Json, account_id: str, *, code: str = "invalid_tx", reason: str = "account_not_found"
) -> Json:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_tx", "accounts_missing", {})
    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        raise ApplyError(code, reason, {"account_id": account_id})
    return acct


def _active_validator_count_for_bootstrap_sunset(state: Json) -> int:
    """Return the committed active-validator count used to sunset PoH bootstrap.

    This is intentionally consensus-state only.  Environment variables, local node
    posture, relay status, or frontend/operator flags must never keep bootstrap
    authority alive once the chain has enough active validators to run regular BFT
    quorum.
    """
    candidates: list[str] = []

    roles = state.get("roles")
    if isinstance(roles, dict):
        validators = roles.get("validators")
        if isinstance(validators, dict) and isinstance(validators.get("active_set"), list):
            candidates = [str(item).strip() for item in validators.get("active_set") or []]

    if not candidates:
        consensus = state.get("consensus")
        if isinstance(consensus, dict):
            validator_set = consensus.get("validator_set")
            if isinstance(validator_set, dict) and isinstance(validator_set.get("active_set"), list):
                candidates = [str(item).strip() for item in validator_set.get("active_set") or []]

    return len(normalize_validators([item for item in candidates if item]))


def _bootstrap_auto_locked_by_validator_quorum(state: Json) -> tuple[bool, Json]:
    """Hard stop for genesis/bootstrap PoH once regular BFT can run.

    The sunset threshold is deliberately hardcoded to BFT_MIN_VALIDATORS so a
    governance/operator parameter cannot accidentally extend bootstrap identity
    authority after the validator set is large enough for the normal protocol
    quorum path.
    """
    active_count = _active_validator_count_for_bootstrap_sunset(state)
    required = int(BFT_MIN_VALIDATORS)
    return active_count >= required, {
        "active_validators": int(active_count),
        "required_active_validators": int(required),
        "rule": "active_validators>=BFT_MIN_VALIDATORS",
    }


def _consensus_bootstrap_open_enabled(state: Json) -> bool:
    params = state.get("params")
    params = params if isinstance(params, dict) else {}
    raw = params.get("poh_bootstrap_open")
    if isinstance(raw, bool):
        return raw
    return str(raw or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _bootstrap_allowlist_enabled(params: Json) -> bool:
    allowlist = params.get("bootstrap_allowlist")
    if not isinstance(allowlist, dict) or not allowlist:
        return False

    # ``bootstrap_allowlist`` also carries genesis-bootstrap founder/operator
    # metadata used by bootstrap/status surfaces.  When the explicit policy selector
    # is ``open``, those genesis metadata rows must not activate allowlist mode or
    # cause a false dual-mode conflict.  Any non-genesis row remains an active
    # allowlist policy and preserves the existing fail-closed behavior.
    raw_mode = str(params.get("poh_bootstrap_mode") or "").strip().lower()
    if raw_mode == "open":
        for rec in allowlist.values():
            if not (isinstance(rec, dict) and str(rec.get("source") or "") == "genesis_bootstrap"):
                return True
        return False

    return True


def _consensus_bootstrap_policy_mode(state: Json) -> str:
    """Resolve the single active bootstrap policy mode.

    Modes:
      - closed
      - open
      - allowlist

    `poh_bootstrap_mode` is the authoritative explicit selector when present.
    Legacy fields (`poh_bootstrap_open`, `bootstrap_allowlist`) are still honored for
    backward compatibility, but only when they do not create an ambiguous dual-mode
    policy. Any conflicting combination fails closed.
    """

    params = state.get("params")
    params = params if isinstance(params, dict) else {}

    raw_mode = str(params.get("poh_bootstrap_mode") or "").strip().lower()
    open_enabled = _consensus_bootstrap_open_enabled(state)
    allowlist_enabled = _bootstrap_allowlist_enabled(params)

    if raw_mode:
        if raw_mode not in {"closed", "open", "allowlist"}:
            raise ApplyError(
                "invalid_state",
                "invalid_bootstrap_mode",
                {"mode": raw_mode},
            )
        if raw_mode == "closed" and (open_enabled or allowlist_enabled):
            raise ApplyError(
                "invalid_state",
                "bootstrap_mode_conflict",
                {
                    "mode": raw_mode,
                    "open_enabled": open_enabled,
                    "allowlist_enabled": allowlist_enabled,
                },
            )
        if raw_mode == "open" and allowlist_enabled:
            raise ApplyError(
                "invalid_state",
                "bootstrap_mode_conflict",
                {
                    "mode": raw_mode,
                    "open_enabled": open_enabled,
                    "allowlist_enabled": allowlist_enabled,
                },
            )
        if raw_mode == "allowlist" and open_enabled:
            raise ApplyError(
                "invalid_state",
                "bootstrap_mode_conflict",
                {
                    "mode": raw_mode,
                    "open_enabled": open_enabled,
                    "allowlist_enabled": allowlist_enabled,
                },
            )
        return raw_mode

    if open_enabled and allowlist_enabled:
        raise ApplyError(
            "invalid_state",
            "bootstrap_mode_conflict",
            {
                "mode": "implicit",
                "open_enabled": open_enabled,
                "allowlist_enabled": allowlist_enabled,
            },
        )
    if open_enabled:
        return "open"
    if allowlist_enabled:
        return "allowlist"
    return "closed"




def poh_bootstrap_policy_summary(state: Json) -> Json:
    """Return consensus-visible PoH bootstrap/live policy commitments.

    This is read-only observability for status endpoints and tester gates. It
    deliberately derives the policy from committed state instead of local env or
    frontend flags, so external testers can see whether bootstrap identity is
    closed, open-bounded, allowlist-bounded, or auto-locked by validator quorum.
    """
    params = state.get("params")
    params = params if isinstance(params, dict) else {}
    height = _as_int(state.get("height") or 0, 0)
    auto_locked, auto_meta = _bootstrap_auto_locked_by_validator_quorum(state)
    try:
        mode = _consensus_bootstrap_policy_mode(state)
        mode_error = ""
    except ApplyError as exc:
        mode = "invalid"
        mode_error = str(getattr(exc, "reason", "bootstrap_policy_invalid") or "bootstrap_policy_invalid")

    open_max_height = _as_int(params.get("poh_bootstrap_max_height") or 0, 0)
    allowlist_expires_height = _as_int(params.get("bootstrap_expires_height") or 0, 0)
    allowlist = params.get("bootstrap_allowlist")
    allowlist_count = len(allowlist) if isinstance(allowlist, dict) else 0

    return {
        "mode": mode,
        "valid": not bool(mode_error),
        "mode_error": mode_error,
        "open_enabled": _consensus_bootstrap_open_enabled(state),
        "allowlist_enabled": _bootstrap_allowlist_enabled(params),
        "open_max_height": open_max_height or None,
        "open_expired": bool(mode == "open" and open_max_height > 0 and height > open_max_height),
        "allowlist_expires_height": allowlist_expires_height or None,
        "allowlist_expired": bool(mode == "allowlist" and allowlist_expires_height > 0 and height > allowlist_expires_height),
        "allowlist_count": int(allowlist_count),
        "auto_locked_by_validator_quorum": bool(auto_locked),
        "auto_lock": auto_meta,
        "live_policy_mode": _live_poh_policy_mode(state),
        "production_live_quorum_required": _live_poh_production_mode(state),
    }


def _account_has_pubkey(acct: Json, pubkey: str) -> bool:
    """Return True if acct exposes pubkey in any supported active-key schema."""
    if not pubkey:
        return False
    pk = str(pubkey).strip()
    if not pk:
        return False

    seen: set[str] = set()

    def _add(candidate: Any, *, active: bool = True) -> None:
        if not active or not isinstance(candidate, str):
            return
        c = candidate.strip()
        if c:
            seen.add(c)

    _add(acct.get("pubkey"))

    pubkeys = acct.get("pubkeys")
    if isinstance(pubkeys, list):
        for item in pubkeys:
            _add(item)

    active_keys = acct.get("active_keys")
    if isinstance(active_keys, list):
        for item in active_keys:
            _add(item)

    keys = acct.get("keys")
    if isinstance(keys, dict) and pk in keys:
        rec = keys.get(pk)
        if isinstance(rec, dict):
            _add(pk, active=bool(rec.get("active", False)) and not bool(rec.get("revoked", False)))
        else:
            _add(pk, active=bool(rec))

    if isinstance(keys, dict):
        by_id = keys.get("by_id")
        if isinstance(by_id, dict):
            for rec in by_id.values():
                if isinstance(rec, dict):
                    _add(rec.get("pubkey"), active=not bool(rec.get("revoked", False)))

    if isinstance(keys, list):
        for item in keys:
            if isinstance(item, str):
                _add(item)
                continue
            if not isinstance(item, dict):
                continue
            _add(item.get("pubkey"), active=item.get("active", True) is not False)

    return pk in seen


def _require_active_live(state: Json, account_id: str, *, case_id: str = "") -> Json:
    acct = _require_account_exists(
        state, account_id, code="invalid_tx", reason="juror_account_not_found"
    )
    if bool(acct.get("banned", False)):
        raise ApplyError("invalid_tx", "juror_banned", {"case_id": case_id, "juror": account_id})
    if bool(acct.get("locked", False)):
        raise ApplyError("invalid_tx", "juror_locked", {"case_id": case_id, "juror": account_id})
    tier = _as_int(acct.get("poh_tier") or 0, 0)
    if tier < 2:
        raise ApplyError(
            "invalid_tx", "juror_not_live", {"case_id": case_id, "juror": account_id, "tier": tier, "required": 2}
        )
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





def _proof_commitment_index(state: Json) -> Json:
    poh = _poh_root(state)
    index = poh.get("proof_commitment_index")
    if not isinstance(index, dict):
        index = {}
        poh["proof_commitment_index"] = index
    return index




def apply_poh_tier_revoke(state: Json, env: Any) -> Json:
    p = _payload(env)
    account_id = _as_str(p.get("account_id") or "").strip()
    if not account_id:
        raise ApplyError("invalid_tx", "missing_account_id", {})
    _require_account_exists(state, account_id)
    rec = revoke_account_poh_status(
        state,
        account_id=account_id,
        reason=_as_str(p.get("reason") or "revoked"),
        last_updated_height=int(state.get("height") or 0),
    )
    return {"applied": "POH_TIER_REVOKE", "account_id": account_id, "status": rec.get("status")}




def apply_poh_tier_set(state: Json, tx: Json) -> None:
    payload = tx.get("payload") or {}
    account_id = str(payload.get("account_id") or "")
    try:
        tier = require_valid_poh_tier(payload.get("tier") or 0)
    except ValueError as exc:
        raise ApplyError(
            "invalid_tx",
            "invalid_poh_tier",
            {"account_id": account_id, "max_tier": 2},
        ) from exc

    if not account_id:
        raise ApplyError("invalid_tx", "missing_account", {})

    acct = _require_registered_account(state, account_id)
    acct["poh_tier"] = tier


def apply_poh_bootstrap_tier2_grant(state: Json, tx: Json) -> None:
    """Bootstrap a Live Verification PoH grant.

    The active bootstrap mechanism must resolve to exactly one consensus-visible
    policy mode:
      - open      : self-bootstrap only, bounded by `poh_bootstrap_max_height`
      - allowlist : account must be present in `bootstrap_allowlist`, bounded by
                    `bootstrap_expires_height`
      - closed    : no bootstrap path is active

    `poh_bootstrap_mode` is the authoritative selector when present. Legacy fields
    remain backward-compatible only when they imply a single unambiguous mode.
    Any conflicting combination fails closed.
    """

    payload = tx.get("payload") or {}
    account_id = str(payload.get("account_id") or "").strip()
    signer = str(tx.get("signer") or "").strip()
    nonce = int(tx.get("nonce") or 0)

    if not account_id:
        raise ApplyError("invalid_tx", "missing_account", {})

    current_height = int(state.get("height") or 0)
    params = state.get("params") or {}
    auto_locked, auto_lock_meta = _bootstrap_auto_locked_by_validator_quorum(state)
    if auto_locked:
        detail = {"account_id": account_id}
        detail.update(auto_lock_meta)
        raise ApplyError("forbidden", "bootstrap_auto_locked_validator_quorum", detail)

    mode = _consensus_bootstrap_policy_mode(state)

    if mode == "closed":
        raise ApplyError("forbidden", "bootstrap_closed", {"account_id": account_id})

    # --- Open bootstrap (explicit on-chain opt-in) ---
    if mode == "open":
        max_h = int(params.get("poh_bootstrap_max_height") or 0)
        if max_h <= 0:
            raise ApplyError(
                "invalid_state",
                "bootstrap_open_requires_max_height",
                {"account_id": account_id},
            )
        if current_height > max_h:
            raise ApplyError(
                "forbidden", "bootstrap_expired", {"height": current_height, "expires_height": max_h}
            )

        if signer != account_id:
            raise ApplyError(
                "forbidden", "bootstrap_self_only", {"signer": signer, "account_id": account_id}
            )

        accounts = state.get("accounts") or {}
        acct = accounts.get(account_id)
        if not isinstance(acct, dict):
            raise ApplyError("invalid_tx", "account_not_found", {"account_id": account_id})

        expected_pubkey = str(payload.get("pubkey") or "").strip()
        if expected_pubkey and not _account_has_pubkey(acct, expected_pubkey):
            raise ApplyError("forbidden", "bootstrap_pubkey_mismatch", {"account_id": account_id})

        acct["poh_tier"] = 2
        acct["poh_bootstrap_granted"] = True
        acct["poh_bootstrap_mode"] = "open"
        acct["poh_bootstrap_height"] = current_height
        try:
            acct["nonce"] = max(int(acct.get("nonce") or 0), int(nonce))
        except Exception:
            acct["nonce"] = int(nonce)
        record_bootstrap_tier2_grant(
            state,
            account_id=account_id,
            signer=signer,
            mode="open",
            source="poh_bootstrap_tx",
            height=current_height,
            tx_type="POH_BOOTSTRAP_TIER2_GRANT",
            nonce=nonce,
            authority_path="self_signed_open_bootstrap",
            reason_code=str(payload.get("reason_code") or "bootstrap_open_live_verified"),
            expires_height=max_h,
            pubkey=expected_pubkey,
        )
        _mint_poh_nft(state, owner=account_id, tier=2, source_id="bootstrap_open", ts_ms=0)
        return

    # --- Allowlist bootstrap ---
    allowlist = params.get("bootstrap_allowlist") or {}
    expires_height = int(params.get("bootstrap_expires_height") or 0)
    if expires_height <= 0:
        raise ApplyError(
            "invalid_state",
            "bootstrap_allowlist_requires_expiry",
            {"account_id": account_id},
        )

    if account_id not in allowlist:
        raise ApplyError("forbidden", "not_bootstrap_account", {"account_id": account_id})

    if current_height > expires_height:
        raise ApplyError(
            "forbidden",
            "bootstrap_expired",
            {"height": current_height, "expires_height": expires_height},
        )

    entry = allowlist.get(account_id) or {}
    expected_pubkey = str(entry.get("pubkey") or "").strip()

    accounts = state.get("accounts") or {}
    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        raise ApplyError("invalid_tx", "account_not_found", {"account_id": account_id})

    if expected_pubkey and not _account_has_pubkey(acct, expected_pubkey):
        raise ApplyError("forbidden", "bootstrap_pubkey_mismatch", {"account_id": account_id})

    acct["poh_tier"] = 2
    acct["poh_bootstrap_granted"] = True
    acct["poh_bootstrap_mode"] = "allowlist"
    acct["poh_bootstrap_height"] = current_height
    try:
        acct["nonce"] = max(int(acct.get("nonce") or 0), int(nonce))
    except Exception:
        acct["nonce"] = int(nonce)
    record_bootstrap_tier2_grant(
        state,
        account_id=account_id,
        signer=signer,
        mode="allowlist",
        source="poh_bootstrap_tx",
        height=current_height,
        tx_type="POH_BOOTSTRAP_TIER2_GRANT",
        nonce=nonce,
        authority_path="allowlist_bootstrap",
        reason_code=str(payload.get("reason_code") or entry.get("reason_code") or "bootstrap_allowlist_live_verified"),
        expires_height=expires_height,
        pubkey=expected_pubkey,
    )
    _mint_poh_nft(state, owner=account_id, tier=2, source_id="bootstrap", ts_ms=0)




def _reviewer_accountability_root(state: Json) -> Json:
    poh = _poh_root(state)
    root = poh.get("reviewer_accountability")
    if not isinstance(root, dict):
        root = {"by_reviewer": {}, "events": []}
        poh["reviewer_accountability"] = root
    by_reviewer = root.get("by_reviewer")
    if not isinstance(by_reviewer, dict):
        by_reviewer = {}
        root["by_reviewer"] = by_reviewer
    events = root.get("events")
    if not isinstance(events, list):
        events = []
        root["events"] = events
    return root




def _reviewer_collusion_suspicion_root(state: Json) -> Json:
    poh = _poh_root(state)
    root = poh.get("reviewer_collusion_suspicions")
    if not isinstance(root, dict):
        root = {"by_case": {}, "events": []}
        poh["reviewer_collusion_suspicions"] = root
    by_case = root.get("by_case")
    if not isinstance(by_case, dict):
        by_case = {}
        root["by_case"] = by_case
    events = root.get("events")
    if not isinstance(events, list):
        events = []
        root["events"] = events
    return root


def _record_reviewer_collusion_suspicion(
    state: Json,
    *,
    challenge_id: str,
    case_id: str,
    account_id: str,
    reviewers: list[str],
) -> Json:
    cleaned = sorted({str(r).strip() for r in reviewers if str(r).strip()})
    if len(cleaned) < 2 or not case_id:
        return {"applied": False, "reason": "insufficient_common_prior_approvals", "reviewer_count": len(cleaned)}
    root = _reviewer_collusion_suspicion_root(state)
    by_case = root["by_case"]
    events = root["events"]
    height = int(state.get("height") or 0)
    suspicion_id = f"poh-reviewer-collusion:{case_id}:{challenge_id}"
    rec = {
        "suspicion_id": suspicion_id,
        "challenge_id": challenge_id,
        "case_id": case_id,
        "account_id": account_id,
        "reviewers": cleaned,
        "reviewer_count": len(cleaned),
        "status": "suspected_prior_approval_cluster",
        "reason": "challenge_upheld_multiple_prior_approvals",
        "height": height,
        "requires_followup_review": True,
        "escalation_level": "review_required",
        "review_window_open_height": height,
        "review_window_close_height": height + 1440,
        "recovery_eligible_after_height": height + 1440,
        "recovery_policy": "eligible_after_followup_review_or_successful_reverification",
    }
    by_case[suspicion_id] = rec
    events.append({"event": "poh_reviewer_collusion_suspicion", **rec})
    return {"applied": True, "suspicion_id": suspicion_id, "reviewers": cleaned, "reviewer_count": len(cleaned)}

def _record_challenge_reviewer_accountability(state: Json, *, challenge_id: str, case_id: str, account_id: str) -> Json:
    if not case_id:
        return {"applied": False, "reason": "missing_case_id"}
    cases = _async_cases(state)
    case = cases.get(case_id)
    if not isinstance(case, dict):
        return {"applied": False, "reason": "case_not_found", "case_id": case_id}
    reviews = case.get("reviews")
    if not isinstance(reviews, dict) or not reviews:
        return {"applied": False, "reason": "no_reviews", "case_id": case_id}

    root = _reviewer_accountability_root(state)
    by_reviewer = root["by_reviewer"]
    events = root["events"]
    recorded: list[str] = []
    for reviewer_id in sorted(str(k) for k in reviews.keys() if str(k).strip()):
        review = reviews.get(reviewer_id)
        if not isinstance(review, dict):
            continue
        verdict = _as_str(review.get("verdict") or "").strip().lower()
        if verdict not in {"approve", "approved", "pass", "yes"}:
            continue
        rec = by_reviewer.get(reviewer_id)
        if not isinstance(rec, dict):
            rec = {"reviewer_id": reviewer_id, "challenge_upheld_review_count": 0, "events": []}
        event = {
            "event": "challenge_upheld_prior_approval",
            "challenge_id": challenge_id,
            "case_id": case_id,
            "account_id": account_id,
            "height": int(state.get("height") or 0),
        }
        rec["challenge_upheld_review_count"] = _as_int(rec.get("challenge_upheld_review_count") or 0, 0) + 1
        rec["status"] = "reviewer_accountability_flagged"
        rec["eligible_for_poh_review"] = False
        rec["eligibility_reason"] = "prior_approval_challenge_upheld"
        rec.setdefault("events", []).append(event)
        by_reviewer[reviewer_id] = rec
        acct = state.get("accounts", {}).get(reviewer_id) if isinstance(state.get("accounts"), dict) else None
        if isinstance(acct, dict):
            acct["poh_reviewer_eligible"] = False
            acct["poh_reviewer_suspended_reason"] = "prior_approval_challenge_upheld"
            acct["poh_reviewer_suspended_at_height"] = int(state.get("height") or 0)
        roles = state.get("roles")
        if isinstance(roles, dict):
            reviewers = roles.get("poh_reviewers")
            if isinstance(reviewers, dict):
                suspended = reviewers.get("suspended")
                if not isinstance(suspended, dict):
                    suspended = {}
                    reviewers["suspended"] = suspended
                suspended[reviewer_id] = {"reason": "prior_approval_challenge_upheld", "challenge_id": challenge_id, "case_id": case_id}
        events.append({"reviewer_id": reviewer_id, **event})
        recorded.append(reviewer_id)
    collusion = _record_reviewer_collusion_suspicion(
        state,
        challenge_id=challenge_id,
        case_id=case_id,
        account_id=account_id,
        reviewers=recorded,
    )
    return {"applied": bool(recorded), "reviewers": recorded, "case_id": case_id, "collusion_suspicion": collusion}

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
    case_id = _as_str(p.get("case_id") or p.get("target_case_id") or "").strip()
    if case_id:
        ch["case_id"] = case_id

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

    consequence: Json = {"applied": False}
    if resolution == "upheld":
        account_id = _as_str(ch.get("account_id") or "").strip()
        if not account_id:
            raise ApplyError("invalid_tx", "challenge_missing_account_id", {"challenge_id": cid})
        rec = revoke_account_poh_status(
            state,
            account_id=account_id,
            reason="challenge_upheld",
            last_updated_height=int(state.get("height") or 0),
        )
        reverify = _record_reverification_required(
            state,
            account_id=account_id,
            challenge_id=cid,
            reason="challenge_upheld",
        )
        retention = _record_challenge_evidence_retention_policy(
            state,
            challenge_id=cid,
            account_id=account_id,
            case_id=_as_str(p.get("case_id") or ch.get("case_id") or "").strip(),
            status="retain_until_reverification_or_appeal",
            reason="challenge_upheld",
        )
        accountability = _record_challenge_reviewer_accountability(
            state,
            challenge_id=cid,
            case_id=_as_str(p.get("case_id") or ch.get("case_id") or "").strip(),
            account_id=account_id,
        )
        ch["consequence"] = {
            "type": "poh_status_revoked",
            "account_id": account_id,
            "poh_tier": 0,
            "status": _as_str(rec.get("status") or "revoked"),
            "reverification_status": _as_str(reverify.get("status") or "required"),
            "reverification_required": True,
            "evidence_retention": retention,
            "reviewer_accountability": accountability,
        }
        consequence = dict(ch["consequence"])
        consequence["applied"] = True
    else:
        account_id = _as_str(ch.get("account_id") or "").strip()
        retention = _record_challenge_evidence_retention_policy(
            state,
            challenge_id=cid,
            account_id=account_id,
            case_id=_as_str(p.get("case_id") or ch.get("case_id") or "").strip(),
            status="dismissed_minimal_retention",
            reason="challenge_dismissed",
        )
        # Preserve the legacy dismissed/no-op consequence shape for callers and
        # older compatibility tests.  The evidence-retention policy is still
        # recorded on the challenge record and canonical PoH evidence-retention
        # state, but it must not change the stable no-op consequence envelope.
        ch["evidence_retention"] = retention
        ch["consequence"] = {"type": "none", "applied": False}
        consequence = dict(ch["consequence"])

    return {
        "applied": "POH_CHALLENGE_RESOLVE",
        "challenge_id": cid,
        "resolution": resolution,
        "consequence": consequence,
    }



ASYNC_PRIVATE_FIELD_DENYLIST: frozenset[str] = frozenset(
    {
        "raw_response",
        "raw_video",
        "private_notes",
        "juror_private_notes",
        "em" + "ail",
        "em" + "ail_hash",
        "phone",
        "phone_number",
        "ip_address",
        "device_fingerprint",
        "browser_fingerprint",
        "government_id",
        "provider_metadata",
        "kyc_metadata",
        "oauth_provider_metadata",
    }
)


def _reject_native_async_private_fields(payload: Json) -> None:
    leaked = sorted(k for k in ASYNC_PRIVATE_FIELD_DENYLIST if k in payload and payload.get(k) not in (None, ""))
    if leaked:
        raise ApplyError("invalid_tx", "native_async_private_field_forbidden", {"fields": leaked})


def _validate_async_review_policy(
    *,
    assigned_jurors: int,
    minimum_reviews: int,
    approval_threshold: int,
    rejection_threshold: int,
    case_id: str = "",
) -> None:
    """Validate the canonical native async PoH review denominator.

    Native async verification is a consensus outcome.  The denominator and
    thresholds must come from chain state at case-open time and remain coherent
    through assignment/finalization.  A malformed policy must fail closed instead
    of making finalization impossible or allowing a later tx to lower thresholds.
    """

    details: Json = {
        "assigned_jurors": int(assigned_jurors),
        "minimum_reviews": int(minimum_reviews),
        "approval_threshold": int(approval_threshold),
        "rejection_threshold": int(rejection_threshold),
    }
    if case_id:
        details["case_id"] = case_id

    if int(assigned_jurors) < 1:
        raise ApplyError("invalid_state", "invalid_async_poh_threshold_policy", details)
    if int(minimum_reviews) < 1 or int(minimum_reviews) > int(assigned_jurors):
        raise ApplyError("invalid_state", "invalid_async_poh_threshold_policy", details)
    if int(approval_threshold) < 1 or int(approval_threshold) > int(minimum_reviews):
        raise ApplyError("invalid_state", "invalid_async_poh_threshold_policy", details)
    if int(rejection_threshold) < 1 or int(rejection_threshold) > int(minimum_reviews):
        raise ApplyError("invalid_state", "invalid_async_poh_threshold_policy", details)


def _async_defaults_from_state(state: Json) -> tuple[int, int, int, int, int]:
    params = state.get("params")
    params = params if isinstance(params, dict) else {}
    poh = params.get("poh")
    poh = poh if isinstance(poh, dict) else {}
    assigned_jurors = max(1, _as_int(poh.get("async_n_jurors") or 3, 3))
    min_reviews = max(1, _as_int(poh.get("async_min_reviews") or 3, 3))
    approval_threshold = max(1, _as_int(poh.get("async_approval_threshold") or 2, 2))
    rejection_threshold = max(1, _as_int(poh.get("async_rejection_threshold") or 2, 2))
    expiry_window = max(1, _as_int(poh.get("async_expiry_window_blocks") or 100000, 100000))
    _validate_async_review_policy(
        assigned_jurors=assigned_jurors,
        minimum_reviews=min_reviews,
        approval_threshold=approval_threshold,
        rejection_threshold=rejection_threshold,
    )
    return assigned_jurors, min_reviews, approval_threshold, rejection_threshold, expiry_window


def _get_async_case(state: Json, case_id: str) -> Json:
    case = _async_cases(state).get(case_id)
    if not isinstance(case, dict):
        raise ApplyError("invalid_tx", "async_case_not_found", {"case_id": case_id})
    return case


def _async_case_open_or_reviewable(case: Json, *, case_id: str) -> str:
    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("approved", "rejected", "expired", "finalized"):
        raise ApplyError("invalid_tx", "async_case_finalized", {"case_id": case_id, "status": status})
    return status


def _require_async_evidence_mutable(case: Json, *, case_id: str) -> None:
    """Fail closed once evidence has entered review scope.

    Jurors must vote on a stable evidence set.  After assignment starts, the
    applicant may not replace response/evidence commitments until a future
    explicit follow-up transaction exists and seals a new evidence root.
    """

    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("assigned", "under_review", "needs_followup", "approved", "rejected", "expired", "finalized"):
        raise ApplyError(
            "invalid_tx",
            "async_evidence_locked",
            {"case_id": case_id, "status": status},
        )


def _async_case_has_declared_evidence(case: Json) -> bool:
    """Return true once the applicant has committed evidence to the case.

    The production scheduler waits until POH_ASYNC_EVIDENCE_BIND has succeeded
    before it emits POH_ASYNC_JUROR_ASSIGN, because assignment locks evidence
    and must not race the applicant's bind transaction.  The apply rule remains
    slightly more permissive for direct SYSTEM/bootstrap fixtures and replay
    compatibility: if SYSTEM supplies a juror assignment after a valid evidence
    declaration, assignment is still admissible.
    """

    commitments = case.get("evidence_commitments")
    if isinstance(commitments, dict) and any(_as_str(k).strip() for k in commitments.keys()):
        return True
    reviewer_private = case.get("reviewer_private_evidence")
    if isinstance(reviewer_private, dict) and any(_as_str(k).strip() for k in reviewer_private.keys()):
        return True
    binds = case.get("evidence_binds")
    if isinstance(binds, dict) and any(_as_str(k).strip() for k in binds.keys()):
        return True
    public_ids = case.get("public_evidence_ids")
    if isinstance(public_ids, list) and any(_as_str(item).strip() for item in public_ids):
        return True
    return False


def _async_reviews_have_followup_request(case: Json) -> bool:
    reviews = case.get("reviews")
    reviews = reviews if isinstance(reviews, dict) else {}
    for review_any in reviews.values():
        review = review_any if isinstance(review_any, dict) else {}
        if _as_str(review.get("verdict") or "").strip().lower() == "needs_followup":
            return True
    return False


def _append_unique_str(values: Any, value: str) -> list[str]:
    out: list[str] = []
    if isinstance(values, list):
        for item in values:
            item_s = _as_str(item).strip()
            if item_s and item_s not in out:
                out.append(item_s)
    value_s = _as_str(value).strip()
    if value_s and value_s not in out:
        out.append(value_s)
    return out


def _async_review_counts(case: Json) -> tuple[int, int, int]:
    reviews = case.get("reviews")
    reviews = reviews if isinstance(reviews, dict) else {}
    approvals = 0
    rejections = 0
    counted = 0
    for review_any in reviews.values():
        review = review_any if isinstance(review_any, dict) else {}
        verdict = _as_str(review.get("verdict") or "").strip().lower()
        if verdict == "approve":
            approvals += 1
            counted += 1
        elif verdict in ("reject", "invalid_evidence"):
            rejections += 1
            counted += 1
        elif verdict in ("abstain", "needs_followup"):
            # Abstain and needs_followup are real reviews, but they do not
            # satisfy the finalization denominator. needs_followup pauses the
            # case until a future explicit follow-up path exists.
            continue
    return approvals, rejections, counted


def apply_poh_async_request_open(state: Json, env: Any) -> Json:
    p = _payload(env)
    _reject_native_async_private_fields(p)
    account_id = _as_str(p.get("account_id") or _signer(env)).strip()
    if not account_id:
        raise ApplyError("invalid_tx", "missing_account_id", {})
    _require_subject_signer(env, account_id)
    acct = _require_registered_account(state, account_id)
    if bool(acct.get("banned", False)):
        raise ApplyError("forbidden", "account_banned", {"account_id": account_id})
    if bool(acct.get("locked", False)):
        raise ApplyError("forbidden", "account_locked", {"account_id": account_id})

    configured_jurors, configured_min_reviews, configured_approval_threshold, configured_rejection_threshold, expiry_window = _async_defaults_from_state(state)
    policy = adaptive_bootstrap_review_policy(
        state,
        configured_jurors=configured_jurors,
        configured_min_reviews=configured_min_reviews,
        configured_approval_threshold=configured_approval_threshold,
        configured_rejection_threshold=configured_rejection_threshold,
    )
    assigned_jurors = int(policy["assigned_jurors"])
    min_reviews = int(policy["minimum_reviews"])
    approval_threshold = int(policy["approval_threshold"])
    rejection_threshold = int(policy["rejection_threshold"])
    height = int(state.get("height") or 0)
    case_id = _as_str(p.get("case_id") or "").strip() or _case_id(
        "pohasync", account_id=account_id, nonce=_as_int(_get_env(env, "nonce", 0))
    )
    cases = _async_cases(state)
    if case_id in cases:
        raise ApplyError("invalid_tx", "case_already_exists", {"case_id": case_id})

    challenge_id = _as_str(p.get("challenge_id") or "").strip() or f"challenge:{case_id}"
    challenge_commitment = _as_str(p.get("challenge_commitment") or "").strip()
    if not challenge_commitment:
        challenge_commitment = _sha256_hex(f"{_chain_id(state)}|POH_ASYNC_CHALLENGE|{case_id}|{account_id}|{challenge_id}".encode())
    challenge_commitment = _validate_commitment_format(
        challenge_commitment, field="challenge_commitment", case_id=case_id, required=True
    )
    response_commitment = _validate_commitment_format(
        p.get("response_commitment"), field="response_commitment", case_id=case_id, required=False
    )
    expires_height = _as_int(p.get("expires_height") or 0, 0) or height + expiry_window
    if expires_height <= height:
        raise ApplyError("invalid_tx", "invalid_expiry_height", {"case_id": case_id, "expires_height": expires_height})

    cases[case_id] = {
        "case_id": case_id,
        "account_id": account_id,
        "opened_by": _signer(env),
        "opened_height": height,
        "expires_height": expires_height,
        "status": "open",
        "challenge_id": challenge_id,
        "challenge_commitment": challenge_commitment,
        "response_commitment": response_commitment,
        "evidence_commitments": {},
        "public_evidence_ids": [],
        "assigned_jurors": [],
        "accepted_jurors": [],
        "declined_jurors": [],
        "reviews": {},
        "outcome": None,
        "finalized_height": None,
        "receipt_id": None,
        "target_tier": 1,
        "configured_assigned_juror_count": configured_jurors,
        "configured_minimum_reviews": configured_min_reviews,
        "configured_approval_threshold": configured_approval_threshold,
        "configured_rejection_threshold": configured_rejection_threshold,
        "assigned_juror_count": assigned_jurors,
        "minimum_reviews": min_reviews,
        "approval_threshold": approval_threshold,
        "rejection_threshold": rejection_threshold,
        "protocol_native": True,
        "external_identity_authority": "forbidden",
    }
    policy = adaptive_bootstrap_review_policy(
        state,
        configured_jurors=configured_jurors,
        configured_min_reviews=configured_min_reviews,
        configured_approval_threshold=configured_approval_threshold,
        configured_rejection_threshold=configured_rejection_threshold,
        height=height,
    )
    if bool(policy.get("bootstrap_adaptive")):
        cases[case_id]["bootstrap_adaptive_quorum"] = {
            "active_validators": int(policy["active_validators"]),
            "bft_min_validators": int(policy["bft_min_validators"]),
            "assigned_jurors": int(policy["assigned_jurors"]),
            "minimum_reviews": int(policy["minimum_reviews"]),
            "approval_threshold": int(policy["approval_threshold"]),
            "rejection_threshold": int(policy["rejection_threshold"]),
        }

    return {
        "applied": "POH_ASYNC_REQUEST_OPEN",
        "case_id": case_id,
        "account_id": account_id,
        "status": "open",
        "expires_height": expires_height,
    }


def apply_poh_async_evidence_declare(state: Json, env: Any) -> Json:
    p = _payload(env)
    _reject_native_async_private_fields(p)
    case_id = _as_str(p.get("case_id") or "").strip()
    evidence_commitment = _as_str(p.get("evidence_commitment") or "").strip()
    response_commitment = _as_str(p.get("response_commitment") or "").strip()
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    evidence_commitment = _validate_commitment_format(
        evidence_commitment, field="evidence_commitment", case_id=case_id, required=False
    )
    response_commitment = _validate_commitment_format(
        response_commitment, field="response_commitment", case_id=case_id, required=False
    )
    if not evidence_commitment and not response_commitment:
        raise ApplyError("invalid_tx", "missing_evidence_commitment", {"case_id": case_id})
    case = _get_async_case(state, case_id)
    _async_case_open_or_reviewable(case, case_id=case_id)
    _require_async_evidence_mutable(case, case_id=case_id)
    account_id = _as_str(case.get("account_id") or "").strip()
    _require_subject_signer(env, account_id)

    evidence_id = _as_str(p.get("evidence_id") or "").strip()
    if not evidence_id:
        basis = evidence_commitment or response_commitment or str(_as_int(_get_env(env, "nonce", 0)))
        evidence_id = f"async-evidence:{_sha256_hex(f'{case_id}|{basis}'.encode())[:24]}"

    commitments = case.get("evidence_commitments")
    if not isinstance(commitments, dict):
        commitments = {}
        case["evidence_commitments"] = commitments
    rec: Json = {
        "evidence_id": evidence_id,
        "evidence_commitment": evidence_commitment,
        "response_commitment": response_commitment,
        "kind": _as_str(p.get("kind") or "commitment").strip() or "commitment",
        "declared_height": int(state.get("height") or 0),
    }

    commitments[evidence_id] = rec
    if response_commitment:
        case["response_commitment"] = response_commitment

    # Option B privacy posture: async evidence remains reviewer-private by
    # default.  Public case state keeps only commitments.  Content-addressed
    # evidence references are stored in a separate reviewer-private envelope and
    # are exposed only through scoped reviewer/subject APIs.
    private_rec: Json = {
        "evidence_id": evidence_id,
        "evidence_commitment": evidence_commitment,
        "response_commitment": response_commitment,
        "kind": rec["kind"],
        "declared_height": rec["declared_height"],
        "visibility": "reviewer_private",
    }
    for key in ("evidence_cid", "mime", "name", "filename", "size"):
        value = p.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
        private_rec[key] = value

    uri = _validate_ipfs_uri(p.get("uri"), field="uri", case_id=case_id)
    if uri:
        private_rec["uri"] = uri

    video_commitment = _validate_commitment_format(
        p.get("video_commitment"), field="video_commitment", case_id=case_id, required=False
    )
    if video_commitment:
        private_rec["video_commitment"] = video_commitment

    reviewer_private = case.get("reviewer_private_evidence")
    if not isinstance(reviewer_private, dict):
        reviewer_private = {}
        case["reviewer_private_evidence"] = reviewer_private
    if any(k in private_rec for k in ("evidence_cid", "uri", "video_commitment")):
        reviewer_private[evidence_id] = private_rec

    # Preserve the old fields as explicitly empty public surfaces so stale
    # clients/tests do not mistake absence for unredacted public evidence.
    case["public_evidence_ids"] = []
    case["reviewable_evidence"] = {}

    case["status"] = "evidence_submitted"
    return {"applied": "POH_ASYNC_EVIDENCE_DECLARE", "case_id": case_id, "evidence_id": evidence_id}


def apply_poh_async_evidence_bind(state: Json, env: Any) -> Json:
    p = _payload(env)
    _reject_native_async_private_fields(p)
    case_id = _as_str(p.get("case_id") or "").strip()
    evidence_id = _as_str(p.get("evidence_id") or "").strip()
    if not case_id or not evidence_id:
        raise ApplyError("invalid_tx", "missing_case_or_evidence_id", {"case_id": case_id, "evidence_id": evidence_id})
    case = _get_async_case(state, case_id)
    _async_case_open_or_reviewable(case, case_id=case_id)
    _require_async_evidence_mutable(case, case_id=case_id)
    account_id = _as_str(case.get("account_id") or "").strip()
    _require_subject_signer(env, account_id)
    commitments = case.get("evidence_commitments")
    if not isinstance(commitments, dict) or evidence_id not in commitments:
        raise ApplyError("invalid_tx", "evidence_not_declared", {"case_id": case_id, "evidence_id": evidence_id})
    binds = case.get("evidence_binds")
    if not isinstance(binds, dict):
        binds = {}
        case["evidence_binds"] = binds
    target_id = _as_str(p.get("target_id") or "").strip() or case_id
    bind_id = f"bind:{case_id}:{evidence_id}:{target_id}"
    binds[bind_id] = {"bind_id": bind_id, "evidence_id": evidence_id, "target_id": target_id}
    return {"applied": "POH_ASYNC_EVIDENCE_BIND", "case_id": case_id, "bind_id": bind_id}


def apply_poh_async_juror_assign(state: Json, env: Any) -> Json:
    _require_system_tx(env, "POH_ASYNC_JUROR_ASSIGN")
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    juror_values = p.get("jurors")
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    if not isinstance(juror_values, list):
        raise ApplyError("invalid_tx", "missing_jurors", {"case_id": case_id})
    case = _get_async_case(state, case_id)
    _async_case_open_or_reviewable(case, case_id=case_id)
    forbidden_threshold_fields = ("min_reviews", "approval_threshold", "rejection_threshold")
    supplied_threshold_fields = [field for field in forbidden_threshold_fields if p.get(field) is not None]
    if supplied_threshold_fields:
        raise ApplyError(
            "invalid_tx",
            "async_threshold_override_forbidden",
            {"case_id": case_id, "fields": supplied_threshold_fields},
        )
    if not _async_case_has_declared_evidence(case):
        raise ApplyError(
            "invalid_tx",
            "async_evidence_required_before_assignment",
            {"case_id": case_id},
        )

    policy = adaptive_bootstrap_review_policy(
        state,
        configured_jurors=_as_int(case.get("configured_assigned_juror_count") or case.get("assigned_juror_count") or 3, 3),
        configured_min_reviews=_as_int(case.get("configured_minimum_reviews") or case.get("minimum_reviews") or 3, 3),
        configured_approval_threshold=_as_int(case.get("configured_approval_threshold") or case.get("approval_threshold") or 2, 2),
        configured_rejection_threshold=_as_int(case.get("configured_rejection_threshold") or case.get("rejection_threshold") or 2, 2),
    )
    case["assigned_juror_count"] = int(policy["assigned_jurors"])
    case["minimum_reviews"] = int(policy["minimum_reviews"])
    case["approval_threshold"] = int(policy["approval_threshold"])
    case["rejection_threshold"] = int(policy["rejection_threshold"])
    if bool(policy.get("bootstrap_adaptive")):
        case["bootstrap_adaptive_quorum"] = {
            "active_validators": int(policy["active_validators"]),
            "bft_min_validators": int(policy["bft_min_validators"]),
            "assigned_jurors": int(policy["assigned_jurors"]),
            "minimum_reviews": int(policy["minimum_reviews"]),
            "approval_threshold": int(policy["approval_threshold"]),
            "rejection_threshold": int(policy["rejection_threshold"]),
        }
    assigned_needed = _as_int(case.get("assigned_juror_count") or 3, 3)
    jurors: list[str] = []
    for item in juror_values:
        jid = _as_str(item).strip()
        if jid and jid not in jurors:
            jurors.append(jid)
    if len(jurors) != assigned_needed:
        raise ApplyError("invalid_tx", "invalid_async_juror_count", {"case_id": case_id, "expected": assigned_needed, "actual": len(jurors)})

    account_id = _as_str(case.get("account_id") or "").strip()
    for jid in jurors:
        if jid == account_id:
            raise ApplyError("invalid_tx", "subject_cannot_review_self", {"case_id": case_id, "juror": jid})
        _require_active_live(state, jid, case_id=case_id)

    _validate_async_review_policy(
        assigned_jurors=assigned_needed,
        minimum_reviews=_as_int(case.get("minimum_reviews") or 3, 3),
        approval_threshold=_as_int(case.get("approval_threshold") or 2, 2),
        rejection_threshold=_as_int(case.get("rejection_threshold") or 2, 2),
        case_id=case_id,
    )

    case["assigned_jurors"] = jurors
    juror_map = case.get("jurors")
    if not isinstance(juror_map, dict):
        juror_map = {}
        case["jurors"] = juror_map
    for jid in jurors:
        juror_map.setdefault(jid, {"juror_id": jid, "status": "assigned"})

    case["status"] = "assigned"
    return {"applied": "POH_ASYNC_JUROR_ASSIGN", "case_id": case_id, "jurors": jurors}


def apply_poh_async_juror_accept(state: Json, env: Any) -> Json:
    case_id = _as_str(_payload(env).get("case_id") or "").strip()
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    case = _get_async_case(state, case_id)
    _async_case_open_or_reviewable(case, case_id=case_id)
    juror_id = _signer(env)
    _require_active_live(state, juror_id, case_id=case_id)
    if juror_id not in list(case.get("assigned_jurors") or []):
        raise ApplyError("forbidden", "juror_not_assigned", {"case_id": case_id, "juror": juror_id})
    if juror_id in list(case.get("declined_jurors") or []):
        raise ApplyError("invalid_tx", "juror_already_declined", {"case_id": case_id, "juror": juror_id})
    case["accepted_jurors"] = _append_unique_str(case.get("accepted_jurors"), juror_id)
    jurors = case.get("jurors")
    if isinstance(jurors, dict):
        jurors.setdefault(juror_id, {})["status"] = "accepted"
    case["status"] = "under_review"
    return {"applied": "POH_ASYNC_JUROR_ACCEPT", "case_id": case_id, "juror": juror_id}


def apply_poh_async_juror_decline(state: Json, env: Any) -> Json:
    case_id = _as_str(_payload(env).get("case_id") or "").strip()
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    case = _get_async_case(state, case_id)
    _async_case_open_or_reviewable(case, case_id=case_id)
    juror_id = _signer(env)
    _require_active_live(state, juror_id, case_id=case_id)
    if juror_id not in list(case.get("assigned_jurors") or []):
        raise ApplyError("forbidden", "juror_not_assigned", {"case_id": case_id, "juror": juror_id})
    if juror_id in list(case.get("accepted_jurors") or []):
        raise ApplyError("invalid_tx", "juror_already_accepted", {"case_id": case_id, "juror": juror_id})
    case["declined_jurors"] = _append_unique_str(case.get("declined_jurors"), juror_id)
    jurors = case.get("jurors")
    if isinstance(jurors, dict):
        jurors.setdefault(juror_id, {})["status"] = "declined"
    return {"applied": "POH_ASYNC_JUROR_DECLINE", "case_id": case_id, "juror": juror_id}


def apply_poh_async_review_submit(state: Json, env: Any) -> Json:
    p = _payload(env)
    _reject_native_async_private_fields(p)
    case_id = _as_str(p.get("case_id") or "").strip()
    verdict = _as_str(p.get("verdict") or "").strip().lower()
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    if verdict not in ("approve", "reject", "needs_followup", "invalid_evidence", "abstain"):
        raise ApplyError("invalid_tx", "invalid_async_verdict", {"case_id": case_id, "verdict": verdict})
    case = _get_async_case(state, case_id)
    _async_case_open_or_reviewable(case, case_id=case_id)
    juror_id = _signer(env)
    _require_active_live(state, juror_id, case_id=case_id)
    if juror_id not in list(case.get("assigned_jurors") or []):
        raise ApplyError("forbidden", "juror_not_assigned", {"case_id": case_id, "juror": juror_id})
    if juror_id not in list(case.get("accepted_jurors") or []):
        raise ApplyError("forbidden", "juror_not_accepted", {"case_id": case_id, "juror": juror_id})
    if juror_id in list(case.get("declined_jurors") or []):
        raise ApplyError("forbidden", "juror_declined", {"case_id": case_id, "juror": juror_id})
    reviews = case.get("reviews")
    if not isinstance(reviews, dict):
        reviews = {}
        case["reviews"] = reviews
    if juror_id in reviews:
        raise ApplyError("invalid_tx", "duplicate_async_review", {"case_id": case_id, "juror": juror_id})
    review_commitment = _as_str(p.get("review_commitment") or "").strip()
    if not review_commitment:
        review_commitment = _sha256_hex(f"{_chain_id(state)}|POH_ASYNC_REVIEW|{case_id}|{juror_id}|{verdict}".encode())
    reviews[juror_id] = {
        "case_id": case_id,
        "juror_id": juror_id,
        "verdict": verdict,
        "reason_code": _as_str(p.get("reason_code") or "").strip(),
        "review_commitment": review_commitment,
        "submitted_height": int(state.get("height") or 0),
        "signature": _as_str(_get_env(env, "sig", "")).strip(),
    }
    case["status"] = "needs_followup" if verdict == "needs_followup" else "under_review"
    return {"applied": "POH_ASYNC_REVIEW_SUBMIT", "case_id": case_id, "juror": juror_id, "verdict": verdict}


def apply_poh_async_finalize(state: Json, env: Any) -> Json:
    _require_system_tx(env, "POH_ASYNC_FINALIZE")
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    case = _get_async_case(state, case_id)
    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("approved", "rejected", "expired", "finalized"):
        return {
            "applied": "POH_ASYNC_FINALIZE",
            "case_id": case_id,
            "outcome": _as_str(case.get("outcome") or status),
            "tier_awarded": _as_int(case.get("tier_awarded") or 0, 0),
        }

    approvals, rejections, counted = _async_review_counts(case)
    if _async_reviews_have_followup_request(case):
        case["status"] = "needs_followup"
        raise ApplyError(
            "invalid_tx",
            "async_case_needs_followup",
            {"case_id": case_id, "reviews": counted, "approvals": approvals, "rejections": rejections},
        )
    assigned_jurors = _as_int(case.get("assigned_juror_count") or 0, 0)
    assigned_list = case.get("assigned_jurors")
    if isinstance(assigned_list, list) and assigned_list:
        assigned_jurors = len([jid for jid in assigned_list if _as_str(jid).strip()])
    minimum_reviews = _as_int(case.get("minimum_reviews") or 3, 3)
    approval_threshold = _as_int(case.get("approval_threshold") or 2, 2)
    rejection_threshold = _as_int(case.get("rejection_threshold") or 2, 2)
    _validate_async_review_policy(
        assigned_jurors=assigned_jurors,
        minimum_reviews=minimum_reviews,
        approval_threshold=approval_threshold,
        rejection_threshold=rejection_threshold,
        case_id=case_id,
    )
    height = int(state.get("height") or 0)
    expires_height = _as_int(case.get("expires_height") or 0, 0)

    outcome = ""
    tier_awarded = 0
    if counted >= minimum_reviews and approvals >= approval_threshold:
        outcome = "approved"
        tier_awarded = 1
    elif counted >= minimum_reviews and rejections >= rejection_threshold:
        outcome = "rejected"
    elif expires_height and height > expires_height:
        outcome = "expired"
    else:
        raise ApplyError(
            "invalid_tx",
            "async_finalize_premature",
            {
                "case_id": case_id,
                "reviews": counted,
                "minimum_reviews": minimum_reviews,
                "approvals": approvals,
                "rejections": rejections,
                "approval_threshold": approval_threshold,
                "rejection_threshold": rejection_threshold,
            },
        )

    token_id = ""
    account_id = _as_str(case.get("account_id") or "").strip()
    if not account_id:
        raise ApplyError("invalid_tx", "missing_account_id", {"case_id": case_id})
    if tier_awarded:
        target_acct = _require_registered_account(state, account_id)
        target_acct["poh_tier"] = max(_as_int(target_acct.get("poh_tier") or 0), 1)
        set_account_poh_status(
            state,
            account_id=account_id,
            poh_tier=1,
            status=POH_STATUS_ACTIVE,
            verified_at_height=height,
            proof_commitment=_as_str(case.get("response_commitment") or case.get("challenge_commitment") or "").strip() or None,
            last_updated_height=height,
        )
        token_id = _mint_poh_nft(
            state, owner=account_id, tier=1, source_id=case_id, ts_ms=_as_int(p.get("ts_ms") or 0)
        )
        reverify_completion = _mark_reverification_completed(
            state, account_id=account_id, case_id=case_id, height=height
        )
        if bool(reverify_completion.get("applied")):
            case["reverification_completed"] = dict(reverify_completion)

    case["status"] = outcome
    case["outcome"] = outcome
    case["tier_awarded"] = tier_awarded
    case["finalized_height"] = height
    case["finalized_ts_ms"] = _as_int(p.get("ts_ms") or 0)
    if token_id:
        case["poh_nft_token_id"] = token_id
    return {
        "applied": "POH_ASYNC_FINALIZE",
        "case_id": case_id,
        "outcome": outcome,
        "tier_awarded": tier_awarded,
        "token_id": token_id,
    }


def apply_poh_async_receipt(state: Json, env: Any) -> Json:
    _require_system_tx(env, "POH_ASYNC_RECEIPT")
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    case = _get_async_case(state, case_id)
    if _as_str(case.get("outcome") or "").strip().lower() not in ("approved", "rejected", "expired"):
        raise ApplyError("invalid_tx", "async_case_not_finalized", {"case_id": case_id})
    receipt_id = _as_str(p.get("receipt_id") or "").strip()
    if not receipt_id:
        receipt_id = f"receipt:{_sha256_hex(f'{_chain_id(state)}|POH_ASYNC_RECEIPT|{case_id}'.encode())[:32]}"
    outcome = _as_str(case.get("outcome") or "").strip()
    tier_awarded = _as_int(case.get("tier_awarded") or 0, 0)
    supplied_outcome = _as_str(p.get("outcome") or "").strip()
    if supplied_outcome and supplied_outcome != outcome:
        raise ApplyError("invalid_tx", "async_receipt_outcome_mismatch", {"case_id": case_id, "outcome": outcome, "supplied_outcome": supplied_outcome})
    if p.get("tier_awarded") is not None and _as_int(p.get("tier_awarded") or 0, 0) != tier_awarded:
        raise ApplyError("invalid_tx", "async_receipt_tier_mismatch", {"case_id": case_id, "tier_awarded": tier_awarded, "supplied_tier_awarded": _as_int(p.get("tier_awarded") or 0, 0)})
    case["receipt_id"] = receipt_id
    case["receipt"] = {
        "receipt_id": receipt_id,
        "case_id": case_id,
        "account_id": _as_str(case.get("account_id") or "").strip(),
        "verification_type": "async",
        "outcome": outcome,
        "tier_awarded": tier_awarded,
        "finalized_height": _as_int(case.get("finalized_height") or 0, 0),
        "threshold_summary": {
            "minimum_reviews": _as_int(case.get("minimum_reviews") or 3, 3),
            "approval_threshold": _as_int(case.get("approval_threshold") or 2, 2),
            "rejection_threshold": _as_int(case.get("rejection_threshold") or 2, 2),
        },
    }
    return {"applied": "POH_ASYNC_RECEIPT", "case_id": case_id, "receipt_id": receipt_id}



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

    # PoH escalation is subject-owned.  A reviewer, relayer, frontend, or
    # malicious caller may not open a Tier 2/3 case for another account unless a
    # later explicit delegation tx is added.  This closes the highest-risk
    # target-substitution path found in the devnet readiness audit.
    _require_subject_signer(env, account_id)

    if target_tier > 2:
        raise ApplyError(
            "invalid_tx",
            "live_legacy_request_disabled",
            {
                "tx_type": "POH_TIER2_REQUEST_OPEN",
                "required_tx_type": "POH_LIVE_REQUEST_OPEN",
                "required_min_tier": 1,
            },
        )

    if target_tier != 2:
        raise ApplyError("invalid_tx", "unsupported_target_tier", {"target_tier": target_tier})

    _require_account_min_tier(
        state,
        account_id,
        min_tier=1,
        reason="tier2_request_requires_tier1",
    )

    if not video_commitment:
        if video_cid:
            video_commitment = _sha256_hex(video_cid.encode("utf-8"))
        else:
            raise ApplyError("invalid_tx", "missing_video_commitment", {})

    case_id = _case_id("poh2", account_id=account_id, nonce=_as_int(_get_env(env, "nonce", 0)))
    cases = _tier2_cases(state)
    if case_id in cases:
        raise ApplyError("invalid_tx", "case_already_exists", {"case_id": case_id})

    evidence_index = _evidence_commitment_index(state)
    existing = evidence_index.get(video_commitment)
    if isinstance(existing, dict):
        existing_case = _as_str(existing.get("case_id") or "").strip()
        existing_account = _as_str(existing.get("account_id") or "").strip()
        if existing_case != case_id or existing_account != account_id:
            raise ApplyError(
                "invalid_tx",
                "evidence_commitment_replayed",
                {
                    "case_id": case_id,
                    "account_id": account_id,
                    "existing_case_id": existing_case,
                    "existing_account_id": existing_account,
                },
            )
    elif existing:
        raise ApplyError("invalid_tx", "evidence_commitment_replayed", {"case_id": case_id})

    cases[case_id] = {
        "case_id": case_id,
        "account_id": account_id,
        "requested_by": _signer(env),
        "video_commitment": video_commitment,
        "status": "open",
        "jurors": {},
        "target_tier": 2,
    }
    evidence_index[video_commitment] = {
        "case_id": case_id,
        "account_id": account_id,
        "target_tier": 2,
        "accepted_at_height": int(state.get("height") or 0),
    }

    return {"applied": "POH_TIER2_REQUEST_OPEN", "case_id": case_id}


def apply_poh_live_request_open(state: Json, env: Any) -> Json:
    """Open a dedicated protocol-native live-verification request.

    This is the only live-verification request path. Legacy
    POH_TIER2_REQUEST_OPEN is limited to async escalation; live verification uses POH_LIVE_REQUEST_OPEN
    from Tier1 or an overloaded tx.  The subject must sign for itself, already
    hold canonical Tier1, and provide non-empty session/room/prompt commitments.
    Media relays remain transport only; the protocol stores commitments and
    reviewer attestations, not relay-granted identity authority.
    """

    p = _payload(env)
    account_id = _as_str(p.get("account_id") or p.get("target") or "").strip()
    if not account_id:
        raise ApplyError("invalid_tx", "missing_account_id", {})

    _require_subject_signer(env, account_id)
    _require_account_min_tier(state, account_id, min_tier=1, reason="live_request_requires_tier1")

    cases = _live_cases(state)
    for existing_case_id, existing_any in cases.items():
        existing = existing_any if isinstance(existing_any, dict) else {}
        if _as_str(existing.get("account_id") or "").strip() != account_id:
            continue
        status = _as_str(existing.get("status") or "").strip().lower()
        if status not in ("", "awarded", "finalized", "rejected", "expired", "cancelled"):
            raise ApplyError(
                "forbidden",
                "active_live_case_exists",
                {"account_id": account_id, "case_id": str(existing_case_id), "status": status},
            )

    case_id = _case_id("poh_live", account_id=account_id, nonce=_as_int(_get_env(env, "nonce", 0)))
    if case_id in cases:
        raise ApplyError("invalid_tx", "case_already_exists", {"case_id": case_id})

    requested_height = int(state.get("height") or 0)
    requested_ts_ms = _as_int(p.get("ts_ms") or 0)
    request_commitment = _sha256_hex(
        f"{_chain_id(state)}|POH_LIVE_REQUEST|{case_id}|{account_id}|{requested_height}".encode()
    )

    commitments = _require_live_request_commitments(p)
    session_commitment = commitments["session_commitment"]
    room_commitment = commitments["room_commitment"]
    prompt_commitment = commitments["prompt_commitment"]
    device_pairing_commitment = commitments["device_pairing_commitment"]

    case: Json = {
        "case_id": case_id,
        "account_id": account_id,
        "requested_by": _signer(env),
        "status": "requested",
        "jurors": {},
        "target_tier": 2,
        "request_commitment": request_commitment,
        "requested_height": requested_height,
        "requested_ts_ms": requested_ts_ms,
        "protocol_native": True,
        "relay_authority": "transport_only",
    }
    for key, value in (
        ("session_commitment", session_commitment),
        ("room_commitment", room_commitment),
        ("prompt_commitment", prompt_commitment),
        ("device_pairing_commitment", device_pairing_commitment),
    ):
        if value:
            case[key] = value
    cases[case_id] = case

    session_id = f"session:{case_id}"
    session: Json = {
        "session_id": session_id,
        "case_id": case_id,
        "account_id": account_id,
        "status": "requested",
        "created_height": requested_height,
        "created_ts_ms": requested_ts_ms,
        "request_commitment": request_commitment,
        "relay_authority": "transport_only",
    }
    for key, value in (
        ("session_commitment", session_commitment),
        ("room_commitment", room_commitment),
        ("prompt_commitment", prompt_commitment),
        ("device_pairing_commitment", device_pairing_commitment),
    ):
        if value:
            session[key] = value
    _live_sessions(state)[session_id] = session
    _live_session_participants(state).setdefault(session_id, {})[account_id] = {
        "role": "subject",
        "status": "requested",
        "joined_ts_ms": None,
        "left_ts_ms": None,
    }

    return {
        "applied": "POH_LIVE_REQUEST_OPEN",
        "case_id": case_id,
        "session_id": session_id,
        "target_tier": 2,
    }


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

    normalized_jurors = [_as_str(x).strip() for x in jurors]
    if any(not jid for jid in normalized_jurors):
        raise ApplyError("invalid_tx", "bad_jurors", {})
    if len(normalized_jurors) != len(set(normalized_jurors)):
        raise ApplyError("invalid_tx", "duplicate_jurors", {})

    min_total, pass_threshold, fail_max, n_jurors_default = _tier2_defaults_from_state(state)
    n_jurors = _as_int(p.get("n_jurors") or n_jurors_default, n_jurors_default)
    if n_jurors <= 0:
        n_jurors = n_jurors_default
    if len(normalized_jurors) != n_jurors:
        raise ApplyError("invalid_tx", "wrong_juror_count", {"need": n_jurors, "got": len(normalized_jurors)})

    case = _get_tier2_case(state, case_id)
    if _as_str(case.get("status") or "") not in ("open", "assigned"):
        raise ApplyError("invalid_tx", "case_not_open", {"case_id": case_id})

    target_account = _as_str(case.get("account_id") or "").strip()
    if not target_account:
        raise ApplyError("invalid_state", "case_missing_account_id", {"case_id": case_id})

    jm: Json = {}
    for jid in normalized_jurors:
        if jid == target_account:
            raise ApplyError("forbidden", "juror_self_review_forbidden", {"case_id": case_id, "juror": jid})
        _require_active_live(state, jid, case_id=case_id)
        jm[jid] = {"verdict": None, "ts_ms": None, "assigned_height": int(state.get("height") or 0)}

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
    _require_active_live(state, signer, case_id=case_id)
    if signer == _as_str(case.get("account_id") or "").strip():
        raise ApplyError("forbidden", "juror_self_review_forbidden", {"case_id": case_id, "juror": signer})
    jrec = jm.get(signer)
    if not isinstance(jrec, dict):
        raise ApplyError("forbidden", "juror_required", {"case_id": case_id})
    if _as_str(jrec.get("status") or "").strip().lower() == "declined":
        raise ApplyError("forbidden", "juror_already_declined", {"case_id": case_id})

    jrec["accepted"] = True
    jrec["status"] = "accepted"
    jrec["accepted_ts_ms"] = _as_int(p.get("ts_ms") or 0)

    return {"applied": "POH_TIER2_JUROR_ACCEPT", "case_id": case_id, "juror": signer}


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
    _require_active_live(state, signer, case_id=case_id)
    if signer == _as_str(case.get("account_id") or "").strip():
        raise ApplyError("forbidden", "juror_self_review_forbidden", {"case_id": case_id, "juror": signer})
    jrec = jm.get(signer)
    if not isinstance(jrec, dict):
        raise ApplyError("forbidden", "juror_required", {"case_id": case_id})
    if _as_str(jrec.get("verdict") or "").strip().lower() in ("pass", "fail"):
        raise ApplyError("forbidden", "juror_already_reviewed", {"case_id": case_id})

    jrec["accepted"] = False
    jrec["status"] = "declined"
    jrec["declined_ts_ms"] = _as_int(p.get("ts_ms") or 0)

    return {"applied": "POH_TIER2_JUROR_DECLINE", "case_id": case_id, "juror": signer}


def apply_poh_tier2_review_submit(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    verdict = _as_str(p.get("verdict") or "").strip().lower()

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    if verdict not in ("pass", "fail"):
        raise ApplyError("invalid_tx", "bad_verdict", {"verdict": verdict})

    case = _get_tier2_case(state, case_id)
    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("awarded", "finalized", "rejected"):
        raise ApplyError(
            "forbidden",
            "case_finalized",
            {"case_id": case_id, "status": status},
        )
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})

    signer = _signer(env)
    _require_active_live(state, signer, case_id=case_id)
    if signer == _as_str(case.get("account_id") or "").strip():
        raise ApplyError("forbidden", "juror_self_review_forbidden", {"case_id": case_id, "juror": signer})
    jrec = jm.get(signer)
    if not isinstance(jrec, dict):
        raise ApplyError("forbidden", "juror_required", {"case_id": case_id})
    if _as_str(jrec.get("status") or "").strip().lower() == "declined":
        raise ApplyError("forbidden", "juror_declined", {"case_id": case_id})
    if _as_str(jrec.get("verdict") or "").strip().lower() in ("pass", "fail"):
        raise ApplyError("forbidden", "review_already_submitted", {"case_id": case_id})

    jrec["accepted"] = True
    jrec["status"] = "reviewed"
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
        return {
            "applied": "POH_TIER2_FINALIZE",
            "case_id": case_id,
            "outcome": outcome,
            "tier_awarded": tier,
            "token_id": token_id,
        }

    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})

    min_total = int(case.get("min_total_reviews") or 0)
    pass_threshold = int(case.get("pass_threshold") or 0)
    fail_max = int(case.get("fail_max") or 0)

    total = 0
    passes = 0
    fails = 0
    target_account = _as_str(case.get("account_id") or "").strip()
    if not target_account:
        raise ApplyError("invalid_tx", "missing_account_id", {"case_id": case_id})
    target_acct = _require_registered_account(state, target_account)
    for _jid, jrec_any in jm.items():
        jid = _as_str(_jid).strip()
        if jid == target_account:
            raise ApplyError("forbidden", "juror_self_review_forbidden", {"case_id": case_id, "juror": jid})
        _require_active_live(state, jid, case_id=case_id)
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
        target_acct["poh_tier"] = max(_as_int(target_acct.get("poh_tier") or 0), 2)
        token_id = _mint_poh_nft(
            state, owner=target_account, tier=2, source_id=case_id, ts_ms=_as_int(p.get("ts_ms") or 0)
        )

    case["status"] = "awarded" if outcome == "pass" else "rejected"
    case["outcome"] = outcome
    case["tier_awarded"] = tier_awarded
    case["finalized_ts_ms"] = _as_int(p.get("ts_ms") or 0)
    if token_id:
        case["poh_nft_token_id"] = token_id

    return {
        "applied": "POH_TIER2_FINALIZE",
        "case_id": case_id,
        "outcome": outcome,
        "tier_awarded": tier_awarded,
        "token_id": token_id,
    }


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


def _get_live_case(state: Json, case_id: str) -> Json:
    cases = _live_cases(state)
    case = cases.get(case_id)
    if not isinstance(case, dict):
        raise ApplyError("not_found", "live_case_not_found", {"case_id": case_id})
    return case


def apply_poh_live_session_init(state: Json, env: Any) -> Json:
    _require_system_tx(env, "POH_LIVE_SESSION_INIT")
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    account_id = _as_str(p.get("account_id") or "").strip()
    session_commitment = _as_str(p.get("session_commitment") or "").strip()

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    if not account_id:
        raise ApplyError("invalid_tx", "missing_account_id", {})

    if not session_commitment:
        raise ApplyError("invalid_tx", "missing_session_commitment", {"case_id": case_id})

    cases = _live_cases(state)
    case = cases.get(case_id)
    if not isinstance(case, dict):
        raise ApplyError("not_found", "live_case_not_found", {"case_id": case_id})

    expected_commitments = _require_live_case_commitments(case, case_id=case_id)
    if session_commitment != expected_commitments["session_commitment"]:
        raise ApplyError("invalid_tx", "bad_session_commitment", {"case_id": case_id})

    existing_account = _as_str(case.get("account_id") or "").strip()
    if existing_account and existing_account != account_id:
        raise ApplyError(
            "invalid_tx",
            "live_session_init_account_mismatch",
            {"case_id": case_id, "case_account_id": existing_account, "payload_account_id": account_id},
        )

    room_commitment = _as_str(p.get("room_commitment") or "").strip()
    prompt_commitment = _as_str(p.get("prompt_commitment") or "").strip()
    device_pairing_commitment = _as_str(p.get("device_pairing_commitment") or "").strip()
    relay_commitment = _validate_commitment_format(
        p.get("relay_commitment"), field="relay_commitment", case_id=case_id, required=False
    )
    join_url = _as_str(p.get("join_url") or "").strip()
    if join_url:
        # The chain stores relay commitments only.  Raw live-room join URLs
        # belong in self-hosted/access-controlled transport, not consensus state.
        if not relay_commitment:
            relay_commitment = _sha256_hex(join_url.encode("utf-8"))

    # Defense in depth for migrated/legacy states and future caller mistakes:
    # consensus live-room records may expose commitments, never raw join URLs or
    # one-time room links. The API sanitizes too, but apply-time state remains
    # the primary authority.
    for raw_key in ("join_url", "room_url", "relay_url", "meeting_url"):
        case.pop(raw_key, None)

    status = _as_str(case.get("status") or "").strip().lower()
    if status not in ("requested", "open"):
        raise ApplyError("invalid_tx", "live_case_not_requested", {"case_id": case_id, "status": status})

    case["status"] = "open"
    case.setdefault("jurors", {})
    case["init_ts_ms"] = _as_int(p.get("ts_ms") or 0)
    case["session_commitment"] = session_commitment
    case["relay_authority"] = "transport_only"
    for key, value in (
        ("room_commitment", room_commitment),
        ("prompt_commitment", prompt_commitment),
        ("device_pairing_commitment", device_pairing_commitment),
        ("relay_commitment", relay_commitment),
    ):
        if value:
            case[key] = value

    session_id = f"session:{case_id}"
    session = _live_sessions(state).get(session_id)
    if not isinstance(session, dict):
        session = {"session_id": session_id, "case_id": case_id, "account_id": account_id}
        _live_sessions(state)[session_id] = session
    session["status"] = "open"
    session.setdefault("created_ts_ms", _as_int(p.get("ts_ms") or 0))
    session["started_ts_ms"] = _as_int(p.get("ts_ms") or 0)
    session["session_commitment"] = session_commitment
    session["relay_authority"] = "transport_only"
    for raw_key in ("join_url", "room_url", "relay_url", "meeting_url"):
        session.pop(raw_key, None)

    for key, value in (
        ("room_commitment", room_commitment),
        ("prompt_commitment", prompt_commitment),
        ("device_pairing_commitment", device_pairing_commitment),
        ("relay_commitment", relay_commitment),
    ):
        if value:
            session[key] = value

    _live_session_participants(state).setdefault(session_id, {}).setdefault(
        account_id,
        {"role": "subject", "status": "session_open", "joined_ts_ms": None, "left_ts_ms": None},
    )

    return {
        "applied": "POH_LIVE_SESSION_INIT",
        "case_id": case_id,
        "session_id": session_id,
        "session_commitment": session_commitment,
    }


def apply_poh_live_juror_assign(state: Json, env: Any) -> Json:
    """Assign Live Verification jurors (legacy POH_LIVE_* tx family).

    Production hardening:
    - requires SYSTEM tx (env.system True)
    - accepts adaptive 1..10 unique juror ids only in bootstrap mode; production mode requires fixed 5-person panel
    - first up-to-3 jurors are active/interacting reviewers
    - remaining jurors are watching/observing witnesses
    - pass/fail uses a frozen deterministic n-of-m threshold over active reviewers
    - every juror must exist, not banned, not locked, and PoH tier >= 2 / Live Verified Human
    - subject account (being verified) cannot be a juror
    """
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    jurors = p.get("jurors")

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    _require_system_tx(env, "POH_LIVE_JUROR_ASSIGN")
    if not isinstance(jurors, list) or not (1 <= len(jurors) <= MAX_LIVE_JURORS):
        raise ApplyError(
            "invalid_tx",
            "bad_jurors",
            {"min": 1, "max": MAX_LIVE_JURORS, "actual": len(jurors) if isinstance(jurors, list) else 0},
        )

    production_policy = _live_poh_production_mode(state)
    if production_policy and len(jurors) != PRODUCTION_LIVE_PANEL_SIZE:
        raise ApplyError(
            "invalid_tx",
            "live_production_panel_size_required",
            {"expected": PRODUCTION_LIVE_PANEL_SIZE, "actual": len(jurors)},
        )
    if production_policy and (
        p.get("pass_threshold_num") is not None or p.get("pass_threshold_den") is not None
    ):
        raise ApplyError(
            "invalid_tx",
            "live_production_threshold_override_forbidden",
            {"case_id": case_id},
        )

    case = _get_live_case(state, case_id)
    _require_live_case_commitments(case, case_id=case_id)
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
            raise ApplyError(
                "invalid_tx", "subject_cannot_be_juror", {"case_id": case_id, "juror": jid}
            )
        seen.add(jid)
        _require_active_live(state, jid, case_id=case_id)
        cleaned.append(jid)

    threshold_num, threshold_den = _live_threshold_from_assignment(state, p)
    quorum = live_quorum_summary(
        panel_size=len(cleaned), numerator=threshold_num, denominator=threshold_den
    )
    quorum["mode"] = "production" if production_policy else "bootstrap"
    if production_policy:
        quorum = _apply_production_live_quorum_overlay(quorum)

    jm: Json = {}
    active_count = live_active_reviewer_count(len(cleaned))
    for i, jid in enumerate(cleaned):
        role = "interacting" if i < active_count else "observing"
        jm[jid] = {"role": role, "accepted": None, "attended": None, "verdict": None}

    case["jurors"] = jm
    case["live_quorum"] = quorum
    case["status"] = "init"

    return {"applied": "POH_LIVE_JUROR_ASSIGN", "case_id": case_id, "live_quorum": quorum}


def apply_poh_live_juror_accept(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})

    signer = _signer(env)
    _require_active_live(state, signer, case_id=case_id)

    case = _get_live_case(state, case_id)
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})

    if signer not in jm:
        raise ApplyError("forbidden", "juror_required", {"case_id": case_id})

    jrec = jm.get(signer)
    if not isinstance(jrec, dict):
        jrec = {}
        jm[signer] = jrec

    if jrec.get("accepted") is False:
        raise ApplyError("forbidden", "juror_already_declined", {"case_id": case_id, "juror": signer})
    if jrec.get("attended") is True:
        raise ApplyError("forbidden", "attendance_already_marked", {"case_id": case_id, "juror": signer})
    if _as_str(jrec.get("verdict") or "").strip().lower() in ("pass", "fail"):
        raise ApplyError("forbidden", "verdict_already_submitted", {"case_id": case_id, "juror": signer})

    jrec["accepted"] = True
    jrec["accepted_ts_ms"] = _as_int(p.get("ts_ms") or 0)

    session_id = f"session:{case_id}"
    _live_session_participants(state).setdefault(session_id, {})[signer] = {
        "role": _as_str(jrec.get("role") or "juror"),
        "status": "accepted",
        "joined_ts_ms": None,
        "left_ts_ms": None,
    }

    return {"applied": "POH_LIVE_JUROR_ACCEPT", "case_id": case_id}


def apply_poh_live_juror_decline(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})

    signer = _signer(env)
    _require_active_live(state, signer, case_id=case_id)

    case = _get_live_case(state, case_id)
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})

    if signer not in jm:
        raise ApplyError("forbidden", "juror_required", {"case_id": case_id})

    jrec = jm.get(signer)
    if not isinstance(jrec, dict):
        jrec = {}
        jm[signer] = jrec

    if jrec.get("accepted") is True:
        raise ApplyError("forbidden", "juror_already_accepted", {"case_id": case_id, "juror": signer})
    if jrec.get("attended") is True:
        raise ApplyError("forbidden", "attendance_already_marked", {"case_id": case_id, "juror": signer})
    if _as_str(jrec.get("verdict") or "").strip().lower() in ("pass", "fail"):
        raise ApplyError("forbidden", "verdict_already_submitted", {"case_id": case_id, "juror": signer})

    jrec["accepted"] = False
    jrec["declined_ts_ms"] = _as_int(p.get("ts_ms") or 0)

    session_id = f"session:{case_id}"
    _live_session_participants(state).setdefault(session_id, {})[signer] = {
        "role": _as_str(jrec.get("role") or "juror"),
        "status": "declined",
        "joined_ts_ms": None,
        "left_ts_ms": None,
    }

    return {"applied": "POH_LIVE_JUROR_DECLINE", "case_id": case_id}


def apply_poh_live_juror_replace(state: Json, env: Any) -> Json:
    """SYSTEM tx to replace a declined / no-show juror.

    Payload:
      - case_id
      - old_juror_id
      - new_juror_id

    Rules:
      - system-only
      - old juror must be assigned
      - new juror must be Live Verified Human, not banned/locked, exist, not already assigned, not the subject
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
        raise ApplyError("forbidden", "system_only", {"tx_type": "POH_LIVE_JUROR_REPLACE"})

    case = _get_live_case(state, case_id)
    subject = _as_str(case.get("account_id") or "").strip()
    if subject and new_id == subject:
        raise ApplyError(
            "invalid_tx", "subject_cannot_be_juror", {"case_id": case_id, "juror": new_id}
        )

    jm = case.get("jurors")
    if not isinstance(jm, dict):
        raise ApplyError("invalid_tx", "jurors_not_assigned", {"case_id": case_id})
    if old_id not in jm:
        raise ApplyError(
            "invalid_tx", "juror_not_assigned", {"case_id": case_id, "juror_id": old_id}
        )
    if new_id in jm:
        raise ApplyError(
            "invalid_tx", "juror_already_assigned", {"case_id": case_id, "juror_id": new_id}
        )

    old_rec_any = jm.get(old_id)
    old_rec = old_rec_any if isinstance(old_rec_any, dict) else {}

    if old_rec.get("accepted") is not False and old_rec.get("attended") is True:
        raise ApplyError(
            "invalid_tx", "juror_not_replaceable", {"case_id": case_id, "juror": old_id}
        )

    _require_active_live(state, new_id, case_id=case_id)

    role = _as_str(old_rec.get("role") or "").strip() or "observing"

    old_rec["replaced"] = True
    old_rec["replaced_by"] = new_id
    if old_rec.get("attended") is None:
        old_rec["attended"] = False
    jm[old_id] = old_rec

    jm[new_id] = {"role": role, "accepted": None, "attended": None, "verdict": None}

    case["status"] = _as_str(case.get("status") or "init")

    return {
        "applied": "POH_LIVE_JUROR_REPLACE",
        "case_id": case_id,
        "old_juror_id": old_id,
        "new_juror_id": new_id,
        "role": role,
    }


def apply_poh_live_attendance_mark(state: Json, env: Any) -> Json:
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
        raise ApplyError(
            "forbidden",
            "juror_signer_mismatch",
            {"case_id": case_id, "juror_id": juror_id, "signer": signer},
        )

    _require_active_live(state, signer, case_id=case_id)

    case = _get_live_case(state, case_id)
    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("awarded", "finalized", "rejected"):
        raise ApplyError(
            "forbidden",
            "case_finalized",
            {"case_id": case_id, "status": status},
        )

    _require_live_payload_session_matches(case, p, case_id=case_id)

    jm = case.get("jurors")
    if not isinstance(jm, dict) or juror_id not in jm:
        raise ApplyError(
            "invalid_tx", "juror_not_assigned", {"case_id": case_id, "juror_id": juror_id}
        )
    jrec = jm.get(juror_id)
    if not isinstance(jrec, dict):
        jrec = {}
        jm[juror_id] = jrec

    if jrec.get("accepted") is not True:
        raise ApplyError("forbidden", "accept_required", {"case_id": case_id, "juror": juror_id})

    if attended is False:
        raise ApplyError(
            "forbidden", "cannot_self_mark_absent", {"case_id": case_id, "juror": juror_id}
        )

    jrec["attended"] = True
    jrec["attended_ts_ms"] = _as_int(p.get("ts_ms") or 0)

    session_id = f"session:{case_id}"
    _live_session_participants(state).setdefault(session_id, {})[juror_id] = {
        "role": _as_str(jrec.get("role") or "juror"),
        "status": "attended",
        "joined_ts_ms": _as_int(p.get("ts_ms") or 0),
        "left_ts_ms": None,
    }

    return {
        "applied": "POH_LIVE_ATTENDANCE_MARK",
        "case_id": case_id,
        "juror_id": juror_id,
        "attended": True,
    }


def apply_poh_live_verdict_submit(state: Json, env: Any) -> Json:
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    verdict = _as_str(p.get("verdict") or "").strip().lower()

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})
    if verdict not in ("pass", "fail"):
        raise ApplyError("invalid_tx", "bad_verdict", {"verdict": verdict})

    signer = _signer(env)
    _require_active_live(state, signer, case_id=case_id)

    case = _get_live_case(state, case_id)
    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("awarded", "finalized", "rejected"):
        raise ApplyError(
            "forbidden",
            "case_finalized",
            {"case_id": case_id, "status": status},
        )

    _require_live_payload_session_matches(case, p, case_id=case_id)

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

    if _as_str(jrec.get("verdict") or "").strip().lower() in ("pass", "fail"):
        raise ApplyError("forbidden", "verdict_already_submitted", {"case_id": case_id, "juror": signer})

    jrec["verdict"] = verdict
    jrec["verdict_ts_ms"] = _as_int(p.get("ts_ms") or 0)

    return {"applied": "POH_LIVE_VERDICT_SUBMIT", "case_id": case_id, "verdict": verdict}


def apply_poh_live_finalize(state: Json, env: Any) -> Json:
    _require_system_tx(env, "POH_LIVE_FINALIZE")
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()

    if not case_id:
        raise ApplyError("invalid_tx", "missing_case_id", {})

    case = _get_live_case(state, case_id)
    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("awarded", "finalized", "rejected"):
        tier = _as_int(case.get("tier_awarded") or 0)
        outcome = _as_str(case.get("outcome") or "")
        token_id = _as_str(case.get("poh_nft_token_id") or "").strip()
        return {
            "applied": "POH_LIVE_FINALIZE",
            "case_id": case_id,
            "outcome": outcome,
            "tier_awarded": tier,
            "token_id": token_id,
        }

    target_account = _as_str(case.get("account_id") or "").strip()
    if not target_account:
        raise ApplyError("invalid_tx", "missing_account_id", {"case_id": case_id})
    target_acct = _require_registered_account(state, target_account)

    _require_live_case_commitments(case, case_id=case_id)

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

    production_policy = _live_poh_production_mode(state)

    if not (1 <= len(active) <= MAX_LIVE_JURORS):
        raise ApplyError(
            "invalid_tx",
            "jurors_not_ready",
            {"case_id": case_id, "min": 1, "max": MAX_LIVE_JURORS, "actual": len(active)},
        )
    if production_policy and len(active) != PRODUCTION_LIVE_PANEL_SIZE:
        raise ApplyError(
            "invalid_tx",
            "live_production_panel_size_required",
            {"case_id": case_id, "expected": PRODUCTION_LIVE_PANEL_SIZE, "actual": len(active)},
        )

    configured_quorum = case.get("live_quorum") if isinstance(case.get("live_quorum"), dict) else {}
    threshold_num, threshold_den = normalize_live_threshold(
        numerator=configured_quorum.get("pass_threshold_num"),
        denominator=configured_quorum.get("pass_threshold_den"),
    )

    active_reviewers: list[Json] = []
    for _jid, jrec in active.items():
        if _as_str(jrec.get("role") or "") == "interacting":
            active_reviewers.append(jrec)

    expected_active = PRODUCTION_LIVE_MIN_PRESENT if production_policy else live_active_reviewer_count(len(active))
    if len(active_reviewers) != expected_active or expected_active <= 0:
        raise ApplyError(
            "invalid_tx",
            "live_active_reviewers_not_ready",
            {"case_id": case_id, "expected": expected_active, "actual": len(active_reviewers)},
        )

    passes = 0
    failures = 0
    have = 0
    for jrec in active_reviewers:
        if jrec.get("accepted") is not True or jrec.get("attended") is not True:
            raise ApplyError("invalid_tx", "attendance_not_ready", {"case_id": case_id})
        v = _as_str(jrec.get("verdict") or "").strip().lower()
        if v not in ("pass", "fail"):
            raise ApplyError("invalid_tx", "verdicts_not_ready", {"case_id": case_id})
        have += 1
        if v == "pass":
            passes += 1
        else:
            failures += 1

    required_pass = (
        PRODUCTION_LIVE_APPROVAL_THRESHOLD
        if production_policy
        else required_live_passes(have, numerator=threshold_num, denominator=threshold_den)
    )
    if production_policy and have < PRODUCTION_LIVE_MIN_VERDICTS:
        raise ApplyError(
            "invalid_tx",
            "live_production_verdict_quorum_required",
            {"case_id": case_id, "need": PRODUCTION_LIVE_MIN_VERDICTS, "have": have},
        )
    if have != expected_active or required_pass <= 0:
        raise ApplyError("invalid_tx", "verdicts_not_ready", {"case_id": case_id})

    quorum = live_quorum_summary(
        panel_size=len(active), numerator=threshold_num, denominator=threshold_den
    )
    quorum["mode"] = "production" if production_policy else "bootstrap"
    if production_policy:
        quorum = _apply_production_live_quorum_overlay(quorum)
    quorum["actual_verdicts"] = have
    quorum["actual_passes"] = passes
    quorum["actual_failures"] = failures

    outcome = "pass" if passes >= required_pass else "fail"
    tier_awarded = 2 if outcome == "pass" else 0

    token_id = ""
    if outcome == "pass":
        target_acct["poh_tier"] = max(_as_int(target_acct.get("poh_tier") or 0), 2)
        token_id = _mint_poh_nft(
            state, owner=target_account, tier=2, source_id=case_id, ts_ms=_as_int(p.get("ts_ms") or 0)
        )

    case["status"] = "awarded" if outcome == "pass" else "rejected"
    case["outcome"] = outcome
    case["tier_awarded"] = tier_awarded
    case["live_quorum"] = quorum
    case["finalized_ts_ms"] = _as_int(p.get("ts_ms") or 0)
    if token_id:
        case["poh_nft_token_id"] = token_id

    session_id = f"session:{case_id}"
    session = _live_sessions(state).get(session_id)
    if isinstance(session, dict):
        session["status"] = "finalized"
        session["ended_ts_ms"] = _as_int(p.get("ts_ms") or 0)
        session["outcome"] = outcome
        session["tier_awarded"] = tier_awarded

    return {
        "applied": "POH_LIVE_FINALIZE",
        "case_id": case_id,
        "outcome": outcome,
        "tier_awarded": tier_awarded,
        "token_id": token_id,
        "live_quorum": quorum,
    }


def apply_poh_live_receipt(state: Json, env: Any) -> Json:
    _require_system_tx(env, "POH_LIVE_RECEIPT")
    p = _payload(env)
    case_id = _as_str(p.get("case_id") or "").strip()
    receipt_id = _as_str(p.get("receipt_id") or "").strip()
    if case_id:
        try:
            case = _get_live_case(state, case_id)
            case["live_receipt_emitted"] = True
            if receipt_id:
                case["live_receipt_id"] = receipt_id
        except Exception:
            pass
    return {"applied": "POH_LIVE_RECEIPT", "case_id": case_id, "receipt_id": receipt_id}


def apply_poh(state: Json, env: Any) -> Json | None:
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
            poh["applications"][app_id] = {
                "application_id": app_id,
                "account_id": account_id,
                "payload": p,
            }
            return {"applied": t, "application_id": app_id}

        if t == "POH_EVIDENCE_DECLARE":
            evidence_id = (
                _as_str(p.get("evidence_id") or "").strip()
                or _as_str(p.get("cid") or p.get("video_cid") or "").strip()
            )
            if not evidence_id:
                evidence_id = f"evi:{_signer(env)}:{_as_int(_get_env(env, 'nonce', 0))}"
            poh["evidence"][evidence_id] = {"evidence_id": evidence_id, "payload": p}
            return {"applied": t, "evidence_id": evidence_id}

        if t == "POH_EVIDENCE_BIND":
            bind_id = f"bind:{_signer(env)}:{_as_int(_get_env(env, 'nonce', 0))}"
            poh.setdefault("evidence_binds", {})
            poh["evidence_binds"][bind_id] = {"bind_id": bind_id, "payload": p}
            return {"applied": t, "bind_id": bind_id}


    if t == "POH_ASYNC_REQUEST_OPEN":
        return apply_poh_async_request_open(state, env)

    if t == "POH_ASYNC_EVIDENCE_DECLARE":
        return apply_poh_async_evidence_declare(state, env)

    if t == "POH_ASYNC_EVIDENCE_BIND":
        return apply_poh_async_evidence_bind(state, env)

    if t == "POH_ASYNC_JUROR_ASSIGN":
        return apply_poh_async_juror_assign(state, env)

    if t == "POH_ASYNC_JUROR_ACCEPT":
        return apply_poh_async_juror_accept(state, env)

    if t == "POH_ASYNC_JUROR_DECLINE":
        return apply_poh_async_juror_decline(state, env)

    if t == "POH_ASYNC_REVIEW_SUBMIT":
        return apply_poh_async_review_submit(state, env)

    if t == "POH_ASYNC_FINALIZE":
        return apply_poh_async_finalize(state, env)

    if t == "POH_ASYNC_RECEIPT":
        return apply_poh_async_receipt(state, env)

    if t == "POH_TIER_REVOKE":
        return apply_poh_tier_revoke(state, env)

    if t == "POH_TIER_SET":
        apply_poh_tier_set(state, {"payload": _payload(env)})
        return {"applied": "POH_TIER_SET"}

    if t == "POH_BOOTSTRAP_TIER2_GRANT":
        apply_poh_bootstrap_tier2_grant(
            state,
            {
                "payload": _payload(env),
                "signer": _signer(env),
                "nonce": _as_int(_get_env(env, "nonce", 0)),
            },
        )
        return {"applied": "POH_BOOTSTRAP_TIER2_GRANT"}

    if t == "POH_CHALLENGE_OPEN":
        return apply_poh_challenge_open(state, env)

    if t == "POH_CHALLENGE_RESOLVE":
        return apply_poh_challenge_resolve(state, env)

    if t == "POH_TIER2_REQUEST_OPEN":
        return apply_poh_tier2_request_open(state, env)

    if t == "POH_LIVE_REQUEST_OPEN":
        return apply_poh_live_request_open(state, env)

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

    if t == "POH_LIVE_SESSION_INIT":
        return apply_poh_live_session_init(state, env)

    if t == "POH_LIVE_JUROR_ASSIGN":
        return apply_poh_live_juror_assign(state, env)

    if t == "POH_LIVE_JUROR_ACCEPT":
        return apply_poh_live_juror_accept(state, env)

    if t == "POH_LIVE_JUROR_DECLINE":
        return apply_poh_live_juror_decline(state, env)

    if t == "POH_LIVE_JUROR_REPLACE":
        return apply_poh_live_juror_replace(state, env)

    if t == "POH_LIVE_ATTENDANCE_MARK":
        return apply_poh_live_attendance_mark(state, env)

    if t == "POH_LIVE_VERDICT_SUBMIT":
        return apply_poh_live_verdict_submit(state, env)

    if t == "POH_LIVE_FINALIZE":
        return apply_poh_live_finalize(state, env)

    if t == "POH_LIVE_RECEIPT":
        return apply_poh_live_receipt(state, env)

    return None
