from __future__ import annotations

import base64
import hashlib
from typing import Any

from ..errors import ApplyError
from ..tx_admission_types import TxEnvelope
from ..session_keys import revoke_session_record, store_session_record
from ..public_protocol_policy import public_protocol_policy_violation
from ..account_recovery_policy import (
    RECOVERY_FAILED_WINDOW_BLOCKS,
    RECOVERY_MAX_FAILED_ATTEMPTS,
    RECOVERY_REQUEST_COOLDOWN_BLOCKS,
    RECOVERY_RESTRICTION_BLOCKS,
)
from ..recovery_review import (
    CONTINUITY_APPROVAL_THRESHOLD,
    CONTINUITY_PANEL_SIZE,
    RECOVERY_REVIEW_WINDOW_BLOCKS,
    REVERSAL_APPROVAL_THRESHOLD,
    REVERSAL_PANEL_SIZE,
    recovery_conflict_reason,
    review_counts as recovery_review_counts,
)
from ..reviewer_responsibilities import POH_ASYNC_REVIEW_LANE, reviewer_lane_active
from ..poh.state import effective_poh_tier
from ..poh.evidence_lifecycle import (
    close_case_evidence,
    evidence_record,
    mark_reviewer_accessible,
    register_encrypted_evidence,
)
from weall.crypto.account_keys import (
    account_key_pubkey,
    account_key_record_from_payload,
    validate_account_key_record,
)
from weall.crypto.signature_profiles import default_signature_profile_for_mode

Json = dict[str, Any]


# KEY-115 continuity evidence classes.  The aliases preserve deterministic
# replay of the pre-M2 labels while every new request is normalized into the
# canonical v2 identifiers below.  Social continuity is corroborating evidence
# only and can never be the strong anchor.
CONTINUITY_EVIDENCE_CLASS_ALIASES: dict[str, str] = {
    "precommitted_external_key": "precommitted_external_key",
    "precommitted_external_key_signature": "precommitted_external_key",
    "external_key": "precommitted_external_key",
    "salted_credential_document_commitment": "salted_credential_document_commitment",
    "salted_credential_commitment": "salted_credential_document_commitment",
    "salted_document_commitment": "salted_credential_document_commitment",
    "government_record": "salted_credential_document_commitment",
    "registered_non_authority_device_key": "registered_non_authority_device_key",
    "registered_device_key": "registered_non_authority_device_key",
    "non_authority_device_key": "registered_non_authority_device_key",
    "external_account_or_credential_issuer_control": "external_account_or_credential_issuer_control",
    "external_account_control": "external_account_or_credential_issuer_control",
    "credential_issuer_control": "external_account_or_credential_issuer_control",
    "unpublished_activity_archive_preimage": "unpublished_activity_archive_preimage",
    "historical_account_activity": "unpublished_activity_archive_preimage",
    "activity_archive_preimage": "unpublished_activity_archive_preimage",
    "social_continuity_attestations": "social_continuity_attestations",
    "social_continuity": "social_continuity_attestations",
}
CONTINUITY_STRONG_ANCHOR_CLASSES: frozenset[str] = frozenset(
    value
    for value in CONTINUITY_EVIDENCE_CLASS_ALIASES.values()
    if value != "social_continuity_attestations"
)
CONTINUITY_SOCIAL_ATTESTOR_MINIMUM = 5


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _as_str(x: Any) -> str:
    if x is None:
        return ""
    return str(x)


def _payload(env: TxEnvelope) -> Json:
    p = getattr(env, "payload", None)
    if not isinstance(p, dict):
        return {}
    return p


def _ensure(state: Json, k: str, default: Any) -> Any:
    if k not in state or state.get(k) is None:
        state[k] = default
    return state[k]


def _expect_nonce(a: Json, env: TxEnvelope) -> int:
    want = _as_int(a.get("nonce"), 0) + 1
    got = _as_int(getattr(env, "nonce", None), 0)

    # Consensus-critical rule: account nonces are strictly sequential at apply-time.
    # System receipts are often emitted with nonce=0; in that case we consume
    # the next expected nonce deterministically.
    if bool(getattr(env, "system", False)) and got == 0:
        got = want

    if got != want:
        raise ApplyError("invalid_tx", "bad_nonce", {"want": want, "got": got})
    return got


def _require_known_not_banned_allow_locked(state: Json, account_id: str) -> Json:
    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})
    account = accounts.get(account_id)
    if not isinstance(account, dict):
        raise ApplyError("invalid_tx", "unknown_account", {"account_id": account_id})
    if account.get("banned") is True:
        raise ApplyError("forbidden", "account_banned", {"account_id": account_id})
    return account


def _guardian_recovery_admission_enabled(state: Json) -> bool:
    params = state.get("params")
    if not isinstance(params, dict):
        return False
    raw = params.get("guardian_recovery_new_admission")
    # Missing selectors fail closed on every current pinned chain. Historical
    # replay fixtures that need to execute legacy guardian transactions must set
    # the selector explicitly for that replay context.
    if raw is None:
        return False
    if isinstance(raw, bool):
        return raw
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _require_guardian_recovery_admission(state: Json) -> None:
    if not _guardian_recovery_admission_enabled(state):
        raise ApplyError("forbidden", "guardian_recovery_retired", {})


def _require_not_banned_or_locked(state: Json, account_id: str) -> Json:
    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})
    a = accounts.get(account_id)
    if not isinstance(a, dict):
        raise ApplyError("invalid_tx", "unknown_account", {"account_id": account_id})
    if a.get("banned") is True:
        raise ApplyError("forbidden", "account_banned", {"account_id": account_id})
    if a.get("locked") is True:
        raise ApplyError("forbidden", "account_locked", {"account_id": account_id})
    return a


def _mk_key_id(pubkey: str) -> str:
    # Stable, deterministic key id for by_id mapping
    h = hashlib.sha256(pubkey.encode("utf-8")).hexdigest()
    return f"k:{h[:16]}"


def _current_height(state: Json) -> int:
    return _as_int(state.get("height") or state.get("block_height"), 0)


def _key_record_from_payload_or_raise(state: Json, payload: Json, *, key_type: str) -> Json:
    # Account key records must be schedule-independent. Block height may differ
    # across equivalent replay chunking/restart schedules, so do not bake the
    # current height into the key record itself.
    rec = account_key_record_from_payload(
        payload,
        created_height=0,
        default_profile=default_signature_profile_for_mode(),
        key_type=key_type,
    )
    chain_config = state.get("chain_config") if isinstance(state.get("chain_config"), dict) else None
    ok, reason = validate_account_key_record(rec, chain_config=chain_config, require_verifier=False)
    if not ok:
        raise ApplyError("invalid_tx", reason, {"sig_profile": rec.get("sig_profile")})
    return rec




def _validate_evidence_kem_pubkey(value: Any, *, required: bool = False) -> str | None:
    raw = _as_str(value).strip()
    if not raw:
        if required:
            raise ApplyError("invalid_tx", "missing_evidence_kem_pubkey", {})
        return None
    try:
        decoded = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ApplyError("invalid_tx", "invalid_evidence_kem_pubkey_base64", {}) from exc
    # FIPS 203 ML-KEM-768 public key length. The algorithm identifier is pinned
    # separately so future migrations cannot reinterpret this byte string.
    if len(decoded) != 1184:
        raise ApplyError(
            "invalid_tx",
            "invalid_evidence_kem_pubkey_length",
            {"expected": 1184, "actual": len(decoded)},
        )
    return raw

def _mk_device_id_hash(device_id: str) -> str:
    h = hashlib.sha256(device_id.encode("utf-8")).hexdigest()
    return f"d:{h[:16]}"


def _reject_non_public_protocol_payload(env: TxEnvelope) -> None:
    violation = public_protocol_policy_violation(env)
    if violation is not None:
        raise ApplyError(violation.code, violation.reason, violation.details)


def _extract_active_pubkeys(acct: Json) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def _add(pk: Any) -> None:
        if not isinstance(pk, str):
            return
        p = pk.strip()
        if not p or p in seen:
            return
        seen.add(p)
        out.append(p)

    keys = acct.get("keys")

    # Canonical by_id wins when present because it carries revocation state.
    if isinstance(keys, dict):
        by_id = keys.get("by_id")
        if isinstance(by_id, dict):
            for rec in by_id.values():
                if not isinstance(rec, dict):
                    continue
                if bool(rec.get("revoked", False)):
                    continue
                _add(account_key_pubkey(rec))
            out.sort()
            return out

    if isinstance(keys, list):
        for item in keys:
            if isinstance(item, str):
                _add(item)
                continue
            if not isinstance(item, dict):
                continue
            if item.get("active", True) is False:
                continue
            _add(account_key_pubkey(item))
        out.sort()
        return out

    if isinstance(keys, dict):
        for pk, rec in keys.items():
            if not isinstance(pk, str):
                continue
            if isinstance(rec, dict):
                if bool(rec.get("active", False)) and not bool(rec.get("revoked", False)):
                    _add(pk)
            elif bool(rec):
                _add(pk)
        if out:
            out.sort()
            return out

    # Legacy mirrors are only consulted when canonical keys are absent.
    _add(acct.get("pubkey"))

    pubkeys = acct.get("pubkeys")
    if isinstance(pubkeys, list):
        for pk in pubkeys:
            _add(pk)

    active_keys = acct.get("active_keys")
    if isinstance(active_keys, list):
        for pk in active_keys:
            _add(pk)

    out.sort()
    return out


def _sync_account_key_views(a: Json) -> None:
    active = _extract_active_pubkeys(a)
    a["active_keys"] = list(active)
    a["pubkeys"] = list(active)
    a["pubkey"] = active[0] if active else ""


def _apply_account_register(state: Json, env: TxEnvelope) -> Json:
    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})

    signer = _as_str(env.signer)
    if not signer:
        raise ApplyError("invalid_tx", "missing_signer", {})

    if signer in accounts:
        raise ApplyError("invalid_tx", "account_exists", {"account_id": signer})

    p = _payload(env)
    key_record = _key_record_from_payload_or_raise(state, p, key_type="main")
    pubkey = account_key_pubkey(key_record)
    if not pubkey:
        raise ApplyError("invalid_tx", "missing_pubkey", {})

    recovery_pubkey = _as_str(p.get("recovery_pubkey") or "").strip()
    recovery_key: Json | None = None
    if recovery_pubkey:
        recovery_key = _key_record_from_payload_or_raise(
            state,
            {
                "pubkey": recovery_pubkey,
                "sig_profile": p.get("recovery_sig_profile")
                or default_signature_profile_for_mode(),
            },
            key_type="recovery",
        )
        if account_key_pubkey(recovery_key) == pubkey:
            raise ApplyError("invalid_tx", "recovery_key_must_be_independent", {})

    evidence_kem_pubkey = _validate_evidence_kem_pubkey(p.get("evidence_kem_pubkey"))
    evidence_kem_algorithm = _as_str(p.get("evidence_kem_algorithm") or "ml-kem-768").lower()
    if evidence_kem_pubkey and evidence_kem_algorithm != "ml-kem-768":
        raise ApplyError("invalid_tx", "unsupported_evidence_kem_algorithm", {"algorithm": evidence_kem_algorithm})
    params = state.get("params") if isinstance(state.get("params"), dict) else {}
    if bool(params.get("require_recovery_key_at_account_register")) and recovery_key is None:
        raise ApplyError("invalid_tx", "recovery_key_required_at_account_register", {})
    if bool(params.get("require_evidence_kem_at_account_register")) and not evidence_kem_pubkey:
        raise ApplyError("invalid_tx", "evidence_kem_key_required_at_account_register", {})

    # New accounts start as Tier 0. Tier 1 must be earned through the bounded
    # native asynchronous verification path and cannot be bypassed by registering
    # a fresh account.
    offline_key: Json | None = None
    generation = 0
    if recovery_key is not None:
        generation = 1
        offline_key = {
            "pubkey": account_key_pubkey(recovery_key),
            "sig_profile": recovery_key.get("sig_profile"),
            "key_id": recovery_key.get("key_id")
            or _mk_key_id(account_key_pubkey(recovery_key)),
            "commitment": _as_str(p.get("recovery_key_commitment") or "").strip() or None,
            "generation": generation,
            "registered_height": _current_height(state),
            "registered_via": "account_register",
        }

    accounts[signer] = {
        "nonce": _as_int(getattr(env, "nonce", 0), 0),
        "account_type": "human",
        "poh_tier": 0,
        "banned": False,
        "locked": False,
        "reputation": "0",
        "keys": {
            "by_id": {
                str(key_record.get("key_id") or _mk_key_id(pubkey)): key_record
            }
        },
        "devices": {"by_id": {}},
        "recovery": {
            "mode": "offline_key" if offline_key else None,
            "config": None,
            "offline_key": offline_key,
            "prior_offline_keys": [],
            "proposals": {},
            "requests": {},
            "authority_generation": generation,
            "failed_attempt_heights": [],
            "history": [],
        },
        "evidence_encryption": {
            "algorithm": evidence_kem_algorithm if evidence_kem_pubkey else None,
            "public_key": evidence_kem_pubkey,
            "registered_height": _current_height(state) if evidence_kem_pubkey else None,
        },
        # Session secrets remain browser-local. Consensus stores only public
        # session records and revocation state.
        "session_keys": {},
    }
    _sync_account_key_views(accounts[signer])
    return state


def _apply_account_key_add(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    _expect_nonce(a, env)
    p = _payload(env)

    key_type = _as_str(p.get("key_type") or "secondary").strip().lower()
    key_record = _key_record_from_payload_or_raise(state, p, key_type=key_type)
    pubkey = account_key_pubkey(key_record)
    if not pubkey:
        raise ApplyError("invalid_tx", "missing_pubkey", {})

    keys = a.get("keys")
    if not isinstance(keys, dict):
        keys = {}
        a["keys"] = keys
    by_id = keys.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        keys["by_id"] = by_id

    kid = _mk_key_id(pubkey)
    if kid in by_id and isinstance(by_id.get(kid), dict) and by_id[kid].get("revoked") is not True:
        raise ApplyError("invalid_tx", "key_exists", {"pubkey": pubkey})

    key_record["key_id"] = str(key_record.get("key_id") or kid)
    by_id[kid] = key_record
    a["nonce"] = _as_int(a.get("nonce"), 0) + 1
    _sync_account_key_views(a)
    return state


def _apply_account_key_revoke(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    _expect_nonce(a, env)
    p = _payload(env)

    pubkey = _as_str(p.get("pubkey") or "").strip()
    if not pubkey:
        raise ApplyError("invalid_tx", "missing_pubkey", {})

    keys = a.get("keys")
    if not isinstance(keys, dict) or not isinstance(keys.get("by_id"), dict):
        raise ApplyError("invalid_state", "keys_not_configured", {})

    by_id = keys["by_id"]
    match_kid: str | None = None
    for kid, rec in by_id.items():
        if not isinstance(rec, dict):
            continue
        if account_key_pubkey(rec) == pubkey and rec.get("revoked") is not True:
            match_kid = kid
            break

    if not match_kid:
        raise ApplyError("invalid_tx", "unknown_key", {"pubkey": pubkey})

    by_id[match_kid]["revoked"] = True
    by_id[match_kid]["revoked_at"] = _as_int(state.get("height"), 0)
    a["nonce"] = _as_int(a.get("nonce"), 0) + 1
    _sync_account_key_views(a)
    return state


def _apply_account_device_register(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    device_id = _as_str(p.get("device_id") or "").strip()
    device_type = _as_str(p.get("device_type") or "").strip().lower()
    label = _as_str(p.get("label") or "").strip()
    pubkey = _as_str(p.get("pubkey") or "").strip()

    if not device_id:
        raise ApplyError("invalid_tx", "missing_device_id", {})
    if not device_type:
        # Back-compat: tests and older clients may omit device_type.
        # Infer "node" from conventional identifiers; otherwise default.
        if device_id.startswith("node:") or label.lower().startswith("node"):
            device_type = "node"
        else:
            device_type = "generic"
    if not pubkey:
        raise ApplyError("invalid_tx", "missing_pubkey", {"device_id": device_id})

    devices = a.get("devices")
    if not isinstance(devices, dict):
        devices = {}
        a["devices"] = devices
    by_id = devices.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        devices["by_id"] = by_id

    if (
        device_id in by_id
        and isinstance(by_id.get(device_id), dict)
        and by_id[device_id].get("revoked") is not True
    ):
        raise ApplyError("invalid_tx", "device_exists", {"device_id": device_id})

    # Enforce one node device per account (used to gate peer hello identity).
    if device_type == "node":
        for _did, _rec in by_id.items():
            if _did == device_id:
                continue
            if not isinstance(_rec, dict):
                continue
            if _rec.get("revoked") is True:
                continue
            if _as_str(_rec.get("device_type") or "").strip().lower() == "node":
                # IMPORTANT: tests assert this reason string is visible.
                raise ApplyError(
                    "forbidden", "one_node_per_account", {"device_id": device_id, "existing": _did}
                )

    by_id[device_id] = {
        "device_id": device_id,
        "device_type": device_type,
        "label": label or None,
        "pubkey": pubkey,
        "revoked": False,
        "revoked_at": None,
        "device_id_hash": _mk_device_id_hash(device_id),
    }

    a["nonce"] = exp
    return state


def _apply_account_device_revoke(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    device_id = _as_str(p.get("device_id") or "").strip()
    if not device_id:
        raise ApplyError("invalid_tx", "missing_device_id", {})

    devices = a.get("devices")
    if not isinstance(devices, dict) or not isinstance(devices.get("by_id"), dict):
        raise ApplyError("invalid_tx", "no_devices", {})

    by_id = devices["by_id"]
    rec = by_id.get(device_id)
    if not isinstance(rec, dict) or rec.get("revoked") is True:
        raise ApplyError("invalid_tx", "unknown_device", {"device_id": device_id})

    rec["revoked"] = True
    rec["revoked_at"] = _as_int(state.get("height"), 0)

    a["nonce"] = exp
    return state


# --------------------------------------------------------------------
# Added: session key issue/revoke (required by API private endpoint gates)
# --------------------------------------------------------------------
def _apply_account_session_key_issue(state: Json, env: TxEnvelope) -> Json:
    """Issue or refresh an on-chain session key.

    Accepted payload shapes:
      - {"session_key": "...", "ttl_s": 3600}
      - {"session_pubkey": "...", "expires_ts_ms": 1700000000000}
      - legacy alias: {"session": "..."}
    """
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    sk = _as_str(p.get("session_key") or p.get("session_pubkey") or p.get("session") or "").strip()
    if not sk:
        raise ApplyError("invalid_tx", "missing_session_key", {})

    ttl_s = _as_int(p.get("ttl_s"), 0)
    if ttl_s <= 0:
        # Derive TTL from expires_ts_ms if provided and chain time exists.
        try:
            ex_ms = int(p.get("expires_ts_ms") or 0)
        except Exception:
            ex_ms = 0
        now_s = _as_int(state.get("time"), 0)
        now_ms = now_s * 1000
        if ex_ms > 0 and now_ms > 0:
            ttl_s = max(0, int((ex_ms - now_ms) // 1000))

    ttl_s = max(0, int(ttl_s))

    sessions = a.get("session_keys")
    if not isinstance(sessions, dict):
        sessions = {}
        a["session_keys"] = sessions

    issued_at_ts = _as_int(state.get("time"), 0)
    if issued_at_ts < 0:
        issued_at_ts = 0

    store_session_record(
        sessions,
        sk,
        {
            "active": True,
            "issued_at_ts": issued_at_ts,
            "ttl_s": ttl_s,
            "issued_at_height": _as_int(state.get("height"), 0),
        },
    )

    a["nonce"] = exp
    return state


def _apply_account_session_key_revoke(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    sk = _as_str(p.get("session_key") or p.get("session_pubkey") or p.get("session") or "").strip()
    if not sk:
        raise ApplyError("invalid_tx", "missing_session_key", {})

    sessions = a.get("session_keys")
    if not isinstance(sessions, dict):
        raise ApplyError("invalid_tx", "no_session_keys", {})

    rec = revoke_session_record(sessions, sk)
    if not isinstance(rec, dict):
        raise ApplyError("invalid_tx", "unknown_session_key", {"session_key_hash": "unmatched"})

    rec["active"] = False
    rec["revoked_at_height"] = _as_int(state.get("height"), 0)
    rec["revoked_at_ts"] = _as_int(state.get("time"), 0)

    a["nonce"] = exp
    return state


def _apply_account_lock(state: Json, env: TxEnvelope) -> Json:
    # System tx: lock a target account.
    p = _payload(env)
    target = _as_str(p.get("target") or "").strip()
    if not target:
        raise ApplyError("invalid_tx", "missing_target", {})

    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})

    a = accounts.get(target)
    if not isinstance(a, dict):
        # Autocreate for MVP? Keep consistent with existing tests.
        accounts[target] = {
            "nonce": 0,
            "poh_tier": 0,
            "banned": False,
            "locked": False,
            "reputation": "0",
        }
        a = accounts[target]

    exp = _expect_nonce(a, env)

    a["locked"] = True
    a["nonce"] = exp
    return state


def _apply_account_unlock(state: Json, env: TxEnvelope) -> Json:
    p = _payload(env)
    target = _as_str(p.get("target") or "").strip()
    if not target:
        raise ApplyError("invalid_tx", "missing_target", {})

    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})

    a = accounts.get(target)
    if not isinstance(a, dict):
        raise ApplyError("invalid_tx", "unknown_account", {"account_id": target})

    exp = _expect_nonce(a, env)
    a["locked"] = False
    a["nonce"] = exp
    return state


def _apply_account_ban(state: Json, env: TxEnvelope) -> Json:
    p = _payload(env)
    target = _as_str(p.get("target") or "").strip()
    if not target:
        raise ApplyError("invalid_tx", "missing_target", {})

    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})

    a = accounts.get(target)
    if not isinstance(a, dict):
        raise ApplyError("invalid_tx", "unknown_account", {"account_id": target})

    exp = _expect_nonce(a, env)
    a["banned"] = True
    a["nonce"] = exp
    return state


def _apply_account_unban(state: Json, env: TxEnvelope) -> Json:
    p = _payload(env)
    target = _as_str(p.get("target") or "").strip()
    if not target:
        raise ApplyError("invalid_tx", "missing_target", {})

    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})

    a = accounts.get(target)
    if not isinstance(a, dict):
        raise ApplyError("invalid_tx", "unknown_account", {"account_id": target})

    exp = _expect_nonce(a, env)
    a["banned"] = False
    a["nonce"] = exp
    return state




def _normalized_guardians(a: Json) -> tuple[Json, list[str], int]:
    recovery = a.get("recovery")
    if not isinstance(recovery, dict):
        recovery = {}
        a["recovery"] = recovery

    cfg = recovery.get("config")
    if not isinstance(cfg, dict):
        cfg = {}
        recovery["config"] = cfg

    raw_guardians = cfg.get("guardians")
    guardians: list[str] = []
    if isinstance(raw_guardians, list):
        for g in raw_guardians:
            gs = _as_str(g).strip()
            if gs and gs not in guardians:
                guardians.append(gs)

    threshold = _as_int(cfg.get("threshold"), 0)
    if guardians and threshold <= 0:
        threshold = min(1, len(guardians))
    if guardians and threshold > len(guardians):
        threshold = len(guardians)

    cfg["guardians"] = guardians
    cfg["threshold"] = threshold
    return recovery, guardians, threshold


def _iter_recovery_requests(state: Json):
    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})
    for account_id, acct in accounts.items():
        if not isinstance(acct, dict):
            continue
        recovery = acct.get("recovery")
        if not isinstance(recovery, dict):
            continue
        requests = recovery.get("requests")
        if not isinstance(requests, dict):
            continue
        yield account_id, acct, recovery, requests


def _find_recovery_request(state: Json, request_id: str) -> tuple[str, Json, Json, Json]:
    for account_id, acct, recovery, requests in _iter_recovery_requests(state):
        req = requests.get(request_id)
        if isinstance(req, dict):
            return account_id, acct, recovery, req
    raise ApplyError("invalid_tx", "unknown_request", {"request_id": request_id})


def _apply_account_security_policy_set(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    raw_policy = p.get("policy")
    current_policy = a.get("security_policy") if isinstance(a.get("security_policy"), dict) else {}
    if isinstance(raw_policy, dict):
        policy = {**dict(current_policy), **dict(raw_policy)}
    else:
        policy = dict(current_policy)

    for key in ("lock_on_recovery_request", "require_guardian_threshold_for_unlock"):
        if key in p and p.get(key) is not None:
            policy[key] = bool(p.get(key))
    if p.get("session_ttl_s") is not None:
        policy["session_ttl_s"] = _as_int(p.get("session_ttl_s"), 0)
    evidence_kem_pubkey = _validate_evidence_kem_pubkey(p.get("evidence_kem_pubkey"), required=False)
    if evidence_kem_pubkey:
        algorithm = _as_str(p.get("evidence_kem_algorithm") or "ml-kem-768").strip().lower()
        if algorithm != "ml-kem-768":
            raise ApplyError("invalid_tx", "unsupported_evidence_kem_algorithm", {"algorithm": algorithm})
        a["evidence_encryption"] = {
            "algorithm": algorithm,
            "public_key": evidence_kem_pubkey,
            "updated_height": _current_height(state),
        }
    _reject_non_public_protocol_payload(env)

    a["security_policy"] = policy
    a["nonce"] = exp
    return state


def _apply_account_guardian_add(state: Json, env: TxEnvelope) -> Json:
    _require_guardian_recovery_admission(state)
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    guardian_id = _as_str(p.get("guardian_id") or "").strip()
    if not guardian_id:
        raise ApplyError("invalid_tx", "missing_guardian_id", {})
    if guardian_id == _as_str(env.signer).strip():
        raise ApplyError("invalid_tx", "guardian_self_reference", {})

    recovery, guardians, threshold = _normalized_guardians(a)
    if guardian_id in guardians:
        raise ApplyError("invalid_tx", "guardian_exists", {"guardian_id": guardian_id})
    guardians.append(guardian_id)
    recovery["config"] = {"guardians": guardians, "threshold": max(1, threshold)}

    a["nonce"] = exp
    return state


def _apply_account_guardian_remove(state: Json, env: TxEnvelope) -> Json:
    _require_guardian_recovery_admission(state)
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    guardian_id = _as_str(p.get("guardian_id") or "").strip()
    if not guardian_id:
        raise ApplyError("invalid_tx", "missing_guardian_id", {})

    recovery, guardians, threshold = _normalized_guardians(a)
    if guardian_id not in guardians:
        raise ApplyError("invalid_tx", "unknown_guardian", {"guardian_id": guardian_id})
    guardians = [g for g in guardians if g != guardian_id]
    if guardians:
        threshold = min(max(1, threshold), len(guardians))
        recovery["config"] = {"guardians": guardians, "threshold": threshold}
    else:
        recovery["config"] = None

    a["nonce"] = exp
    return state



def _all_account_pubkeys(account: Json) -> set[str]:
    """Return every authority key ever recorded for the account.

    Recovery must never reactivate a previously revoked or compromised key.  A
    fresh replacement key is therefore compared with the complete key history,
    not only the currently active view.
    """

    out: set[str] = set()
    keys = account.get("keys")
    by_id = keys.get("by_id") if isinstance(keys, dict) else None
    if isinstance(by_id, dict):
        for record in by_id.values():
            if not isinstance(record, dict):
                continue
            pubkey = _as_str(account_key_pubkey(record)).strip()
            if pubkey:
                out.add(pubkey)
    for field in ("pubkey",):
        pubkey = _as_str(account.get(field)).strip()
        if pubkey:
            out.add(pubkey)
    for field in ("pubkeys", "active_keys"):
        values = account.get(field)
        if isinstance(values, list):
            out.update(_as_str(value).strip() for value in values if _as_str(value).strip())
    return out


def _recovery_key_history(recovery: Json) -> set[str]:
    out: set[str] = set()
    current = recovery.get("offline_key")
    if isinstance(current, dict):
        pubkey = _as_str(current.get("pubkey")).strip()
        if pubkey:
            out.add(pubkey)
    prior = recovery.get("prior_offline_keys")
    if isinstance(prior, list):
        for record in prior:
            if isinstance(record, dict):
                pubkey = _as_str(record.get("pubkey")).strip()
                if pubkey:
                    out.add(pubkey)
    return out


def _validate_independent_recovery_key(
    state: Json,
    account: Json,
    payload: Json,
    *,
    proposed_active_pubkey: str = "",
    require_fresh: bool = False,
) -> Json:
    record = _key_record_from_payload_or_raise(state, payload, key_type="recovery")
    pubkey = _as_str(account_key_pubkey(record)).strip()
    if not pubkey:
        raise ApplyError("invalid_tx", "missing_recovery_pubkey", {})
    if proposed_active_pubkey and pubkey == _as_str(proposed_active_pubkey).strip():
        raise ApplyError("invalid_tx", "recovery_key_must_be_independent", {})
    if pubkey in _all_account_pubkeys(account):
        raise ApplyError("invalid_tx", "recovery_key_must_be_independent", {})
    recovery = account.get("recovery") if isinstance(account.get("recovery"), dict) else {}
    if require_fresh and pubkey in _recovery_key_history(recovery):
        raise ApplyError("invalid_tx", "recovery_key_must_be_fresh", {})
    return record


def _require_fresh_recovered_authority(account: Json, pubkey: str) -> None:
    candidate = _as_str(pubkey).strip()
    if not candidate:
        raise ApplyError("invalid_tx", "missing_new_pubkey", {})
    if candidate in _all_account_pubkeys(account) or candidate in _recovery_key_history(
        account.get("recovery") if isinstance(account.get("recovery"), dict) else {}
    ):
        raise ApplyError("invalid_tx", "recovered_authority_key_must_be_fresh", {})


def _append_failed_recovery_attempt(recovery: Json, *, height: int, request_id: str, reason: str) -> None:
    window_start = int(height) - RECOVERY_FAILED_WINDOW_BLOCKS
    failed = []
    for raw in recovery.get("failed_attempts", []):
        if not isinstance(raw, dict):
            continue
        if _as_int(raw.get("height"), -1) >= window_start:
            failed.append(dict(raw))
    if not any(_as_str(item.get("request_id")) == request_id for item in failed):
        failed.append({"height": int(height), "request_id": request_id, "reason": reason})
    recovery["failed_attempts"] = failed
    recovery["failed_attempt_heights"] = [_as_int(item.get("height"), 0) for item in failed]


def _canonical_continuity_class_id(raw: Any) -> str:
    class_id = _as_str(raw).strip().lower().replace("-", "_").replace(" ", "_")
    canonical = CONTINUITY_EVIDENCE_CLASS_ALIASES.get(class_id)
    if not canonical:
        raise ApplyError(
            "invalid_tx",
            "unknown_continuity_evidence_class",
            {"class_id": class_id},
        )
    return canonical


def _recovery_evidence_summary(payload: Json) -> tuple[list[Json], str, bool]:
    raw_classes = payload.get("evidence_class_commitments")
    if not isinstance(raw_classes, list):
        raw_classes = []
    classes: list[Json] = []
    seen: set[str] = set()
    social_required = False
    for raw in raw_classes:
        if not isinstance(raw, dict):
            raise ApplyError("invalid_tx", "invalid_continuity_evidence_class", {})
        class_id = _canonical_continuity_class_id(raw.get("class_id") or raw.get("kind") or "")
        commitment = _as_str(raw.get("commitment") or "").strip()
        if not commitment:
            raise ApplyError(
                "invalid_tx",
                "continuity_evidence_class_commitment_required",
                {"class_id": class_id},
            )
        if class_id in seen:
            raise ApplyError("invalid_tx", "duplicate_continuity_evidence_class", {"class_id": class_id})
        seen.add(class_id)
        classes.append({"class_id": class_id, "commitment": commitment})
        social_required = social_required or class_id == "social_continuity_attestations"

    strong_anchor = _as_str(payload.get("strong_anchor_commitment") or "").strip()
    if len(classes) < 2:
        raise ApplyError("invalid_tx", "insufficient_continuity_evidence_classes", {})
    if not strong_anchor or not any(
        item["class_id"] in CONTINUITY_STRONG_ANCHOR_CLASSES for item in classes
    ):
        raise ApplyError("invalid_tx", "continuity_strong_anchor_required", {})
    return classes, strong_anchor, social_required


def _register_recovery_encrypted_evidence(
    state: Json,
    *,
    request_id: str,
    target: str,
    payload: Json,
    height: int,
    declared_class_ids: set[str],
) -> list[str]:
    raw_items = payload.get("recovery_evidence")
    if not isinstance(raw_items, list) or not raw_items:
        raise ApplyError("invalid_tx", "encrypted_recovery_evidence_required", {})
    evidence_ids: list[str] = []
    classes: set[str] = set()
    strong_anchor_present = False
    for raw in raw_items:
        if not isinstance(raw, dict):
            raise ApplyError("invalid_tx", "invalid_recovery_evidence_item", {})
        evidence_id = _as_str(raw.get("evidence_id") or "").strip()
        class_id = _canonical_continuity_class_id(raw.get("class_id") or "")
        ciphertext_cid = _as_str(raw.get("ciphertext_cid") or "").strip()
        ciphertext_commitment = _as_str(raw.get("ciphertext_commitment") or "").strip()
        context_commitment = _as_str(raw.get("encryption_context_commitment") or "").strip()
        providers = raw.get("provider_ids")
        if not evidence_id or not class_id or not ciphertext_cid:
            raise ApplyError("invalid_tx", "invalid_recovery_evidence_item", {"evidence_id": evidence_id})
        if evidence_id in evidence_ids:
            raise ApplyError("invalid_tx", "duplicate_recovery_evidence_id", {"evidence_id": evidence_id})
        if not ciphertext_commitment or not context_commitment:
            raise ApplyError("invalid_tx", "recovery_evidence_commitments_required", {"evidence_id": evidence_id})
        if not isinstance(providers, list) or not [value for value in providers if _as_str(value).strip()]:
            raise ApplyError("invalid_tx", "recovery_evidence_providers_required", {"evidence_id": evidence_id})
        if raw.get("cid") or raw.get("uri") or raw.get("video_cid"):
            raise ApplyError("invalid_tx", "plaintext_poh_evidence_forbidden", {"evidence_id": evidence_id})
        try:
            register_encrypted_evidence(
                state,
                case_id=f"account-recovery:{request_id}",
                evidence_id=evidence_id,
                subject_id=target,
                ciphertext_cid=ciphertext_cid,
                ciphertext_commitment=ciphertext_commitment,
                encryption_context_commitment=context_commitment,
                provider_ids=[_as_str(value).strip() for value in providers if _as_str(value).strip()],
                declared_height=height,
            )
        except ValueError as exc:
            raise ApplyError("invalid_tx", str(exc), {"evidence_id": evidence_id}) from exc
        evidence_ids.append(evidence_id)
        classes.add(class_id)
        strong_anchor_present = strong_anchor_present or (
            class_id in CONTINUITY_STRONG_ANCHOR_CLASSES and bool(raw.get("strong_anchor"))
        )
    if classes != declared_class_ids:
        raise ApplyError(
            "invalid_tx",
            "recovery_evidence_class_set_mismatch",
            {"declared": sorted(declared_class_ids), "encrypted": sorted(classes)},
        )
    if not strong_anchor_present:
        raise ApplyError("invalid_tx", "continuity_strong_anchor_evidence_required", {})
    return evidence_ids


def _prior_recovery_reviewer_ids(recovery: Json) -> set[str]:
    out: set[str] = set()
    for entry in recovery.get("history", []):
        if not isinstance(entry, dict):
            continue
        for reviewer in entry.get("reviewer_ids", []):
            reviewer_id = _as_str(reviewer).strip()
            if reviewer_id:
                out.add(reviewer_id)
    return out


def _revoke_account_authority(account: Json, *, height: int, reason: str) -> tuple[list[str], list[str], int]:
    keys = account.get("keys")
    if not isinstance(keys, dict):
        keys = {}
        account["keys"] = keys
    by_id = keys.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        keys["by_id"] = by_id
    revoked_key_ids: list[str] = []
    for key_id in sorted(str(key) for key in by_id.keys()):
        record = by_id.get(key_id)
        if not isinstance(record, dict) or record.get("revoked") is True:
            continue
        record["revoked"] = True
        record["revoked_at"] = int(height)
        record["revocation_reason"] = reason
        revoked_key_ids.append(key_id)

    revoked_devices: list[str] = []
    devices = account.get("devices")
    device_map = devices.get("by_id") if isinstance(devices, dict) else None
    if isinstance(device_map, dict):
        for device_id in sorted(str(key) for key in device_map.keys()):
            record = device_map.get(device_id)
            if not isinstance(record, dict) or record.get("revoked") is True:
                continue
            record["revoked"] = True
            record["revoked_at"] = int(height)
            record["revocation_reason"] = reason
            revoked_devices.append(device_id)

    revoked_sessions = 0
    sessions = account.get("session_keys")
    if isinstance(sessions, dict):
        for record in sessions.values():
            if not isinstance(record, dict) or record.get("active") is False:
                continue
            record["active"] = False
            record["revoked_at_height"] = int(height)
            record["revocation_reason"] = reason
            revoked_sessions += 1
    return revoked_key_ids, revoked_devices, revoked_sessions


def _install_recovered_authority(
    state: Json,
    account: Json,
    recovery: Json,
    request: Json,
    *,
    height: int,
) -> tuple[int, str, list[str], list[str], int]:
    generation = _as_int(recovery.get("authority_generation"), 0)
    new_key = _key_record_from_payload_or_raise(
        state,
        {"pubkey": request.get("new_pubkey"), "sig_profile": request.get("new_sig_profile")},
        key_type="recovered",
    )
    new_pubkey = _as_str(account_key_pubkey(new_key)).strip()
    _require_fresh_recovered_authority(account, new_pubkey)
    new_recovery_key = _validate_independent_recovery_key(
        state,
        account,
        {
            "pubkey": request.get("new_recovery_pubkey"),
            "sig_profile": request.get("new_recovery_sig_profile"),
        },
        proposed_active_pubkey=new_pubkey,
        require_fresh=True,
    )
    revoked_key_ids, revoked_devices, revoked_sessions = _revoke_account_authority(
        account,
        height=height,
        reason="account_recovery_authority_replacement",
    )
    keys = account.setdefault("keys", {})
    by_id = keys.setdefault("by_id", {})
    new_key_id = str(new_key.get("key_id") or _mk_key_id(new_pubkey))
    next_generation = generation + 1
    new_key["key_id"] = new_key_id
    new_key["authority_generation"] = next_generation
    by_id[new_key_id] = new_key

    old_offline = recovery.get("offline_key")
    if isinstance(old_offline, dict) and _as_str(old_offline.get("pubkey")).strip():
        prior = recovery.setdefault("prior_offline_keys", [])
        if isinstance(prior, list):
            archived = dict(old_offline)
            archived["retired_height"] = int(height)
            archived["retired_by_request"] = _as_str(request.get("request_id"))
            prior.append(archived)

    recovery["mode"] = "offline_key"
    recovery["authority_generation"] = next_generation
    recovery["offline_key"] = {
        "pubkey": account_key_pubkey(new_recovery_key),
        "sig_profile": new_recovery_key.get("sig_profile"),
        "key_id": new_recovery_key.get("key_id") or _mk_key_id(account_key_pubkey(new_recovery_key)),
        "commitment": request.get("new_recovery_key_commitment"),
        "generation": next_generation,
        "registered_height": int(height),
    }
    return next_generation, new_key_id, revoked_key_ids, revoked_devices, revoked_sessions

def _apply_account_recovery_config_set(state: Json, env: TxEnvelope) -> Json:
    account = _require_not_banned_or_locked(state, env.signer)
    expected_nonce = _expect_nonce(account, env)
    payload = _payload(env)

    recovery_pubkey = _as_str(payload.get("recovery_pubkey") or "").strip()
    recovery_key_commitment = _as_str(payload.get("recovery_key_commitment") or "").strip()
    recovery_sig_profile = _as_str(
        payload.get("recovery_sig_profile") or default_signature_profile_for_mode()
    ).strip()

    recovery = account.get("recovery")
    if not isinstance(recovery, dict):
        recovery = {}
        account["recovery"] = recovery

    if recovery_pubkey:
        candidate = _validate_independent_recovery_key(
            state,
            account,
            {"pubkey": recovery_pubkey, "sig_profile": recovery_sig_profile},
            require_fresh=True,
        )
        current = recovery.get("offline_key")
        current_generation = _as_int(recovery.get("authority_generation"), 0)
        if isinstance(current, dict) and _as_str(current.get("pubkey")).strip():
            if _as_str(payload.get("authorization")).strip().lower() != "offline_key":
                raise ApplyError("forbidden", "recovery_rotation_requires_offline_key", {})
            supplied_generation = _as_int(payload.get("current_recovery_generation"), -1)
            expected_generation = _as_int(current.get("generation"), current_generation)
            if supplied_generation != expected_generation:
                raise ApplyError(
                    "invalid_tx",
                    "recovery_generation_mismatch",
                    {"want": expected_generation, "got": supplied_generation},
                )
            prior = recovery.setdefault("prior_offline_keys", [])
            if isinstance(prior, list):
                archived = dict(current)
                archived["retired_height"] = _current_height(state)
                archived["retired_reason"] = "authorized_rotation"
                prior.append(archived)
        elif current_generation not in {0}:
            raise ApplyError("invalid_state", "missing_current_recovery_key", {})

        generation = current_generation + 1
        recovery["mode"] = "offline_key"
        recovery["config"] = None
        recovery["offline_key"] = {
            "pubkey": account_key_pubkey(candidate),
            "sig_profile": candidate.get("sig_profile"),
            "key_id": candidate.get("key_id") or _mk_key_id(account_key_pubkey(candidate)),
            "commitment": recovery_key_commitment or None,
            "generation": generation,
            "registered_height": _current_height(state),
        }
        recovery["authority_generation"] = generation
        recovery.setdefault("prior_offline_keys", [])
        recovery.setdefault("failed_attempt_heights", [])
        recovery.setdefault("failed_attempts", [])
        account["nonce"] = expected_nonce
        return state

    _require_guardian_recovery_admission(state)
    raw_config = payload.get("config")
    if not isinstance(raw_config, dict):
        raw_config = {"guardians": payload.get("guardians"), "threshold": payload.get("threshold")}
    guardians = raw_config.get("guardians")
    threshold = raw_config.get("threshold")
    if not isinstance(guardians, list) or not guardians:
        raise ApplyError("invalid_tx", "invalid_guardians", {})
    guardians_norm: list[str] = []
    for guardian in guardians:
        guardian_id = _as_str(guardian).strip()
        if guardian_id and guardian_id not in guardians_norm:
            guardians_norm.append(guardian_id)
    threshold_int = _as_int(threshold, 0)
    if not guardians_norm or threshold_int <= 0 or threshold_int > len(guardians_norm):
        raise ApplyError("invalid_tx", "invalid_guardian_configuration", {})
    recovery["mode"] = "legacy_guardian"
    recovery["config"] = {"guardians": guardians_norm, "threshold": threshold_int}
    account["nonce"] = expected_nonce
    return state

def _apply_account_recovery_propose(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    proposal_id = _as_str(p.get("proposal_id") or "").strip()
    new_pubkey = _as_str(p.get("new_pubkey") or "").strip()
    if not proposal_id:
        raise ApplyError("invalid_tx", "missing_proposal_id", {})
    if not new_pubkey:
        raise ApplyError("invalid_tx", "missing_new_pubkey", {})

    recovery = a.get("recovery")
    if not isinstance(recovery, dict) or not isinstance(recovery.get("config"), dict):
        raise ApplyError("invalid_tx", "recovery_not_configured", {})

    proposals = recovery.get("proposals")
    if not isinstance(proposals, dict):
        proposals = {}
        recovery["proposals"] = proposals

    if proposal_id in proposals:
        raise ApplyError("invalid_tx", "proposal_exists", {"proposal_id": proposal_id})

    proposals[proposal_id] = {
        "new_pubkey": new_pubkey,
        "approvals": [],
        "executed": False,
    }

    a["nonce"] = exp
    return state


def _apply_account_recovery_evidence_bind(state: Json, env: TxEnvelope) -> Json:
    payload = _payload(env)
    request_id = _as_str(payload.get("request_id") or "").strip()
    evidence_id = _as_str(payload.get("evidence_id") or "").strip()
    if not request_id or not evidence_id:
        raise ApplyError("invalid_tx", "missing_recovery_evidence_bind_fields", {})
    account_id, account, _recovery, request = _find_recovery_request(state, request_id)
    if _as_str(env.signer).strip() != account_id:
        raise ApplyError("forbidden", "recovery_target_must_sign", {"target": account_id})
    method = _as_str(request.get("method") or "").strip().lower()
    if method not in {"continuity", "reversal"}:
        raise ApplyError("invalid_tx", "recovery_evidence_bind_not_applicable", {"method": method})
    if _as_str(request.get("status") or "").strip().lower() not in {"assigned", "under_review"}:
        raise ApplyError("invalid_tx", "recovery_review_not_assigned", {"request_id": request_id})
    evidence_ids = {_as_str(value).strip() for value in request.get("evidence_ids", []) if _as_str(value).strip()}
    if evidence_id not in evidence_ids:
        raise ApplyError("invalid_tx", "recovery_evidence_not_declared", {"evidence_id": evidence_id})
    reviewers = {_as_str(value).strip() for value in request.get("assigned_reviewers", []) if _as_str(value).strip()}
    if not reviewers:
        raise ApplyError("invalid_tx", "recovery_reviewers_not_assigned", {})
    envelopes = payload.get("key_envelope_commitments")
    if not isinstance(envelopes, dict):
        raise ApplyError("invalid_tx", "recovery_key_envelopes_required", {})
    try:
        mark_reviewer_accessible(
            state,
            evidence_id=evidence_id,
            key_envelope_commitments=envelopes,
            required_principals={account_id, *reviewers},
            height=_current_height(state),
        )
    except ValueError as exc:
        raise ApplyError("invalid_tx", str(exc), {"evidence_id": evidence_id}) from exc
    bound = [_as_str(value).strip() for value in request.get("evidence_bound_ids", []) if _as_str(value).strip()]
    if evidence_id not in bound:
        bound.append(evidence_id)
    request["evidence_bound_ids"] = sorted(bound)
    request["evidence_access_ready"] = evidence_ids.issubset(set(bound))
    account["nonce"] = _expect_nonce(account, env)
    return state


def _apply_account_recovery_social_attestation(state: Json, env: TxEnvelope) -> Json:
    payload = _payload(env)
    request_id = _as_str(payload.get("request_id") or "").strip()
    account_id, _subject, _recovery, request = _find_recovery_request(state, request_id)
    if _as_str(request.get("status")).strip().lower() != "awaiting_social_attestations":
        raise ApplyError(
            "invalid_tx",
            "social_continuity_attestation_window_not_open",
            {"request_id": request_id, "status": request.get("status")},
        )
    if request.get("social_attestation_required") is not True:
        raise ApplyError("invalid_tx", "social_continuity_not_required", {"request_id": request_id})

    attestor_id = _as_str(env.signer).strip()
    attestor = _require_not_banned_or_locked(state, attestor_id)
    expected_nonce = _expect_nonce(attestor, env)
    if attestor_id == account_id:
        raise ApplyError("forbidden", "social_continuity_self_attestation_forbidden", {})
    if effective_poh_tier(state, attestor_id, at_height=_current_height(state)) < 2:
        raise ApplyError(
            "forbidden",
            "social_continuity_attestor_requires_tier2",
            {"attestor_id": attestor_id},
        )

    attestation_commitment = _as_str(payload.get("attestation_commitment") or "").strip()
    household_commitment = _as_str(payload.get("household_commitment") or "").strip()
    independence_commitment = _as_str(payload.get("independence_commitment") or "").strip()
    reason_code = _as_str(payload.get("reason_code") or "").strip().lower()
    if not attestation_commitment or not household_commitment or not independence_commitment:
        raise ApplyError("invalid_tx", "social_continuity_commitments_required", {})
    if reason_code != "no_financial_or_institutional_dependency_v1":
        raise ApplyError("invalid_tx", "social_continuity_independence_declaration_required", {})

    attestations = request.setdefault("social_attestations", {})
    if not isinstance(attestations, dict):
        raise ApplyError("invalid_state", "social_continuity_attestations_not_dict", {})
    if attestor_id in attestations:
        raise ApplyError("invalid_tx", "duplicate_social_continuity_attestor", {"attestor_id": attestor_id})
    for existing in attestations.values():
        if not isinstance(existing, dict):
            continue
        if _as_str(existing.get("household_commitment")) == household_commitment:
            raise ApplyError(
                "invalid_tx",
                "social_continuity_households_not_distinct",
                {"household_commitment": household_commitment},
            )
        if _as_str(existing.get("attestation_commitment")) == attestation_commitment:
            raise ApplyError("invalid_tx", "duplicate_social_continuity_attestation_commitment", {})
        if _as_str(existing.get("independence_commitment")) == independence_commitment:
            raise ApplyError("invalid_tx", "duplicate_social_continuity_independence_commitment", {})

    attestations[attestor_id] = {
        "attestation_commitment": attestation_commitment,
        "household_commitment": household_commitment,
        "independence_commitment": independence_commitment,
        "reason_code": reason_code,
        "submitted_height": _current_height(state),
    }
    request["social_attestation_count"] = len(attestations)
    request["social_attestation_commitments"] = sorted(
        _as_str(item.get("attestation_commitment"))
        for item in attestations.values()
        if isinstance(item, dict) and _as_str(item.get("attestation_commitment"))
    )
    if len(attestations) >= _as_int(
        request.get("social_attestation_minimum"), CONTINUITY_SOCIAL_ATTESTOR_MINIMUM
    ):
        request["status"] = "awaiting_assignment"
        request["social_attestations_satisfied_height"] = _current_height(state)
    attestor["nonce"] = expected_nonce
    return state


def _apply_account_recovery_approve(state: Json, env: TxEnvelope) -> Json:
    payload = _payload(env)
    request_id = _as_str(payload.get("request_id") or "").strip()
    if not request_id:
        return _apply_account_recovery_vote(state, env)
    decision = _as_str(payload.get("decision") or "").strip().lower()
    if decision == "evidence_bind":
        return _apply_account_recovery_evidence_bind(state, env)
    if decision == "social_attest":
        return _apply_account_recovery_social_attestation(state, env)

    account_id, subject, _recovery, request = _find_recovery_request(state, request_id)
    method = _as_str(request.get("method") or "legacy_guardian").strip().lower()
    if method in {"continuity", "reversal"}:
        reviewer = _require_not_banned_or_locked(state, env.signer)
        expected_nonce = _expect_nonce(reviewer, env)
        reviewer_id = _as_str(env.signer).strip()
        status = _as_str(request.get("status")).strip().lower()
        if status not in {"under_review", "assigned"}:
            raise ApplyError("invalid_tx", "recovery_review_not_open", {"status": status})
        assigned = {_as_str(value).strip() for value in request.get("assigned_reviewers", [])}
        if reviewer_id not in assigned:
            raise ApplyError("forbidden", "reviewer_not_assigned", {"request_id": request_id})
        if request.get("evidence_access_ready") is not True:
            raise ApplyError("invalid_tx", "recovery_evidence_bind_required", {"request_id": request_id})
        for evidence_id in request.get("evidence_ids", []):
            rec = evidence_record(state, _as_str(evidence_id).strip())
            envelopes = rec.get("key_envelope_commitments") if isinstance(rec, dict) else None
            if not isinstance(envelopes, dict) or reviewer_id not in envelopes:
                raise ApplyError(
                    "invalid_tx",
                    "recovery_reviewer_key_envelope_required",
                    {"request_id": request_id, "evidence_id": evidence_id, "reviewer_id": reviewer_id},
                )
        reason = recovery_conflict_reason(
            state,
            reviewer_id=reviewer_id,
            target_id=account_id,
            excluded_reviewers=set(request.get("excluded_reviewers", [])),
        )
        if reason:
            raise ApplyError("forbidden", reason, {"request_id": request_id})
        decision = _as_str(payload.get("decision") or payload.get("vote") or "").strip().lower()
        if decision in {"yes", "pass"}:
            decision = "approve"
        elif decision in {"no", "fail"}:
            decision = "reject"
        if decision not in {"approve", "reject"}:
            raise ApplyError("invalid_tx", "invalid_recovery_review_decision", {"decision": decision})
        reviews = request.setdefault("reviews", {})
        if not isinstance(reviews, dict):
            raise ApplyError("invalid_state", "recovery_reviews_not_dict", {})
        if reviewer_id in reviews:
            raise ApplyError("invalid_tx", "recovery_review_already_submitted", {})
        reviews[reviewer_id] = {
            "decision": decision,
            "review_commitment": _as_str(payload.get("review_commitment") or "").strip() or None,
            "reason_code": _as_str(payload.get("reason_code") or "").strip() or None,
            "height": _current_height(state),
        }
        approvals, rejections, submitted = recovery_review_counts(request)
        request["approval_count"] = approvals
        request["rejection_count"] = rejections
        request["submitted_review_count"] = submitted
        reviewer["nonce"] = expected_nonce
        return state

    _require_guardian_recovery_admission(state)
    _recovery, guardians, threshold = _normalized_guardians(subject)
    guardian = _require_not_banned_or_locked(state, env.signer)
    expected_nonce = _expect_nonce(guardian, env)
    guardian_id = _as_str(env.signer).strip()
    if guardian_id not in guardians:
        raise ApplyError("forbidden", "not_a_guardian", {"guardian": guardian_id})
    status = _as_str(request.get("status") or "open").strip().lower()
    if status not in {"open", "approved"}:
        raise ApplyError("invalid_tx", "request_not_open", {"request_id": request_id, "status": status})
    approvals = request.setdefault("approvals", [])
    if guardian_id in approvals:
        raise ApplyError("invalid_tx", "already_approved", {"guardian": guardian_id})
    approvals.append(guardian_id)
    request["guardian_threshold"] = threshold
    request["guardians_snapshot"] = list(guardians)
    request["status"] = "approved" if len(approvals) >= max(1, threshold) else "open"
    guardian["nonce"] = expected_nonce
    return state

def _apply_account_recovery_execute(state: Json, env: TxEnvelope) -> Json:
    # Execute if approvals >= threshold; adds new key.
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    proposal_id = _as_str(p.get("proposal_id") or "").strip()
    if not proposal_id:
        raise ApplyError("invalid_tx", "missing_proposal_id", {})

    recovery = a.get("recovery")
    if not isinstance(recovery, dict) or not isinstance(recovery.get("config"), dict):
        raise ApplyError("invalid_tx", "recovery_not_configured", {})

    cfg = recovery["config"]
    thr = _as_int(cfg.get("threshold"), 0)

    proposals = recovery.get("proposals")
    if not isinstance(proposals, dict):
        raise ApplyError("invalid_tx", "proposal_missing", {"proposal_id": proposal_id})

    prop = proposals.get(proposal_id)
    if not isinstance(prop, dict):
        raise ApplyError("invalid_tx", "proposal_missing", {"proposal_id": proposal_id})

    if prop.get("executed") is True:
        raise ApplyError("invalid_tx", "proposal_executed", {"proposal_id": proposal_id})

    approvals = prop.get("approvals")
    if not isinstance(approvals, list):
        approvals = []
    if len(approvals) < thr:
        raise ApplyError("forbidden", "threshold_not_met", {"have": len(approvals), "need": thr})

    new_pubkey = _as_str(prop.get("new_pubkey") or "").strip()
    if not new_pubkey:
        raise ApplyError("invalid_state", "missing_new_pubkey", {"proposal_id": proposal_id})

    # Add the new key
    keys = a.get("keys")
    if not isinstance(keys, dict):
        keys = {}
        a["keys"] = keys
    by_id = keys.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        keys["by_id"] = by_id

    kid = _mk_key_id(new_pubkey)
    if kid in by_id and isinstance(by_id.get(kid), dict) and by_id[kid].get("revoked") is not True:
        raise ApplyError("invalid_tx", "key_exists", {"pubkey": new_pubkey})

    recovery_payload = dict(prop)
    recovery_payload.setdefault("pubkey", new_pubkey)
    recovery_payload.setdefault("sig_profile", prop.get("sig_profile") or default_signature_profile_for_mode())
    key_record = _key_record_from_payload_or_raise(state, recovery_payload, key_type="recovered")
    key_record["key_id"] = str(key_record.get("key_id") or kid)
    by_id[kid] = key_record
    prop["executed"] = True

    a["nonce"] = exp
    _sync_account_key_views(a)
    return state


def _apply_account_recovery_request(state: Json, env: TxEnvelope) -> Json:
    """Open offline-key, continuity, reversal, or explicit legacy recovery."""

    payload = _payload(env)
    target = _as_str(payload.get("target") or env.signer).strip()
    request_id = _as_str(payload.get("request_id") or "").strip()
    if not request_id:
        raise ApplyError("invalid_tx", "missing_request_id", {})
    if not target:
        raise ApplyError("invalid_tx", "missing_target", {})
    subject = _require_known_not_banned_allow_locked(state, target)
    recovery = subject.setdefault("recovery", {})
    if not isinstance(recovery, dict):
        raise ApplyError("invalid_state", "recovery_not_dict", {})
    requests = recovery.setdefault("requests", {})
    if not isinstance(requests, dict):
        raise ApplyError("invalid_state", "recovery_requests_not_dict", {})
    if request_id in requests:
        raise ApplyError("invalid_tx", "request_exists", {"request_id": request_id})
    for existing_id, existing in requests.items():
        if isinstance(existing, dict) and _as_str(existing.get("status")).lower() in {
            "open", "awaiting_social_attestations", "awaiting_assignment", "assigned",
            "under_review", "approved", "finalized"
        }:
            raise ApplyError("forbidden", "active_recovery_request_exists", {"request_id": str(existing_id)})

    height = _current_height(state)
    last_opened = _as_int(recovery.get("last_request_opened_height"), -RECOVERY_REQUEST_COOLDOWN_BLOCKS)
    method = _as_str(payload.get("method") or recovery.get("mode") or "legacy_guardian").strip().lower()
    if method != "reversal" and height - last_opened < RECOVERY_REQUEST_COOLDOWN_BLOCKS:
        raise ApplyError(
            "forbidden",
            "recovery_request_cooldown",
            {"next_height": last_opened + RECOVERY_REQUEST_COOLDOWN_BLOCKS},
        )
    failed_heights = [
        _as_int(value, -1)
        for value in recovery.get("failed_attempt_heights", [])
        if _as_int(value, -1) >= height - RECOVERY_FAILED_WINDOW_BLOCKS
    ]
    recovery["failed_attempt_heights"] = failed_heights
    if len(failed_heights) >= RECOVERY_MAX_FAILED_ATTEMPTS:
        raise ApplyError("forbidden", "recovery_failed_attempt_limit", {"have": len(failed_heights)})

    if method in {"offline_key", "continuity", "reversal"}:
        if _as_str(env.signer).strip() != target:
            raise ApplyError("forbidden", "recovery_target_must_sign", {"target": target})
        nonce_actor = subject
    else:
        nonce_actor = _require_not_banned_or_locked(state, _as_str(env.signer).strip())
    expected_nonce = _expect_nonce(nonce_actor, env)

    if method in {"offline_key", "continuity", "reversal"}:
        new_pubkey = _as_str(payload.get("new_pubkey") or "").strip()
        new_recovery_pubkey = _as_str(payload.get("new_recovery_pubkey") or "").strip()
        if not new_pubkey or not new_recovery_pubkey:
            raise ApplyError("invalid_tx", "missing_replacement_authority", {})
        new_sig_profile = _as_str(payload.get("new_sig_profile") or default_signature_profile_for_mode()).strip()
        new_recovery_sig_profile = _as_str(
            payload.get("new_recovery_sig_profile") or default_signature_profile_for_mode()
        ).strip()
        _key_record_from_payload_or_raise(
            state, {"pubkey": new_pubkey, "sig_profile": new_sig_profile}, key_type="recovered"
        )
        _require_fresh_recovered_authority(subject, new_pubkey)
        _validate_independent_recovery_key(
            state,
            subject,
            {"pubkey": new_recovery_pubkey, "sig_profile": new_recovery_sig_profile},
            proposed_active_pubkey=new_pubkey,
            require_fresh=True,
        )
        base = {
            "request_id": request_id,
            "target": target,
            "requester": target,
            "method": method,
            "created_at": height,
            "new_pubkey": new_pubkey,
            "new_sig_profile": new_sig_profile,
            "new_recovery_pubkey": new_recovery_pubkey,
            "new_recovery_sig_profile": new_recovery_sig_profile,
            "new_recovery_key_commitment": _as_str(payload.get("new_recovery_key_commitment") or "").strip() or None,
            "authorization": _as_str(payload.get("authorization") or method).strip().lower(),
        }
        if method == "offline_key":
            offline_key = recovery.get("offline_key")
            if not isinstance(offline_key, dict) or not _as_str(offline_key.get("pubkey")).strip():
                raise ApplyError("invalid_tx", "offline_recovery_not_configured", {})
            generation = _as_int(payload.get("recovery_generation"), -1)
            expected_generation = _as_int(offline_key.get("generation"), 0)
            if generation != expected_generation:
                raise ApplyError(
                    "invalid_tx", "recovery_generation_mismatch", {"want": expected_generation, "got": generation}
                )
            base.update({"status": "approved", "recovery_generation": generation})
        else:
            evidence_classes, strong_anchor, social_required = _recovery_evidence_summary(payload)
            recovery_evidence_ids = _register_recovery_encrypted_evidence(
                state,
                request_id=request_id,
                target=target,
                payload=payload,
                height=height,
                declared_class_ids={item["class_id"] for item in evidence_classes},
            )
            excluded = _prior_recovery_reviewer_ids(recovery)
            if method == "reversal":
                challenged_id = _as_str(payload.get("challenged_request_id") or "").strip()
                challenged = requests.get(challenged_id)
                if not challenged_id or not isinstance(challenged, dict):
                    raise ApplyError("invalid_tx", "unknown_challenged_recovery", {})
                if _as_str(challenged.get("status")).lower() not in {"finalized", "receipt_recorded"}:
                    raise ApplyError("invalid_tx", "challenged_recovery_not_finalized", {})
                restriction_until = _as_int(recovery.get("restriction_until_height"), 0)
                if height > restriction_until:
                    raise ApplyError("forbidden", "recovery_reversal_window_closed", {})
                if recovery.get("active_reversal_request_id"):
                    raise ApplyError("forbidden", "recovery_reversal_already_open", {})
                excluded.update({_as_str(v).strip() for v in challenged.get("assigned_reviewers", [])})
                recovery["active_reversal_request_id"] = request_id
                recovery["restriction_until_height"] = max(
                    restriction_until, height + RECOVERY_REVIEW_WINDOW_BLOCKS
                )
                base["challenged_request_id"] = challenged_id
            base.update(
                {
                    "status": (
                        "awaiting_social_attestations" if social_required else "awaiting_assignment"
                    ),
                    "evidence_class_commitments": evidence_classes,
                    "strong_anchor_commitment": strong_anchor,
                    "social_attestation_required": social_required,
                    "social_attestation_minimum": (
                        CONTINUITY_SOCIAL_ATTESTOR_MINIMUM if social_required else 0
                    ),
                    "social_attestations": {},
                    "social_attestation_commitments": [],
                    "evidence_policy_version": _as_str(payload.get("evidence_policy_version") or "m2-v1"),
                    "evidence_ids": recovery_evidence_ids,
                    "evidence_bound_ids": [],
                    "evidence_access_ready": False,
                    "panel_size": REVERSAL_PANEL_SIZE if method == "reversal" else CONTINUITY_PANEL_SIZE,
                    "approval_threshold": REVERSAL_APPROVAL_THRESHOLD if method == "reversal" else CONTINUITY_APPROVAL_THRESHOLD,
                    "review_deadline_height": height + RECOVERY_REVIEW_WINDOW_BLOCKS,
                    "assigned_reviewers": [],
                    "excluded_reviewers": sorted(value for value in excluded if value),
                    "reviews": {},
                }
            )
        requests[request_id] = base
    else:
        _require_guardian_recovery_admission(state)
        recovery, guardians, threshold = _normalized_guardians(subject)
        requests = recovery.setdefault("requests", {})
        requests[request_id] = {
            "request_id": request_id,
            "status": "open",
            "target": target,
            "requester": _as_str(env.signer).strip(),
            "method": "legacy_guardian",
            "approvals": [],
            "votes": {},
            "guardian_threshold": threshold,
            "guardians_snapshot": list(guardians),
            "created_at": height,
        }

    recovery["last_request_opened_height"] = height
    subject["locked"] = True
    nonce_actor["nonce"] = expected_nonce
    return state

def _apply_account_recovery_cancel(state: Json, env: TxEnvelope) -> Json:
    actor = _require_known_not_banned_allow_locked(state, env.signer)
    expected_nonce = _expect_nonce(actor, env)
    request_id = _as_str(_payload(env).get("request_id") or "").strip()
    if not request_id:
        raise ApplyError("invalid_tx", "missing_request_id", {})
    account_id, account, _recovery, request = _find_recovery_request(state, request_id)
    method = _as_str(request.get("method") or "legacy_guardian").strip().lower()
    if method != "legacy_guardian":
        # An ordinary or displaced active key cannot cancel, delay, or veto an
        # independently authorized recovery. Reversal is the only challenge path.
        raise ApplyError("forbidden", "independent_recovery_not_cancellable", {"request_id": request_id})
    _require_guardian_recovery_admission(state)
    requester = _as_str(request.get("requester") or "").strip()
    if _as_str(env.signer).strip() not in {requester, account_id}:
        raise ApplyError("forbidden", "not_request_owner", {"request_id": request_id})
    status = _as_str(request.get("status") or "open").strip().lower()
    if status in {"cancelled", "finalized", "receipt_recorded"}:
        raise ApplyError("invalid_tx", "request_not_cancellable", {"request_id": request_id, "status": status})
    request["status"] = "cancelled"
    request["cancelled_by"] = _as_str(env.signer).strip()
    request["cancelled_at"] = _current_height(state)
    account["locked"] = False
    actor["nonce"] = expected_nonce
    return state

def _apply_account_recovery_finalize(state: Json, env: TxEnvelope) -> Json:
    request_id = _as_str(_payload(env).get("request_id") or "").strip()
    if not request_id:
        raise ApplyError("invalid_tx", "missing_request_id", {})
    account_id, account, recovery, request = _find_recovery_request(state, request_id)
    status = _as_str(request.get("status") or "").strip().lower()
    if status != "approved":
        raise ApplyError("forbidden", "recovery_not_authorized", {"request_id": request_id, "status": status})
    method = _as_str(request.get("method") or "legacy_guardian").strip().lower()
    height = _current_height(state)

    if method in {"offline_key", "continuity", "reversal"}:
        if method == "offline_key":
            current_offline = recovery.get("offline_key")
            if not isinstance(current_offline, dict):
                raise ApplyError("invalid_state", "offline_recovery_not_configured", {})
            generation = _as_int(request.get("recovery_generation"), -1)
            if generation != _as_int(current_offline.get("generation"), 0):
                raise ApplyError("forbidden", "stale_recovery_generation", {"request_id": request_id})
        next_generation, new_key_id, revoked_keys, revoked_devices, revoked_sessions = _install_recovered_authority(
            state, account, recovery, request, height=height
        )
        restriction_until = height + RECOVERY_RESTRICTION_BLOCKS
        if method == "reversal":
            restriction_until = max(
                restriction_until,
                _as_int(recovery.get("restriction_until_height"), 0),
            )
            recovery["active_reversal_request_id"] = None
        recovery["restriction_until_height"] = restriction_until
        recovery["last_finalized_height"] = height
        reviewer_ids = sorted(_as_str(value).strip() for value in request.get("assigned_reviewers", []) if _as_str(value).strip())
        history = recovery.setdefault("history", [])
        history.append(
            {
                "request_id": request_id,
                "method": method,
                "finalized_height": height,
                "authority_generation": next_generation,
                "new_key_id": new_key_id,
                "revoked_key_ids": revoked_keys,
                "revoked_device_ids": revoked_devices,
                "revoked_session_count": revoked_sessions,
                "restriction_until_height": restriction_until,
                "reviewer_ids": reviewer_ids,
                "challenged_request_id": request.get("challenged_request_id"),
            }
        )
        if method == "reversal":
            incidents = state.setdefault("account_recovery_incidents", [])
            incidents.append(
                {
                    "request_id": request_id,
                    "account_id": account_id,
                    "challenged_request_id": request.get("challenged_request_id"),
                    "height": height,
                    "status": "restored",
                }
            )
        for other_id, other in recovery.get("requests", {}).items():
            if other_id != request_id and isinstance(other, dict) and _as_str(other.get("status")).lower() in {
                "open", "awaiting_assignment", "assigned", "under_review", "approved"
            }:
                other["status"] = "superseded"
                other["superseded_by"] = request_id
        _sync_account_key_views(account)
    else:
        _require_guardian_recovery_admission(state)
        approvals = request.get("approvals") if isinstance(request.get("approvals"), list) else []
        threshold = _as_int(request.get("guardian_threshold"), 0)
        if len(approvals) < max(1, threshold):
            raise ApplyError("forbidden", "threshold_not_met", {"have": len(approvals), "need": max(1, threshold)})

    if method in {"continuity", "reversal"}:
        close_case_evidence(
            state, case_id=f"account-recovery:{request_id}", finalized_height=height
        )
    request["status"] = "finalized"
    request["finalized_at"] = height
    request["finalized_by"] = _as_str(getattr(env, "signer", "")).strip() or "SYSTEM"
    account["locked"] = False
    return state

def _apply_account_recovery_receipt(state: Json, env: TxEnvelope) -> Json:
    payload = _payload(env)
    request_id = _as_str(payload.get("request_id") or "").strip()
    if not request_id:
        raise ApplyError("invalid_tx", "missing_request_id", {})
    account_id, account, recovery, request = _find_recovery_request(state, request_id)
    status = _as_str(payload.get("status") or request.get("status") or "finalized").strip().lower()
    if status in {"rejected", "expired", "assignment_unavailable"}:
        _append_failed_recovery_attempt(recovery, height=_current_height(state), request_id=request_id, reason=status)
        close_case_evidence(
            state, case_id=f"account-recovery:{request_id}", finalized_height=_current_height(state)
        )
        if _as_str(request.get("method")).lower() != "reversal":
            account["locked"] = False
        else:
            recovery["active_reversal_request_id"] = None
    request["status"] = "receipt_recorded"
    request["receipt_status"] = status
    request["receipt_at"] = _current_height(state)
    receipts = state.setdefault("account_recovery_receipts", [])
    receipts.append(
        {
            "request_id": request_id,
            "account_id": account_id,
            "method": _as_str(request.get("method") or "legacy_guardian"),
            "status": status,
            "height": request["receipt_at"],
            "authority_generation": _as_int(recovery.get("authority_generation"), 0),
            "restriction_until_height": _as_int(recovery.get("restriction_until_height"), 0),
            "approval_count": _as_int(request.get("approval_count"), 0),
            "rejection_count": _as_int(request.get("rejection_count"), 0),
            "panel_commitment": request.get("panel_commitment"),
            "challenged_request_id": request.get("challenged_request_id"),
        }
    )
    return state

def _apply_account_recovery_vote(state: Json, env: TxEnvelope) -> Json:
    """Cast a vote on a recovery request (minimal MVP)."""
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    request_id = _as_str(p.get("request_id") or "").strip()
    vote = _as_str(p.get("vote") or "").strip().lower()
    if not request_id:
        raise ApplyError("invalid_tx", "missing_request_id", {})
    if vote not in {"yes", "no"}:
        raise ApplyError("invalid_tx", "invalid_vote", {"vote": vote})

    # For MVP smoke, requests live under the *subject* account (the one being recovered).
    # We search all accounts to find the request.
    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})

    found_req: Json | None = None
    for _aid, acct in accounts.items():
        if not isinstance(acct, dict):
            continue
        rec = acct.get("recovery")
        if not isinstance(rec, dict):
            continue
        reqs = rec.get("requests")
        if not isinstance(reqs, dict):
            continue
        r = reqs.get(request_id)
        if isinstance(r, dict):
            found_req = r
            break

    if found_req is None:
        raise ApplyError("invalid_tx", "unknown_request", {"request_id": request_id})

    votes = found_req.get("votes")
    if not isinstance(votes, dict):
        votes = {}
        found_req["votes"] = votes
    votes[env.signer] = vote

    a["nonce"] = exp
    return state


def apply_identity(state: Json, env: TxEnvelope) -> Json | None:
    _reject_non_public_protocol_payload(env)
    tx = _as_str(getattr(env, "tx_type", "")).strip().upper()

    if tx == "ACCOUNT_REGISTER":
        return _apply_account_register(state, env)

    if tx == "ACCOUNT_KEY_ADD":
        return _apply_account_key_add(state, env)

    if tx == "ACCOUNT_KEY_REVOKE":
        return _apply_account_key_revoke(state, env)

    if tx == "ACCOUNT_DEVICE_REGISTER":
        return _apply_account_device_register(state, env)

    if tx == "ACCOUNT_DEVICE_REVOKE":
        return _apply_account_device_revoke(state, env)

    if tx == "ACCOUNT_SESSION_KEY_ISSUE":
        return _apply_account_session_key_issue(state, env)

    if tx == "ACCOUNT_SESSION_KEY_REVOKE":
        return _apply_account_session_key_revoke(state, env)

    if tx == "ACCOUNT_GUARDIAN_ADD":
        return _apply_account_guardian_add(state, env)

    if tx == "ACCOUNT_GUARDIAN_REMOVE":
        return _apply_account_guardian_remove(state, env)

    if tx == "ACCOUNT_SECURITY_POLICY_SET":
        return _apply_account_security_policy_set(state, env)

    if tx == "ACCOUNT_LOCK":
        return _apply_account_lock(state, env)

    if tx == "ACCOUNT_UNLOCK":
        return _apply_account_unlock(state, env)

    if tx == "ACCOUNT_BAN":
        return _apply_account_ban(state, env)


    if tx == "ACCOUNT_RECOVERY_CONFIG_SET":
        return _apply_account_recovery_config_set(state, env)


    if tx == "ACCOUNT_RECOVERY_APPROVE":
        return _apply_account_recovery_approve(state, env)


    if tx == "ACCOUNT_RECOVERY_REQUEST":
        return _apply_account_recovery_request(state, env)

    if tx == "ACCOUNT_RECOVERY_CANCEL":
        return _apply_account_recovery_cancel(state, env)

    if tx == "ACCOUNT_RECOVERY_FINALIZE":
        return _apply_account_recovery_finalize(state, env)

    if tx == "ACCOUNT_RECOVERY_RECEIPT":
        return _apply_account_recovery_receipt(state, env)


    # Not an identity-domain tx; allow other domain appliers to claim it.
    return None
