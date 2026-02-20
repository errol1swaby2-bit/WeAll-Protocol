# src/weall/runtime/genesis_config.py
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

Json = Dict[str, Any]


@dataclass(frozen=True, slots=True)
class GenesisValidator:
    account: str
    pubkey: str
    active: bool = True


@dataclass(frozen=True, slots=True)
class GenesisConfig:
    chain_id: str
    validators: List[GenesisValidator]
    active_set: Optional[List[str]] = None


def load_genesis(path: str) -> GenesisConfig:
    """Load GenesisConfig from a JSON file.

    Supported input shapes:
      - { "chain_id": "...", "validators": [ { "account": "...", "pubkey": "...", "active": true }, ... ],
          "active_set": ["acct1", ...] }
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(str(p))

    with p.open("r", encoding="utf-8") as f:
        obj = json.load(f)

    if not isinstance(obj, dict):
        raise ValueError("genesis config must be a JSON object")

    chain_id = str(obj.get("chain_id") or "").strip()
    if not chain_id:
        chain_id = str(os.environ.get("WEALL_CHAIN_ID", "")).strip()

    vals_raw = obj.get("validators")
    if not isinstance(vals_raw, list):
        vals_raw = []

    vals: List[GenesisValidator] = []
    for rec in vals_raw:
        if not isinstance(rec, dict):
            continue
        acct = str(rec.get("account") or "").strip()
        pk = str(rec.get("pubkey") or "").strip()
        if not acct or not pk:
            continue
        active = bool(rec.get("active", True))
        vals.append(GenesisValidator(account=acct, pubkey=pk, active=active))

    active_set = obj.get("active_set")
    if isinstance(active_set, list):
        active_set = [str(x) for x in active_set if str(x).strip()]
    else:
        active_set = None

    return GenesisConfig(chain_id=chain_id, validators=vals, active_set=active_set)


def apply_genesis_config_to_ledger_state(state: Json, cfg: GenesisConfig) -> Tuple[bool, Json]:
    """Apply genesis validator config to a ledger state dict.

    Returns (changed, state). Safe to call repeatedly; it is idempotent.

    Policy:
      - Only applies when ledger height == 0 (genesis state).
      - Ensures accounts exist for each validator and includes their pubkey as an ACTIVE key.
      - Sets roles.validators.active_set to cfg.active_set or all active validators.

    IMPORTANT: This function writes the *canonical* identity schema:
      accounts[acct_id]["keys"] is a dict mapping pubkey -> {"pubkey": str, "active": bool}
      accounts[acct_id]["devices"] is a dict (even if empty)

    This keeps genesis config compatible with:
      - weall.runtime.apply.identity
      - weall.net.peer_identity
    """
    try:
        height = int(state.get("height", 0) or 0)
    except Exception:
        height = 0

    if height != 0:
        return False, state

    changed = False

    # Optional chain_id consistency (don't override, but can store for reference)
    if cfg.chain_id:
        meta = state.get("meta")
        if not isinstance(meta, dict):
            meta = {}
            state["meta"] = meta
            changed = True
        if meta.get("chain_id") != cfg.chain_id:
            meta["chain_id"] = cfg.chain_id
            changed = True

    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        accounts = {}
        state["accounts"] = accounts
        changed = True

    def _ensure_account(acct_id: str) -> Json:
        nonlocal changed
        acct = accounts.get(acct_id)
        if not isinstance(acct, dict):
            acct = {}
            accounts[acct_id] = acct
            changed = True

        acct.setdefault("account_id", str(acct_id))
        acct.setdefault("nonce", 0)
        acct.setdefault("locked", False)
        acct.setdefault("poh_tier", 0)
        acct.setdefault("banned", False)
        acct.setdefault("balance", 0)
        acct.setdefault("reputation", 0.0)

        # Canonical keys dict
        keys = acct.get("keys")
        if isinstance(keys, list):
            migrated: Dict[str, Any] = {}
            for rec in keys:
                if not isinstance(rec, dict):
                    continue
                pk = str(rec.get("pubkey") or "").strip()
                if not pk:
                    continue
                migrated[pk] = {"pubkey": pk, "active": bool(rec.get("active", True))}
            acct["keys"] = migrated
            changed = True
        elif not isinstance(keys, dict):
            acct["keys"] = {}
            changed = True

        # Canonical devices dict (peer identity requires it)
        devices = acct.get("devices")
        if not isinstance(devices, dict):
            acct["devices"] = {}
            changed = True

        # Other identity roots (safe defaults)
        if not isinstance(acct.get("guardians"), list):
            acct["guardians"] = []
            changed = True
        if not isinstance(acct.get("security_policy"), dict):
            acct["security_policy"] = {}
            changed = True
        if not isinstance(acct.get("session_keys"), dict):
            acct["session_keys"] = {}
            changed = True
        if not isinstance(acct.get("recovery"), dict):
            acct["recovery"] = {}
            changed = True

        return acct

    for v in cfg.validators:
        acct = _ensure_account(str(v.account))

        keys = acct.get("keys")
        assert isinstance(keys, dict)

        pk = str(v.pubkey or "").strip()
        if not pk:
            # Skip invalid entry, but don't crash genesis.
            continue

        cur = keys.get(pk)
        if not isinstance(cur, dict):
            keys[pk] = {"pubkey": pk, "active": bool(v.active)}
            changed = True
        else:
            # normalize fields
            if cur.get("pubkey") != pk:
                cur["pubkey"] = pk
                changed = True
            if bool(cur.get("active", False)) != bool(v.active):
                cur["active"] = bool(v.active)
                changed = True

    roles = state.get("roles")
    if not isinstance(roles, dict):
        roles = {}
        state["roles"] = roles
        changed = True

    validators = roles.get("validators")
    if not isinstance(validators, dict):
        validators = {}
        roles["validators"] = validators
        changed = True

    # Compute default active set: all active validators
    default_active = [v.account for v in cfg.validators if v.active]
    active_set = cfg.active_set or default_active

    if validators.get("active_set") != active_set:
        validators["active_set"] = list(active_set)
        changed = True

    # Track that genesis config was applied (helps debugging)
    validators.setdefault("_genesis_config_applied", True)
    return changed, state
