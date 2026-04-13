# src/weall/runtime/genesis_config.py
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from weall.ledger.roles_schema import canonicalize_account_set

Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class GenesisValidator:
    account: str
    pubkey: str
    active: bool = True


@dataclass(frozen=True, slots=True)
class GenesisConfig:
    chain_id: str
    validators: list[GenesisValidator]
    active_set: list[str] | None = None


def load_genesis(path: str) -> GenesisConfig:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(str(p))

    with p.open("r", encoding="utf-8") as f:
        obj = json.load(f)

    chain_id = str(obj.get("chain_id") or "").strip()
    if not chain_id:
        raise ValueError("genesis_config_missing_chain_id")

    vals = []
    for rec in obj.get("validators", []):
        acct = str(rec.get("account") or "").strip()
        pk = str(rec.get("pubkey") or "").strip()
        if acct and pk:
            vals.append(GenesisValidator(account=acct, pubkey=pk, active=bool(rec.get("active", True))))

    active_set = obj.get("active_set")
    if isinstance(active_set, list):
        active_set = canonicalize_account_set(active_set)
    else:
        active_set = None

    return GenesisConfig(chain_id=chain_id, validators=vals, active_set=active_set)


def apply_genesis_config_to_ledger_state(state: Json, cfg: GenesisConfig) -> tuple[bool, Json]:
    try:
        height = int(state.get("height", 0) or 0)
    except Exception:
        height = 0

    if height != 0:
        return False, state

    changed = False

    # Ensure params exist and make bootstrap policy explicit for fresh genesis state.
    params = state.get("params")
    if not isinstance(params, dict):
        params = {}
        state["params"] = params
        changed = True

    if "poh_bootstrap_mode" not in params:
        if params.get("poh_bootstrap_open") is True:
            params["poh_bootstrap_mode"] = "open"
            changed = True
        elif isinstance(params.get("bootstrap_allowlist"), dict) and params.get("bootstrap_allowlist"):
            params["poh_bootstrap_mode"] = "allowlist"
            changed = True

    # === Existing logic ===

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
        acct.setdefault("reputation", "0")

        if not isinstance(acct.get("keys"), dict):
            acct["keys"] = {}
            changed = True

        if not isinstance(acct.get("devices"), dict):
            acct["devices"] = {}
            changed = True

        return acct

    for v in cfg.validators:
        acct = _ensure_account(str(v.account))
        keys = acct["keys"]
        pk = str(v.pubkey).strip()
        if pk and pk not in keys:
            keys[pk] = {"pubkey": pk, "active": bool(v.active)}
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

    default_active = canonicalize_account_set([v.account for v in cfg.validators if v.active])
    active_set = canonicalize_account_set(cfg.active_set or default_active)

    if validators.get("active_set") != active_set:
        validators["active_set"] = list(active_set)
        changed = True

    validators.setdefault("_genesis_config_applied", True)

    return changed, state
