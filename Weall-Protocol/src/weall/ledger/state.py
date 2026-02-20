from __future__ import annotations

from dataclasses import dataclass, field
import copy
from typing import Any, Dict, List


Json = Dict[str, Any]


@dataclass(frozen=True, slots=True)
class LedgerView:
    """
    Immutable read-only ledger view used by runtime components.
    """

    accounts: Dict[str, Any] = field(default_factory=dict)
    roles: Dict[str, Any] = field(default_factory=dict)

    # protocol params + time markers (needed for Genesis economic lock at admission-time)
    params: Dict[str, Any] = field(default_factory=dict)
    last_block_ts_ms: int = 0

    @classmethod
    def from_ledger(cls, state: Dict[str, Any]) -> "LedgerView":
        return cls(
            accounts=copy.deepcopy(state.get("accounts", {})),
            roles=copy.deepcopy(state.get("roles", {})),
            params=copy.deepcopy(state.get("params", {})) if isinstance(state.get("params"), dict) else {},
            last_block_ts_ms=int(state.get("last_block_ts_ms", 0) or 0),
        )

    def to_ledger(self) -> Dict[str, Any]:
        return {
            "accounts": copy.deepcopy(self.accounts),
            "roles": copy.deepcopy(self.roles),
            "params": copy.deepcopy(self.params),
            "last_block_ts_ms": int(self.last_block_ts_ms),
        }

    @property
    def ledger(self) -> Dict[str, Any]:
        return self.to_ledger()

    def get_account(self, account_id: str) -> Dict[str, Any]:
        acct = self.accounts.get(account_id)
        return acct if isinstance(acct, dict) else {}

    def get_nonce(self, account_id: str) -> int:
        acct = self.get_account(account_id)
        try:
            return int(acct.get("nonce", 0))
        except Exception:
            return 0

    def poh_tier(self, account_id: str) -> int:
        acct = self.get_account(account_id)
        try:
            return int(acct.get("poh_tier", 0))
        except Exception:
            return 0

    def reputation(self, account_id: str) -> float:
        acct = self.get_account(account_id)
        try:
            return float(acct.get("reputation", 0.0))
        except Exception:
            return 0.0

    def get_param(self, key: str, default: Any = None) -> Any:
        try:
            return self.params.get(key, default)
        except Exception:
            return default

    def get_active_keys(self, account_id: str) -> List[str]:
        """
        Returns active public keys for an account.

        Supported schemas:
          - Canonical (current):
              accounts[account_id]["keys"] = {
                "<pubkey>": {"pubkey": "<pubkey>", "active": true|false},
                ...
              }

          - Legacy list-form:
              accounts[account_id]["keys"] = [
                {"pubkey": "<pubkey>", "active": true|false},
                ...
              ]

          - Legacy:
              accounts[account_id]["active_keys"] = ["<pubkey>", ...]

        If missing/malformed, returns [].
        """
        acct = self.get_account(account_id)

        out: List[str] = []
        seen = set()

        def _add(pk: Any) -> None:
            nonlocal out, seen
            if not isinstance(pk, str):
                return
            p = pk.strip()
            if not p or p in seen:
                return
            seen.add(p)
            out.append(p)

        # Legacy: active_keys list
        legacy = acct.get("active_keys")
        if isinstance(legacy, list):
            for pk in legacy:
                _add(pk)

        keys = acct.get("keys")

        # Legacy list-form keys
        if isinstance(keys, list):
            for rec in keys:
                if not isinstance(rec, dict):
                    continue
                if rec.get("active", True) is False:
                    continue
                _add(rec.get("pubkey"))
            return out

        # Canonical dict-form keys
        if isinstance(keys, dict):
            for pk, rec in keys.items():
                if not isinstance(pk, str) or not pk.strip():
                    continue
                if isinstance(rec, dict):
                    if bool(rec.get("active", False)):
                        _add(pk)
                else:
                    # tolerate older shape keys={pubkey: True/False}
                    if bool(rec):
                        _add(pk)
            return out

        return out

    def get_active_validator_set(self) -> List[str]:
        validators = self.roles.get("validators")
        if not isinstance(validators, dict):
            return []
        aset = validators.get("active_set")
        if not isinstance(aset, list):
            return []
        out: List[str] = []
        seen = set()
        for v in aset:
            s = str(v).strip()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
        return out

    def get_system_signer(self) -> str:
        v = self.params.get("system_signer")
        return str(v).strip() if v is not None else ""
