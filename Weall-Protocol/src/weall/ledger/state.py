from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from weall.ledger.roles_schema import canonicalize_account_set
from weall.runtime.reputation_units import account_reputation_units, units_to_reputation

Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class LedgerView:
    """Immutable read-only ledger view used by runtime components.

    NOTE: This view is used at admission-time as well as in other runtime components.
    It intentionally copies only the stable, consensus-relevant subtrees needed for
    authorization and gating.

    We include a minimal `poh` subtree so gate expressions like "Juror" can be
    resolved deterministically during admission.
    """

    accounts: dict[str, Any] = field(default_factory=dict)
    roles: dict[str, Any] = field(default_factory=dict)

    # consensus replay-domain identity
    chain_id: str = ""

    # protocol params + time markers (needed for Genesis economic lock at admission-time)
    params: dict[str, Any] = field(default_factory=dict)
    last_block_ts_ms: int = 0

    # optional protocol subtree used by gating (e.g. PoH juror assignments)
    poh: dict[str, Any] = field(default_factory=dict)

    # dispute assignment state is needed at admission-time for juror-gated
    # actions such as accept/decline/attendance/vote. Keep a minimal copy so
    # gate evaluation can deterministically admit against the canonical dispute
    # object rather than relying on separate global role registries.
    disputes_by_id: dict[str, Any] = field(default_factory=dict)

    # consensus/validator metadata is also needed by some gate checks and live
    # bootstrap flows. Preserve the minimal subtree instead of dropping it.
    consensus: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_ledger(cls, state: dict[str, Any]) -> LedgerView:
        return cls(
            accounts=copy.deepcopy(state.get("accounts", {})),
            roles=copy.deepcopy(state.get("roles", {})),
            chain_id=str(state.get("chain_id") or ""),
            params=copy.deepcopy(state.get("params", {}))
            if isinstance(state.get("params"), dict)
            else {},
            last_block_ts_ms=int(state.get("last_block_ts_ms", 0) or 0),
            poh=copy.deepcopy(state.get("poh", {})) if isinstance(state.get("poh"), dict) else {},
            disputes_by_id=copy.deepcopy(state.get("disputes_by_id", {})) if isinstance(state.get("disputes_by_id"), dict) else {},
            consensus=copy.deepcopy(state.get("consensus", {})) if isinstance(state.get("consensus"), dict) else {},
        )

    def to_ledger(self) -> dict[str, Any]:
        return {
            "accounts": copy.deepcopy(self.accounts),
            "roles": copy.deepcopy(self.roles),
            "chain_id": str(self.chain_id or ""),
            "params": copy.deepcopy(self.params),
            "last_block_ts_ms": int(self.last_block_ts_ms),
            "poh": copy.deepcopy(self.poh),
            "disputes_by_id": copy.deepcopy(self.disputes_by_id),
            "consensus": copy.deepcopy(self.consensus),
        }

    @property
    def ledger(self) -> dict[str, Any]:
        return self.to_ledger()

    def get_account(self, account_id: str) -> dict[str, Any]:
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

    def reputation_units(self, account_id: str) -> int:
        acct = self.get_account(account_id)
        return int(account_reputation_units(acct, default=0))

    def reputation(self, account_id: str) -> float:
        return units_to_reputation(self.reputation_units(account_id), default=0.0)

    def get_param(self, key: str, default: Any = None) -> Any:
        try:
            return self.params.get(key, default)
        except Exception:
            return default

    def get_active_keys(self, account_id: str) -> list[str]:
        """Returns active public keys for an account.

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

        out: list[str] = []
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

        # Legacy single + list mirrors
        _add(acct.get("pubkey"))

        pubkeys = acct.get("pubkeys")
        if isinstance(pubkeys, list):
            for pk in pubkeys:
                _add(pk)

        active_keys = acct.get("active_keys")
        if isinstance(active_keys, list):
            for pk in active_keys:
                _add(pk)

        keys = acct.get("keys")

        # Legacy list-form keys
        if isinstance(keys, list):
            for rec in keys:
                if isinstance(rec, str):
                    _add(rec)
                    continue
                if not isinstance(rec, dict):
                    continue
                if rec.get("active", True) is False:
                    continue
                _add(rec.get("pubkey"))
            return out

        # Canonical dict-form keys
        if isinstance(keys, dict):
            by_id = keys.get("by_id") if isinstance(keys.get("by_id"), dict) else None
            if isinstance(by_id, dict):
                for rec in by_id.values():
                    if not isinstance(rec, dict):
                        continue
                    if bool(rec.get("revoked", False)):
                        continue
                    _add(rec.get("pubkey"))
                return out

            for pk, rec in keys.items():
                if not isinstance(pk, str) or not pk.strip():
                    continue
                if isinstance(rec, dict):
                    if bool(rec.get("active", False)) and not bool(rec.get("revoked", False)):
                        _add(pk)
                else:
                    # tolerate older shape keys={pubkey: True/False}
                    if bool(rec):
                        _add(pk)
            return out

        return out

    def get_active_validator_set(self) -> list[str]:
        validators = self.roles.get("validators")
        if not isinstance(validators, dict):
            return []
        return canonicalize_account_set(validators.get("active_set"))

    def get_system_signer(self) -> str:
        v = self.params.get("system_signer")
        return str(v).strip() if v is not None else ""
