from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from weall.ledger.roles_schema import canonicalize_account_set
from weall.runtime.reputation_units import account_reputation_units, units_to_reputation

Json = dict[str, Any]


class _AccountNonceRecordOverlay(dict):
    """Read-only account record that exposes one deterministic nonce override.

    The admission path needs to evaluate a transaction as if the signer nonce
    cursor had advanced inside the candidate block.  The old implementation
    achieved that by deep-copying the whole ledger and mutating one account.
    This overlay preserves the same read semantics without cloning unrelated
    account state.
    """

    def __init__(self, account: dict[str, Any], nonce: int) -> None:
        dict.__init__(self)
        self._account = account
        self._nonce = max(0, int(nonce or 0))

    def __contains__(self, key: object) -> bool:
        return key == "nonce" or key in self._account

    def __len__(self) -> int:
        return len(set(self._account.keys()) | {"nonce"})

    def __iter__(self):
        seen = set()
        yield "nonce"
        seen.add("nonce")
        for key in self._account:
            if key not in seen:
                yield key

    def __bool__(self) -> bool:
        return True

    def __getitem__(self, key: Any) -> Any:
        if key == "nonce":
            return self._nonce
        return self._account[key]

    def get(self, key: Any, default: Any = None) -> Any:
        if key == "nonce":
            return self._nonce
        return self._account.get(key, default)

    def keys(self):  # type: ignore[override]
        return list(iter(self))

    def values(self):  # type: ignore[override]
        for key in self:
            yield self.get(key)

    def items(self):  # type: ignore[override]
        for key in self:
            yield key, self.get(key)

    def copy(self) -> dict[str, Any]:  # type: ignore[override]
        out = dict(self._account)
        out["nonce"] = self._nonce
        return out


class _AccountsNonceOverlay(dict):
    """Read-only accounts mapping with one account nonce override."""

    def __init__(self, accounts: dict[str, Any], account_id: str, nonce: int) -> None:
        dict.__init__(self)
        self._accounts = accounts
        self._account_id = str(account_id or "")
        self._nonce = max(0, int(nonce or 0))

    def __contains__(self, key: object) -> bool:
        return key == self._account_id or key in self._accounts

    def __len__(self) -> int:
        keys = set(self._accounts.keys())
        if self._account_id:
            keys.add(self._account_id)
        return len(keys)

    def __iter__(self):
        seen = set()
        for key in self._accounts:
            seen.add(key)
            yield key
        if self._account_id and self._account_id not in seen:
            yield self._account_id

    def __bool__(self) -> bool:
        return bool(self._accounts) or bool(self._account_id)

    def _account_view(self) -> _AccountNonceRecordOverlay:
        raw = self._accounts.get(self._account_id)
        acct = raw if isinstance(raw, dict) else {}
        return _AccountNonceRecordOverlay(acct, self._nonce)

    def __getitem__(self, key: Any) -> Any:
        if key == self._account_id:
            return self._account_view()
        return self._accounts[key]

    def get(self, key: Any, default: Any = None) -> Any:
        if key == self._account_id:
            return self._account_view()
        return self._accounts.get(key, default)

    def keys(self):  # type: ignore[override]
        return list(iter(self))

    def values(self):  # type: ignore[override]
        for key in self:
            yield self.get(key)

    def items(self):  # type: ignore[override]
        for key in self:
            yield key, self.get(key)

    def copy(self) -> dict[str, Any]:  # type: ignore[override]
        out = dict(self._accounts)
        if self._account_id:
            out[self._account_id] = self._account_view().copy()
        return out


@dataclass(frozen=True, slots=True)
class LedgerView:
    """Immutable read-only ledger view used by runtime components.

    The view intentionally holds references to canonical ledger subtrees instead
    of deep-copying them.  Runtime admission and replay are read-only consumers;
    consensus mutation must happen through the executor/apply paths.  Candidate
    block nonce cursors are represented by deterministic overlay views rather
    than by cloning the full accounts map.

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
        accounts = state.get("accounts", {})
        roles = state.get("roles", {})
        params = state.get("params", {})
        poh = state.get("poh", {})
        disputes_by_id = state.get("disputes_by_id", {})
        consensus = state.get("consensus", {})
        return cls(
            accounts=accounts if isinstance(accounts, dict) else {},
            roles=roles if isinstance(roles, dict) else {},
            chain_id=str(state.get("chain_id") or ""),
            params=params if isinstance(params, dict) else {},
            last_block_ts_ms=int(state.get("last_block_ts_ms", 0) or 0),
            poh=poh if isinstance(poh, dict) else {},
            disputes_by_id=disputes_by_id if isinstance(disputes_by_id, dict) else {},
            consensus=consensus if isinstance(consensus, dict) else {},
        )

    def with_account_nonce(self, account_id: str, nonce: int) -> LedgerView:
        """Return a view with ``account_id``'s nonce overridden.

        This is a consensus-safe read overlay used for intra-block nonce
        admission.  It does not mutate the underlying ledger and does not clone
        the account map.
        """

        return LedgerView(
            accounts=_AccountsNonceOverlay(self.accounts, account_id, int(nonce or 0)),
            roles=self.roles,
            chain_id=str(self.chain_id or ""),
            params=self.params,
            last_block_ts_ms=int(self.last_block_ts_ms),
            poh=self.poh,
            disputes_by_id=self.disputes_by_id,
            consensus=self.consensus,
        )

    def to_ledger(self) -> dict[str, Any]:
        # Read-only ledger materialization for verification/gating callers.  The
        # returned mapping intentionally shares subtrees with the view to avoid
        # full-state clone costs in admission and block replay.
        return {
            "accounts": self.accounts,
            "roles": self.roles,
            "chain_id": str(self.chain_id or ""),
            "params": self.params,
            "last_block_ts_ms": int(self.last_block_ts_ms),
            "poh": self.poh,
            "disputes_by_id": self.disputes_by_id,
            "consensus": self.consensus,
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
