"""weall.ledger.types

Route B: LedgerState object model + strict schema validation + versioned migrations.

This module defines:
  - LedgerState: JSON-backed MutableMapping dataclass
  - strict minimal schema enforcement
  - state_version enforcement (migration happens before strict validation)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, MutableMapping, Optional

from weall.ledger.migrations import CURRENT_STATE_VERSION

Json = Dict[str, Any]


def _coerce_int(v: Any, *, field: str) -> int:
    try:
        # bool is an int subclass; disallow it explicitly
        if isinstance(v, bool):
            raise ValueError("bool is not a valid int")
        return int(v)
    except Exception as e:
        raise ValueError(f"LedgerState schema error: field '{field}' must be int-coercible (got {type(v).__name__})") from e


def _coerce_str(v: Any, *, field: str) -> str:
    try:
        return str(v) if v is not None else ""
    except Exception as e:
        raise ValueError(f"LedgerState schema error: field '{field}' must be str-coercible (got {type(v).__name__})") from e


def _require_dict(v: Any, *, field: str, strict: bool) -> Dict[str, Any]:
    if isinstance(v, dict):
        return v
    if v is None:
        return {}
    if strict:
        raise ValueError(f"LedgerState schema error: field '{field}' must be dict (got {type(v).__name__})")
    return {}


def _require_boolish(v: Any, *, field: str) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and v in (0, 1):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return True
        if s in {"0", "false", "no", "n", "off"}:
            return False
    raise ValueError(f"LedgerState schema error: field '{field}' must be bool-ish (got {type(v).__name__})")


@dataclass
class LedgerState(MutableMapping[str, Any]):
    """Mutable ledger state with a stable, JSON-backed schema."""
    _data: Json = field(default_factory=dict)

    # ---- Mapping protocol (back-compat) ----

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._data[key] = value

    def __delitem__(self, key: str) -> None:
        del self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        return self._data.get(key, default)

    # ---- JSON interop ----

    def to_dict(self) -> Json:
        return dict(self._data)

    @classmethod
    def from_dict(cls, d: Any) -> "LedgerState":
        return cls(_data=d if isinstance(d, dict) else {})

    # ---- Convenience roots ----

    @property
    def state_version(self) -> int:
        try:
            return int(self._data.get("state_version", 0))
        except Exception:
            return 0

    @property
    def height(self) -> int:
        try:
            return int(self._data.get("height", 0))
        except Exception:
            return 0

    @height.setter
    def height(self, v: int) -> None:
        self._data["height"] = int(v)

    @property
    def tip(self) -> str:
        return str(self._data.get("tip", "") or "")

    @tip.setter
    def tip(self, v: str) -> None:
        self._data["tip"] = str(v or "")

    @property
    def accounts(self) -> Json:
        a = self._data.get("accounts")
        if not isinstance(a, dict):
            a = {}
            self._data["accounts"] = a
        return a

    @property
    def roles(self) -> Json:
        r = self._data.get("roles")
        if not isinstance(r, dict):
            r = {}
            self._data["roles"] = r
        return r

    @property
    def finalized(self) -> Json:
        f = self._data.get("finalized")
        if not isinstance(f, dict):
            f = {"height": 0, "block_id": ""}
            self._data["finalized"] = f
        if "height" not in f:
            f["height"] = 0
        if "block_id" not in f:
            f["block_id"] = ""
        return f

    @property
    def block_attestations(self) -> Json:
        ba = self._data.get("block_attestations")
        if not isinstance(ba, dict):
            ba = {}
            self._data["block_attestations"] = ba
        return ba

    @property
    def blocks(self) -> Json:
        b = self._data.get("blocks")
        if not isinstance(b, dict):
            b = {}
            self._data["blocks"] = b
        return b

    @property
    def params(self) -> Json:
        p = self._data.get("params")
        if not isinstance(p, dict):
            p = {}
            self._data["params"] = p
        return p

    # ---- Schema normalization + strict validation ----

    def ensure_minimal_schema(
        self,
        *,
        ensure_producer: Optional[str] = None,
        strict: bool = True,
    ) -> None:
        """
        Backfill required roots and validate minimal invariants.

        IMPORTANT:
          - This function assumes migrations have already upgraded state_version
            to CURRENT_STATE_VERSION.
          - If strict=True and state_version != CURRENT_STATE_VERSION, this raises.
        """

        # state_version must exist and match
        if "state_version" not in self._data:
            if strict:
                raise ValueError(
                    "LedgerState schema error: missing state_version (run migrations before strict validation)."
                )
            self._data["state_version"] = CURRENT_STATE_VERSION
        else:
            v = _coerce_int(self._data.get("state_version"), field="state_version") if strict else int(self._data.get("state_version") or 0)
            if strict and v != CURRENT_STATE_VERSION:
                raise ValueError(
                    f"LedgerState schema error: state_version={v} != CURRENT_STATE_VERSION={CURRENT_STATE_VERSION} "
                    "(run migrations)."
                )
            if not strict:
                self._data["state_version"] = CURRENT_STATE_VERSION
            else:
                self._data["state_version"] = v

        # height/tip
        if "height" not in self._data:
            self._data["height"] = 0
        else:
            self._data["height"] = _coerce_int(self._data.get("height"), field="height") if strict else int(self._data.get("height") or 0)

        if "tip" not in self._data:
            self._data["tip"] = ""
        else:
            self._data["tip"] = _coerce_str(self._data.get("tip"), field="tip") if strict else str(self._data.get("tip") or "")

        # roots
        self._data["accounts"] = _require_dict(self._data.get("accounts"), field="accounts", strict=strict)
        self._data["roles"] = _require_dict(self._data.get("roles"), field="roles", strict=strict)
        self._data["blocks"] = _require_dict(self._data.get("blocks"), field="blocks", strict=strict)
        self._data["params"] = _require_dict(self._data.get("params"), field="params", strict=strict)
        self._data["block_attestations"] = _require_dict(
            self._data.get("block_attestations"), field="block_attestations", strict=strict
        )

        # finalized
        fin_raw = self._data.get("finalized")
        if fin_raw is None:
            fin = {"height": 0, "block_id": ""}
            self._data["finalized"] = fin
        else:
            fin = _require_dict(fin_raw, field="finalized", strict=strict)
            self._data["finalized"] = fin

        if "height" not in fin:
            fin["height"] = 0
        else:
            fin["height"] = _coerce_int(fin.get("height"), field="finalized.height") if strict else int(fin.get("height") or 0)

        if "block_id" not in fin:
            fin["block_id"] = ""
        else:
            fin["block_id"] = _coerce_str(fin.get("block_id"), field="finalized.block_id") if strict else str(fin.get("block_id") or "")

        # validate accounts entries (minimal)
        accounts = self._data["accounts"]
        if isinstance(accounts, dict):
            for aid, acct_raw in list(accounts.items()):
                if strict:
                    _ = _coerce_str(aid, field="accounts.<account_id>")
                if not isinstance(acct_raw, dict):
                    if strict:
                        raise ValueError(
                            f"LedgerState schema error: accounts['{aid}'] must be dict (got {type(acct_raw).__name__})"
                        )
                    accounts[aid] = {}
                    acct_raw = accounts[aid]

                acct = acct_raw
                acct["nonce"] = _coerce_int(acct.get("nonce", 0), field=f"accounts['{aid}'].nonce") if strict else int(acct.get("nonce") or 0)
                acct["poh_tier"] = _coerce_int(acct.get("poh_tier", 0), field=f"accounts['{aid}'].poh_tier") if strict else int(acct.get("poh_tier") or 0)

                if strict:
                    acct["banned"] = _require_boolish(acct.get("banned", False), field=f"accounts['{aid}'].banned")
                    acct["locked"] = _require_boolish(acct.get("locked", False), field=f"accounts['{aid}'].locked")
                else:
                    acct["banned"] = bool(acct.get("banned", False))
                    acct["locked"] = bool(acct.get("locked", False))

                if strict:
                    try:
                        acct["reputation"] = float(acct.get("reputation", 0.0))
                    except Exception as e:
                        raise ValueError(
                            f"LedgerState schema error: accounts['{aid}'].reputation must be float-coercible "
                            f"(got {type(acct.get('reputation')).__name__})"
                        ) from e
                else:
                    try:
                        acct["reputation"] = float(acct.get("reputation", 0.0))
                    except Exception:
                        acct["reputation"] = 0.0

        # Ensure producer exists
        if ensure_producer:
            pid = str(ensure_producer).strip()
            if pid and pid not in self.accounts:
                self.accounts[pid] = {
                    "nonce": 0,
                    "poh_tier": 3,
                    "banned": False,
                    "locked": False,
                    "reputation": 0.0,
                }


__all__ = ["LedgerState", "Json"]
