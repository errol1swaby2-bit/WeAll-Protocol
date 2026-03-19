from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

Json = dict[str, Any]


class CanonError(Exception):
    """Raised for tx canon/index loading/validation errors."""


@dataclass(frozen=True)
class CanonRule:
    """
    Lightweight representation of tx canon rules.

    Note: In the current generated tx_index.json, many tx records are minimal.
    Some admission rules are MVP-hardcoded in runtime admission until schema is
    fully encoded in the index.
    """

    tx_type: str
    payload_required: tuple[str, ...] = ()
    payload_account_id_fields: tuple[str, ...] = ()
    requires_parent: bool = False
    receipt_only: bool = False
    meta: Json = field(default_factory=dict)


def _d(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _s(x: Any) -> str:
    return "" if x is None else str(x)


def _as_tuple_str(xs: Any) -> tuple[str, ...]:
    if not xs:
        return ()
    if isinstance(xs, (list, tuple)):
        return tuple(_s(x) for x in xs if _s(x))
    return ()


def _canon_rule_from_json(tx_type: str, j: Json) -> CanonRule:
    j = _d(j)
    return CanonRule(
        tx_type=tx_type,
        payload_required=_as_tuple_str(j.get("payload_required")),
        payload_account_id_fields=_as_tuple_str(j.get("payload_account_id_fields")),
        requires_parent=bool(j.get("requires_parent") or False),
        receipt_only=bool(j.get("receipt_only") or False),
        meta=_d(j.get("meta")),
    )


def _validate_index(idx: Json) -> None:
    if not isinstance(idx, dict):
        raise ValueError("tx index must be a dict")

    # Supported shapes:
    #  - legacy: {"tx": {"TX_TYPE": {rule...}}}
    #  - current: {"by_name": {...}, "by_id": {...}, "tx_types": [...]}
    if "tx" in idx:
        if not isinstance(idx.get("tx"), dict):
            raise ValueError("tx index 'tx' must be a dict")
        return

    if "by_name" in idx:
        if not isinstance(idx.get("by_name"), dict):
            raise ValueError("tx index 'by_name' must be a dict")
        if "by_id" in idx and not isinstance(idx.get("by_id"), dict):
            raise ValueError("tx index 'by_id' must be a dict")
        if "tx_types" in idx and not isinstance(idx.get("tx_types"), list):
            raise ValueError("tx index 'tx_types' must be a list")
        return

    raise ValueError("tx index must contain either 'tx' or 'by_name'")


def load_tx_index_json_raw(path: str | Path) -> Json:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"tx index json not found: {p}")
    with p.open("r", encoding="utf-8") as f:
        idx = json.load(f)
    _validate_index(idx)
    return idx


def load_tx_index_json(path: str | Path) -> TxIndex:
    return TxIndex.load_from_file(path)


def _tx_rules_dict(canon: Any) -> Json:
    if isinstance(canon, TxIndex):
        return canon.by_name

    if not isinstance(canon, dict):
        raw = getattr(canon, "raw", None)
        if isinstance(raw, dict):
            canon = raw
        else:
            return {}

    tx = canon.get("tx")
    if isinstance(tx, dict):
        return tx

    by_name = canon.get("by_name")
    if not isinstance(by_name, dict):
        return {}
    by_id = canon.get("by_id")
    by_id = by_id if isinstance(by_id, dict) else {}
    tx_types = canon.get("tx_types")
    tx_types = tx_types if isinstance(tx_types, list) else []

    out: Json = {}
    for name, ident in by_name.items():
        if not isinstance(name, str):
            continue

        if isinstance(ident, int):
            rec = (
                tx_types[ident]
                if 0 <= ident < len(tx_types) and isinstance(tx_types[ident], dict)
                else {}
            )
            out[name] = rec
            continue

        if isinstance(ident, str):
            rec = by_id.get(ident)
            out[name] = rec if isinstance(rec, dict) else {}
            continue

    return out


@dataclass(slots=True)
class TxIndex:
    """
    Normalized transaction index.

    IMPORTANT: tests construct TxIndex directly; keep defaults permissive.
    """

    tx_types: list[Json] = field(default_factory=list)
    by_name: dict[str, Json] = field(default_factory=dict)
    by_id: dict[int, Json] = field(default_factory=dict)
    by_id_str: dict[str, Json] = field(default_factory=dict)
    meta: Json = field(default_factory=dict)
    source_sha256: str = ""
    raw: Json = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Json, *, source_sha256: str = "") -> TxIndex:
        if not isinstance(raw, dict):
            raise CanonError("tx index must be a dict")

        # current generated format
        tx_types0 = raw.get("tx_types")
        if isinstance(tx_types0, list) and tx_types0:
            tx_types: list[Json] = [t if isinstance(t, dict) else {} for t in tx_types0]
            by_name: dict[str, Json] = {}
            by_id_str: dict[str, Json] = {}
            by_id: dict[int, Json] = {}

            for seq, t in enumerate(tx_types, start=1):
                name = _s(t.get("name")).upper()
                if name:
                    by_name[name] = t

                tid = t.get("id")
                if tid is not None:
                    tid_s = _s(tid)
                    if tid_s:
                        by_id_str[tid_s] = t
                    try:
                        by_id[int(tid)] = t
                    except Exception:
                        pass

                if seq not in by_id:
                    by_id[seq] = t

            return cls(
                tx_types=tx_types,
                by_name=by_name,
                by_id=by_id,
                by_id_str=by_id_str,
                meta=_d(raw.get("meta")),
                source_sha256=_s(source_sha256 or raw.get("source_sha256") or ""),
                raw=raw,
            )

        # legacy format
        tx_map = raw.get("tx")
        if isinstance(tx_map, dict):
            tx_types = []
            by_name = {}
            by_id = {}
            by_id_str = {}
            i = 0
            for name, spec in tx_map.items():
                if not isinstance(name, str):
                    continue
                i += 1
                entry: Json = {"id": i, "name": name}
                if isinstance(spec, dict):
                    entry.update(spec)
                tx_types.append(entry)
                by_name[name.upper()] = entry
                by_id[i] = entry
                by_id_str[str(i)] = entry
            return cls(
                tx_types=tx_types,
                by_name=by_name,
                by_id=by_id,
                by_id_str=by_id_str,
                meta=_d(raw.get("meta")),
                source_sha256=_s(source_sha256 or raw.get("source_sha256") or ""),
                raw=raw,
            )

        return cls(meta=_d(raw.get("meta")), source_sha256=_s(source_sha256), raw=raw)

    @classmethod
    def load_from_file(cls, path: str | Path) -> TxIndex:
        try:
            raw = load_tx_index_json_raw(path)
        except Exception as e:
            raise CanonError(str(e)) from e
        return cls.from_raw(raw)

    def get(self, tx_type: str, default: Any = None) -> Any:
        name = _s(tx_type).upper().strip()
        return self.by_name.get(name, default)

    def is_known(self, tx_type: str) -> bool:
        return bool(self.get(tx_type) is not None)

    def list_types(self) -> list[str]:
        return sorted(self.by_name.keys())


def get_canon_rule(canon: Json, tx_type: str) -> CanonRule:
    tx = _tx_rules_dict(canon)
    rule = _d(tx.get(tx_type))
    base = _canon_rule_from_json(tx_type, rule)
    if "receipt_only" in rule:
        return CanonRule(
            tx_type=base.tx_type,
            payload_required=base.payload_required,
            payload_account_id_fields=base.payload_account_id_fields,
            requires_parent=base.requires_parent,
            receipt_only=bool(rule.get("receipt_only") or False),
            meta=base.meta,
        )
    return base


def list_tx_types(canon: Json) -> list[str]:
    tx = _tx_rules_dict(canon)
    return sorted([k for k in tx.keys() if isinstance(k, str)])


def is_tx_type_known(canon: Json, tx_type: str) -> bool:
    tx = _tx_rules_dict(canon)
    return str(tx_type) in tx


_DEFAULT_TX_INDEX_CANDIDATES: tuple[str, ...] = (
    "generated/tx_index.json",
    "generated/tx_canon_index.json",
    "generated/tx_canon.json",
    "tx_index.json",
)


def load_tx_canon_index(path: str | None = None) -> Json:
    if path:
        return load_tx_index_json_raw(path)

    env_path = os.getenv("WEALL_TX_INDEX_PATH", "").strip()
    if env_path:
        return load_tx_index_json_raw(env_path)

    here = Path(__file__).resolve()
    roots = []
    if len(here.parents) >= 4:
        roots.append(here.parents[3])
    if len(here.parents) >= 3:
        roots.append(here.parents[2])

    tried: list[Path] = []
    for root in roots:
        for rel in _DEFAULT_TX_INDEX_CANDIDATES:
            candidate = (root / rel).resolve()
            tried.append(candidate)
            if candidate.exists():
                return load_tx_index_json_raw(str(candidate))

    raise FileNotFoundError(
        "Could not locate tx canon index. Set WEALL_TX_INDEX_PATH or generate tx_index.json. "
        f"Tried: {[str(p) for p in tried]}"
    )


def load_tx_index_auto(path: str | None = None) -> TxIndex:
    return TxIndex.from_raw(load_tx_canon_index(path=path))


__all__ = [
    "CanonError",
    "CanonRule",
    "TxIndex",
    "get_canon_rule",
    "is_tx_type_known",
    "list_tx_types",
    "load_tx_canon_index",
    "load_tx_index_auto",
    "load_tx_index_json",
]
