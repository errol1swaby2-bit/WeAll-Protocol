from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import yaml

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


@dataclass(frozen=True)
class TxCanonPaths:
    repo_root: Path
    spec_path: Path
    out_path: Path


@dataclass(frozen=True)
class GeneratedTxIndex:
    path: Path
    source_sha256: str
    tx_count: int
    regenerated: bool


@dataclass(frozen=True)
class _SpecTxEntry:
    id_num: int
    name: str
    domain: str
    origin: str
    gate: str
    context: str
    receipt_only: bool
    gates: dict[str, Any] | None


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


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def default_tx_canon_paths(
    *,
    spec_path: str | Path | None = None,
    out_path: str | Path | None = None,
) -> TxCanonPaths:
    repo_root = _repo_root()

    spec = Path(spec_path) if spec_path is not None else repo_root / "specs" / "tx_canon" / "tx_canon.yaml"
    out = Path(out_path) if out_path is not None else repo_root / "generated" / "tx_index.json"

    if not spec.is_absolute():
        spec = (repo_root / spec).resolve()

    if not out.is_absolute():
        out = (repo_root / out).resolve()

    return TxCanonPaths(repo_root=repo_root, spec_path=spec, out_path=out)


def _stable_id_hex(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _load_yaml(path: Path) -> Json:
    obj = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise CanonError("tx_canon.yaml must be a mapping")
    return obj


def _parse_spec_entries(spec: Json) -> list[_SpecTxEntry]:
    txs = spec.get("txs")
    if not isinstance(txs, list) or not txs:
        raise CanonError("tx_canon.yaml must have non-empty list field: txs")

    out: list[_SpecTxEntry] = []

    for idx, t in enumerate(txs):
        if not isinstance(t, dict):
            raise CanonError(f"tx[{idx}] must be a mapping")

        try:
            id_num = int(t.get("id"))
        except Exception as exc:
            raise CanonError(f"tx[{idx}].id must be an int") from exc

        name = str(t.get("name") or "").strip()
        if not name:
            raise CanonError(f"tx[{idx}].name missing")

        domain = str(t.get("domain") or "").strip() or "Unknown"
        origin = str(t.get("origin") or "USER").strip() or "USER"
        context = str(t.get("context") or "mempool").strip() or "mempool"
        receipt_only = bool(t.get("receipt_only") is True)

        legacy_gate = str(t.get("gate") or "").strip()
        gates = t.get("gates")
        if gates is not None and not isinstance(gates, dict):
            raise CanonError(f"tx[{idx}].gates must be a mapping if present")

        merged_gates: dict[str, Any] | None = dict(gates) if isinstance(gates, dict) else None

        subject_gate = ""
        if isinstance(merged_gates, dict) and str(merged_gates.get("subject_gate") or "").strip():
            subject_gate = str(merged_gates.get("subject_gate") or "").strip()
        elif legacy_gate:
            subject_gate = legacy_gate

        if subject_gate:
            if merged_gates is None:
                merged_gates = {}
            merged_gates.setdefault("subject_gate", subject_gate)

        out.append(
            _SpecTxEntry(
                id_num=id_num,
                name=name,
                domain=domain,
                origin=origin,
                gate=subject_gate,
                context=context,
                receipt_only=receipt_only,
                gates=merged_gates,
            )
        )

    ids = [e.id_num for e in out]
    if len(ids) != len(set(ids)):
        raise CanonError("duplicate tx ids in tx_canon.yaml")

    names = [e.name for e in out]
    if len(names) != len(set(names)):
        raise CanonError("duplicate tx names in tx_canon.yaml")

    out.sort(key=lambda e: e.id_num)
    return out


def _emit_generated_index(entries: list[_SpecTxEntry], *, spec: Json, source_sha256: str) -> Json:
    tx_types: list[Json] = []
    by_id: dict[str, int] = {}
    by_name: dict[str, int] = {}

    for seq, e in enumerate(entries):
        rec: Json = {
            "name": e.name,
            "domain": e.domain,
            "origin": e.origin,
            "context": e.context,
            "receipt_only": bool(e.receipt_only),
            "id": _stable_id_hex(e.name),
        }
        if e.gate:
            rec["subject_gate"] = e.gate
        if e.gates is not None:
            rec["gates"] = e.gates

        tx_types.append(rec)
        by_id[str(e.id_num)] = seq
        by_name[e.name] = seq

    meta = {
        "version": spec.get("version"),
        "source": spec.get("source"),
        "law": spec.get("law"),
    }

    return {
        "meta": meta,
        "source_sha256": source_sha256,
        "by_id": by_id,
        "by_name": by_name,
        "tx_types": tx_types,
    }


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


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        delete=False,
        prefix=f".{path.name}.",
        suffix=".tmp",
    ) as tmp:
        tmp.write(content)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def _index_tx_count(raw: Json) -> int:
    tx_types = raw.get("tx_types")
    if isinstance(tx_types, list):
        return len(tx_types)
    tx_map = raw.get("tx")
    if isinstance(tx_map, dict):
        return len(tx_map)
    return 0


def generate_tx_index_json(
    *,
    spec_path: str | Path | None = None,
    out_path: str | Path | None = None,
) -> GeneratedTxIndex:
    paths = default_tx_canon_paths(spec_path=spec_path, out_path=out_path)

    if not paths.spec_path.exists():
        raise CanonError(f"spec not found: {paths.spec_path}")

    source_sha256 = _sha256_file(paths.spec_path)
    spec = _load_yaml(paths.spec_path)
    entries = _parse_spec_entries(spec)
    obj = _emit_generated_index(entries, spec=spec, source_sha256=source_sha256)

    payload = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    _atomic_write_text(paths.out_path, payload)

    return GeneratedTxIndex(
        path=paths.out_path,
        source_sha256=source_sha256,
        tx_count=len(entries),
        regenerated=True,
    )


def ensure_tx_index_json(
    *,
    spec_path: str | Path | None = None,
    out_path: str | Path | None = None,
    force: bool = False,
) -> GeneratedTxIndex:
    paths = default_tx_canon_paths(spec_path=spec_path, out_path=out_path)

    if not paths.spec_path.exists():
        raise CanonError(f"spec not found: {paths.spec_path}")

    current_source_sha256 = _sha256_file(paths.spec_path)

    if not force and paths.out_path.exists():
        try:
            raw = json.loads(paths.out_path.read_text(encoding="utf-8"))
            _validate_index(raw)

            existing_hash = str(raw.get("source_sha256") or "").strip()
            if existing_hash == current_source_sha256 and _index_tx_count(raw) > 0:
                return GeneratedTxIndex(
                    path=paths.out_path,
                    source_sha256=current_source_sha256,
                    tx_count=_index_tx_count(raw),
                    regenerated=False,
                )
        except Exception:
            pass

    return generate_tx_index_json(spec_path=paths.spec_path, out_path=paths.out_path)


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
            receipt_only=bool(rule.get("receipt_only")),
            meta=base.meta,
        )
    return base


__all__ = [
    "CanonError",
    "CanonRule",
    "GeneratedTxIndex",
    "TxCanonPaths",
    "TxIndex",
    "default_tx_canon_paths",
    "ensure_tx_index_json",
    "generate_tx_index_json",
    "get_canon_rule",
    "load_tx_index_json",
    "load_tx_index_json_raw",
]
