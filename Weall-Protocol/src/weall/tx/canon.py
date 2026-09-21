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
    parent: str
    parent_tx_types: tuple[str, ...]
    system_only: bool
    via_gov_execute: bool
    min_reputation: float | int | None
    gates: dict[str, Any] | None


def _d(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _s(x: Any) -> str:
    return "" if x is None else str(x)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def default_tx_canon_paths(
    *,
    spec_path: str | Path | None = None,
    out_path: str | Path | None = None,
) -> TxCanonPaths:
    repo_root = _repo_root()

    spec = (
        Path(spec_path)
        if spec_path is not None
        else repo_root / "specs" / "tx_canon" / "tx_canon.yaml"
    )
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
        parent = str(t.get("parent") or "").strip()
        parent_any_raw = t.get("parent_any_of")
        if parent_any_raw is None:
            parent_tx_types = (parent,) if parent else ()
        else:
            if not isinstance(parent_any_raw, list) or not parent_any_raw:
                raise CanonError(f"tx[{idx}].parent_any_of must be a non-empty list if present")
            normalized_parents: list[str] = []
            seen_parents: set[str] = set()
            for parent_idx, raw_parent in enumerate(parent_any_raw):
                if not isinstance(raw_parent, str) or not raw_parent.strip():
                    raise CanonError(
                        f"tx[{idx}].parent_any_of[{parent_idx}] must be a non-empty TxType string"
                    )
                parent_name = raw_parent.strip()
                if parent_name in seen_parents:
                    raise CanonError(f"tx[{idx}].parent_any_of contains duplicate {parent_name}")
                seen_parents.add(parent_name)
                normalized_parents.append(parent_name)
            if not parent:
                raise CanonError(f"tx[{idx}].parent_any_of requires compatibility-primary parent")
            if parent not in seen_parents:
                raise CanonError(f"tx[{idx}].parent must be included in parent_any_of")
            parent_tx_types = tuple(normalized_parents)
        system_only = bool(t.get("system_only") is True)
        via_gov_execute = bool(t.get("via_gov_execute") is True)
        min_reputation_raw = t.get("min_reputation")
        min_reputation: float | int | None
        if min_reputation_raw is None:
            min_reputation = None
        elif isinstance(min_reputation_raw, bool) or not isinstance(
            min_reputation_raw, (int, float)
        ):
            raise CanonError(f"tx[{idx}].min_reputation must be numeric if present")
        else:
            min_reputation = min_reputation_raw

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
                parent=parent,
                parent_tx_types=parent_tx_types,
                system_only=system_only,
                via_gov_execute=via_gov_execute,
                min_reputation=min_reputation,
                gates=merged_gates,
            )
        )

    ids = [e.id_num for e in out]
    if len(ids) != len(set(ids)):
        raise CanonError("duplicate tx ids in tx_canon.yaml")

    names = [e.name for e in out]
    if len(names) != len(set(names)):
        raise CanonError("duplicate tx names in tx_canon.yaml")

    known_names = set(names)
    for entry in out:
        for parent_name in entry.parent_tx_types:
            if parent_name not in known_names:
                raise CanonError(f"tx {entry.name} references unknown parent TxType {parent_name}")

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
        if e.parent:
            # Canon ``parent`` names the compatibility-primary causal TxType. It is
            # relationship metadata, not a concrete transaction-instance reference.
            # Multi-causal receipt flows additionally expose ``parent_tx_types``.
            rec["parent_tx_type"] = e.parent
        if len(e.parent_tx_types) > 1:
            rec["parent_tx_types"] = list(e.parent_tx_types)
        if e.system_only:
            rec["system_only"] = True
        if e.via_gov_execute:
            rec["via_gov_execute"] = True
        if e.min_reputation is not None:
            rec["min_reputation"] = e.min_reputation
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
        by_name = idx.get("by_name")
        by_id = idx.get("by_id")
        tx_types = idx.get("tx_types")
        if not isinstance(by_name, dict):
            raise ValueError("tx index 'by_name' must be a dict")
        if not isinstance(by_id, dict):
            raise ValueError("tx index 'by_id' must be a dict")
        if not isinstance(tx_types, list):
            raise ValueError("tx index 'tx_types' must be a list")

        # Empty indexes are retained for isolated startup/unit-test fixtures, but
        # any populated current index must be internally bijective. This prevents
        # consumers from silently reconstructing a different ID/name view.
        if not tx_types:
            if by_name or by_id:
                raise ValueError("empty tx_types requires empty by_name and by_id")
            return

        if len(by_name) != len(tx_types):
            raise ValueError("tx index 'by_name' must cover tx_types exactly")
        if len(by_id) != len(tx_types):
            raise ValueError("tx index 'by_id' must cover tx_types exactly")

        names: set[str] = set()
        for pos, rec in enumerate(tx_types):
            if not isinstance(rec, dict):
                raise ValueError(f"tx index tx_types[{pos}] must be a dict")
            name = str(rec.get("name") or "").strip()
            if not name:
                raise ValueError(f"tx index tx_types[{pos}] is missing name")
            if name in names:
                raise ValueError(f"tx index duplicate tx name: {name}")
            names.add(name)

        by_name_positions: set[int] = set()
        for name, pos in by_name.items():
            if not isinstance(name, str) or type(pos) is not int:
                raise ValueError("tx index 'by_name' entries must map names to integer indexes")
            if pos < 0 or pos >= len(tx_types):
                raise ValueError(f"tx index 'by_name' index out of range for {name!r}")
            if str(tx_types[pos].get("name") or "").strip() != name:
                raise ValueError(f"tx index 'by_name' mismatch for {name!r}")
            by_name_positions.add(pos)
        if by_name_positions != set(range(len(tx_types))):
            raise ValueError("tx index 'by_name' indexes must cover tx_types exactly")

        by_id_positions: set[int] = set()
        for raw_id, pos in by_id.items():
            if not isinstance(raw_id, str) or type(pos) is not int:
                raise ValueError("tx index 'by_id' entries must map string ids to integer indexes")
            try:
                int(raw_id)
            except ValueError as exc:
                raise ValueError(f"tx index contains invalid numeric id {raw_id!r}") from exc
            if pos < 0 or pos >= len(tx_types):
                raise ValueError(f"tx index 'by_id' index out of range for {raw_id!r}")
            by_id_positions.add(pos)
        if by_id_positions != set(range(len(tx_types))):
            raise ValueError("tx index 'by_id' indexes must cover tx_types exactly")
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


def _resolve_existing_tx_index_path(path: str | Path) -> Path:
    requested = Path(path)
    if requested.exists():
        return requested

    search_relatives: list[Path] = []
    if not requested.is_absolute():
        search_relatives.append(requested)
    else:
        parts = requested.parts
        for marker in ("generated", "tx_index.json"):
            if marker in parts:
                idx = parts.index(marker)
                search_relatives.append(Path(*parts[idx:]))
                break
        if requested.name:
            search_relatives.append(Path(requested.name))

    module_path = Path(__file__).resolve()
    candidate_bases = list(module_path.parents)
    seen: set[Path] = set()
    for rel in search_relatives:
        for base in candidate_bases:
            candidate = (base / rel).resolve()
            if candidate in seen:
                continue
            seen.add(candidate)
            if candidate.exists():
                return candidate

    raise FileNotFoundError(f"tx index json not found: {requested}")


def load_tx_index_json_raw(path: str | Path) -> Json:
    p = _resolve_existing_tx_index_path(path)
    with p.open("r", encoding="utf-8") as f:
        idx = json.load(f)
    _validate_index(idx)
    return idx


def load_tx_index_json(path: str | Path) -> TxIndex:
    return TxIndex.load_from_file(path)


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
        if isinstance(tx_types0, list):
            try:
                _validate_index(raw)
            except ValueError as exc:
                raise CanonError(str(exc)) from exc

            tx_types: list[Json] = [t for t in tx_types0 if isinstance(t, dict)]
            if not tx_types:
                return cls(
                    meta=_d(raw.get("meta")),
                    source_sha256=_s(source_sha256 or raw.get("source_sha256") or ""),
                    raw=raw,
                )

            raw_by_name = raw.get("by_name")
            raw_by_id = raw.get("by_id")
            if not isinstance(raw_by_name, dict) or not isinstance(raw_by_id, dict):
                raise CanonError("validated current tx index lost lookup maps")

            by_name: dict[str, Json] = {}
            by_id: dict[int, Json] = {}
            by_id_str: dict[str, Json] = {}

            # Honor the generated lookup maps instead of rebuilding a different
            # interpretation from record order or the stable hash identifier.
            for name, pos in raw_by_name.items():
                rec = tx_types[int(pos)]
                by_name[str(name).upper()] = rec

            for raw_id, pos in raw_by_id.items():
                rec = tx_types[int(pos)]
                by_id[int(raw_id)] = rec

            # Preserve the historical stable-string lookup as a compatibility
            # surface. It is intentionally distinct from canonical numeric IDs.
            for rec in tx_types:
                stable_id = _s(rec.get("id"))
                if stable_id:
                    by_id_str[stable_id] = rec

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


__all__ = [
    "CanonError",
    "GeneratedTxIndex",
    "TxCanonPaths",
    "TxIndex",
    "default_tx_canon_paths",
    "ensure_tx_index_json",
    "generate_tx_index_json",
    "load_tx_index_json",
    "load_tx_index_json_raw",
]
