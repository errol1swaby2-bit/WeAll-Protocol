# src/weall/tx/canon.py
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TypedDict


# NOTE: PyYAML is available in the WeAll dev/test environment. We keep the import
# local in the YAML loader so JSON-only tooling stays lightweight.


class CanonError(RuntimeError):
    pass


class CanonTxType(TypedDict, total=False):
    """
    Canonical TxType entry.

    total=False so we can carry extra forward-compatible fields
    while validating required fields at load-time.
    """
    id: int
    name: str
    domain: str
    origin: str
    context: str
    receipt_only: bool

    # Gate field(s). We normalize these on load.
    gate: str
    subject_gate: str

    via_gov_execute: bool
    min_reputation: float | int
    parent_types: List[str]
    notes: str


@dataclass(frozen=True)
class TxIndex:
    """
    Normalized TxType index.

    - by_id uses int keys (canonical internal view)
    - by_id_str uses str keys (interop view: matches common JSON map keys like "1")
    """
    tx_types: List[CanonTxType]
    by_name: Dict[str, CanonTxType]
    by_id: Dict[int, CanonTxType]
    by_id_str: Dict[str, CanonTxType]
    meta: Dict[str, Any]
    source_sha256: str

    def get(self, name: str) -> Optional[CanonTxType]:
        return self.by_name.get(name)

    def get_by_id(self, tx_id: int) -> Optional[CanonTxType]:
        return self.by_id.get(int(tx_id))

    def get_by_id_str(self, tx_id: str) -> Optional[CanonTxType]:
        return self.by_id_str.get(str(tx_id))

    @classmethod
    def load_from_file(cls, path: str | Path) -> "TxIndex":
        """Load a tx_index.json into a TxIndex.

        Several CLI tools call `TxIndex.load_from_file(...)` for convenience.
        The canonical loader is `load_tx_index_json`, but exposing this
        shim keeps the API stable.
        """
        # Prefer the generated JSON artifact (fast, canonical).
        # But for dev/testnet zips it may be missing or empty; in that case
        # fall back to specs/tx_canon/tx_canon.yaml.
        try:
            return load_tx_index_json(path)
        except CanonError:
            fb = _try_load_fallback_from_yaml()
            if fb is not None:
                return fb
            raise


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _candidate_roots_for_repo_search() -> List[Path]:
    """
    Build a list of "root" directories to probe for generated artifacts.

    This is intentionally conservative and fast:
      - CWD + its parents
      - the directory containing this file + its parents
    """
    roots: List[Path] = []
    try:
        cwd = Path.cwd().resolve()
        roots.append(cwd)
        roots.extend(list(cwd.parents))
    except Exception:
        pass

    try:
        here = Path(__file__).resolve()
        roots.append(here.parent)
        roots.extend(list(here.parents))
    except Exception:
        pass

    # de-dup while preserving order
    seen: set[str] = set()
    out: List[Path] = []
    for r in roots:
        k = str(r)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


def _resolve_existing_path(path: str | Path) -> Optional[Path]:
    """
    Resolve a canon artifact path robustly so tests/tools can run from
    different working directories (e.g. repo root vs ~/projects).

    Resolution strategy:
      1) direct path as given
      2) if relative: search upwards from CWD and from this file for:
           - <root>/<path>
           - <root>/Weall-Protocol/<path>         (common monorepo layout)
           - <root>/weall_release/Weall-Protocol/<path> (rare sandbox layouts)
      3) if path looks like generated/tx_index.json, also try:
           - <root>/generated/tx_index.json
           - <root>/Weall-Protocol/generated/tx_index.json
    """
    p = Path(path)
    if p.exists():
        return p

    if p.is_absolute():
        return None

    rel = p

    # Special-case hinting
    is_generated_tx_index = rel.as_posix().endswith("generated/tx_index.json") or rel.as_posix().endswith(
        "generated\\tx_index.json"
    )

    for root in _candidate_roots_for_repo_search():
        # Try <root>/<rel>
        c1 = (root / rel).resolve()
        if c1.exists():
            return c1

        # Try <root>/Weall-Protocol/<rel>
        c2 = (root / "Weall-Protocol" / rel).resolve()
        if c2.exists():
            return c2

        # Try <root>/weall_release/Weall-Protocol/<rel> (sandbox helper)
        c3 = (root / "weall_release" / "Weall-Protocol" / rel).resolve()
        if c3.exists():
            return c3

        if is_generated_tx_index:
            # Try common direct generated location
            c4 = (root / "generated" / "tx_index.json").resolve()
            if c4.exists():
                return c4

            c5 = (root / "Weall-Protocol" / "generated" / "tx_index.json").resolve()
            if c5.exists():
                return c5

    return None


def _read_bytes(path: str | Path) -> bytes:
    p = _resolve_existing_path(path)
    if not p:
        raise CanonError(f"canon artifact not found: {Path(path)}")
    return p.read_bytes()


def _is_int_string(s: str) -> bool:
    try:
        int(s)
        return True
    except Exception:
        return False


def _looks_like_tx_obj(v: Any) -> bool:
    if not isinstance(v, dict):
        return False
    # id may be int or numeric-string; name must be str
    vid = v.get("id")
    if isinstance(vid, int):
        ok_id = True
    elif isinstance(vid, str) and _is_int_string(vid):
        ok_id = True
    else:
        ok_id = False
    return ok_id and isinstance(v.get("name"), str)


def _normalize_id(v: Any) -> Optional[int]:
    if isinstance(v, int):
        return v
    if isinstance(v, str) and _is_int_string(v):
        try:
            return int(v)
        except Exception:
            return None
    return None


def _validate_entry(tx: CanonTxType) -> None:
    if not isinstance(tx, dict):
        raise CanonError("tx entry must be an object")

    if "name" not in tx:
        raise CanonError("tx entry missing required field: name")
    if "id" not in tx:
        raise CanonError(f"tx '{tx.get('name', '?')}' missing required field: id")

    name = tx.get("name")
    tx_id = tx.get("id")

    if not isinstance(name, str) or not name:
        raise CanonError("tx entry 'name' must be non-empty string")

    norm_id = _normalize_id(tx_id)
    if norm_id is None:
        raise CanonError(f"tx '{name}' id must be int (or numeric-string)")
    # enforce normalized int in-place
    tx["id"] = norm_id


def _extract_from_id_keyed_mapping(d: Dict[str, Any]) -> Tuple[List[CanonTxType], Dict[str, Any], int]:
    """
    If dict contains numeric-string keys whose values look like tx objects,
    extract those as entries. Everything else is meta.
    Returns (entries, meta, score) where score reflects confidence.
    """
    entries: List[CanonTxType] = []
    meta: Dict[str, Any] = {}
    idkey_count = 0
    txobj_count = 0

    for k, v in d.items():
        if isinstance(k, str) and _is_int_string(k):
            idkey_count += 1
            if _looks_like_tx_obj(v):
                txobj_count += 1
                entries.append(v)  # type: ignore[arg-type]
            else:
                meta[k] = v
        else:
            meta[k] = v

    score = txobj_count * 10 - max(0, (idkey_count - txobj_count))

    if entries:
        # normalize ids before sorting
        for e in entries:
            _validate_entry(e)
        entries.sort(key=lambda x: int(x.get("id", 0)))
    return entries, meta, score


def _extract_from_list(lst: List[Any]) -> Tuple[List[CanonTxType], Dict[str, Any], int]:
    entries: List[CanonTxType] = [v for v in lst if _looks_like_tx_obj(v)]  # type: ignore[list-item]
    score = len(entries) * 10
    meta: Dict[str, Any] = {}
    if entries:
        for e in entries:
            _validate_entry(e)
        entries.sort(key=lambda x: int(x.get("id", 0)))
    return entries, meta, score


def _scan_for_best_candidate(
    obj: Any, path: str = "$", depth: int = 0, max_depth: int = 12
) -> Tuple[List[CanonTxType], Dict[str, Any], int, str]:
    """
    Recursively scan JSON to find the best subtree that represents tx entries.
    Candidates:
      - list with tx objects
      - dict with 'tx_types' list
      - dict with 'txs' as list/dict
      - dict with id-keyed mapping (possibly mixed with meta keys)
    Returns (entries, meta, score, where_found)
    """
    best_entries: List[CanonTxType] = []
    best_meta: Dict[str, Any] = {}
    best_score = -10**9
    best_where = ""

    if depth > max_depth:
        return best_entries, best_meta, best_score, best_where

    if isinstance(obj, list):
        entries, meta, score = _extract_from_list(obj)
        if score > best_score:
            best_entries, best_meta, best_score, best_where = entries, meta, score, path

    elif isinstance(obj, dict):
        if "tx_types" in obj and isinstance(obj["tx_types"], list):
            entries, _m, score = _extract_from_list(obj["tx_types"])  # type: ignore[arg-type]
            meta = {k: v for k, v in obj.items() if k != "tx_types"}
            if score > best_score:
                best_entries, best_meta, best_score, best_where = entries, meta, score, f"{path}.tx_types"

        if "txs" in obj:
            if isinstance(obj["txs"], list):
                entries, _m, score = _extract_from_list(obj["txs"])  # type: ignore[arg-type]
                meta = {k: v for k, v in obj.items() if k != "txs"}
                if score > best_score:
                    best_entries, best_meta, best_score, best_where = entries, meta, score, f"{path}.txs"
            elif isinstance(obj["txs"], dict):
                entries, inner_meta, score = _extract_from_id_keyed_mapping(obj["txs"])  # type: ignore[arg-type]
                meta = {k: v for k, v in obj.items() if k != "txs"}
                meta.update(inner_meta)
                if score > best_score:
                    best_entries, best_meta, best_score, best_where = entries, meta, score, f"{path}.txs"

        entries, meta, score = _extract_from_id_keyed_mapping(obj)
        if score > best_score:
            best_entries, best_meta, best_score, best_where = entries, meta, score, path

        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                e2, m2, s2, w2 = _scan_for_best_candidate(v, f"{path}.{k}", depth + 1, max_depth)
                if s2 > best_score:
                    parent_meta = {kk: vv for kk, vv in obj.items() if kk != k}
                    parent_meta.update(m2)
                    best_entries, best_meta, best_score, best_where = e2, parent_meta, s2, w2

    return best_entries, best_meta, best_score, best_where


def _extract_source_sha(obj: Any, meta: Dict[str, Any], raw: bytes) -> str:
    """
    Prefer declared source_sha256 if present.
    Supported locations:
      - obj["_generated"]["source_sha256"]
      - obj["_generated"]["source_hash"]
      - obj["source_sha256"]
      - meta["source_sha256"]
    Fallback: sha256 of the whole artifact bytes.
    """
    if isinstance(obj, dict):
        gen = obj.get("_generated")
        if isinstance(gen, dict):
            s = gen.get("source_sha256")
            if isinstance(s, str) and len(s) >= 16:
                return s
            s2 = gen.get("source_hash")
            if isinstance(s2, str) and len(s2) >= 16:
                return s2
        top = obj.get("source_sha256")
        if isinstance(top, str) and len(top) >= 16:
            return top

    s3 = meta.get("source_sha256")
    if isinstance(s3, str) and len(s3) >= 16:
        return s3

    return _sha256_bytes(raw)


def _normalize_gate_fields(tx: CanonTxType) -> None:
    """
    Normalize gate-related keys without deleting original fields.
    Canon consumers may look for:
      - subject_gate (preferred)
      - gate (legacy)
    """
    gate = tx.get("gate")
    subject_gate = tx.get("subject_gate")

    # If only one is present, mirror it to the other
    if isinstance(subject_gate, str) and subject_gate.strip():
        tx.setdefault("gate", subject_gate.strip())
        tx["subject_gate"] = subject_gate.strip()
        return

    if isinstance(gate, str) and gate.strip():
        tx.setdefault("subject_gate", gate.strip())
        tx["gate"] = gate.strip()
        return

    # If neither is present, don't invent; leave missing and let admission choose default Tier0+
    return


def load_tx_index_json(path: str | Path) -> TxIndex:
    """
    Load generated/tx_index.json (authoritative canon artifact) and return a normalized index.

    This loader is intentionally tolerant: it finds tx entries wherever they live in the JSON.
    """
    raw = _read_bytes(path)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise CanonError(f"failed to parse tx_index.json: {e}") from e

    tx_list, meta, score, where = _scan_for_best_candidate(obj)

    # In some packaging flows (e.g. source zips), generated/tx_index.json may be
    # present but empty. For dev/testnet runs we fall back to the YAML canon.
    if not tx_list or score <= 0:
        fb = _try_load_fallback_from_yaml()
        if fb is None:
            raise CanonError(
                "tx_index.json does not appear to contain tx entries. Expected objects with fields {id:int, name:str} "
                "in a list or an id-keyed mapping (possibly nested)."
            )
        return fb

    by_name: Dict[str, CanonTxType] = {}
    by_id: Dict[int, CanonTxType] = {}
    by_id_str: Dict[str, CanonTxType] = {}

    for entry in tx_list:
        tx = entry  # type: ignore[assignment]
        _validate_entry(tx)
        _normalize_gate_fields(tx)

        name = tx["name"]
        tx_id = int(tx["id"])

        if name in by_name:
            raise CanonError(f"duplicate tx name in index: {name}")
        if tx_id in by_id:
            raise CanonError(f"duplicate tx id in index: {tx_id}")

        by_name[name] = tx
        by_id[tx_id] = tx
        by_id_str[str(tx_id)] = tx

    src_sha = _extract_source_sha(obj, meta, raw)

    # Helpful provenance for debugging without breaking consumers
    meta.setdefault("_loader_found_at", where)
    meta.setdefault("_loader_score", score)

    return TxIndex(
        tx_types=tx_list,
        by_name=by_name,
        by_id=by_id,
        by_id_str=by_id_str,
        meta=meta,
        source_sha256=src_sha,
    )


def _try_load_fallback_from_yaml() -> Optional[TxIndex]:
    """Best-effort fallback to specs/tx_canon/tx_canon.yaml.

    This keeps runtime usable in "source release" bundles where generated artifacts
    were not built. The YAML canon is treated as authoritative input.
    """

    # Import locally to keep JSON-only tooling light.
    try:
        import yaml  # type: ignore
    except Exception:
        return None

    # Locate the YAML file relative to common repo roots.
    rel = Path("specs/tx_canon/tx_canon.yaml")
    p = _resolve_existing_path(rel)
    if not p:
        return None

    try:
        raw = p.read_bytes()
        obj = yaml.safe_load(raw.decode("utf-8"))
    except Exception:
        return None

    if not isinstance(obj, dict):
        return None

    txs = obj.get("tx_types") or obj.get("txs") or obj.get("types")
    if not isinstance(txs, list):
        return None

    tx_list: List[CanonTxType] = []
    for it in txs:
        if not isinstance(it, dict):
            continue
        # Accept either "id" or "tx_id" keys.
        if "id" not in it and "tx_id" in it:
            it = dict(it)
            it["id"] = it.get("tx_id")
        if not _looks_like_tx_obj(it):
            continue
        tx: CanonTxType = dict(it)  # type: ignore[assignment]
        _validate_entry(tx)
        _normalize_gate_fields(tx)
        tx_list.append(tx)

    if not tx_list:
        return None

    # Build normalized maps.
    by_name: Dict[str, CanonTxType] = {}
    by_id: Dict[int, CanonTxType] = {}
    by_id_str: Dict[str, CanonTxType] = {}

    for tx in tx_list:
        name = tx["name"]
        tx_id = int(tx["id"])  # type: ignore[arg-type]

        if name in by_name or tx_id in by_id:
            # Keep the failure explicit; duplicates mean canon is malformed.
            return None

        by_name[name] = tx
        by_id[tx_id] = tx
        by_id_str[str(tx_id)] = tx

    meta: Dict[str, Any] = {
        "_fallback": True,
        "_source": str(p),
    }
    src_sha = _sha256_bytes(raw)

    return TxIndex(
        tx_types=tx_list,
        by_name=by_name,
        by_id=by_id,
        by_id_str=by_id_str,
        meta=meta,
        source_sha256=src_sha,
    )
