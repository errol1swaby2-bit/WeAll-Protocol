#!/usr/bin/env python3
"""Fail closed when generated transaction-canon artifacts drift.

This checker intentionally uses only the Python standard library so release and
zip-audit environments can run it even before the application dependencies are
installed.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC = REPO_ROOT / "specs" / "tx_canon" / "tx_canon.yaml"
TX_INDEX = REPO_ROOT / "generated" / "tx_index.json"
TX_CONTRACT_MAP = REPO_ROOT / "generated" / "tx_contract_map.json"
HELPER_CONTRACT_MAP = REPO_ROOT / "generated" / "helper_contract_map.json"
EXPECTED_CANON_COUNT = 231
EXPECTED_CANON_VERSION = "1.25.0"


def _die(message: str) -> int:
    print(f"❌ {message}", file=sys.stderr)
    return 1


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - CLI diagnostics only.
        raise SystemExit(_die(f"could not read JSON artifact {path}: {exc}")) from exc
    if not isinstance(value, dict):
        raise SystemExit(_die(f"JSON artifact is not an object: {path}"))
    return value


def _tx_index_names(raw: dict[str, Any]) -> set[str]:
    rows = raw.get("tx_types")
    if not isinstance(rows, list):
        raise SystemExit(_die("generated/tx_index.json missing tx_types list"))
    out: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise SystemExit(_die("generated/tx_index.json contains a non-object tx row"))
        name = str(row.get("name") or "").strip().upper()
        if not name:
            raise SystemExit(_die("generated/tx_index.json contains a tx row without name"))
        if name in out:
            raise SystemExit(_die(f"duplicate tx name in generated/tx_index.json: {name}"))
        out.add(name)
    return out


def _contract_names(raw: dict[str, Any], *, map_name: str) -> set[str]:
    rows = raw.get("rows")
    if rows is None:
        rows = raw.get("contracts")
    if not isinstance(rows, list):
        raise SystemExit(_die(f"{map_name} missing rows/contracts list"))
    out: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise SystemExit(_die(f"{map_name} contains a non-object contract row"))
        name = str(row.get("tx_type") or "").strip().upper()
        if not name:
            raise SystemExit(_die(f"{map_name} contains a contract row without tx_type"))
        if name in out:
            raise SystemExit(_die(f"duplicate tx_type in {map_name}: {name}"))
        out.add(name)
    return out


def _reported_count(raw: dict[str, Any], *, top_level_key: str = "tx_count") -> int | None:
    value = raw.get(top_level_key)
    if value is None and isinstance(raw.get("summary"), dict):
        value = raw["summary"].get(top_level_key)
    try:
        return None if value is None else int(value)
    except Exception:
        return None


def _assert_same_names(label: str, expected: set[str], actual: set[str]) -> None:
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing={missing[:20]}")
        if extra:
            details.append(f"extra={extra[:20]}")
        raise SystemExit(_die(f"{label} does not match tx_index names: {'; '.join(details)}"))


def main() -> int:
    if not SPEC.exists():
        return _die(f"missing tx canon spec: {SPEC}")
    if not TX_INDEX.exists():
        return _die(f"missing generated tx index: {TX_INDEX}")

    tx_index = _read_json(TX_INDEX)
    tx_contract_map = _read_json(TX_CONTRACT_MAP)
    helper_contract_map = _read_json(HELPER_CONTRACT_MAP)

    expected_hash = hashlib.sha256(SPEC.read_bytes()).hexdigest()
    if str(tx_index.get("source_sha256") or "") != expected_hash:
        return _die("generated/tx_index.json source_sha256 does not match specs/tx_canon/tx_canon.yaml")

    meta = tx_index.get("meta") if isinstance(tx_index.get("meta"), dict) else {}
    if str(meta.get("version") or "") != EXPECTED_CANON_VERSION:
        return _die(
            f"generated tx canon version mismatch: expected {EXPECTED_CANON_VERSION}, got {meta.get('version')!r}"
        )

    index_names = _tx_index_names(tx_index)
    if len(index_names) != EXPECTED_CANON_COUNT:
        return _die(f"tx canon count mismatch: expected {EXPECTED_CANON_COUNT}, got {len(index_names)}")

    if "POH_LIVE_JUROR_REPLACE" not in index_names:
        return _die("POH_LIVE_JUROR_REPLACE is not canonical in generated/tx_index.json")

    tx_contract_names = _contract_names(tx_contract_map, map_name="generated/tx_contract_map.json")
    helper_contract_names = _contract_names(helper_contract_map, map_name="generated/helper_contract_map.json")

    _assert_same_names("generated/tx_contract_map.json", index_names, tx_contract_names)
    _assert_same_names("generated/helper_contract_map.json", index_names, helper_contract_names)

    if _reported_count(tx_contract_map) != len(index_names):
        return _die("generated/tx_contract_map.json tx_count does not match tx_index")
    if _reported_count(helper_contract_map) != len(index_names):
        return _die("generated/helper_contract_map.json summary.tx_count does not match tx_index")

    print(f"✅ tx canon artifacts are synchronized ({len(index_names)} tx types, version {EXPECTED_CANON_VERSION})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
