#!/usr/bin/env python3
"""
Generate a human-friendly coverage report for tx canon + schemas.

This reads:
- generated/tx_index.json
and summarizes:
- mempool vs block-only
- receipt-only
- domains/origins counts
- which tx types have schemas implemented

Output: generated/tx_coverage_report.md
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from weall.runtime.tx_schema import model_for_tx_type
from weall.tx.canon import load_tx_index_json_raw

REPO_ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = REPO_ROOT / "generated" / "tx_index.json"
OUT_MD = REPO_ROOT / "generated" / "tx_coverage_report.md"


def _as_bool(x: Any) -> bool:
    if isinstance(x, bool):
        return x
    s = "" if x is None else str(x).strip().lower()
    return s in {"1", "true", "yes", "y", "on"}


def _load_index() -> dict[str, Any]:
    if not TX_INDEX.exists():
        raise SystemExit(f"Missing generated tx index: {TX_INDEX}")
    try:
        return load_tx_index_json_raw(TX_INDEX)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Invalid tx index: {TX_INDEX}: {exc}") from exc


def _tx_records(idx: dict[str, Any]) -> list[dict[str, Any]]:
    """Return canonical tx records from the current or legacy tx-index shape."""
    tx_types = idx.get("tx_types")
    if isinstance(tx_types, list):
        if not tx_types:
            raise SystemExit("generated/tx_index.json has an empty tx_types list")

        txs: list[dict[str, Any]] = []
        for pos, record in enumerate(tx_types):
            if not isinstance(record, dict):
                raise SystemExit(f"generated/tx_index.json tx_types[{pos}] is not an object")
            name = record.get("name")
            if not isinstance(name, str) or not name.strip():
                raise SystemExit(f"generated/tx_index.json tx_types[{pos}] is missing name")
            txs.append(record)

        by_name = idx.get("by_name")
        by_id = idx.get("by_id")
        if not isinstance(by_name, dict) or len(by_name) != len(txs):
            raise SystemExit("generated/tx_index.json by_name does not cover tx_types")
        if not isinstance(by_id, dict) or len(by_id) != len(txs):
            raise SystemExit("generated/tx_index.json by_id does not cover tx_types")

        for name, pos in by_name.items():
            if not isinstance(name, str) or type(pos) is not int:
                raise SystemExit(
                    "generated/tx_index.json by_name entries must map names to indexes"
                )
            if pos < 0 or pos >= len(txs) or txs[pos].get("name") != name:
                raise SystemExit(f"generated/tx_index.json by_name mismatch for {name!r}")

        if set(by_name.values()) != set(range(len(txs))):
            raise SystemExit("generated/tx_index.json by_name indexes do not cover tx_types")

        for raw_id, pos in by_id.items():
            if not isinstance(raw_id, str) or type(pos) is not int:
                raise SystemExit("generated/tx_index.json by_id entries must map ids to indexes")
            try:
                int(raw_id)
            except ValueError as exc:
                raise SystemExit(
                    f"generated/tx_index.json contains invalid numeric id {raw_id!r}"
                ) from exc
            if pos < 0 or pos >= len(txs):
                raise SystemExit(f"generated/tx_index.json by_id index out of range for {raw_id!r}")

        if set(by_id.values()) != set(range(len(txs))):
            raise SystemExit("generated/tx_index.json by_id indexes do not cover tx_types")

        return txs

    legacy = idx.get("tx")
    if isinstance(legacy, dict) and legacy:
        txs = []
        for name, spec in legacy.items():
            if not isinstance(name, str) or not name.strip():
                raise SystemExit("legacy generated/tx_index.json contains an invalid tx name")
            record: dict[str, Any] = {"name": name}
            if isinstance(spec, dict):
                record.update(spec)
            txs.append(record)
        return txs

    raise SystemExit("generated/tx_index.json has no supported transaction record collection")


def _has_schema(tx_name: str) -> bool:
    return model_for_tx_type(str(tx_name or "").strip().upper()) is not None


def _row(tx: dict[str, Any]) -> str:
    name = str(tx.get("name") or "")
    domain = str(tx.get("domain") or "")
    context = str(tx.get("context") or "")
    origin = str(tx.get("origin") or "")
    receipt_only = _as_bool(tx.get("receipt_only"))
    schema = _has_schema(name)
    return f"| `{name}` | `{domain}` | `{context}` | `{origin}` | `{receipt_only}` | `{schema}` |"


def _summaries(txs: list[dict[str, Any]]) -> list[str]:
    total = len(txs)
    mempool = sum(1 for t in txs if str(t.get("context") or "").strip().lower() != "block")
    block = total - mempool
    receipt_only = sum(1 for t in txs if _as_bool(t.get("receipt_only")))

    origins: dict[str, int] = {}
    domains: dict[str, int] = {}
    schemas = sum(1 for t in txs if _has_schema(str(t.get("name") or "")))

    for t in txs:
        origin = str(t.get("origin") or "")
        domain = str(t.get("domain") or "")
        origins[origin] = origins.get(origin, 0) + 1
        domains[domain] = domains.get(domain, 0) + 1

    def fmt_counts(d: dict[str, int]) -> str:
        items = sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))
        return ", ".join(f"{k}:{v}" for k, v in items if k)

    return [
        f"- total tx types: **{total}**",
        f"- mempool txs: **{mempool}**",
        f"- block-only txs: **{block}**",
        f"- receipt-only txs: **{receipt_only}**",
        f"- txs with schema: **{schemas}**",
        f"- domains: {fmt_counts(domains)}",
        f"- origins: {fmt_counts(origins)}",
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate transaction coverage report")
    parser.add_argument("--out", default=str(OUT_MD), help="output Markdown report path")
    args = parser.parse_args(argv)

    idx = _load_index()
    txs = _tx_records(idx)
    txs.sort(key=lambda t: (str(t.get("domain") or ""), str(t.get("name") or "")))

    lines: list[str] = []
    lines.append("# WeAll Tx Coverage Report")
    lines.append("")
    lines.extend(_summaries(txs))
    lines.append("")
    lines.append("| tx_type | domain | context | origin | receipt_only | has_schema |")
    lines.append("|---|---|---|---|---|---|")
    lines.extend(_row(t) for t in txs)
    lines.append("")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"✅ wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
