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

import json
from pathlib import Path
from typing import Any

from weall.runtime.tx_schema import has_schema

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
    d = json.loads(TX_INDEX.read_text(encoding="utf-8"))
    if not isinstance(d, dict):
        raise SystemExit(f"Invalid tx index json root: {TX_INDEX}")
    return d


def _row(tx: dict[str, Any]) -> str:
    name = str(tx.get("name") or "")
    domain = str(tx.get("domain") or "")
    context = str(tx.get("context") or "")
    origin = str(tx.get("origin") or "")
    receipt_only = _as_bool(tx.get("receipt_only"))
    schema = has_schema(name)
    return f"| `{name}` | `{domain}` | `{context}` | `{origin}` | `{receipt_only}` | `{schema}` |"


def _summaries(txs: list[dict[str, Any]]) -> list[str]:
    total = len(txs)
    mempool = sum(1 for t in txs if str(t.get("context") or "").strip().lower() != "block")
    block = total - mempool
    receipt_only = sum(1 for t in txs if _as_bool(t.get("receipt_only")))

    origins: dict[str, int] = {}
    domains: dict[str, int] = {}
    schemas = sum(1 for t in txs if has_schema(str(t.get("name") or "")))

    for t in txs:
        origins[str(t.get("origin") or "")] = origins.get(str(t.get("origin") or ""), 0) + 1
        domains[str(t.get("domain") or "")] = domains.get(str(t.get("domain") or ""), 0) + 1

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


def main() -> None:
    idx = _load_index()
    by_id = idx.get("by_id")

    if not isinstance(by_id, dict):
        raise SystemExit("generated/tx_index.json missing by_id map")

    txs: list[dict[str, Any]] = []
    for _k, v in by_id.items():
        if isinstance(v, dict) and isinstance(v.get("name"), str):
            txs.append(v)

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

    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"✅ wrote {OUT_MD}")


if __name__ == "__main__":
    main()
