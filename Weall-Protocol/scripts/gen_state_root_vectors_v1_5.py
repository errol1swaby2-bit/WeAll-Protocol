#!/usr/bin/env python3
from __future__ import annotations

"""Generate deterministic v1.5 state-root fixtures."""

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from weall.runtime.state_hash import compute_state_root

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = REPO_ROOT / "generated" / "state_root_vectors_v1_5.json"
Json = dict[str, Any]


def fixture_states() -> list[Json]:
    base: Json = {
        "state_version": 1,
        "height": 7,
        "accounts": {
            "alice": {"nonce": 2, "poh_tier": 2, "reputation_milli": 1200},
            "bob": {"nonce": 1, "poh_tier": 1, "reputation_milli": 50},
        },
        "content": {"posts": {"p1": {"author": "alice", "body_cid": "cid:post:1"}}},
        "params": {"chain_id": "weall-test", "economics_enabled": False},
    }
    reordered: Json = {
        "params": {"economics_enabled": False, "chain_id": "weall-test"},
        "content": {"posts": {"p1": {"body_cid": "cid:post:1", "author": "alice"}}},
        "accounts": {
            "bob": {"reputation_milli": 50, "poh_tier": 1, "nonce": 1},
            "alice": {"reputation_milli": 1200, "poh_tier": 2, "nonce": 2},
        },
        "height": 7,
        "state_version": 1,
    }
    with_ephemeral = deepcopy(base)
    with_ephemeral["created_ms"] = 999
    with_ephemeral["meta"] = {"local": True}
    with_ephemeral["tip_hash"] = "local-tip"
    with_ephemeral["content"]["posts"]["p1"]["tip_ts_ms"] = 123
    list_order_changed = deepcopy(base)
    list_order_changed["notifications"] = {"queue": ["n2", "n1"]}
    list_order_reference = deepcopy(base)
    list_order_reference["notifications"] = {"queue": ["n1", "n2"]}
    return [
        {"name": "base", "state": base},
        {"name": "reordered_dicts_same_semantics", "state": reordered, "same_root_as": "base"},
        {"name": "with_ephemeral_fields_same_semantics", "state": with_ephemeral, "same_root_as": "base"},
        {"name": "list_order_reference", "state": list_order_reference},
        {"name": "list_order_changed", "state": list_order_changed, "different_root_from": "list_order_reference"},
    ]


def build_payload() -> Json:
    vectors = []
    roots: dict[str, str] = {}
    for rec in fixture_states():
        root = compute_state_root(rec["state"])
        roots[str(rec["name"])] = root
        out = {k: v for k, v in rec.items() if k != "state"}
        out["state_root"] = root
        vectors.append(out)
    return {
        "schema": "weall.v1_5.state_root_vectors",
        "canonicalization_contract": {
            "dict_keys_sorted": True,
            "list_order_preserved": True,
            "ephemeral_keys_ignored": ["created_ms", "bft", "meta", "tip_hash", "tip_ts_ms"],
        },
        "vectors": vectors,
        "assertions": [
            {"kind": "equal", "left": "base", "right": "reordered_dicts_same_semantics"},
            {"kind": "equal", "left": "base", "right": "with_ephemeral_fields_same_semantics"},
            {"kind": "not_equal", "left": "list_order_reference", "right": "list_order_changed"},
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    out = Path(args.out)
    data = json.dumps(build_payload(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.check:
        if not out.exists():
            raise SystemExit(f"missing generated state-root vectors: {out}")
        if out.read_text(encoding="utf-8") != data:
            raise SystemExit(f"stale generated state-root vectors: {out}")
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(data, encoding="utf-8")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
