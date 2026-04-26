#!/usr/bin/env python3
"""Controlled-devnet join-anchor helper.

This tool intentionally uses only the Python standard library so it can run on a
fresh operator machine before the project virtualenv is fully validated.

The exported join anchor is not an authority by itself. It is a locally pinned
expectation file used by joining-node scripts to reject accidental or malicious
wrong-chain peers before state sync.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

Json = dict[str, Any]

FORMAT = "weall.devnet.join_anchor.v1"
STABLE_FIELDS = (
    "chain_id",
    "schema_version",
    "tx_index_hash",
    "production_consensus_profile_hash",
    "protocol_profile_hash",
)
BOOTSTRAP_FIELDS = ("enabled", "mode", "profile_hash")
ANCHOR_FIELDS = (
    "height",
    "tip_hash",
    "state_root",
    "finalized_height",
    "finalized_block_id",
    "snapshot_hash",
)


class JoinAnchorError(RuntimeError):
    pass


def _read_json(path: str | Path) -> Json:
    try:
        with Path(path).open("r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise JoinAnchorError(f"anchor_file_not_found:{path}") from exc
    except json.JSONDecodeError as exc:
        raise JoinAnchorError(f"invalid_anchor_json:{path}:{exc}") from exc
    if not isinstance(data, dict):
        raise JoinAnchorError("anchor_must_be_json_object")
    return data


def _write_json(path: str | Path, data: Json) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def _fetch_json(api: str, path: str, *, timeout: float = 15.0) -> Json:
    url = api.rstrip("/") + path
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        raise JoinAnchorError(f"http_error:{exc.code}:{url}:{body}") from exc
    except Exception as exc:
        raise JoinAnchorError(f"fetch_failed:{url}:{exc}") from exc
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        raise JoinAnchorError(f"invalid_json_response:{url}:{exc}") from exc
    if not isinstance(data, dict):
        raise JoinAnchorError(f"json_response_not_object:{url}")
    return data


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _safe_int(value: Any) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    try:
        return int(value)
    except Exception:
        return 0


def _stable_from_genesis(genesis: Json) -> Json:
    bootstrap = genesis.get("genesis_bootstrap") if isinstance(genesis.get("genesis_bootstrap"), dict) else {}
    return {
        **{field: _safe_str(genesis.get(field)) for field in STABLE_FIELDS},
        "genesis_bootstrap": {
            "enabled": bool(bootstrap.get("enabled", False)),
            "mode": _safe_str(bootstrap.get("mode")),
            "profile_hash": _safe_str(bootstrap.get("profile_hash")),
        },
    }


def _anchor_from(value: Any) -> Json:
    src = value if isinstance(value, dict) else {}
    out: Json = {}
    for field in ANCHOR_FIELDS:
        if field in {"height", "finalized_height"}:
            out[field] = _safe_int(src.get(field))
        else:
            out[field] = _safe_str(src.get(field))
    return out


def _expected_from(genesis: Json, identity: Json | None = None) -> Json:
    expected = _stable_from_genesis(genesis)
    identity = identity if isinstance(identity, dict) else {}
    expected["trusted_anchor"] = _anchor_from(
        identity.get("snapshot_anchor")
        if isinstance(identity.get("snapshot_anchor"), dict)
        else genesis.get("trusted_anchor")
    )
    expected["identity_height"] = _safe_int(identity.get("height"))
    expected["identity_tip_hash"] = _safe_str(identity.get("tip_hash"))
    expected["identity_state_root"] = _safe_str(identity.get("state_root"))
    return expected


def _normalize_anchor(data: Json) -> Json:
    if isinstance(data.get("expected"), dict):
        return dict(data["expected"])
    # Backward compatibility: older devnet_export_join_anchor.sh wrote raw
    # /v1/chain/genesis output. Treat it as an anchor expectation.
    if any(field in data for field in STABLE_FIELDS):
        return _expected_from(data, {"snapshot_anchor": data.get("trusted_anchor")})
    raise JoinAnchorError("unrecognized_join_anchor_format")


def export_anchor(api: str, out: str) -> Json:
    genesis = _fetch_json(api, "/v1/chain/genesis")
    identity = _fetch_json(api, "/v1/chain/identity")
    if not genesis.get("ok", False):
        raise JoinAnchorError("peer_genesis_not_ok")
    if not identity.get("ok", False):
        raise JoinAnchorError("peer_identity_not_ok")
    expected = _expected_from(genesis, identity)
    payload: Json = {
        "ok": True,
        "format": FORMAT,
        "source_api": api.rstrip("/"),
        "exported_at_ms": int(time.time() * 1000),
        "expected": expected,
        "genesis": genesis,
        "identity": identity,
    }
    _write_json(out, payload)
    return payload


def _compare_stable(expected: Json, live_expected: Json) -> list[Json]:
    mismatches: list[Json] = []
    for field in STABLE_FIELDS:
        if _safe_str(expected.get(field)) != _safe_str(live_expected.get(field)):
            mismatches.append(
                {"field": field, "expected": expected.get(field), "actual": live_expected.get(field)}
            )
    exp_boot = expected.get("genesis_bootstrap") if isinstance(expected.get("genesis_bootstrap"), dict) else {}
    act_boot = live_expected.get("genesis_bootstrap") if isinstance(live_expected.get("genesis_bootstrap"), dict) else {}
    for field in BOOTSTRAP_FIELDS:
        exp_val: Any = bool(exp_boot.get(field, False)) if field == "enabled" else _safe_str(exp_boot.get(field))
        act_val: Any = bool(act_boot.get(field, False)) if field == "enabled" else _safe_str(act_boot.get(field))
        if exp_val != act_val:
            mismatches.append(
                {
                    "field": f"genesis_bootstrap.{field}",
                    "expected": exp_val,
                    "actual": act_val,
                }
            )
    return mismatches


def _compare_anchor(expected: Json, live_expected: Json) -> list[Json]:
    mismatches: list[Json] = []
    exp_anchor = expected.get("trusted_anchor") if isinstance(expected.get("trusted_anchor"), dict) else {}
    act_anchor = live_expected.get("trusted_anchor") if isinstance(live_expected.get("trusted_anchor"), dict) else {}
    for field in ANCHOR_FIELDS:
        exp_val: Any = _safe_int(exp_anchor.get(field)) if field in {"height", "finalized_height"} else _safe_str(exp_anchor.get(field))
        act_val: Any = _safe_int(act_anchor.get(field)) if field in {"height", "finalized_height"} else _safe_str(act_anchor.get(field))
        if exp_val != act_val:
            mismatches.append(
                {"field": f"trusted_anchor.{field}", "expected": exp_val, "actual": act_val}
            )
    return mismatches


def verify_anchor(api: str, anchor_path: str, *, strict_current_anchor: bool = False) -> Json:
    anchor_data = _read_json(anchor_path)
    expected = _normalize_anchor(anchor_data)
    live_genesis = _fetch_json(api, "/v1/chain/genesis")
    live_identity = _fetch_json(api, "/v1/chain/identity")
    live_expected = _expected_from(live_genesis, live_identity)
    mismatches = _compare_stable(expected, live_expected)
    if strict_current_anchor:
        mismatches.extend(_compare_anchor(expected, live_expected))
    ok = not mismatches
    result: Json = {
        "ok": ok,
        "format": FORMAT,
        "api": api.rstrip("/"),
        "anchor_path": str(anchor_path),
        "strict_current_anchor": bool(strict_current_anchor),
        "checked_fields": list(STABLE_FIELDS)
        + [f"genesis_bootstrap.{field}" for field in BOOTSTRAP_FIELDS]
        + ([f"trusted_anchor.{field}" for field in ANCHOR_FIELDS] if strict_current_anchor else []),
        "expected": expected,
        "actual": live_expected,
        "mismatches": mismatches,
    }
    if not ok:
        raise JoinAnchorError("join_anchor_mismatch:" + json.dumps(result, sort_keys=True))
    return result


def _set_nested(root: Json, dotted: str, value: Any) -> None:
    cur: Json = root
    parts = [p for p in dotted.split(".") if p]
    if not parts:
        raise JoinAnchorError("empty_tamper_field")
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def tamper_anchor(in_path: str, out_path: str, field: str, value: str) -> Json:
    data = _read_json(in_path)
    if isinstance(data.get("expected"), dict):
        _set_nested(data["expected"], field, value)
    else:
        # Backward compatible raw genesis file.
        _set_nested(data, field, value)
    _write_json(out_path, data)
    return data


def _print(data: Json) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Controlled-devnet join-anchor helper")
    sub = parser.add_subparsers(dest="command", required=True)

    p_export = sub.add_parser("export", help="Export a locally pinned join-anchor file")
    p_export.add_argument("--api", default="http://127.0.0.1:8001")
    p_export.add_argument("--out", default="./.weall-devnet/join-anchor.json")

    p_verify = sub.add_parser("verify", help="Verify a peer against a locally pinned join-anchor file")
    p_verify.add_argument("--api", default="http://127.0.0.1:8001")
    p_verify.add_argument("--anchor", default="./.weall-devnet/join-anchor.json")
    p_verify.add_argument(
        "--strict-current-anchor",
        action="store_true",
        help="Also require the peer's current state-sync anchor to match exactly",
    )

    p_tamper = sub.add_parser("tamper", help="Write a deliberately tampered anchor for rejection tests")
    p_tamper.add_argument("--in", dest="in_path", required=True)
    p_tamper.add_argument("--out", dest="out_path", required=True)
    p_tamper.add_argument("--field", required=True)
    p_tamper.add_argument("--value", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "export":
            _print(export_anchor(args.api, args.out))
            return 0
        if args.command == "verify":
            _print(verify_anchor(args.api, args.anchor, strict_current_anchor=args.strict_current_anchor))
            return 0
        if args.command == "tamper":
            _print(tamper_anchor(args.in_path, args.out_path, args.field, args.value))
            return 0
        raise JoinAnchorError(f"unknown_command:{args.command}")
    except JoinAnchorError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
