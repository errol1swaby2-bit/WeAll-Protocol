#!/usr/bin/env python3
from __future__ import annotations

"""Generate a conservative v1.5 failure-code registry.

The registry is intentionally source-derived and reviewer-oriented. It does not
claim every possible Python exception; it inventories stable API/apply error
codes that are deliberately emitted through ApiError/ApplyError-style surfaces.
"""

import argparse
import ast
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "failure_code_registry_v1_5.json"
SCAN_ROOTS = [ROOT / "src" / "weall" / "api", ROOT / "src" / "weall" / "runtime"]

STATUS_BY_API_METHOD = {
    "bad_request": 400,
    "forbidden": 403,
    "not_found": 404,
    "too_many": 429,
    "payload_too_large": 413,
    "bad_gateway": 502,
    "service_unavailable": 503,
    "internal": 500,
}

STATIC_LAUNCH_CODES = [
    "NON_PUBLIC_GROUP_UNSUPPORTED",
    "OPAQUE_PROTOCOL_PAYLOAD_UNSUPPORTED",
    "PUBLIC_READ_VISIBILITY_REQUIRED",
    "GENESIS_TESTNET_ENDPOINT_PLACEHOLDER",
    "GENESIS_TESTNET_API_UNREACHABLE",
    "GENESIS_TESTNET_P2P_UNREACHABLE",
    "GENESIS_TESTNET_WRONG_CHAIN_ID",
    "GENESIS_TESTNET_WRONG_NETWORK_ID",
    "GENESIS_TESTNET_WRONG_GENESIS_HASH",
    "GENESIS_TESTNET_WRONG_PROFILE_HASH",
    "GENESIS_TESTNET_WRONG_TX_INDEX_HASH",
    "GENESIS_TESTNET_REGISTRY_SIGNATURE_INVALID",
    "GENESIS_TESTNET_REGISTRY_SIGNER_UNPINNED",
    "GENESIS_TESTNET_DIRECT_P2P_REQUIRED",
    "GENESIS_TESTNET_RELAY_ONLY_NOT_READY",
    "OBSERVER_BOOT_NO_VALID_REGISTRY_SOURCE",
    "OBSERVER_BOOT_NO_DIRECT_P2P_SEED",
    "OBSERVER_BOOT_CHAIN_ID_MISMATCH",
    "OBSERVER_BOOT_GENESIS_HASH_MISMATCH",
    "VALIDATOR_PROMOTION_POH_REQUIRED",
    "VALIDATOR_PROMOTION_TIER2_REQUIRED",
    "VALIDATOR_PROMOTION_OPERATOR_OPT_IN_REQUIRED",
    "VALIDATOR_PROMOTION_VALIDATION_OPT_IN_REQUIRED",
    "VALIDATOR_PROMOTION_THRESHOLD_NOT_MET",
    "VALIDATOR_PROMOTION_PROTOCOL_STATE_BLOCKED",
]


def _literal(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _module_domain(path: Path) -> str:
    rel = path.relative_to(ROOT).as_posix()
    if "/api/" in rel:
        return "api"
    if "/runtime/apply/" in rel:
        return "runtime_apply"
    if "/runtime/" in rel:
        return "runtime"
    return "unknown"


def _extract_from_file(path: Path) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    rel = path.relative_to(ROOT).as_posix()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        code: str | None = None
        http_status: int | None = None
        family = "unknown"
        reason = ""
        if name.startswith("ApiError."):
            method = name.rsplit(".", 1)[-1]
            if node.args:
                value = _literal(node.args[0])
                if isinstance(value, str) and value.strip():
                    code = value.strip()
            http_status = STATUS_BY_API_METHOD.get(method)
            family = f"ApiError.{method}"
            if len(node.args) > 1:
                msg = _literal(node.args[1])
                if isinstance(msg, str):
                    reason = msg[:120]
        elif name.endswith("ApplyError") or name.endswith("ProtocolApplyError"):
            if node.args:
                value = _literal(node.args[0])
                if isinstance(value, str) and value.strip():
                    code = value.strip()
            family = name.rsplit(".", 1)[-1]
            if len(node.args) > 1:
                msg = _literal(node.args[1])
                if isinstance(msg, str):
                    reason = msg[:120]
        if not code:
            continue
        out.append(
            {
                "code": code,
                "family": family,
                "http_status": http_status,
                "source": rel,
                "source_lineno": int(getattr(node, "lineno", 0) or 0),
                "domain": _module_domain(path),
                "sample_reason": reason,
            }
        )
    return out


def build_payload() -> dict[str, Any]:
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for root in SCAN_ROOTS:
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            for rec in _extract_from_file(path):
                key = (rec["code"], rec["family"], rec["source"])
                if key not in seen or rec["source_lineno"] < seen[key]["source_lineno"]:
                    seen[key] = rec
    for code in STATIC_LAUNCH_CODES:
        key = (code, "LaunchReadiness", "scripts/gen_failure_code_registry_v1_5.py")
        seen.setdefault(
            key,
            {
                "code": code,
                "family": "LaunchReadiness",
                "http_status": None,
                "source": "scripts/gen_failure_code_registry_v1_5.py",
                "source_lineno": 0,
                "domain": "launch_readiness",
                "sample_reason": "stable public genesis launch readiness failure code",
            },
        )
    entries = sorted(seen.values(), key=lambda r: (r["code"], r["family"], r["source"], r["source_lineno"]))
    by_code: dict[str, int] = {}
    by_domain: dict[str, int] = {}
    for rec in entries:
        by_code[str(rec["code"])] = by_code.get(str(rec["code"]), 0) + 1
        by_domain[str(rec["domain"])] = by_domain.get(str(rec["domain"]), 0) + 1
    return {
        "schema": "weall.v1_5.failure_code_registry",
        "version": "2026-06-batch10a",
        "truth_boundary": "Source-derived registry of stable ApiError/apply error codes; route/runtime tests remain the authority for exact response bodies.",
        "scanner": {
            "roots": [p.relative_to(ROOT).as_posix() for p in SCAN_ROOTS],
            "families": sorted({str(r["family"]) for r in entries}),
        },
        "entry_count": len(entries),
        "unique_code_count": len(by_code),
        "by_domain": dict(sorted(by_domain.items())),
        "codes": entries,
    }


def _render(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate/check the v1.5 failure-code registry.")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    payload = build_payload()
    rendered = _render(payload)
    if args.json:
        print(rendered, end="")
        return 0
    if args.check:
        if not OUT.exists():
            raise SystemExit(f"missing generated failure-code registry: {OUT.relative_to(ROOT)}")
        if OUT.read_text(encoding="utf-8") != rendered:
            raise SystemExit(f"stale generated failure-code registry: {OUT.relative_to(ROOT)}")
        print(f"OK: {OUT.relative_to(ROOT)} is current ({payload['entry_count']} entries)")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({payload['entry_count']} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
