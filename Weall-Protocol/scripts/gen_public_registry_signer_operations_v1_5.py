#!/usr/bin/env python3
from __future__ import annotations

"""Generate/check public registry signer operations evidence."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "public_registry_signer_operations_v1_5.json"
Json = dict[str, Any]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def _contains(rel: str, needle: str) -> bool:
    try:
        return needle in (ROOT / rel).read_text(encoding="utf-8")
    except Exception:
        return False


def build() -> Json:
    checks = {
        "runbook_present": (ROOT / "docs" / "PUBLIC_REGISTRY_SIGNER_OPERATIONS.md").is_file(),
        "runtime_requires_pinned_signer": _contains("src/weall/api/public_seed_registry.py", "public_seed_registry_signer_pin_missing"),
        "runtime_rejects_unpinned_signer": _contains("src/weall/api/public_seed_registry.py", "public_seed_registry_unpinned_signer"),
        "signing_script_present": (ROOT / "scripts" / "sign_public_seed_registry_v1_5.py").is_file(),
        "placeholder_gate_present": _contains("src/weall/api/public_seed_registry.py", "public_seed_registry_placeholder_"),
    }
    operations = [
        "generate offline registry signing key and publish only public key pin",
        "sign registry with domain weall.public_seed_registry.v1",
        "validate with the runtime loader before publication",
        "rotate by accepting old and new pins during overlap",
        "revoke compromised signer by removing the old pin and republishing registry from the new key",
        "never commit registry private key, endpoint private keys, or endpoint-key-map files",
    ]
    payload: Json = {
        "schema": "weall.v1_5.public_registry_signer_operations",
        "version": "2026-06-b629-public-registry-signer-ops",
        "ok": all(checks.values()),
        "public_observer_launch_ready": False,
        "source_checks": checks,
        "required_operations": operations,
        "launch_boundary": "Signer operations are documented and enforceable; the real public registry and key custody evidence are external launch artifacts.",
    }
    payload["artifact_digest"] = hashlib.sha256(_canon({"checks": checks, "operations": operations}).encode("utf-8")).hexdigest()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check public registry signer operations artifact.")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = build()
    text = _pretty(payload)
    if args.json:
        print(text, end="")
        return 0 if payload.get("ok") else 1
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("public_registry_signer_operations_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is current ({len(payload['required_operations'])} operations)")
        return 0 if payload.get("ok") else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(payload['required_operations'])} operations)")
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
