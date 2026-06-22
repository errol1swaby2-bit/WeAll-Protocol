#!/usr/bin/env python3
from __future__ import annotations

"""Generate/check public genesis seed endpoint launch-gate evidence."""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
OUT = ROOT / "generated" / "public_genesis_seed_endpoint_requirements_v1_5.json"
Json = dict[str, Any]


def _pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def build() -> Json:
    from weall.api.public_seed_registry import PublicSeedRegistryError, load_public_seed_registry

    old_env = {k: os.environ.get(k) for k in ["WEALL_PUBLIC_TESTNET", "WEALL_MODE"]}
    os.environ["WEALL_PUBLIC_TESTNET"] = "1"
    os.environ["WEALL_MODE"] = "prod"
    errors: list[str] = []
    registry: Json = {}
    try:
        registry = load_public_seed_registry(allow_local=False)
    except PublicSeedRegistryError as exc:
        errors.append(str(exc))
    finally:
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    static_gate_passes = not errors and bool(registry.get("seed_api_urls")) and bool(registry.get("seed_p2p_urls"))
    return {
        "schema": "weall.v1_5.public_genesis_seed_endpoint_requirements",
        "version": "2026-06-public-genesis-launch",
        "static_launch_gate_passes": bool(static_gate_passes),
        "live_reachability_probe_required": True,
        "live_reachability_probe_status": "not_evaluated_by_generator",
        "requirements": [
            "checked-in signed registry must verify against pinned signer",
            "seed API URL must be HTTPS and public-hosted in production public mode",
            "seed P2P URL must be tcp/tls and public-hosted in production public mode",
            "placeholder, localhost, loopback, private, link-local, and unspecified endpoint values are blocked",
            "direct P2P URI must not be confused with HTTPS API URL",
            "relay-only launch is not genesis-launch-ready",
        ],
        "checked_in_registry": {
            "source_kind": registry.get("registry_source_kind"),
            "chain_id": registry.get("chain_id"),
            "network_id": registry.get("network_id"),
            "signature_status": registry.get("seed_registry_signature_status"),
            "seed_api_urls": registry.get("seed_api_urls") or [],
            "seed_p2p_urls": registry.get("seed_p2p_urls") or [],
            "validator_endpoint_count": len(registry.get("validator_endpoints") or []),
            "errors": errors,
        },
        "failure_codes": [
            "GENESIS_TESTNET_ENDPOINT_PLACEHOLDER",
            "GENESIS_TESTNET_API_UNREACHABLE",
            "GENESIS_TESTNET_P2P_UNREACHABLE",
            "GENESIS_TESTNET_RELAY_ONLY_NOT_READY",
            "OBSERVER_BOOT_NO_DIRECT_P2P_SEED",
        ],
        "source_files": [
            "configs/public_testnet_seed_registry.json",
            "configs/public_testnet_trust_roots.json",
            "src/weall/api/public_seed_registry.py",
            "scripts/boot_public_observer_testnet.sh",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check public genesis seed endpoint requirements artifact.")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = build()
    text = _pretty(payload)
    if args.json:
        print(text, end="")
        return 0
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit(f"stale generated public genesis endpoint requirements: {OUT.relative_to(ROOT)}")
        print(f"OK: {OUT.relative_to(ROOT)} is current")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
