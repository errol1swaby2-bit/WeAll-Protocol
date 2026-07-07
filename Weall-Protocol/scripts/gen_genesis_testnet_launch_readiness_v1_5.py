#!/usr/bin/env python3
from __future__ import annotations

"""Generate/check public genesis testnet launch readiness evidence."""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
OUT = ROOT / "generated" / "genesis_testnet_launch_readiness_v1_5.json"
Json = dict[str, Any]


def _pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _script_checks() -> Json:
    text = (ROOT / "scripts" / "boot_public_observer_testnet.sh").read_text(encoding="utf-8")
    return {
        "loads_checked_in_registry": "public_testnet_seed_registry.json" in text,
        "loads_trust_roots": "public_testnet_trust_roots.json" in text,
        "refuses_observer_validator_signing": "WEALL_VALIDATOR_SIGNING_ENABLED" in text and "public observer boot refuses" in text,
        "enables_direct_p2p_mesh_loop": "WEALL_NET_ENABLED" in text and "WEALL_NET_LOOP_AUTOSTART" in text,
        "initializes_local_node_identity_only": "init_prod_node_identity.sh --emit-shell-env" in text,
        "runs_production_node_entrypoint": "exec bash scripts/run_node.sh" in text,
    }


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

    checks = _script_checks()
    static_ready = not errors and all(bool(v) for v in checks.values()) and bool(registry.get("seed_p2p_urls"))
    return {
        "schema": "weall.v1_5.genesis_testnet_launch_readiness",
        "version": "2026-06-public-genesis-launch",
        "static_readiness_verdict": "ready_for_live_endpoint_rehearsal" if static_ready else "blocked",
        "overall_launch_verdict": "partial_until_live_genesis_reachability_and_rehearsal_pass",
        "checked_in_registry_baseline": True,
        "named_provider_dependency": False,
        "direct_p2p_primary": True,
        "relay_fallback_only": True,
        "production_economics_active": False,
        "mainnet_claim_allowed": False,
        "manual_validator_activation_authority": False,
        "live_rehearsal_required": True,
        "registry": {
            "source_kind": registry.get("registry_source_kind"),
            "chain_id": registry.get("chain_id"),
            "network_id": registry.get("network_id"),
            "genesis_hash": registry.get("genesis_hash"),
            "protocol_profile_hash": registry.get("protocol_profile_hash"),
            "tx_index_hash": registry.get("tx_index_hash"),
            "signature_status": registry.get("seed_registry_signature_status"),
            "seed_api_urls": registry.get("seed_api_urls") or [],
            "seed_p2p_urls": registry.get("seed_p2p_urls") or [],
            "errors": errors,
        },
        "observer_boot_script_checks": checks,
        "source_files": [
            "configs/chains/weall-testnet-v1.json",
            "configs/public_testnet_trust_roots.json",
            "configs/public_testnet_seed_registry.json",
            "src/weall/api/public_seed_registry.py",
            "src/weall/net/net_loop.py",
            "scripts/boot_public_observer_testnet.sh",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check public genesis testnet launch readiness artifact.")
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
            raise SystemExit(f"stale generated genesis launch readiness: {OUT.relative_to(ROOT)}")
        print(f"OK: {OUT.relative_to(ROOT)} is current")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
