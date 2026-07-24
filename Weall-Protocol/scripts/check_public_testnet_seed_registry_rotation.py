#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from weall.api.public_seed_registry import PublicSeedRegistryError, load_public_seed_registry


def main() -> int:
    registry_path = ROOT / "configs" / "public_testnet_seed_registry.json"
    trust_path = ROOT / "configs" / "public_testnet_trust_roots.json"
    manifest_path = ROOT / "configs" / "chains" / "weall-testnet-v1.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    keys = ("network_id", "chain_id", "genesis_hash", "protocol_profile_hash", "tx_index_hash")
    for key in keys:
        expected = str(manifest.get(key) or "")
        if str(registry.get(key) or "") != expected:
            raise SystemExit(f"seed_registry_commitment_mismatch:{key}")
        if str(trust.get(key) or "") != expected:
            raise SystemExit(f"trust_root_commitment_mismatch:{key}")
    if registry.get("seed_registry_rotation_required") is True:
        raise SystemExit(
            "public_testnet_seed_registry_rotation_required: run "
            "scripts/rotate_public_testnet_seed_registry_m2.sh with the operator-held ML-DSA private key"
        )
    os.environ["WEALL_MODE"] = "prod"
    os.environ["WEALL_PUBLIC_TESTNET"] = "1"
    os.environ["WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH"] = str(trust_path)
    os.environ["WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH"] = str(registry_path)
    try:
        loaded = load_public_seed_registry(allow_local=False)
    except PublicSeedRegistryError as exc:
        raise SystemExit(f"public_testnet_seed_registry_invalid:{exc}") from exc
    status = loaded.get("seed_registry_signature_status") or {}
    if status.get("verified") is not True or status.get("trust") != "pinned":
        raise SystemExit(f"public_testnet_seed_registry_not_pinned:{status}")
    print("OK: public-testnet seed registry commitments and pinned signature are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
