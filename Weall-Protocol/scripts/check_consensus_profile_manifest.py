#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.consensus_profile_manifest import (
    DEFAULT_CONSENSUS_PROFILE_MANIFEST,
    load_consensus_profile_manifest,
)
from weall.runtime.protocol_profile import PRODUCTION_CONSENSUS_PROFILE

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    manifest = load_consensus_profile_manifest()
    if manifest.get("protocol_profile") != PRODUCTION_CONSENSUS_PROFILE.to_json():
        raise SystemExit("consensus profile manifest payload differs from runtime profile")
    if manifest.get("protocol_profile_hash") != PRODUCTION_CONSENSUS_PROFILE.profile_hash():
        raise SystemExit("consensus profile manifest hash differs from runtime profile hash")

    for rel in (
        "configs/chains/weall-genesis.json",
        "configs/chains/weall-testnet-v1.json",
        "configs/chains/weall-controlled-devnet.json",
    ):
        obj = json.loads((ROOT / rel).read_text(encoding="utf-8"))
        if obj.get("protocol_profile_hash") != PRODUCTION_CONSENSUS_PROFILE.profile_hash():
            raise SystemExit(f"{rel}: protocol_profile_hash mismatch")

    print(
        "OK: consensus profile manifest verified",
        DEFAULT_CONSENSUS_PROFILE_MANIFEST,
        manifest["manifest_hash"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
