#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.runtime.bootstrap_manifest import (
    build_manifest,
    release_pubkey,
    release_signing_privkey,
    sign_manifest,
)  # noqa: E402
from weall.runtime.chain_config import load_chain_config  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a canonical validator bootstrap bundle for operator verification and trusted-anchor distribution."
    )
    parser.add_argument(
        "--db-path", default=None, help="Path to node SQLite DB. Defaults to chain config db_path."
    )
    parser.add_argument(
        "--tx-index-path",
        default=None,
        help="Path to generated tx index. Defaults to chain config tx_index_path.",
    )
    parser.add_argument(
        "--out", default="generated/validator_bootstrap_bundle.json", help="Output bundle path."
    )
    parser.add_argument("--json", action="store_true", help="Emit structured JSON summary.")
    args = parser.parse_args()

    cfg = load_chain_config()
    db_path = Path(args.db_path or cfg.db_path).resolve()
    tx_index_path = Path(args.tx_index_path or cfg.tx_index_path).resolve()
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    bundle = build_manifest(cfg, db_path=db_path, tx_index_path=tx_index_path)
    privkey = release_signing_privkey()
    if privkey:
        bundle = sign_manifest(bundle, privkey=privkey, signer_pubkey=release_pubkey())
    out_path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    if args.json:
        payload = {
            "ok": True,
            "bundle_path": str(out_path),
            "manifest_hash": str(bundle.get("manifest_hash") or ""),
            "signed": bool(str(bundle.get("signature") or "").strip()),
            "authority_contract": dict(bundle.get("authority_contract") or {}),
            "authority_contract_hash": str(bundle.get("authority_contract_hash") or ""),
        }
        print(json.dumps(payload, sort_keys=True))
    else:
        print(str(out_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
