#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.runtime.bootstrap_manifest import (  # noqa: E402
    canon_json,
    release_manifest_path,
    release_pubkey,
)
from weall.runtime.chain_config import load_chain_config, production_bootstrap_report  # noqa: E402
from weall.runtime.operator_incident_lane import (  # noqa: E402
    build_operator_incident_lane,
    build_operator_incident_lane_summary,
)


def _load_verify_payload(
    bundle_path: Path | None, *, json_mode: bool
) -> tuple[int, dict[str, object] | None, str | None]:
    if bundle_path is None:
        return 0, None, None

    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "verify_validator_bootstrap.py"),
        "--bundle",
        str(bundle_path),
        "--json",
    ]
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, check=False)
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    payload: dict[str, object] | None = None
    parse_error: str | None = None
    if out:
        try:
            parsed = json.loads(out)
            if isinstance(parsed, dict):
                payload = parsed
            else:
                parse_error = "verify_validator_bootstrap emitted non-object JSON"
        except Exception as exc:
            parse_error = f"failed to parse verify_validator_bootstrap output: {exc}"
    elif proc.returncode != 0:
        parse_error = "verify_validator_bootstrap returned non-zero with empty stdout"

    if parse_error is not None and not json_mode:
        print(parse_error, file=sys.stderr)
        if err:
            print(err, file=sys.stderr)
    return int(proc.returncode), payload, parse_error


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run a single public-validator preflight over the local production posture, "
            "release manifest inputs, and optional bootstrap bundle."
        )
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Optional chain config path. Defaults to WEALL_CHAIN_CONFIG_PATH / repo defaults.",
    )
    parser.add_argument(
        "--bundle", default=None, help="Optional validator bootstrap bundle JSON path."
    )
    parser.add_argument(
        "--require-bundle", action="store_true", help="Fail if no bundle path is supplied."
    )
    parser.add_argument(
        "--incident-lane-out",
        default=None,
        help="Optional output path for an observer-first operator incident lane bundle built from the local node state.",
    )
    parser.add_argument("--json", action="store_true", help="Emit compact JSON report.")
    args = parser.parse_args()

    if args.config:
        import os

        os.environ["WEALL_CHAIN_CONFIG_PATH"] = str(Path(args.config).resolve())

    cfg = load_chain_config()
    bootstrap = production_bootstrap_report(cfg)
    bundle_path = Path(args.bundle).resolve() if args.bundle else None
    if args.require_bundle and bundle_path is None:
        payload = {
            "ok": False,
            "mode": str(cfg.mode or "").strip().lower(),
            "chain_id": str(cfg.chain_id or ""),
            "issues": ["missing required bootstrap bundle: pass --bundle <path>"],
        }
        if args.json:
            print(canon_json(payload))
        else:
            print(json.dumps(payload, indent=2, sort_keys=True))
        return 1

    verify_rc, verify_payload, verify_parse_error = _load_verify_payload(
        bundle_path, json_mode=bool(args.json)
    )

    issues: list[str] = list(bootstrap.get("issues") or [])
    if verify_parse_error:
        issues.append(verify_parse_error)
    if verify_payload is not None:
        issues.extend(list(verify_payload.get("issues") or []))
        issues.extend(list(verify_payload.get("bundle_integrity_issues") or []))
    elif bundle_path is not None and verify_rc != 0:
        issues.append(f"verify_validator_bootstrap failed with exit code {verify_rc}")

    seen: set[str] = set()
    deduped_issues: list[str] = []
    for item in issues:
        s = str(item)
        if s not in seen:
            seen.add(s)
            deduped_issues.append(s)

    incident_lane = build_operator_incident_lane(
        cfg=cfg,
        db_path=Path(cfg.db_path).resolve(),
        tx_index_path=Path(cfg.tx_index_path).resolve(),
        remote_forensics=None,
        peer_reports=[],
    )
    incident_lane_summary = build_operator_incident_lane_summary(incident_lane)

    if incident_lane_summary["halt_block_production"]:
        deduped_issues.append(
            "local operator incident lane requires halted block production before validator signing"
        )
    elif incident_lane_summary["safe_mode"] != "normal":
        deduped_issues.append(
            "local operator incident lane requires observer-first recovery before validator signing"
        )

    compatibility_contract = {}
    if isinstance(verify_payload, dict) and isinstance(
        verify_payload.get("release_manifest"), dict
    ):
        compatibility_contract = dict(
            verify_payload.get("release_manifest", {}).get("compatibility_contract") or {}
        )

    signing_ready = bool(not deduped_issues and compatibility_contract.get("ok", True))

    payload = {
        "ok": not deduped_issues,
        "mode": str(cfg.mode or "").strip().lower(),
        "chain_id": str(cfg.chain_id or ""),
        "node_id": str(cfg.node_id or ""),
        "config_path": str(Path(args.config).resolve()) if args.config else None,
        "release_manifest_path": release_manifest_path(),
        "release_manifest_pubkey_present": bool(release_pubkey()),
        "bootstrap": bootstrap,
        "bundle_path": str(bundle_path) if bundle_path is not None else None,
        "bundle_verified": bool(
            bundle_path is not None and verify_payload is not None and verify_rc == 0
        ),
        "bundle_verification": verify_payload,
        "compatibility_contract": compatibility_contract,
        "incident_lane": incident_lane_summary,
        "observer_first_required": True,
        "signing_ready": signing_ready,
        "recommended_sequence": [
            "verify local prod posture",
            "build and review operator incident lane",
            "start in observer mode",
            "confirm /v1/status, /v1/status/consensus, /v1/status/operator",
            "confirm release manifest and bootstrap bundle alignment",
            "confirm compatibility contract hash and payload alignment",
            "enable validator signing only after local verification remains clean",
        ],
        "issues": deduped_issues,
    }

    if args.incident_lane_out:
        out_path = Path(args.incident_lane_out).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(incident_lane, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    if args.json:
        print(canon_json(payload))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
        if deduped_issues:
            print("\nPublic validator preflight failed:")
            for item in deduped_issues:
                print(f"- {item}")
        else:
            print("\nPublic validator preflight passed.")
            print("Observer-first remains required before enabling validator signing.")
            print("Review the operator incident lane before changing safe-mode posture.")
    return 0 if not deduped_issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
