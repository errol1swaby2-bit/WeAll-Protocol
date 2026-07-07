#!/usr/bin/env python3
from __future__ import annotations

"""Generate/check public-observer open-download launch transcript scaffolds.

The tracked artifacts produced here are evidence contracts, not launch claims.
They deliberately keep public_observer_launch_ready=false until an operator runs a
runtime transcript against a real signed registry and live seed/validator APIs.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from weall.api.public_seed_registry import (  # noqa: E402
    PublicSeedRegistryError,
    commitment_payload,
    load_public_seed_registry,
)

Json = dict[str, Any]

OUTPUTS = {
    "registry": ROOT / "generated" / "public_seed_registry_signature_verification_v1_5.json",
    "clean_clone": ROOT / "generated" / "public_observer_clean_clone_bootstrap_transcript_v1_5.json",
    "auto_discovery": ROOT / "generated" / "public_observer_auto_discovery_proof_v1_5.json",
    "state_sync": ROOT / "generated" / "public_observer_state_sync_trusted_anchor_proof_v1_5.json",
}


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _digest(obj: Any) -> str:
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return ""


def _run(cmd: list[str], *, cwd: Path) -> Json:
    proc = subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return {
        "cmd": " ".join(cmd),
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-4000:],
        "ok": proc.returncode == 0,
    }


def _http_json(base_url: str, route: str, *, timeout_s: float = 5.0) -> Json:
    url = base_url.rstrip("/") + route
    req = Request(url, headers={"accept": "application/json"})
    with urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - operator-supplied local/testnet URL
        body = resp.read().decode("utf-8")
    value = json.loads(body)
    return value if isinstance(value, dict) else {"value": value}


def _default_contracts() -> dict[str, Json]:
    registry_validation = {
        "schema": "weall.v1_5.public_seed_registry_signature_verification",
        "version": "2026-06-b629-public-observer-transcript-gate",
        "ok": True,
        "public_observer_launch_ready": False,
        "runtime_registry_verified": False,
        "external_evidence_required_before_launch": True,
        "purpose": "tracked contract for proving a real signed public seed registry before public observer launch",
        "required_runtime_inputs": [
            "configs/public_testnet_seed_registry.json or WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH",
            "WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY",
            "non-placeholder genesis_hash",
            "non-placeholder protocol_profile_hash",
            "non-placeholder tx_index_hash",
            "non-local seed_api_urls for public launch",
            "signed validator endpoint advertisements when validators are public connection targets",
        ],
        "validation_command": "PYTHONPATH=src WEALL_PUBLIC_TESTNET=1 WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY=<pubkey> python scripts/gen_public_observer_launch_transcript_v1_5.py --runtime-json --registry configs/public_testnet_seed_registry.json --api-base <seed-api>",
        "claim_boundary": "This artifact is a schema/gate until --runtime-json is captured against real public testnet endpoints.",
    }

    clean_clone = {
        "schema": "weall.v1_5.public_observer_clean_clone_bootstrap_transcript",
        "version": "2026-06-b629-public-observer-transcript-gate",
        "ok": True,
        "public_observer_launch_ready": False,
        "runtime_transcript_attached": False,
        "external_evidence_required_before_launch": True,
        "required_steps": [
            "fresh git clone from public repository",
            "python -m venv .venv",
            "pip install -r requirements.lock",
            "pip install -e .",
            "set WEALL_PUBLIC_TESTNET=1 and pinned registry signer",
            "bash scripts/boot_public_observer_testnet.sh",
            "verify /v1/nodes/seeds",
            "verify /v1/nodes/validators",
            "verify /v1/observer/edge/status",
            "verify local frontend dashboard can load the local backend",
        ],
        "required_public_warning": "resettable non-economic public observer testnet; no real-world token value; validator activation is protocol-gated",
        "runtime_command": "bash scripts/run_public_observer_launch_rehearsal_v1_5.sh --api-base <seed-api> --registry configs/public_testnet_seed_registry.json --out generated/public_observer_launch_runtime_transcript_v1_5.json",
    }

    auto_discovery = {
        "schema": "weall.v1_5.public_observer_auto_discovery_proof",
        "version": "2026-06-b629-public-observer-transcript-gate",
        "ok": True,
        "public_observer_launch_ready": False,
        "runtime_discovery_proven": False,
        "external_evidence_required_before_launch": True,
        "required_observations": [
            "registry signature verified and signer pinned",
            "seed API URLs discovered from signed registry",
            "seed P2P URLs discovered from signed registry",
            "active validators read from protocol state",
            "verified fresh endpoint counts surfaced",
            "unsigned validator endpoint hints do not become auto-dial targets",
        ],
        "source_gates_present": [
            "tests/prod/test_public_observer_default_registry_and_placeholder_gate.py",
            "tests/prod/test_public_observer_registry_auto_dial.py",
            "tests/prod/test_public_validator_endpoint_discovery.py",
        ],
    }

    state_sync = {
        "schema": "weall.v1_5.public_observer_state_sync_trusted_anchor_proof",
        "version": "2026-06-b629-public-observer-transcript-gate",
        "ok": True,
        "public_observer_launch_ready": False,
        "runtime_state_sync_proven": False,
        "external_evidence_required_before_launch": True,
        "required_observations": [
            "chain identity matches registry chain_id/genesis_hash/profile/tx_index commitments",
            "observer catches up from genesis/current trusted head",
            "state root reported by observer matches seed or active validator",
            "restart preserves synced height/root/posture",
            "mempool/block propagation remains visible after restart",
        ],
        "source_gates_present": [
            "tests/test_state_sync_trusted_anchor.py",
            "tests/test_state_sync_trusted_anchor_aliases.py",
            "tests/test_status_persists_height_after_restart.py",
            "tests/prod/test_multinode_mempool_propagation_convergence.py",
        ],
    }

    for payload in (registry_validation, clean_clone, auto_discovery, state_sync):
        payload["artifact_digest"] = _digest({"schema": payload["schema"], "version": payload["version"], "required": payload.get("required_steps") or payload.get("required_observations") or payload.get("required_runtime_inputs")})
    return {
        "registry": registry_validation,
        "clean_clone": clean_clone,
        "auto_discovery": auto_discovery,
        "state_sync": state_sync,
    }


def build_runtime(*, registry_path: Path | None, api_base: str | None) -> Json:
    started_ms = int(time.time() * 1000)
    env = {
        "WEALL_PUBLIC_TESTNET": os.environ.get("WEALL_PUBLIC_TESTNET", ""),
        "WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY": os.environ.get("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", ""),
        "WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH": str(registry_path or os.environ.get("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH") or ""),
    }
    registry: Json = {}
    registry_error = ""
    if registry_path is not None:
        os.environ["WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH"] = str(registry_path)
    os.environ.setdefault("WEALL_PUBLIC_TESTNET", "1")
    try:
        registry = load_public_seed_registry(str(registry_path) if registry_path is not None else None)
    except PublicSeedRegistryError as exc:
        registry_error = str(exc)
    except Exception as exc:
        registry_error = type(exc).__name__ + ": " + str(exc)

    endpoints: dict[str, Json] = {}
    endpoint_errors: dict[str, str] = {}
    if api_base:
        for route in ("/v1/nodes/seeds", "/v1/nodes/validators", "/v1/observer/edge/status", "/v1/chain/identity", "/v1/status", "/v1/chain/head"):
            try:
                endpoints[route] = _http_json(api_base, route)
            except Exception as exc:  # pragma: no cover - runtime transcript path
                endpoint_errors[route] = type(exc).__name__ + ": " + str(exc)

    commitments = commitment_payload(registry) if registry else {}
    identity = endpoints.get("/v1/chain/identity") or {}
    validators = endpoints.get("/v1/nodes/validators") or {}
    registry_verified = bool((registry.get("seed_registry_signature_status") or {}).get("verified")) if registry else False
    validators_fresh = bool(validators.get("all_active_validators_have_verified_fresh_endpoint")) if validators else False
    identity_matches = bool(
        commitments
        and identity
        and str(identity.get("chain_id") or "") == str(commitments.get("chain_id") or "")
        and str(identity.get("genesis_hash") or "") == str(commitments.get("genesis_hash") or "")
        and str(identity.get("protocol_profile_hash") or "") == str(commitments.get("protocol_profile_hash") or "")
        and str(identity.get("tx_index_hash") or "") == str(commitments.get("tx_index_hash") or "")
    )
    runtime_ok = bool(registry_verified and identity_matches and validators_fresh and not endpoint_errors)
    payload: Json = {
        "schema": "weall.v1_5.public_observer_launch_runtime_transcript",
        "version": "2026-06-b629-runtime-public-observer-launch-transcript",
        "ok": runtime_ok,
        "public_observer_launch_ready": runtime_ok,
        "generated_ts_ms": started_ms,
        "registry_path": str(registry_path or ""),
        "api_base": api_base or "",
        "environment": env,
        "registry_error": registry_error,
        "registry_verified": registry_verified,
        "commitments": commitments,
        "queried_routes": endpoints,
        "endpoint_errors": endpoint_errors,
        "identity_matches_registry_commitments": identity_matches,
        "all_active_validators_have_verified_fresh_endpoint": validators_fresh,
        "runtime_artifact_only_do_not_track_as_static_claim": True,
    }
    payload["artifact_digest"] = _digest({k: payload[k] for k in ("schema", "version", "commitments", "endpoint_errors", "identity_matches_registry_commitments")})
    return payload


def write_static() -> dict[str, Json]:
    payloads = _default_contracts()
    for key, path in OUTPUTS.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_pretty(payloads[key]), encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    return payloads


def check_static() -> int:
    payloads = _default_contracts()
    errors: list[str] = []
    for key, path in OUTPUTS.items():
        expected = _pretty(payloads[key])
        if not path.is_file() or path.read_text(encoding="utf-8") != expected:
            errors.append(f"{path.relative_to(ROOT)} is stale; rerun generator")
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"OK: public observer launch transcript artifacts are current ({len(OUTPUTS)} artifacts)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check public observer launch transcript artifacts.")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--runtime-json", action="store_true", help="emit live runtime transcript from registry/API; not a tracked static artifact")
    parser.add_argument("--registry", help="registry path for --runtime-json")
    parser.add_argument("--api-base", help="seed/genesis API base for --runtime-json")
    parser.add_argument("--out", help="optional output path for --runtime-json")
    args = parser.parse_args()
    if args.runtime_json:
        payload = build_runtime(registry_path=Path(args.registry).resolve() if args.registry else None, api_base=args.api_base)
        text = _pretty(payload)
        if args.out:
            out = Path(args.out).resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
            print(f"wrote runtime public observer launch transcript: {out}")
            return 0 if payload.get("ok") else 1
        print(text, end="")
        return 0 if payload.get("ok") else 1
    if args.json:
        payloads = _default_contracts()
        print(_pretty({"schema": "weall.v1_5.public_observer_launch_transcript_bundle", "ok": True, "artifacts": payloads}), end="")
        return 0
    if args.check:
        return check_static()
    write_static()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
