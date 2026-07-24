#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any

Json = dict[str, Any]


def _load(path: Path) -> Json:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"actor_keyfile_not_object:{path}")
    return value


def _b64_hex(value: str, *, field: str, path: Path) -> str:
    raw = str(value or "").strip()
    try:
        return base64.b64encode(bytes.fromhex(raw)).decode("ascii")
    except Exception as exc:
        raise SystemExit(f"invalid_{field}:{path}") from exc


def _actor(path: Path, *, role: str = "") -> Json:
    data = _load(path)
    account = str(data.get("account") or "").strip()
    if not account:
        raise SystemExit(f"actor_account_missing:{path}")
    active_private = str(data.get("private_key_hex") or "").strip()
    active_public = str(data.get("public_key_hex") or "").strip()
    if not active_private or not active_public:
        raise SystemExit(f"actor_active_key_missing:{path}")
    recovery: Json = {
        "type": "weall_recovery_key",
        "version": 2,
        "sigProfile": "pq-mldsa-v1",
        "algorithm": "ML-DSA",
        "parameterSet": "ML-DSA-65",
        "secretKeyFormat": "mldsa65-seed-b64",
        "account": account,
        "publicKeyB64": _b64_hex(active_public, field="public_key_hex", path=path),
        "secretKeyB64": _b64_hex(active_private, field="private_key_hex", path=path),
        "createdAt": "1970-01-01T00:00:00.000Z",
        "warning": "Controlled M2 browser actor material. Delete after rehearsal.",
    }
    if data.get("recovery_public_key_hex") and data.get("recovery_private_key_hex"):
        recovery["recoveryAuthorityPublicKeyB64"] = _b64_hex(
            str(data["recovery_public_key_hex"]), field="recovery_public_key_hex", path=path
        )
        recovery["recoveryAuthoritySecretKeyB64"] = _b64_hex(
            str(data["recovery_private_key_hex"]), field="recovery_private_key_hex", path=path
        )
    if data.get("evidence_kem_public_key_b64") and data.get("evidence_kem_secret_key_b64"):
        recovery["evidenceKemPublicKeyB64"] = str(data["evidence_kem_public_key_b64"])
        recovery["evidenceKemSecretKeyB64"] = str(data["evidence_kem_secret_key_b64"])
    out: Json = {"account": account, "keyfile": str(path.resolve()), "recovery": recovery}
    if role:
        out["role"] = role
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a private local actor manifest for independent-browser M2 E2E."
    )
    parser.add_argument("--api-base", required=True)
    parser.add_argument("--kind", choices=("async", "live"), required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--applicant-keyfile", required=True)
    parser.add_argument(
        "--reviewer", action="append", default=[], help="account|role|keyfile or account|keyfile"
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    reviewers: list[Json] = []
    for raw in args.reviewer:
        parts = str(raw).split("|", 2)
        if len(parts) == 2:
            account, keyfile = parts
            role = "reviewer"
        elif len(parts) == 3:
            account, role, keyfile = parts
        else:
            raise SystemExit(f"bad_reviewer_argument:{raw}")
        actor = _actor(Path(keyfile).expanduser(), role=role)
        if actor["account"] != account:
            raise SystemExit(f"reviewer_account_keyfile_mismatch:{account}:{actor['account']}")
        reviewers.append(actor)
    if not reviewers:
        raise SystemExit("reviewer_manifest_empty")

    output: Json = {
        "schema_version": 1,
        "kind": args.kind,
        "api_base": str(args.api_base).rstrip("/"),
        "case_id": str(args.case_id),
        "applicant": _actor(Path(args.applicant_keyfile).expanduser(), role="applicant"),
        "reviewers": reviewers,
    }
    path = Path(args.output).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    print(
        json.dumps(
            {
                "ok": True,
                "output": str(path),
                "kind": args.kind,
                "case_id": args.case_id,
                "reviewer_count": len(reviewers),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
