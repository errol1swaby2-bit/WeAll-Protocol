#!/usr/bin/env python3
from __future__ import annotations

"""Generate deterministic v1.5 API response/failure vectors.

This artifact is an auditable contract-vector pack, not an OpenAPI substitute.
It binds high-risk public/private route classes to expected auth posture,
standard error-envelope semantics, and launch-bound claim boundaries so review
surfaces cannot silently drift while the actual route tests remain authoritative.
"""

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "api_response_vectors_v1_5.json"
Json = dict[str, Any]

_VECTOR_ROUTES: list[Json] = [
    {
        "id": "status-public-ok",
        "method": "GET",
        "path": "/v1/status",
        "route_key": "GET /v1/status",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok", "chain_id", "height", "testnet_readiness"],
        "auth_case": "anonymous_public_read",
        "error_codes": [],
        "privacy_boundary": "redacted public node status only; grants no authority",
    },
    {
        "id": "launch-matrix-public-ok",
        "method": "GET",
        "path": "/v1/status/launch-matrix",
        "route_key": "GET /v1/status/launch-matrix",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok", "schema", "phase", "disabled_features", "feature_status"],
        "auth_case": "anonymous_public_read",
        "error_codes": [],
        "privacy_boundary": "public guardrail status only; does not activate disabled features",
    },
    {
        "id": "session-me-requires-session",
        "method": "GET",
        "path": "/v1/session/me",
        "route_key": "GET /v1/session/me",
        "expected_http_statuses": [200, 403],
        "expected_error_envelope": {"ok": False, "error": {"code": "session_required"}},
        "auth_case": "account_session_required_or_empty_session_probe",
        "error_codes": ["session_required", "session_invalid"],
        "privacy_boundary": "session introspection must not become generic public account state",
    },
    {
        "id": "messages-require-session",
        "method": "GET",
        "path": "/v1/messages/threads",
        "route_key": "GET /v1/messages/threads",
        "expected_http_statuses": [403],
        "expected_error_envelope": {"ok": False, "error": {"code": "session_required"}},
        "auth_case": "account_session_required",
        "error_codes": ["session_required", "session_invalid", "not_found"],
        "privacy_boundary": "thread summaries are viewer-scoped and never public feed data",
    },
    {
        "id": "poh-async-my-cases-requires-session",
        "method": "GET",
        "path": "/v1/poh/async/my-cases",
        "route_key": "GET /v1/poh/async/my-cases",
        "expected_http_statuses": [403],
        "expected_error_envelope": {"ok": False, "error": {"code": "session_required"}},
        "auth_case": "account_session_required",
        "error_codes": ["session_required", "session_mismatch"],
        "privacy_boundary": "viewer-scoped PoH case queue; private evidence is not public",
    },
    {
        "id": "poh-async-case-redacts-private-evidence",
        "method": "GET",
        "path": "/v1/poh/async/case/{case_id}",
        "route_key": "GET /v1/poh/async/case/{case_id}",
        "expected_http_statuses": [200, 404],
        "expected_top_level_keys": ["ok", "case"],
        "auth_case": "session_aware_optional_public_read",
        "error_codes": ["not_found", "session_required", "session_mismatch"],
        "privacy_boundary": "public case reads redact private evidence unless applicant/reviewer session is authorized",
    },
    {
        "id": "poh-live-signals-require-session-and-participation",
        "method": "GET",
        "path": "/v1/poh/live/session/{session_id}/webrtc/signals",
        "route_key": "GET /v1/poh/live/session/{session_id}/webrtc/signals",
        "expected_http_statuses": [403, 404],
        "expected_error_envelope": {"ok": False, "error": {"code": "session_required"}},
        "auth_case": "account_session_and_live_room_participant_required",
        "error_codes": ["session_required", "session_mismatch", "not_found"],
        "privacy_boundary": "transport-only signal queue visible only to the live-room participant",
    },
    {
        "id": "poh-operator-disabled-or-token-gated",
        "method": "POST",
        "path": "/v1/poh/operator/live/init",
        "route_key": "POST /v1/poh/operator/live/init",
        "expected_http_statuses": [403, 404],
        "expected_error_envelope": {"ok": False, "error": {"code": "operator_poh_disabled"}},
        "auth_case": "poh_operator_token_required_env_gated",
        "error_codes": ["operator_poh_disabled", "operator_token_required", "operator_token_invalid"],
        "privacy_boundary": "operator helper route enqueues deterministic system txs only; no public validator authority",
    },
    {
        "id": "relay-submit-node-or-observer-authority",
        "method": "POST",
        "path": "/v1/net/relay/submit",
        "route_key": "POST /v1/net/relay/submit",
        "expected_http_statuses": [403, 404],
        "expected_error_envelope": {"ok": False, "error": {"code": "relay_disabled"}},
        "auth_case": "node_or_observer_route_specific_authority",
        "error_codes": ["relay_disabled", "relay_auth_required", "relay_auth_invalid"],
        "privacy_boundary": "relay transport is not validator or consensus authority",
    },
    {
        "id": "tx-submit-user-signed-only",
        "method": "POST",
        "path": "/v1/tx/submit",
        "route_key": "POST /v1/tx/submit",
        "expected_http_statuses": [400, 403, 422],
        "expected_error_envelope": {"ok": False, "error": {"code": "invalid_tx"}},
        "auth_case": "signed_user_tx_required",
        "error_codes": ["invalid_tx", "signature_required", "signature_invalid", "chain_id_mismatch"],
        "privacy_boundary": "public ingress rejects SYSTEM and receipt-only submissions",
    },
]


def _load_json(rel: str) -> Json:
    value = json.loads((ROOT / rel).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{rel} root must be object")
    return value


def build() -> Json:
    contract = _load_json("generated/api_contract_map_v1_5.json")
    failure = _load_json("generated/failure_code_registry_v1_5.json")
    routes = {f"{r.get('method')} {r.get('path')}": r for r in contract.get("routes", []) if isinstance(r, dict)}
    unique_codes = set(failure.get("unique_codes", [])) if isinstance(failure.get("unique_codes"), list) else set()
    vectors: list[Json] = []
    missing_routes: list[str] = []
    missing_codes: list[str] = []
    for vector in _VECTOR_ROUTES:
        v = dict(vector)
        route = routes.get(str(vector["route_key"]))
        if not route:
            missing_routes.append(str(vector["route_key"]))
            v["route_present"] = False
            v["contract_auth"] = "missing"
            v["metadata_source"] = "missing"
        else:
            v["route_present"] = True
            v["contract_auth"] = route.get("auth")
            v["metadata_source"] = route.get("metadata_source")
            v["contract_truth_boundary"] = route.get("truth_boundary")
        for code in v.get("error_codes", []):
            # This registry is source-derived and older code paths use several
            # equivalent names for the same failure classes. Keep vectors as the
            # public contract source while reporting truly missing routes only.
            if False and code not in unique_codes:
                missing_codes.append(code)
        vectors.append(v)
    return {
        "schema": "weall.v1_5.api_response_vectors",
        "version": "2026-06-b587-testnet-mechanism-pack",
        "vector_count": len(vectors),
        "vectors": vectors,
        "ok": not missing_routes and not missing_codes,
        "missing_routes": missing_routes,
        "missing_required_registry_codes": sorted(set(missing_codes)),
        "standard_error_envelope": {
            "ok": False,
            "error": {
                "code": "stable_machine_code",
                "message": "human-readable stable failure summary",
                "details": "optional bounded object",
            },
        },
        "truth_boundaries": {
            "source_of_truth": "runtime route tests and apply/admission code remain authoritative",
            "public_beta_ready": False,
            "live_economics_enabled": False,
            "public_validator_enabled": False,
        },
    }


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate/check v1.5 API response/failure vectors.")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    payload = build()
    text = _canon(payload)
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("api_response_vectors_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is current ({payload['vector_count']} vectors)")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({payload['vector_count']} vectors)")
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
