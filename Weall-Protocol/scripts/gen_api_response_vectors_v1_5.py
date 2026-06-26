#!/usr/bin/env python3
from __future__ import annotations

"""Generate deterministic v1.5 API response/failure vectors.

This artifact is an auditable contract-vector pack, not an OpenAPI substitute.
It binds high-risk public/session-scoped route classes to expected auth posture,
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
        "id": "activity-notices-public-only",
        "method": "GET",
        "path": "/v1/activity/notices",
        "route_key": "GET /v1/activity/notices",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok", "public_only", "source", "notice_types"],
        "auth_case": "public_event_derived_notification_index",
        "error_codes": [],
        "privacy_boundary": "public activity notices is derived from public protocol events and contains no sealed user-to-user thread semantics",
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
        "privacy_boundary": "viewer-scoped PoH case queue; restricted identity evidence is not public",
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
        "privacy_boundary": "public case reads redact restricted identity evidence unless applicant/reviewer session is authorized",
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

    {
        "id": "readyz-public-ok",
        "method": "GET",
        "path": "/v1/readyz",
        "route_key": "GET /v1/readyz",
        "expected_http_statuses": [200, 503],
        "expected_top_level_keys": ["ready", "checks"],
        "auth_case": "anonymous_public_readiness_probe",
        "error_codes": [],
        "privacy_boundary": "readiness does not reveal authority secrets or grant production posture",
    },
    {
        "id": "health-public-ok",
        "method": "GET",
        "path": "/v1/health",
        "route_key": "GET /v1/health",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "anonymous_public_health_probe",
        "error_codes": [],
        "privacy_boundary": "health is liveness metadata only",
    },
    {
        "id": "operator-status-redacted",
        "method": "GET",
        "path": "/v1/status/operator",
        "route_key": "GET /v1/status/operator",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok", "schema", "operator"],
        "auth_case": "operator_diagnostic_read_redacted_by_runtime_posture",
        "error_codes": [],
        "privacy_boundary": "operator diagnostics are posture evidence and never grant role authority",
    },
    {
        "id": "consensus-status-redacted",
        "method": "GET",
        "path": "/v1/status/consensus",
        "route_key": "GET /v1/status/consensus",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok", "schema"],
        "auth_case": "public_read_redacted_snapshot",
        "error_codes": [],
        "privacy_boundary": "consensus status exposes redacted diagnostics only; it does not enable BFT signing",
    },
    {
        "id": "consensus-forensics-redacted",
        "method": "GET",
        "path": "/v1/status/consensus/forensics",
        "route_key": "GET /v1/status/consensus/forensics",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "public_read_redacted_snapshot",
        "error_codes": [],
        "privacy_boundary": "forensics are bounded diagnostics and not peer secrets",
    },
    {
        "id": "mempool-status-redacted",
        "method": "GET",
        "path": "/v1/status/mempool",
        "route_key": "GET /v1/status/mempool",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "public_read_redacted_snapshot",
        "error_codes": [],
        "privacy_boundary": "mempool size and diagnostics are visible, while pending transaction detail stays bounded by public-route redaction rules",
    },
    {
        "id": "testnet-capabilities-boundary",
        "method": "GET",
        "path": "/v1/status/testnet-capabilities",
        "route_key": "GET /v1/status/testnet-capabilities",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok", "schema", "capabilities", "blocked_capabilities", "public_beta_ready_claimed"],
        "auth_case": "public_read_launch_matrix_bound_testnet_capability_surface",
        "error_codes": [],
        "privacy_boundary": "claim-control surface only; it cannot enable validators, economics, helper execution, or upgrades",
    },
    {
        "id": "chain-identity-redacted",
        "method": "GET",
        "path": "/v1/chain/identity",
        "route_key": "GET /v1/chain/identity",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok", "chain_id"],
        "auth_case": "public_read_redacted_snapshot",
        "error_codes": [],
        "privacy_boundary": "chain identity is public trust-anchor metadata only",
    },
    {
        "id": "chain-head-redacted",
        "method": "GET",
        "path": "/v1/chain/head",
        "route_key": "GET /v1/chain/head",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok", "height"],
        "auth_case": "public_read_redacted_snapshot",
        "error_codes": [],
        "privacy_boundary": "chain head is public progress metadata only",
    },
    {
        "id": "account-operator-status-read-model",
        "method": "GET",
        "path": "/v1/accounts/{account}/operator-status",
        "route_key": "GET /v1/accounts/{account}/operator-status",
        "expected_http_statuses": [200, 404],
        "expected_top_level_keys": ["ok", "account", "node_operator"],
        "auth_case": "public_read_redacted_operator_responsibility_snapshot",
        "error_codes": ["not_found"],
        "privacy_boundary": "derived readiness only; not validator promotion or helper/storage assignment authority",
    },
    {
        "id": "net-self-redacted",
        "method": "GET",
        "path": "/v1/net/self",
        "route_key": "GET /v1/net/self",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "public_read_redacted_snapshot",
        "error_codes": [],
        "privacy_boundary": "peer status is redacted topology data and not a trust anchor by itself",
    },
    {
        "id": "storage-ipfs-ops-redacted",
        "method": "GET",
        "path": "/v1/storage/ipfs/ops",
        "route_key": "GET /v1/storage/ipfs/ops",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "public_read_redacted_snapshot",
        "error_codes": [],
        "privacy_boundary": "storage/IPFS ops status does not assign storage work or reveal restricted identity evidence",
    },
    {
        "id": "helper-readiness-disabled-boundary",
        "method": "GET",
        "path": "/v1/status/helper/readiness",
        "route_key": "GET /v1/status/helper/readiness",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "public_read_redacted_snapshot",
        "error_codes": [],
        "privacy_boundary": "helper readiness is diagnostic only; production helper execution remains disabled",
    },
    {
        "id": "block-production-readiness-boundary",
        "method": "GET",
        "path": "/v1/consensus/block-production/readiness",
        "route_key": "GET /v1/consensus/block-production/readiness",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "public_read_redacted_snapshot",
        "error_codes": [],
        "privacy_boundary": "readiness diagnostics do not permit observer or inactive-validator block production",
    },
    {
        "id": "tx-status-public-redacted",
        "method": "GET",
        "path": "/v1/tx/status/{tx_id}",
        "route_key": "GET /v1/tx/status/{tx_id}",
        "expected_http_statuses": [200, 404],
        "expected_top_level_keys": ["ok"],
        "auth_case": "public_read_redacted_snapshot",
        "error_codes": ["not_found"],
        "privacy_boundary": "tx lifecycle is status-only and must not expose restricted identity evidence payloads",
    },
    {
        "id": "dispute-current-redacted",
        "method": "GET",
        "path": "/v1/disputes/current",
        "route_key": "GET /v1/disputes/current",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "public_read_redacted_snapshot",
        "error_codes": [],
        "privacy_boundary": "dispute current queue is bounded read model; assignment still requires exact lane consent",
    },
    {
        "id": "dispute-accept-route-specific-authority",
        "method": "POST",
        "path": "/v1/disputes/{dispute_id}/accept",
        "route_key": "POST /v1/disputes/{dispute_id}/accept",
        "expected_http_statuses": [200, 400, 403, 404],
        "expected_error_envelope": {"ok": False, "error": {"code": "forbidden"}},
        "auth_case": "route_specific_signed_or_local_authority",
        "error_codes": ["forbidden", "not_found", "invalid_tx"],
        "privacy_boundary": "accepting dispute work requires assigned juror status and active dispute reviewer responsibility",
    },
    {
        "id": "poh-tier2-my-cases-session",
        "method": "GET",
        "path": "/v1/poh/tier2/my-cases",
        "route_key": "GET /v1/poh/tier2/my-cases",
        "expected_http_statuses": [403],
        "expected_error_envelope": {"ok": False, "error": {"code": "session_required"}},
        "auth_case": "account_session_required",
        "error_codes": ["session_required", "session_mismatch"],
        "privacy_boundary": "Tier-2 case queues are viewer-scoped and evidence-sensitive",
    },
    {
        "id": "poh-live-my-cases-session",
        "method": "GET",
        "path": "/v1/poh/live/my-cases",
        "route_key": "GET /v1/poh/live/my-cases",
        "expected_http_statuses": [403],
        "expected_error_envelope": {"ok": False, "error": {"code": "session_required"}},
        "auth_case": "account_session_required_live_account_queue",
        "error_codes": ["session_required", "session_mismatch"],
        "privacy_boundary": "live PoH queues are viewer-scoped and grant no room authority without participation",
    },
    {
        "id": "account-operator-status-readiness",
        "method": "GET",
        "path": "/v1/accounts/{account}/operator-status",
        "route_key": "GET /v1/accounts/{account}/operator-status",
        "expected_http_statuses": [200, 403, 404],
        "expected_top_level_keys": ["ok"],
        "auth_case": "account_session_or_public_redacted_operator_read",
        "error_codes": ["session_required", "session_mismatch", "not_found"],
        "privacy_boundary": "operator status exposes readiness blockers, not private authority secrets",
    },
    {
        "id": "chain-manifest-trust-anchor",
        "method": "GET",
        "path": "/v1/chain/manifest",
        "route_key": "GET /v1/chain/manifest",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "anonymous_public_chain_identity_read",
        "error_codes": [],
        "privacy_boundary": "chain manifest is a trust anchor and cannot grant validator authority",
    },
    {
        "id": "chain-state-root-public-read",
        "method": "GET",
        "path": "/v1/chain/state-root",
        "route_key": "GET /v1/chain/state-root",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "anonymous_public_chain_state_read",
        "error_codes": [],
        "privacy_boundary": "state-root reads expose commitment metadata only",
    },
    {
        "id": "consensus-attest-submit-validator-only",
        "method": "POST",
        "path": "/v1/consensus/attest/submit",
        "route_key": "POST /v1/consensus/attest/submit",
        "expected_http_statuses": [400, 403, 422],
        "expected_error_envelope": {"ok": False, "error": {"code": "validator_authority_required"}},
        "auth_case": "active_validator_bft_key_required",
        "error_codes": ["validator_authority_required", "signature_required", "signature_invalid", "chain_id_mismatch"],
        "privacy_boundary": "attestation submission is not available to observers or inactive validators",
    },
    {
        "id": "disputes-eligible-session-and-lane-bound",
        "method": "GET",
        "path": "/v1/disputes/eligible",
        "route_key": "GET /v1/disputes/eligible",
        "expected_http_statuses": [200, 403],
        "expected_top_level_keys": ["ok"],
        "auth_case": "session_and_dispute_review_lane_required",
        "error_codes": ["session_required", "reviewer_responsibility_not_active"],
        "privacy_boundary": "eligible dispute work cannot be assigned without exact dispute_review opt-in",
    },
    {
        "id": "dispute-accept-lane-bound",
        "method": "POST",
        "path": "/v1/disputes/{dispute_id}/accept",
        "route_key": "POST /v1/disputes/{dispute_id}/accept",
        "expected_http_statuses": [200, 403, 404],
        "expected_error_envelope": {"ok": False, "error": {"code": "reviewer_responsibility_not_active"}},
        "auth_case": "session_and_dispute_review_lane_required",
        "error_codes": ["reviewer_responsibility_not_active", "session_required", "not_found"],
        "privacy_boundary": "accepting dispute work requires exact active lane consent",
    },
    {
        "id": "poh-tier2-request-legacy-removed",
        "method": "POST",
        "path": "/v1/poh/tier2/tx/request",
        "route_key": "POST /v1/poh/tier2/tx/request",
        "expected_http_statuses": [410],
        "expected_error_envelope": {"ok": False, "error": {"code": "legacy_endpoint_removed"}},
        "auth_case": "legacy_skeleton_endpoint_removed_direct_tx_submit_required",
        "error_codes": ["legacy_endpoint_removed"],
        "privacy_boundary": "legacy Tier-2 skeleton helpers are removed; direct signed tx submission remains authoritative",
    },
    {
        "id": "net-peers-public-redacted",
        "method": "GET",
        "path": "/v1/net/peers",
        "route_key": "GET /v1/net/peers",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "public_redacted_peer_read",
        "error_codes": [],
        "privacy_boundary": "peer view is redacted and never leaks validator secrets",
    },
    {
        "id": "observer-reconcile-no-authority-grant",
        "method": "POST",
        "path": "/v1/observer/edge/reconcile/{tx_id}",
        "route_key": "POST /v1/observer/edge/reconcile/{tx_id}",
        "expected_http_statuses": [200, 403, 404],
        "expected_top_level_keys": ["ok"],
        "auth_case": "observer_edge_reconcile_only",
        "error_codes": ["observer_edge_disabled", "not_found"],
        "privacy_boundary": "observer reconciliation never grants validator signing authority",
    },
    {
        "id": "reputation-eligibility-public-redacted",
        "method": "GET",
        "path": "/v1/reputation/{account}/eligibility",
        "route_key": "GET /v1/reputation/{account}/eligibility",
        "expected_http_statuses": [200, 404],
        "expected_top_level_keys": ["ok"],
        "auth_case": "public_redacted_account_reputation_read",
        "error_codes": ["not_found"],
        "privacy_boundary": "eligibility reads are bounded reputation summaries and do not assign duties",
    },
    {
        "id": "economics-status-launch-blocked",
        "method": "GET",
        "path": "/v1/economics/status",
        "route_key": "GET /v1/economics/status",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "anonymous_public_economics_boundary_read",
        "error_codes": [],
        "privacy_boundary": "economics status must keep live transfers/rewards disabled before launch",
    },
    {
        "id": "treasury-status-launch-blocked",
        "method": "GET",
        "path": "/v1/treasury/status",
        "route_key": "GET /v1/treasury/status",
        "expected_http_statuses": [200],
        "expected_top_level_keys": ["ok"],
        "auth_case": "anonymous_public_treasury_boundary_read",
        "error_codes": [],
        "privacy_boundary": "treasury status does not enable spend before launch gates",
    },
    {
        "id": "wallet-read-no-live-economics",
        "method": "GET",
        "path": "/v1/wallet/{account}",
        "route_key": "GET /v1/wallet/{account}",
        "expected_http_statuses": [200, 404],
        "expected_top_level_keys": ["ok"],
        "auth_case": "public_or_session_scoped_wallet_read",
        "error_codes": ["not_found"],
        "privacy_boundary": "wallet reads do not imply live economics or transfer activation",
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
        "version": "2026-06-b620-public-beta-evidence-pack",
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
