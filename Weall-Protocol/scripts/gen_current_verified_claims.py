from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

TX_INDEX = ROOT / "generated" / "tx_index.json"
BLOCKERS = ROOT / "generated" / "public_beta_blocker_report_v1_5.json"
RELEASE = ROOT / "generated" / "release_evidence_manifest_v1_5.json"

JSON_OUT = ROOT / "generated" / "current_verified_claims.json"
MD_OUT = ROOT / "docs" / "CURRENT_VERIFIED_CLAIMS.md"

SCHEMA = "weall.current_verified_claims.v1"
VERSION = "1.0.0"


def _read_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise SystemExit(f"expected JSON object: {path}")
    return obj


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _claim(
    claim_id: str,
    claim_type: str,
    statement: str,
    status: str,
    evidence: list[str],
    *,
    scope: str = "repository-current",
    current_or_historical: str = "current",
    exact_commit_bound: bool = False,
    notes: str = "",
    value: Any = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "claim_id": claim_id,
        "claim_type": claim_type,
        "scope": scope,
        "current_or_historical": current_or_historical,
        "claim_text": statement,
        "evidence_required": True,
        "evidence_found": True,
        "evidence_location": evidence,
        "exact_commit_bound": exact_commit_bound,
        "status": status,
        "replacement_text": None,
        "notes": notes,
    }
    if value is not None:
        row["value"] = value
    return row


def build() -> dict[str, Any]:
    tx = _read_json(TX_INDEX)
    blockers = _read_json(BLOCKERS)
    release = _read_json(RELEASE)

    tx_types = tx.get("tx_types")
    if not isinstance(tx_types, list):
        raise SystemExit("generated/tx_index.json missing tx_types list")
    tx_meta = tx.get("meta")
    if not isinstance(tx_meta, dict):
        raise SystemExit("generated/tx_index.json missing meta object")

    boundaries = release.get("claim_boundaries")
    if not isinstance(boundaries, dict):
        raise SystemExit("release evidence manifest missing claim_boundaries")

    claims: list[dict[str, Any]] = []

    claims.append(
        _claim(
            "READINESS-001",
            "readiness",
            "Public beta readiness is not currently claimed.",
            "PROVEN_GENERATED_CURRENT",
            [
                "generated/public_beta_blocker_report_v1_5.json",
                "generated/release_evidence_manifest_v1_5.json",
            ],
            value=bool(blockers.get("public_beta_ready")),
            notes="The canonical generated blocker report currently records public_beta_ready=false.",
        )
    )

    claims.append(
        _claim(
            "READINESS-002",
            "readiness",
            "Mainnet readiness is not currently claimed.",
            "PROVEN_GENERATED_CURRENT",
            [
                "generated/public_beta_blocker_report_v1_5.json",
                "generated/release_evidence_manifest_v1_5.json",
            ],
            value=bool(blockers.get("mainnet_ready")),
        )
    )

    claims.append(
        _claim(
            "READINESS-003",
            "readiness",
            "The current reviewer framing is pre-public-testnet / active hardening, not public beta or mainnet.",
            "SUPPORTED_BUT_QUALIFICATION_REQUIRED",
            [
                "docs/reviewer/CURRENT_READINESS_STATEMENT.md",
                "docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md",
                "generated/public_beta_blocker_report_v1_5.json",
            ],
            notes="This is a bounded repository-status statement, not an external validation claim.",
        )
    )

    claims.append(
        _claim(
            "TX-CANON-001",
            "structural_count",
            "The canonical transaction index count and version are generated facts.",
            "PROVEN_GENERATED_CURRENT",
            ["generated/tx_index.json"],
            value={
                "transaction_types": len(tx_types),
                "version": tx_meta.get("version"),
                "law": tx_meta.get("law"),
            },
            notes="Consumers should read the generated artifact rather than copy these values into durable prose.",
        )
    )

    for key in sorted(boundaries):
        value = boundaries[key]
        claims.append(
            _claim(
                f"BOUNDARY-{key.upper().replace('-', '_')}",
                "claim_boundary",
                f"Release claim boundary `{key}` is {'enabled' if value else 'not claimed/enabled'}.",
                "PROVEN_GENERATED_CURRENT",
                ["generated/release_evidence_manifest_v1_5.json"],
                value=value,
            )
        )

    open_ids = blockers.get("remaining_external_evidence_required_ids")
    if not isinstance(open_ids, list):
        open_ids = []

    claims.append(
        _claim(
            "EXTERNAL-VALIDATION-001",
            "external_validation",
            "Open release blockers still require external evidence before stronger public launch claims are allowed.",
            "EXTERNAL_VALIDATION_REQUIRED",
            ["generated/public_beta_blocker_report_v1_5.json"],
            value={"remaining_external_evidence_required_ids": open_ids},
        )
    )

    crypto_open = "AUD-633-P0-004" in open_ids
    claims.append(
        _claim(
            "CRYPTO-REVIEW-001",
            "cryptography",
            "Completed production cryptographic audit and production post-quantum security are not currently claimed.",
            "EXTERNAL_VALIDATION_REQUIRED"
            if crypto_open
            else "SUPPORTED_BUT_QUALIFICATION_REQUIRED",
            [
                "generated/public_beta_blocker_report_v1_5.json",
                "docs/reviewer/CURRENT_READINESS_STATEMENT.md",
            ],
            value={"external_crypto_review_blocker_open": crypto_open},
        )
    )

    claims.append(
        _claim(
            "PERFORMANCE-001",
            "performance",
            "No scalar TPS value is asserted as a current verified performance claim by this manifest.",
            "NOT_CURRENTLY_MEASURABLE",
            ["scripts/check_public_claim_freshness.py"],
            notes=(
                "Historical TPS figures are not promoted to current truth. A future performance "
                "claim requires a fresh exact-subject benchmark with methodology and provenance."
            ),
        )
    )

    claims.append(
        _claim(
            "V2-DERIVATIVE-001",
            "generated_derivative_boundary",
            "V2 structural counts and derivative fingerprints are intentionally not duplicated into this claims manifest.",
            "SUPPORTED_BUT_QUALIFICATION_REQUIRED",
            [
                "generated/v2/spec_compilation_manifest.json",
                "scripts/compile_v2_spec.py",
            ],
            notes=(
                "The V2 compiler owns those generated facts. This manifest is downstream evidence "
                "and must not depend on a V2 derivative that also scans this manifest, which would "
                "create a circular freshness dependency."
            ),
        )
    )

    claims.append(
        _claim(
            "TEST-EVIDENCE-001",
            "testing",
            "Volatile pytest pass counts are intentionally not stored as a durable current claim in this tracked manifest.",
            "SUPPORTED_BUT_QUALIFICATION_REQUIRED",
            [
                ".github/workflows/backend-ci.yml",
                "scripts/check_v2_spec_clean_checkout.py",
            ],
            notes=(
                "Exact test totals belong to run evidence and final clean-commit validation, not a "
                "self-staling tracked claim."
            ),
        )
    )

    return {
        "schema": SCHEMA,
        "version": VERSION,
        "tracked_manifest_is_commit_agnostic": True,
        "exact_commit_binding_required_for_final_audit": True,
        "generation_inputs": {
            str(path.relative_to(ROOT)): _sha256(path) for path in (TX_INDEX, BLOCKERS, RELEASE)
        },
        "claims": claims,
    }


def render_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_markdown(payload: dict[str, Any]) -> str:
    claims = payload["claims"]
    lines = [
        "# Current Verified Claims",
        "",
        "> GENERATED FILE — do not edit by hand.",
        "> Regenerate with `python scripts/gen_current_verified_claims.py`.",
        "",
        "This artifact summarizes bounded claims supported by canonical repository artifacts.",
        "It is intentionally commit-agnostic: final exact-commit binding is established by the",
        "clean-checkout audit after the review-prep changes are committed.",
        "",
        "It does **not** claim public beta readiness, mainnet readiness, completed external",
        "cryptographic review, or a current scalar TPS measurement.",
        "",
        "## Claim register",
        "",
        "| Claim ID | Type | Status | Current claim | Evidence |",
        "| --- | --- | --- | --- | --- |",
    ]

    for row in claims:
        evidence = "<br>".join(f"`{item}`" for item in row["evidence_location"])
        claim = row["claim_text"].replace("|", "\\|")
        lines.append(
            f"| `{row['claim_id']}` | {row['claim_type']} | `{row['status']}` | "
            f"{claim} | {evidence} |"
        )

    by_id = {row["claim_id"]: row for row in claims}
    tx = by_id["TX-CANON-001"]["value"]
    external = by_id["EXTERNAL-VALIDATION-001"]["value"]

    lines += [
        "",
        "## Canonical generated snapshot",
        "",
        f"- Transaction types: **{tx['transaction_types']}** (generated tx canon version `{tx['version']}`).",
        "- Public beta readiness: **not claimed**.",
        "- Mainnet readiness: **not claimed**.",
        f"- Remaining external-evidence blocker IDs: `{', '.join(external['remaining_external_evidence_required_ids'])}`.",
        "",
        "V2 structural counts are intentionally not copied here. Their canonical source is",
        "`generated/v2/spec_compilation_manifest.json`, verified independently by",
        "`python scripts/compile_v2_spec.py --check`.",
        "",
        "## Performance boundary",
        "",
        "Historical TPS measurements are not treated as current verified performance evidence.",
        "No scalar TPS value should be promoted to a current claim without a fresh exact-subject",
        "benchmark recording workload, crypto/signature behavior, persistence, network/consensus",
        "scope, topology, hardware, OS/runtime, duration, repetitions, latency distribution,",
        "throughput distribution, error rate, and resource utilization.",
        "",
        "## External validation boundary",
        "",
        "Internal repository evidence is not a substitute for independent cryptographic, legal,",
        "operator, storage, cross-machine, or other external evidence required by open launch gates.",
        "",
    ]

    return "\n".join(lines)


def _check_or_write(path: Path, expected: str, check: bool) -> bool:
    if check:
        if not path.exists() or path.read_text(encoding="utf-8") != expected:
            print(f"stale or missing: {path.relative_to(ROOT)}")
            return False
        print(f"current: {path.relative_to(ROOT)}")
        return True

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(expected, encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    payload = build()
    ok_json = _check_or_write(JSON_OUT, render_json(payload), args.check)
    ok_md = _check_or_write(MD_OUT, render_markdown(payload), args.check)

    if args.check and not (ok_json and ok_md):
        return 1

    if args.check:
        print("OK: current verified claims artifacts are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
