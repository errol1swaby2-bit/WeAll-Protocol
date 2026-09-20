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
PERFORMANCE = ROOT / "evidence" / "performance" / "current_performance_evidence.json"

JSON_OUT = ROOT / "generated" / "current_verified_claims.json"
MD_OUT = ROOT / "docs" / "CURRENT_VERIFIED_CLAIMS.md"

SCHEMA = "weall.current_verified_claims.v1"
VERSION = "1.0.0"

PERFORMANCE_SCHEMA = "weall.current_performance_evidence.v1"
PERFORMANCE_REQUIRED_BENCHMARK_FIELDS = (
    "benchmark_id", "subject_commit_sha", "subject_tree_sha", "measured_at_utc",
    "workload", "crypto_signature_behavior", "persistence_behavior",
    "network_consensus_scope", "topology", "hardware", "os_runtime",
    "duration_seconds", "repetitions", "latency_distribution",
    "throughput_distribution", "error_rate", "resource_utilization",
)


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"missing required JSON evidence: {path}")
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON evidence {path}: {exc}") from exc
    if not isinstance(obj, dict):
        raise SystemExit(f"expected JSON object: {path}")
    return obj


def _require_bool(obj: dict[str, Any], key: str, *, source: str) -> bool:
    if key not in obj:
        raise SystemExit(f"{source} missing required boolean field: {key}")
    value = obj[key]
    if not isinstance(value, bool):
        raise SystemExit(f"{source} field {key} must be boolean, found {type(value).__name__}")
    return value


def _require_string_list(obj: dict[str, Any], key: str, *, source: str) -> list[str]:
    if key not in obj:
        raise SystemExit(f"{source} missing required list field: {key}")
    value = obj[key]
    if not isinstance(value, list):
        raise SystemExit(f"{source} field {key} must be a list, found {type(value).__name__}")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise SystemExit(f"{source} field {key} must contain only non-empty strings")
    return value


def _validate_performance_registry(obj: dict[str, Any]) -> dict[str, Any]:
    source = str(PERFORMANCE.relative_to(ROOT))
    if obj.get("schema") != PERFORMANCE_SCHEMA:
        raise SystemExit(f"{source} schema must be {PERFORMANCE_SCHEMA!r}")
    if obj.get("subject_scope") != "repository-current":
        raise SystemExit(f"{source} subject_scope must be repository-current")
    allowed = _require_bool(obj, "current_scalar_tps_claim_allowed", source=source)
    historical = _require_bool(obj, "historical_measurements_current_claim_eligible", source=source)
    if historical:
        raise SystemExit(f"{source} must keep historical measurements ineligible for current claims")
    benchmarks = obj.get("qualifying_benchmarks")
    if not isinstance(benchmarks, list):
        raise SystemExit(f"{source} qualifying_benchmarks must be a list")
    if obj.get("qualification_requirements") != list(PERFORMANCE_REQUIRED_BENCHMARK_FIELDS):
        raise SystemExit(f"{source} qualification_requirements do not match the enforced contract")
    seen: set[str] = set()
    for index, benchmark in enumerate(benchmarks):
        if not isinstance(benchmark, dict):
            raise SystemExit(f"{source} qualifying_benchmarks[{index}] must be an object")
        missing = [field for field in PERFORMANCE_REQUIRED_BENCHMARK_FIELDS if field not in benchmark]
        if missing:
            raise SystemExit(f"{source} qualifying_benchmarks[{index}] missing fields: {missing}")
        benchmark_id = benchmark["benchmark_id"]
        if not isinstance(benchmark_id, str) or not benchmark_id.strip() or benchmark_id in seen:
            raise SystemExit(f"{source} qualifying_benchmarks[{index}].benchmark_id invalid or duplicate")
        seen.add(benchmark_id)
        for field in ("subject_commit_sha", "subject_tree_sha"):
            digest = benchmark[field]
            if not isinstance(digest, str) or len(digest) != 40 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
                raise SystemExit(f"{source} qualifying_benchmarks[{index}].{field} must be a 40-character Git SHA")
        duration = benchmark["duration_seconds"]
        repetitions = benchmark["repetitions"]
        if isinstance(duration, bool) or not isinstance(duration, (int, float)) or duration <= 0:
            raise SystemExit(f"{source} qualifying_benchmarks[{index}].duration_seconds must be > 0")
        if isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions <= 0:
            raise SystemExit(f"{source} qualifying_benchmarks[{index}].repetitions must be a positive integer")
    if allowed and not benchmarks:
        raise SystemExit(f"{source} cannot allow a current scalar TPS claim without a qualifying benchmark")
    return {"current_scalar_tps_claim_allowed": allowed, "qualifying_benchmark_count": len(benchmarks)}


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
    performance = _read_json(PERFORMANCE)
    performance_summary = _validate_performance_registry(performance)

    tx_types = tx.get("tx_types")
    if not isinstance(tx_types, list):
        raise SystemExit("generated/tx_index.json missing tx_types list")
    tx_meta = tx.get("meta")
    if not isinstance(tx_meta, dict):
        raise SystemExit("generated/tx_index.json missing meta object")

    boundaries = release.get("claim_boundaries")
    if not isinstance(boundaries, dict):
        raise SystemExit("release evidence manifest missing claim_boundaries")
    for key, value in boundaries.items():
        if not isinstance(value, bool):
            raise SystemExit(f"release evidence manifest claim boundary {key!r} must be boolean")
    public_beta_ready = _require_bool(release, "public_beta_ready", source="generated/release_evidence_manifest_v1_5.json")
    mainnet_ready = _require_bool(release, "mainnet_ready", source="generated/release_evidence_manifest_v1_5.json")
    if boundaries.get("public_beta_ready") is not public_beta_ready:
        raise SystemExit("release evidence manifest public_beta_ready disagrees with claim_boundaries")
    if boundaries.get("mainnet_ready") is not mainnet_ready:
        raise SystemExit("release evidence manifest mainnet_ready disagrees with claim_boundaries")

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
            value=public_beta_ready,
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
            value=mainnet_ready,
        )
    )

    claims.append(
        _claim(
            "READINESS-003",
            "readiness",
            "The current repository posture is pre-public-testnet / active hardening, not public beta or mainnet.",
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

    open_ids = _require_string_list(
        blockers, "remaining_external_evidence_required_ids",
        source="generated/public_beta_blocker_report_v1_5.json",
    )

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
            ["evidence/performance/current_performance_evidence.json"],
            notes=(
                "Historical TPS figures are not promoted to current truth. The dedicated "
                "performance registry is the machine-readable authority for whether any fresh "
                "exact-subject benchmark is eligible for a current scalar performance claim."
            ),
            value=performance_summary,
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
            str(path.relative_to(ROOT)): _sha256(path)
            for path in (TX_INDEX, BLOCKERS, RELEASE, PERFORMANCE)
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
        "clean-checkout audit after the relevant repository changes are committed.",
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
