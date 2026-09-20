from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "Weall-Protocol/scripts/gen_current_verified_claims.py"
PERF = ROOT / "Weall-Protocol/evidence/performance/current_performance_evidence.json"
TEST = ROOT / "Weall-Protocol/tests/test_current_verified_claims_fail_closed.py"

text = GEN.read_text(encoding="utf-8")


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one replacement target, found {count}: {old[:100]!r}")
    text = text.replace(old, new, 1)


replace_once(
    'RELEASE = ROOT / "generated" / "release_evidence_manifest_v1_5.json"\n',
    'RELEASE = ROOT / "generated" / "release_evidence_manifest_v1_5.json"\n'
    'PERFORMANCE = ROOT / "evidence" / "performance" / "current_performance_evidence.json"\n',
)

replace_once(
    'VERSION = "1.0.0"\n\n\n'
    'def _read_json(path: Path) -> dict[str, Any]:\n'
    '    obj = json.loads(path.read_text(encoding="utf-8"))\n'
    '    if not isinstance(obj, dict):\n'
    '        raise SystemExit(f"expected JSON object: {path}")\n'
    '    return obj\n',
    'VERSION = "1.0.0"\n\n'
    'PERFORMANCE_SCHEMA = "weall.current_performance_evidence.v1"\n'
    'PERFORMANCE_REQUIRED_BENCHMARK_FIELDS = (\n'
    '    "benchmark_id", "subject_commit_sha", "subject_tree_sha", "measured_at_utc",\n'
    '    "workload", "crypto_signature_behavior", "persistence_behavior",\n'
    '    "network_consensus_scope", "topology", "hardware", "os_runtime",\n'
    '    "duration_seconds", "repetitions", "latency_distribution",\n'
    '    "throughput_distribution", "error_rate", "resource_utilization",\n'
    ')\n\n\n'
    'def _read_json(path: Path) -> dict[str, Any]:\n'
    '    if not path.is_file():\n'
    '        raise SystemExit(f"missing required JSON evidence: {path}")\n'
    '    try:\n'
    '        obj = json.loads(path.read_text(encoding="utf-8"))\n'
    '    except json.JSONDecodeError as exc:\n'
    '        raise SystemExit(f"invalid JSON evidence {path}: {exc}") from exc\n'
    '    if not isinstance(obj, dict):\n'
    '        raise SystemExit(f"expected JSON object: {path}")\n'
    '    return obj\n\n\n'
    'def _require_bool(obj: dict[str, Any], key: str, *, source: str) -> bool:\n'
    '    if key not in obj:\n'
    '        raise SystemExit(f"{source} missing required boolean field: {key}")\n'
    '    value = obj[key]\n'
    '    if not isinstance(value, bool):\n'
    '        raise SystemExit(f"{source} field {key} must be boolean, found {type(value).__name__}")\n'
    '    return value\n\n\n'
    'def _require_string_list(obj: dict[str, Any], key: str, *, source: str) -> list[str]:\n'
    '    if key not in obj:\n'
    '        raise SystemExit(f"{source} missing required list field: {key}")\n'
    '    value = obj[key]\n'
    '    if not isinstance(value, list):\n'
    '        raise SystemExit(f"{source} field {key} must be a list, found {type(value).__name__}")\n'
    '    if not all(isinstance(item, str) and item.strip() for item in value):\n'
    '        raise SystemExit(f"{source} field {key} must contain only non-empty strings")\n'
    '    return value\n\n\n'
    'def _validate_performance_registry(obj: dict[str, Any]) -> dict[str, Any]:\n'
    '    source = str(PERFORMANCE.relative_to(ROOT))\n'
    '    if obj.get("schema") != PERFORMANCE_SCHEMA:\n'
    '        raise SystemExit(f"{source} schema must be {PERFORMANCE_SCHEMA!r}")\n'
    '    if obj.get("subject_scope") != "repository-current":\n'
    '        raise SystemExit(f"{source} subject_scope must be repository-current")\n'
    '    allowed = _require_bool(obj, "current_scalar_tps_claim_allowed", source=source)\n'
    '    historical = _require_bool(obj, "historical_measurements_current_claim_eligible", source=source)\n'
    '    if historical:\n'
    '        raise SystemExit(f"{source} must keep historical measurements ineligible for current claims")\n'
    '    benchmarks = obj.get("qualifying_benchmarks")\n'
    '    if not isinstance(benchmarks, list):\n'
    '        raise SystemExit(f"{source} qualifying_benchmarks must be a list")\n'
    '    if obj.get("qualification_requirements") != list(PERFORMANCE_REQUIRED_BENCHMARK_FIELDS):\n'
    '        raise SystemExit(f"{source} qualification_requirements do not match the enforced contract")\n'
    '    seen: set[str] = set()\n'
    '    for index, benchmark in enumerate(benchmarks):\n'
    '        if not isinstance(benchmark, dict):\n'
    '            raise SystemExit(f"{source} qualifying_benchmarks[{index}] must be an object")\n'
    '        missing = [field for field in PERFORMANCE_REQUIRED_BENCHMARK_FIELDS if field not in benchmark]\n'
    '        if missing:\n'
    '            raise SystemExit(f"{source} qualifying_benchmarks[{index}] missing fields: {missing}")\n'
    '        benchmark_id = benchmark["benchmark_id"]\n'
    '        if not isinstance(benchmark_id, str) or not benchmark_id.strip() or benchmark_id in seen:\n'
    '            raise SystemExit(f"{source} qualifying_benchmarks[{index}].benchmark_id invalid or duplicate")\n'
    '        seen.add(benchmark_id)\n'
    '        for field in ("subject_commit_sha", "subject_tree_sha"):\n'
    '            digest = benchmark[field]\n'
    '            if not isinstance(digest, str) or len(digest) != 40 or any(ch not in "0123456789abcdef" for ch in digest.lower()):\n'
    '                raise SystemExit(f"{source} qualifying_benchmarks[{index}].{field} must be a 40-character Git SHA")\n'
    '        duration = benchmark["duration_seconds"]\n'
    '        repetitions = benchmark["repetitions"]\n'
    '        if isinstance(duration, bool) or not isinstance(duration, (int, float)) or duration <= 0:\n'
    '            raise SystemExit(f"{source} qualifying_benchmarks[{index}].duration_seconds must be > 0")\n'
    '        if isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions <= 0:\n'
    '            raise SystemExit(f"{source} qualifying_benchmarks[{index}].repetitions must be a positive integer")\n'
    '    if allowed and not benchmarks:\n'
    '        raise SystemExit(f"{source} cannot allow a current scalar TPS claim without a qualifying benchmark")\n'
    '    return {"current_scalar_tps_claim_allowed": allowed, "qualifying_benchmark_count": len(benchmarks)}\n',
)

replace_once(
    '    blockers = _read_json(BLOCKERS)\n    release = _read_json(RELEASE)\n',
    '    blockers = _read_json(BLOCKERS)\n    release = _read_json(RELEASE)\n'
    '    performance = _read_json(PERFORMANCE)\n'
    '    performance_summary = _validate_performance_registry(performance)\n',
)

replace_once(
    '    boundaries = release.get("claim_boundaries")\n'
    '    if not isinstance(boundaries, dict):\n'
    '        raise SystemExit("release evidence manifest missing claim_boundaries")\n',
    '    boundaries = release.get("claim_boundaries")\n'
    '    if not isinstance(boundaries, dict):\n'
    '        raise SystemExit("release evidence manifest missing claim_boundaries")\n'
    '    for key, value in boundaries.items():\n'
    '        if not isinstance(value, bool):\n'
    '            raise SystemExit(f"release evidence manifest claim boundary {key!r} must be boolean")\n'
    '    public_beta_ready = _require_bool(release, "public_beta_ready", source="generated/release_evidence_manifest_v1_5.json")\n'
    '    mainnet_ready = _require_bool(release, "mainnet_ready", source="generated/release_evidence_manifest_v1_5.json")\n'
    '    if boundaries.get("public_beta_ready") is not public_beta_ready:\n'
    '        raise SystemExit("release evidence manifest public_beta_ready disagrees with claim_boundaries")\n'
    '    if boundaries.get("mainnet_ready") is not mainnet_ready:\n'
    '        raise SystemExit("release evidence manifest mainnet_ready disagrees with claim_boundaries")\n',
)

replace_once('            value=bool(blockers.get("public_beta_ready")),\n', '            value=public_beta_ready,\n')
replace_once('            value=bool(blockers.get("mainnet_ready")),\n', '            value=mainnet_ready,\n')
replace_once(
    '    open_ids = blockers.get("remaining_external_evidence_required_ids")\n'
    '    if not isinstance(open_ids, list):\n'
    '        open_ids = []\n',
    '    open_ids = _require_string_list(\n'
    '        blockers, "remaining_external_evidence_required_ids",\n'
    '        source="generated/public_beta_blocker_report_v1_5.json",\n'
    '    )\n',
)
replace_once(
    '            ["scripts/check_public_claim_freshness.py"],\n'
    '            notes=(\n'
    '                "Historical TPS figures are not promoted to current truth. A future performance "\n'
    '                "claim requires a fresh exact-subject benchmark with methodology and provenance."\n'
    '            ),\n',
    '            ["evidence/performance/current_performance_evidence.json"],\n'
    '            notes=(\n'
    '                "Historical TPS figures are not promoted to current truth. The dedicated "\n'
    '                "performance registry is the machine-readable authority for whether any fresh "\n'
    '                "exact-subject benchmark is eligible for a current scalar performance claim."\n'
    '            ),\n'
    '            value=performance_summary,\n',
)
replace_once(
    '        "generation_inputs": {\n'
    '            str(path.relative_to(ROOT)): _sha256(path) for path in (TX_INDEX, BLOCKERS, RELEASE)\n'
    '        },\n',
    '        "generation_inputs": {\n'
    '            str(path.relative_to(ROOT)): _sha256(path)\n'
    '            for path in (TX_INDEX, BLOCKERS, RELEASE, PERFORMANCE)\n'
    '        },\n',
)

GEN.write_text(text, encoding="utf-8")

PERF.parent.mkdir(parents=True, exist_ok=True)
PERF.write_text(json.dumps({
    "schema": "weall.current_performance_evidence.v1",
    "version": "1.0.0",
    "subject_scope": "repository-current",
    "current_scalar_tps_claim_allowed": False,
    "qualifying_benchmarks": [],
    "qualification_requirements": [
        "benchmark_id", "subject_commit_sha", "subject_tree_sha", "measured_at_utc",
        "workload", "crypto_signature_behavior", "persistence_behavior",
        "network_consensus_scope", "topology", "hardware", "os_runtime",
        "duration_seconds", "repetitions", "latency_distribution",
        "throughput_distribution", "error_rate", "resource_utilization"
    ],
    "historical_measurements_current_claim_eligible": False,
    "notes": [
        "Historical TPS measurements are excluded from current verified performance claims.",
        "A benchmark is not eligible for a current scalar TPS claim unless it is explicitly recorded here with exact subject binding and the complete qualification fields above.",
        "An empty qualifying_benchmarks array is affirmative machine-readable evidence that no benchmark has been admitted as current performance evidence by this registry."
    ]
}, indent=2) + "\n", encoding="utf-8")

TEST.write_text(r'''from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "gen_current_verified_claims.py"


def load_module():
    spec = importlib.util.spec_from_file_location("claims_under_test", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def fixtures(tmp_path: Path):
    tx = {"tx_types": ["ACCOUNT_CREATE"], "meta": {"version": "test", "law": "append-only"}}
    blockers = {"remaining_external_evidence_required_ids": ["AUD-633-P0-004"]}
    release = {
        "public_beta_ready": False,
        "mainnet_ready": False,
        "claim_boundaries": {"public_beta_ready": False, "mainnet_ready": False, "live_economics": False},
    }
    performance = {
        "schema": "weall.current_performance_evidence.v1",
        "version": "1.0.0",
        "subject_scope": "repository-current",
        "current_scalar_tps_claim_allowed": False,
        "qualifying_benchmarks": [],
        "qualification_requirements": list(load_module().PERFORMANCE_REQUIRED_BENCHMARK_FIELDS),
        "historical_measurements_current_claim_eligible": False,
        "notes": [],
    }
    paths = {name: tmp_path / f"{name}.json" for name in ("tx", "blockers", "release", "performance")}
    for name, value in (("tx", tx), ("blockers", blockers), ("release", release), ("performance", performance)):
        write_json(paths[name], value)
    return paths, blockers, release, performance


def bind(module, paths, tmp_path: Path) -> None:
    module.ROOT = tmp_path
    module.TX_INDEX = paths["tx"]
    module.BLOCKERS = paths["blockers"]
    module.RELEASE = paths["release"]
    module.PERFORMANCE = paths["performance"]


def claim(payload: dict, claim_id: str) -> dict:
    return next(row for row in payload["claims"] if row["claim_id"] == claim_id)


def test_performance_registry_is_authority(tmp_path: Path) -> None:
    module = load_module()
    paths, _, _, _ = fixtures(tmp_path)
    bind(module, paths, tmp_path)
    row = claim(module.build(), "PERFORMANCE-001")
    assert row["evidence_location"] == ["evidence/performance/current_performance_evidence.json"]
    assert row["value"] == {"current_scalar_tps_claim_allowed": False, "qualifying_benchmark_count": 0}


@pytest.mark.parametrize("key", ["public_beta_ready", "mainnet_ready"])
def test_missing_readiness_boolean_fails_closed(tmp_path: Path, key: str) -> None:
    module = load_module()
    paths, _, release, _ = fixtures(tmp_path)
    del release[key]
    write_json(paths["release"], release)
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match=key):
        module.build()


def test_malformed_blocker_list_fails_closed(tmp_path: Path) -> None:
    module = load_module()
    paths, blockers, _, _ = fixtures(tmp_path)
    blockers["remaining_external_evidence_required_ids"] = "AUD-633-P0-004"
    write_json(paths["blockers"], blockers)
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="must be a list"):
        module.build()


def test_missing_performance_registry_fails_closed(tmp_path: Path) -> None:
    module = load_module()
    paths, _, _, _ = fixtures(tmp_path)
    paths["performance"].unlink()
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="missing required JSON evidence"):
        module.build()


def test_scalar_claim_cannot_be_enabled_without_benchmark(tmp_path: Path) -> None:
    module = load_module()
    paths, _, _, performance = fixtures(tmp_path)
    performance["current_scalar_tps_claim_allowed"] = True
    write_json(paths["performance"], performance)
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="without a qualifying benchmark"):
        module.build()


def test_non_boolean_claim_boundary_fails_closed(tmp_path: Path) -> None:
    module = load_module()
    paths, _, release, _ = fixtures(tmp_path)
    release["claim_boundaries"]["live_economics"] = "false"
    write_json(paths["release"], release)
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="must be boolean"):
        module.build()
''', encoding="utf-8")

subprocess.run([sys.executable, str(ROOT / "Weall-Protocol/scripts/gen_current_verified_claims.py")], cwd=ROOT / "Weall-Protocol", check=True)
subprocess.run([sys.executable, "-m", "py_compile", str(GEN)], check=True)
print("claim evidence repair prepared")
