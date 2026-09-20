from pathlib import Path

GEN = Path('Weall-Protocol/scripts/gen_current_verified_claims.py')
TEST = Path('Weall-Protocol/tests/test_current_verified_claims_fail_closed.py')

text = GEN.read_text(encoding='utf-8')

def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'expected one target, found {count}: {old[:120]!r}')
    text = text.replace(old, new, 1)

replace_once(
    'import argparse\nimport hashlib\nimport json\n',
    'import argparse\nimport hashlib\nimport json\nimport math\nfrom datetime import datetime, timedelta\n',
)

replace_once(
    '''def _read_json(path: Path) -> dict[str, Any]:\n    if not path.is_file():\n        raise SystemExit(f"missing required JSON evidence: {path}")\n    try:\n        obj = json.loads(path.read_text(encoding="utf-8"))\n    except json.JSONDecodeError as exc:\n        raise SystemExit(f"invalid JSON evidence {path}: {exc}") from exc\n    if not isinstance(obj, dict):\n        raise SystemExit(f"expected JSON object: {path}")\n    return obj\n''',
    '''def _reject_nonfinite_json_constant(value: str) -> None:\n    raise ValueError(f"non-finite JSON number is not allowed: {value}")\n\n\ndef _read_json(path: Path) -> dict[str, Any]:\n    if not path.is_file():\n        raise SystemExit(f"missing required JSON evidence: {path}")\n    try:\n        obj = json.loads(\n            path.read_text(encoding="utf-8"),\n            parse_constant=_reject_nonfinite_json_constant,\n        )\n    except (json.JSONDecodeError, ValueError) as exc:\n        raise SystemExit(f"invalid JSON evidence {path}: {exc}") from exc\n    if not isinstance(obj, dict):\n        raise SystemExit(f"expected JSON object: {path}")\n    return obj\n''',
)

marker = '\n\ndef _validate_performance_registry(obj: dict[str, Any]) -> dict[str, Any]:\n'
helpers = '''\n\ndef _require_non_empty_description(\n    obj: dict[str, Any], key: str, *, source: str\n) -> str | dict[str, Any]:\n    if key not in obj:\n        raise SystemExit(f"{source} missing required field: {key}")\n    value = obj[key]\n    if isinstance(value, str) and value.strip():\n        return value\n    if isinstance(value, dict) and value:\n        return value\n    raise SystemExit(\n        f"{source} field {key} must be a non-empty string or non-empty object"\n    )\n\n\ndef _require_non_empty_object(\n    obj: dict[str, Any], key: str, *, source: str\n) -> dict[str, Any]:\n    value = obj.get(key)\n    if not isinstance(value, dict) or not value:\n        raise SystemExit(f"{source} field {key} must be a non-empty object")\n    return value\n\n\ndef _require_finite_json(value: Any, *, source: str) -> None:\n    if isinstance(value, bool) or value is None or isinstance(value, str):\n        return\n    if isinstance(value, (int, float)):\n        if not math.isfinite(float(value)):\n            raise SystemExit(f"{source} contains a non-finite number")\n        return\n    if isinstance(value, list):\n        for index, item in enumerate(value):\n            _require_finite_json(item, source=f"{source}[{index}]")\n        return\n    if isinstance(value, dict):\n        for key, item in value.items():\n            _require_finite_json(item, source=f"{source}.{key}")\n        return\n    raise SystemExit(f"{source} contains unsupported JSON value type: {type(value).__name__}")\n'''
if marker not in text:
    raise SystemExit('performance validator marker not found')
text = text.replace(marker, helpers + marker, 1)

replace_once(
    '''        missing = [\n            field for field in PERFORMANCE_REQUIRED_BENCHMARK_FIELDS if field not in benchmark\n        ]\n        if missing:\n            raise SystemExit(f"{source} qualifying_benchmarks[{index}] missing fields: {missing}")\n        benchmark_id = benchmark["benchmark_id"]\n''',
    '''        missing = [\n            field for field in PERFORMANCE_REQUIRED_BENCHMARK_FIELDS if field not in benchmark\n        ]\n        if missing:\n            raise SystemExit(f"{source} qualifying_benchmarks[{index}] missing fields: {missing}")\n        benchmark_source = f"{source} qualifying_benchmarks[{index}]"\n        _require_finite_json(benchmark, source=benchmark_source)\n        benchmark_id = benchmark["benchmark_id"]\n''',
)

replace_once(
    '''        duration = benchmark["duration_seconds"]\n        repetitions = benchmark["repetitions"]\n        if isinstance(duration, bool) or not isinstance(duration, (int, float)) or duration <= 0:\n            raise SystemExit(\n                f"{source} qualifying_benchmarks[{index}].duration_seconds must be > 0"\n            )\n        if isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions <= 0:\n            raise SystemExit(\n                f"{source} qualifying_benchmarks[{index}].repetitions must be a positive integer"\n            )\n''',
    '''        measured_at = benchmark["measured_at_utc"]\n        if not isinstance(measured_at, str) or not measured_at.strip() or not measured_at.endswith("Z"):\n            raise SystemExit(f"{benchmark_source}.measured_at_utc must be a non-empty UTC timestamp ending in Z")\n        try:\n            measured_dt = datetime.fromisoformat(measured_at[:-1] + "+00:00")\n        except ValueError as exc:\n            raise SystemExit(f"{benchmark_source}.measured_at_utc must be valid ISO-8601 UTC") from exc\n        if measured_dt.utcoffset() != timedelta(0):\n            raise SystemExit(f"{benchmark_source}.measured_at_utc must be UTC")\n\n        for field in (\n            "workload",\n            "crypto_signature_behavior",\n            "persistence_behavior",\n            "network_consensus_scope",\n            "topology",\n            "hardware",\n            "os_runtime",\n        ):\n            _require_non_empty_description(benchmark, field, source=benchmark_source)\n\n        for field in (\n            "latency_distribution",\n            "throughput_distribution",\n            "resource_utilization",\n        ):\n            _require_non_empty_object(benchmark, field, source=benchmark_source)\n\n        duration = benchmark["duration_seconds"]\n        repetitions = benchmark["repetitions"]\n        error_rate = benchmark["error_rate"]\n        if (\n            isinstance(duration, bool)\n            or not isinstance(duration, (int, float))\n            or not math.isfinite(float(duration))\n            or duration <= 0\n        ):\n            raise SystemExit(f"{benchmark_source}.duration_seconds must be a finite number > 0")\n        if isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions <= 0:\n            raise SystemExit(f"{benchmark_source}.repetitions must be a positive integer")\n        if (\n            isinstance(error_rate, bool)\n            or not isinstance(error_rate, (int, float))\n            or not math.isfinite(float(error_rate))\n            or not 0 <= error_rate <= 1\n        ):\n            raise SystemExit(f"{benchmark_source}.error_rate must be a finite number from 0 through 1")\n''',
)

GEN.write_text(text, encoding='utf-8')

append = r'''


def _valid_benchmark(module) -> dict:
    return {
        "benchmark_id": "bench-001",
        "subject_commit_sha": "1" * 40,
        "subject_tree_sha": "2" * 40,
        "measured_at_utc": "2026-09-20T23:59:00Z",
        "workload": "mixed canonical transaction workload",
        "crypto_signature_behavior": "ML-DSA signing enabled for measured authority path",
        "persistence_behavior": "durable persistence enabled",
        "network_consensus_scope": "single-host bounded benchmark; not multi-validator production evidence",
        "topology": "one node plus benchmark client",
        "hardware": "documented benchmark host",
        "os_runtime": "Linux / Python 3.12",
        "duration_seconds": 60,
        "repetitions": 3,
        "latency_distribution": {"p50_ms": 10, "p95_ms": 20, "p99_ms": 30},
        "throughput_distribution": {"median_tps": 100, "min_tps": 95, "max_tps": 105},
        "error_rate": 0.0,
        "resource_utilization": {"cpu_percent": 50, "rss_mb": 512},
    }


def test_performance_benchmark_rejects_null_descriptive_field(tmp_path: Path) -> None:
    module = load_module()
    paths, _, _, performance = fixtures(tmp_path)
    benchmark = _valid_benchmark(module)
    benchmark["workload"] = None
    performance["qualifying_benchmarks"] = [benchmark]
    write_json(paths["performance"], performance)
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="workload"):
        module.build()


def test_performance_benchmark_rejects_invalid_utc_timestamp(tmp_path: Path) -> None:
    module = load_module()
    paths, _, _, performance = fixtures(tmp_path)
    benchmark = _valid_benchmark(module)
    benchmark["measured_at_utc"] = "not-a-timestamp"
    performance["qualifying_benchmarks"] = [benchmark]
    write_json(paths["performance"], performance)
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="measured_at_utc"):
        module.build()


def test_performance_benchmark_rejects_empty_distribution(tmp_path: Path) -> None:
    module = load_module()
    paths, _, _, performance = fixtures(tmp_path)
    benchmark = _valid_benchmark(module)
    benchmark["latency_distribution"] = {}
    performance["qualifying_benchmarks"] = [benchmark]
    write_json(paths["performance"], performance)
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="latency_distribution"):
        module.build()


def test_performance_benchmark_rejects_error_rate_out_of_range(tmp_path: Path) -> None:
    module = load_module()
    paths, _, _, performance = fixtures(tmp_path)
    benchmark = _valid_benchmark(module)
    benchmark["error_rate"] = 1.01
    performance["qualifying_benchmarks"] = [benchmark]
    write_json(paths["performance"], performance)
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="error_rate"):
        module.build()


def test_performance_benchmark_accepts_structurally_complete_evidence(tmp_path: Path) -> None:
    module = load_module()
    paths, _, _, performance = fixtures(tmp_path)
    performance["qualifying_benchmarks"] = [_valid_benchmark(module)]
    write_json(paths["performance"], performance)
    bind(module, paths, tmp_path)
    row = claim(module.build(), "PERFORMANCE-001")
    assert row["value"]["qualifying_benchmark_count"] == 1
    assert row["value"]["current_scalar_tps_claim_allowed"] is False


def test_json_evidence_rejects_nonfinite_constant(tmp_path: Path) -> None:
    module = load_module()
    bad = tmp_path / "bad.json"
    bad.write_text('{"x": NaN}\n', encoding="utf-8")
    with pytest.raises(SystemExit, match="non-finite JSON number"):
        module._read_json(bad)


def test_performance_benchmark_rejects_overflow_to_infinity(tmp_path: Path) -> None:
    module = load_module()
    paths, _, _, performance = fixtures(tmp_path)
    performance["qualifying_benchmarks"] = [_valid_benchmark(module)]
    write_json(paths["performance"], performance)
    raw = paths["performance"].read_text(encoding="utf-8").replace('"duration_seconds": 60', '"duration_seconds": 1e999')
    paths["performance"].write_text(raw, encoding="utf-8")
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="non-finite"):
        module.build()
'''
with TEST.open('a', encoding='utf-8') as fh:
    fh.write(append)
