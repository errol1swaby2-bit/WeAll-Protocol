from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_frontend_status_names_v2_specification_snapshot_unambiguously() -> None:
    compiler = (ROOT / "scripts" / "compile_v2_spec.py").read_text(encoding="utf-8")
    generated = (ROOT.parent / "web" / "src" / "generated" / "protocolStatus.ts").read_text(
        encoding="utf-8"
    )

    assert 'status["v2SpecificationSnapshot"]' in compiler
    assert 'status["repositorySnapshot"]' not in compiler
    assert '"v2SpecificationSnapshot"' in generated
    assert '"repositorySnapshot"' not in generated
