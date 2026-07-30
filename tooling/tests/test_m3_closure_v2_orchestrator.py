from __future__ import annotations

from pathlib import Path

from m3_closure_v2.orchestrator import (
    Orchestrator,
    StageContext,
    StageDefinition,
    StageResult,
)


def test_orchestrator_resumes_valid_stage_receipt(tmp_path: Path) -> None:
    calls: list[str] = []

    def stage_a(ctx: StageContext) -> StageResult:
        calls.append(ctx.stage)
        output = ctx.run_root / "a.txt"
        output.write_text("a\n", encoding="utf-8")
        return StageResult((output,), {"stage": "a"})

    def stage_b(ctx: StageContext) -> StageResult:
        calls.append(ctx.stage)
        output = ctx.run_root / "b.txt"
        output.write_text("b\n", encoding="utf-8")
        return StageResult((output,), {"stage": "b"})

    orchestrator = Orchestrator(
        run_root=tmp_path / "run",
        config={"freeze": "a" * 40},
        stages=[
            StageDefinition("a", (), stage_a),
            StageDefinition("b", ("a",), stage_b),
        ],
    )
    first = orchestrator.run(["b"])
    second = orchestrator.run(["b"])

    assert calls == ["a", "b"]
    assert [item.stage for item in first] == ["a", "b"]
    assert [item.stage for item in second] == ["a", "b"]
