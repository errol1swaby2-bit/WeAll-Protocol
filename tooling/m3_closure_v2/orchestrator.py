from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .errors import ContractError
from .receipts import ReceiptStore, StageReceipt
from .util import canonical_json_sha256


StageRunner = Callable[["StageContext"], "StageResult"]


@dataclass(frozen=True)
class StageResult:
    output_paths: tuple[Path, ...]
    metadata: Mapping[str, Any]


@dataclass(frozen=True)
class StageDefinition:
    name: str
    dependencies: tuple[str, ...]
    runner: StageRunner


@dataclass(frozen=True)
class StageContext:
    stage: str
    run_root: Path
    input_fingerprint: str
    dependency_receipts: Mapping[str, StageReceipt]
    config: Mapping[str, Any]


class Orchestrator:
    def __init__(
        self,
        *,
        run_root: str | Path,
        stages: list[StageDefinition],
        config: Mapping[str, Any],
    ) -> None:
        self.run_root = Path(run_root).resolve()
        self.run_root.mkdir(parents=True, exist_ok=True)
        self.receipts = ReceiptStore(self.run_root / "receipts")
        self.config = dict(config)
        self.stages = {stage.name: stage for stage in stages}
        if len(self.stages) != len(stages):
            raise ContractError("duplicate_stage_name")
        self._validate_graph()

    def _validate_graph(self) -> None:
        for stage in self.stages.values():
            for dependency in stage.dependencies:
                if dependency not in self.stages:
                    raise ContractError(
                        f"stage_dependency_missing:{stage.name}:{dependency}"
                    )

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visiting:
                raise ContractError(f"stage_dependency_cycle:{name}")
            if name in visited:
                return
            visiting.add(name)
            for dependency in self.stages[name].dependencies:
                visit(dependency)
            visiting.remove(name)
            visited.add(name)

        for name in self.stages:
            visit(name)

    def _order_for(self, targets: list[str]) -> list[str]:
        ordered: list[str] = []
        seen: set[str] = set()

        def add(name: str) -> None:
            if name not in self.stages:
                raise ContractError(f"stage_unknown:{name}")
            for dependency in self.stages[name].dependencies:
                add(dependency)
            if name not in seen:
                seen.add(name)
                ordered.append(name)

        for target in targets:
            add(target)
        return ordered

    def run(
        self,
        targets: list[str],
        *,
        resume: bool = True,
    ) -> list[StageReceipt]:
        completed: dict[str, StageReceipt] = {}
        results: list[StageReceipt] = []

        for name in self._order_for(targets):
            stage = self.stages[name]
            dependencies = {
                dependency: completed[dependency]
                for dependency in stage.dependencies
            }
            input_fingerprint = canonical_json_sha256(
                {
                    "stage": name,
                    "config": self.config,
                    "dependencies": {
                        dependency: receipt.receipt_sha256
                        for dependency, receipt in dependencies.items()
                    },
                }
            )

            if resume:
                existing = self.receipts.valid_pass(
                    stage=name,
                    input_fingerprint=input_fingerprint,
                )
                if existing is not None:
                    completed[name] = existing
                    results.append(existing)
                    continue

            started = int(time.time() * 1000)
            stage_root = self.run_root / "stages" / name
            stage_root.mkdir(parents=True, exist_ok=True)
            result = stage.runner(
                StageContext(
                    stage=name,
                    run_root=stage_root,
                    input_fingerprint=input_fingerprint,
                    dependency_receipts=dependencies,
                    config=self.config,
                )
            )
            receipt = self.receipts.create_passed(
                stage=name,
                input_fingerprint=input_fingerprint,
                started_at_unix_ms=started,
                output_paths=list(result.output_paths),
                metadata=result.metadata,
            )
            completed[name] = receipt
            results.append(receipt)

        return results
