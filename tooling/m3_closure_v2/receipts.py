from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .errors import ReceiptError
from .util import atomic_write_json, canonical_json_sha256, sha256_file


@dataclass(frozen=True)
class StageReceipt:
    schema: str
    stage: str
    status: str
    input_fingerprint: str
    started_at_unix_ms: int
    completed_at_unix_ms: int
    outputs: Mapping[str, str]
    metadata: Mapping[str, Any]
    receipt_sha256: str

    def to_json(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "schema": self.schema,
            "stage": self.stage,
            "status": self.status,
            "input_fingerprint": self.input_fingerprint,
            "started_at_unix_ms": self.started_at_unix_ms,
            "completed_at_unix_ms": self.completed_at_unix_ms,
            "outputs": dict(self.outputs),
            "metadata": dict(self.metadata),
        }
        if include_hash:
            payload["receipt_sha256"] = self.receipt_sha256
        return payload


class ReceiptStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, stage: str) -> Path:
        safe = "".join(
            ch if ch.isalnum() or ch in "._-" else "_"
            for ch in str(stage)
        )
        if not safe:
            raise ReceiptError("stage_name_invalid")
        return self.root / f"{safe}.json"

    def create_passed(
        self,
        *,
        stage: str,
        input_fingerprint: str,
        started_at_unix_ms: int,
        output_paths: list[str | Path],
        metadata: Mapping[str, Any] | None = None,
    ) -> StageReceipt:
        outputs: dict[str, str] = {}
        for raw in output_paths:
            path = Path(raw).resolve()
            if not path.is_file():
                raise ReceiptError(f"stage_output_missing:{path}")
            outputs[str(path)] = sha256_file(path)

        base = {
            "schema": "weall.m3.stage-receipt.v1",
            "stage": stage,
            "status": "passed",
            "input_fingerprint": input_fingerprint,
            "started_at_unix_ms": int(started_at_unix_ms),
            "completed_at_unix_ms": int(time.time() * 1000),
            "outputs": outputs,
            "metadata": dict(metadata or {}),
        }
        receipt = StageReceipt(
            **base,
            receipt_sha256=canonical_json_sha256(base),
        )
        atomic_write_json(self.path_for(stage), receipt.to_json())
        return receipt

    def load(self, stage: str) -> StageReceipt:
        path = self.path_for(stage)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReceiptError(f"receipt_unreadable:{path}") from exc

        if not isinstance(raw, dict):
            raise ReceiptError(f"receipt_not_object:{path}")
        claimed = str(raw.get("receipt_sha256") or "")
        unsigned = dict(raw)
        unsigned.pop("receipt_sha256", None)
        actual = canonical_json_sha256(unsigned)
        if claimed != actual:
            raise ReceiptError(f"receipt_hash_mismatch:{path}")

        try:
            return StageReceipt(
                schema=str(raw["schema"]),
                stage=str(raw["stage"]),
                status=str(raw["status"]),
                input_fingerprint=str(raw["input_fingerprint"]),
                started_at_unix_ms=int(raw["started_at_unix_ms"]),
                completed_at_unix_ms=int(raw["completed_at_unix_ms"]),
                outputs=dict(raw["outputs"]),
                metadata=dict(raw["metadata"]),
                receipt_sha256=claimed,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ReceiptError(f"receipt_shape_invalid:{path}") from exc

    def valid_pass(
        self,
        *,
        stage: str,
        input_fingerprint: str,
    ) -> StageReceipt | None:
        try:
            receipt = self.load(stage)
        except ReceiptError:
            return None

        if receipt.status != "passed":
            return None
        if receipt.input_fingerprint != input_fingerprint:
            return None
        for raw_path, expected_hash in receipt.outputs.items():
            path = Path(raw_path)
            if not path.is_file():
                return None
            if sha256_file(path) != expected_hash:
                return None
        return receipt
