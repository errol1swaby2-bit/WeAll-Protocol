from pathlib import Path

GEN = Path("Weall-Protocol/scripts/gen_public_beta_blocker_report_v1_5.py")
TEST = Path("Weall-Protocol/tests/test_public_beta_blocker_report_fail_closed.py")

text = GEN.read_text(encoding="utf-8")


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one replacement target, found {count}: {old[:160]!r}")
    text = text.replace(old, new, 1)


replace_once(
    '        "ok": bool(payload.get("ok", True)) if payload else False,\n',
    '        "ok": payload.get("ok") is True if payload else False,\n',
)

replace_once(
    '    if gate_status.startswith("closed"):\n        category = "closed_by_artifact_or_docs"\n',
    '    is_closed = gate_status.startswith("closed")\n'
    '    if is_closed and remaining_external_evidence:\n'
    '        raise SystemExit(\n'
    '            "closed blocker status contradicts non-empty remaining_external_evidence"\n'
    '        )\n'
    '    if is_closed:\n'
    '        category = "closed_by_artifact_or_docs"\n',
)

marker = "\n\ndef build() -> Json:\n"
if marker not in text:
    raise SystemExit("build() marker not found")

invariant = '''

def _validate_blocker_invariants(blockers: list[Json]) -> None:
    seen_ids: set[str] = set()
    for index, blocker in enumerate(blockers):
        blocker_id = blocker.get("id")
        if not isinstance(blocker_id, str) or not blocker_id.strip():
            raise SystemExit(f"blockers[{index}] missing non-empty id")
        if blocker_id in seen_ids:
            raise SystemExit(f"duplicate blocker id: {blocker_id}")
        seen_ids.add(blocker_id)

        gate_status = blocker.get("gate_status")
        if not isinstance(gate_status, str) or not gate_status.strip():
            raise SystemExit(f"{blocker_id} missing non-empty gate_status")
        is_closed = gate_status.startswith("closed")

        remaining = blocker.get("remaining_external_evidence")
        if not isinstance(remaining, list) or not all(
            isinstance(item, str) and item.strip() for item in remaining
        ):
            raise SystemExit(
                f"{blocker_id} remaining_external_evidence must be a list of non-empty strings"
            )
        if is_closed and remaining:
            raise SystemExit(
                f"{blocker_id} is closed but still declares remaining external evidence"
            )

        safe_to_close = blocker.get("safe_to_close_with_current_repository_evidence")
        if not isinstance(safe_to_close, bool):
            raise SystemExit(f"{blocker_id} safe_to_close flag must be boolean")
        if safe_to_close is not is_closed:
            raise SystemExit(
                f"{blocker_id} safe_to_close flag contradicts gate_status={gate_status!r}"
            )

        blocks = blocker.get("blocks")
        if not isinstance(blocks, list) or not blocks or not all(
            isinstance(item, str) and item.strip() for item in blocks
        ):
            raise SystemExit(f"{blocker_id} blocks must be a non-empty list of strings")
'''
text = text.replace(marker, invariant + marker, 1)

replace_once(
    "    # Fail closed: every blocker that is not explicitly closed remains open.\n",
    "    _validate_blocker_invariants(blockers)\n\n"
    "    # Fail closed: every blocker that is not explicitly closed remains open.\n",
)

GEN.write_text(text, encoding="utf-8")

with TEST.open("a", encoding="utf-8") as fh:
    fh.write('''


def test_closed_status_with_remaining_external_evidence_is_rejected() -> None:
    module = _load_module()
    try:
        module._classify_blocker(
            severity="P1",
            blocks=["public_beta"],
            gate_status="closed_as_artifact_gate",
            remaining_external_evidence=["still missing external transcript"],
            can_be_closed_by_code_only=True,
        )
    except SystemExit as exc:
        assert "contradicts" in str(exc)
    else:
        raise AssertionError("contradictory closed blocker must fail closed")


def test_duplicate_blocker_ids_are_rejected() -> None:
    module = _load_module()
    row = {
        "id": "AUD-DUP",
        "severity": "P1",
        "blocks": ["public_beta"],
        "gate_status": "gate_failed",
        "remaining_external_evidence": [],
        "safe_to_close_with_current_repository_evidence": False,
    }
    try:
        module._validate_blocker_invariants([row, dict(row)])
    except SystemExit as exc:
        assert "duplicate blocker id" in str(exc)
    else:
        raise AssertionError("duplicate blocker IDs must fail closed")


def test_artifact_summary_requires_explicit_ok_true(tmp_path: Path) -> None:
    import json

    module = _load_module()
    module.ROOT = tmp_path
    generated = tmp_path / "generated"
    generated.mkdir()

    (generated / "missing_ok.json").write_text(
        json.dumps({"schema": "test.schema", "payload": {"x": 1}}),
        encoding="utf-8",
    )
    assert module._artifact_summary("generated/missing_ok.json")["ok"] is False

    (generated / "explicit_true.json").write_text(
        json.dumps({"schema": "test.schema", "ok": True}),
        encoding="utf-8",
    )
    assert module._artifact_summary("generated/explicit_true.json")["ok"] is True

    (generated / "explicit_false.json").write_text(
        json.dumps({"schema": "test.schema", "ok": False}),
        encoding="utf-8",
    )
    assert module._artifact_summary("generated/explicit_false.json")["ok"] is False
''')
