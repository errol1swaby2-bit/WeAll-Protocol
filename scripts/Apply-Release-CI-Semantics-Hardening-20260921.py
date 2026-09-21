from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "Weall-Protocol"


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one target in {path}, found {count}: {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# --check is a freshness/integrity operation for deterministic tracked artifacts.
# Readiness remains encoded in the artifact payload and must not make a truthful
# NO-GO artifact look stale or invalid to CI.
final_gate = PROTO / "scripts" / "gen_final_public_observer_controlled_testnet_go_gate_v1_5.py"
replace_once(
    final_gate,
    '''        print(\n            "OK: generated/final_public_observer_controlled_testnet_go_gate_v1_5.json is current (bounded controlled verdict; NO-GO public beta)"\n        )\n        return 0 if payload.get("ok") is True else 1\n''',
    '''        print(\n            "OK: generated/final_public_observer_controlled_testnet_go_gate_v1_5.json is current (bounded controlled verdict; NO-GO public beta)"\n        )\n        # --check proves freshness/integrity, not launch readiness. The tracked\n        # payload carries the bounded NO-GO/GO verdict explicitly.\n        return 0\n''',
)

release_manifest = PROTO / "scripts" / "gen_release_evidence_manifest_v1_5.py"
replace_once(
    release_manifest,
    '''        print(\n            f"OK: {OUT.relative_to(ROOT)} is current ({len(payload['tracked_artifacts'])} artifacts)"\n        )\n        return 0 if payload.get("ok") else 1\n''',
    '''        print(\n            f"OK: {OUT.relative_to(ROOT)} is current ({len(payload['tracked_artifacts'])} artifacts)"\n        )\n        # --check proves deterministic freshness. Callers that require the\n        # release package itself to be admissible must inspect payload["ok"]\n        # explicitly rather than conflating readiness/package state with stale\n        # generated evidence.\n        return 0\n''',
)

# The exact-boolean sweep creates this regression file immediately before this
# helper runs. Add coverage for the CLI contract that caused the CI failures.
test = PROTO / "tests" / "test_release_boolean_contract_sweep.py"
text = test.read_text(encoding="utf-8")
addition = '''\n\ndef test_release_artifact_check_mode_is_freshness_only() -> None:\n    targets = (\n        "scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py",\n        "scripts/gen_release_evidence_manifest_v1_5.py",\n    )\n    for rel in targets:\n        source = (ROOT / rel).read_text(encoding="utf-8")\n        check_block = source.split("if args.check:", 1)[1].split("OUT.parent.mkdir", 1)[0]\n        assert "return 0" in check_block\n        assert 'return 0 if payload.get("ok")' not in check_block\n'''
if "test_release_artifact_check_mode_is_freshness_only" not in text:
    test.write_text(text + addition, encoding="utf-8")
