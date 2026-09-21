from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "Weall-Protocol"


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one target in {path}, found {count}: {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def exact_bool_wrappers(path: Path, keys: set[str]) -> None:
    text = path.read_text(encoding="utf-8")
    before = text
    for key in sorted(keys):
        pattern = re.compile(
            rf'bool\(([A-Za-z_][A-Za-z0-9_]*)\.get\("{re.escape(key)}"\)\)'
        )
        text = pattern.sub(rf'\1.get("{key}") is True', text)
    if text != before:
        path.write_text(text, encoding="utf-8")


boolean_keys = {
    "ok",
    "present",
    "controlled_testnet_mechanisms_complete",
    "controlled_testnet_ready_candidate",
    "controlled_testnet_go_gate_ready_to_run",
    "controlled_rehearsal_candidate_ready",
    "public_beta_ready",
    "mainnet_ready",
    "external_attestation_required_before_public_beta",
    "runtime_commit_binding_required",
    "tracked_manifest_is_commit_agnostic",
    "production_crypto_audit_complete",
}

for rel in (
    "scripts/gen_b582_b586_readiness_truth_and_proof_v1_5.py",
    "scripts/gen_b587_b594_testnet_mechanism_completion_v1_5.py",
    "scripts/run_controlled_testnet_go_gate_v1_5.py",
    "scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py",
    "scripts/gen_release_evidence_manifest_v1_5.py",
    "scripts/rehearse_public_api_write_lifecycle_v1_5.py",
):
    exact_bool_wrappers(PROTO / rel, boolean_keys)

# High-level blocker evidence aggregation consumed a collection of `ok` fields
# directly in boolean context. Require exact booleans so strings such as
# "false" cannot satisfy the repository evidence inventory.
blocker = PROTO / "scripts" / "gen_public_beta_blocker_report_v1_5.py"
replace_once(
    blocker,
    '''    evidence_inventory_ok = bool(\n        validator.get("ok")\n        and storage.get("ok")\n        and protocol_upgrade.get("ok")\n        and protocol_upgrade_hardening.get("ok")\n        and helper_topology_hardening.get("ok")\n        and helper.get("ok")\n        and api_vectors.get("ok")\n        and api_vector_count >= 24\n        and state_roots.get("ok")\n        and clean_clone.get("ok")\n        and external_requirements.get("ok")\n        and high_risk_disabled\n        and legal.get("legal_compliance_ready") is False\n        and frontend_p2_ux.get("ok") is True\n    )\n''',
    '''    evidence_inventory_ok = bool(\n        validator.get("ok") is True\n        and storage.get("ok") is True\n        and protocol_upgrade.get("ok") is True\n        and protocol_upgrade_hardening.get("ok") is True\n        and helper_topology_hardening.get("ok") is True\n        and helper.get("ok") is True\n        and api_vectors.get("ok") is True\n        and api_vector_count >= 24\n        and state_roots.get("ok") is True\n        and clean_clone.get("ok") is True\n        and external_requirements.get("ok") is True\n        and high_risk_disabled\n        and legal.get("legal_compliance_ready") is False\n        and frontend_p2_ux.get("ok") is True\n    )\n''',
)

# This rehearsal reads JSON responses from public API surfaces. The generic
# wrapper sweep above already converts feed/session bool wrappers. Remove the
# remaining optimistic default on the dispute response explicitly.
public_api = PROTO / "scripts" / "rehearse_public_api_write_lifecycle_v1_5.py"
replace_once(
    public_api,
    '                and bool(dispute.get("ok", True))\n',
    '                and dispute.get("ok") is True\n',
)
replace_once(
    public_api,
    '    return 0 if out.get("ok") else 1\n',
    '    return 0 if out.get("ok") is True else 1\n',
)

# Generator command exits are themselves evidence gates. Keep them exact even
# when their current in-process payloads are expected to be proper booleans.
for rel, name in (
    ("scripts/gen_b582_b586_readiness_truth_and_proof_v1_5.py", "artifact"),
    ("scripts/gen_b587_b594_testnet_mechanism_completion_v1_5.py", "payload"),
    ("scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py", "payload"),
):
    path = PROTO / rel
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        f'return 0 if {name}.get("ok") else 1',
        f'return 0 if {name}.get("ok") is True else 1',
    )
    path.write_text(text, encoding="utf-8")

# Regression tests cover both dynamic aggregation and source-level absence of
# the exact fail-open patterns that caused the CI family of findings.
test = PROTO / "tests" / "test_release_boolean_contract_sweep.py"
test.write_text(
    '''from __future__ import annotations\n\nimport re\nfrom pathlib import Path\n\nimport gen_b582_b586_readiness_truth_and_proof_v1_5 as b582\nimport gen_b587_b594_testnet_mechanism_completion_v1_5 as b587\nfrom run_controlled_testnet_go_gate_v1_5 import _summarize_b587\n\nROOT = Path(__file__).resolve().parents[1]\n\n\ndef test_controlled_gate_b587_summary_rejects_truthy_strings() -> None:\n    summary = _summarize_b587(\n        {\n            "ok": "true",\n            "controlled_testnet_mechanisms_complete": "true",\n            "controlled_testnet_ready_candidate": "true",\n            "public_beta_ready": "true",\n            "claim_boundaries": {\n                "live_economics": False,\n                "public_validator_readiness": False,\n                "production_helper_execution": False,\n                "automatic_protocol_upgrades": False,\n            },\n        }\n    )\n    assert summary["ok"] is False\n    assert summary["controlled_testnet_mechanisms_complete"] is False\n    assert summary["controlled_testnet_ready_candidate"] is False\n    assert summary["public_beta_ready"] is False\n\n\ndef test_b582_component_ok_requires_exact_boolean(monkeypatch) -> None:\n    monkeypatch.setattr(b582, "_gap_register_truth", lambda: {"ok": True})\n    monkeypatch.setattr(b582, "_operator_route_metadata_truth", lambda: {"ok": True})\n    monkeypatch.setattr(b582, "run_storage_durability", lambda: {"ok": "true"})\n    monkeypatch.setattr(b582, "run_anti_sybil_lifecycle", lambda: {"ok": True})\n    monkeypatch.setattr(b582, "run_helper_corpus", lambda: {"ok": True})\n    assert b582.build()["ok"] is False\n\n\ndef test_b587_component_ok_requires_exact_boolean(monkeypatch) -> None:\n    capability_map = {\n        key: {"enabled": False}\n        for key in (\n            "live_transfers",\n            "live_rewards",\n            "treasury_spend",\n            "live_economics",\n            "public_validator_join",\n            "public_multi_validator_bft",\n            "automatic_protocol_upgrade_apply",\n            "production_helper_execution",\n        )\n    }\n    monkeypatch.setattr(\n        b587,\n        "build_testnet_capability_surface",\n        lambda state: {\n            "capabilities": capability_map,\n            "required_artifacts": {},\n            "artifact_blockers": [],\n            "controlled_mechanism_artifact_blockers": [],\n            "public_beta_blocker_report": {"present": True, "ok": True},\n        },\n    )\n    monkeypatch.setattr(b587, "build_api_response_vectors", lambda: {"ok": True})\n    monkeypatch.setattr(b587, "run_upgrade_staging", lambda: {"ok": True})\n    monkeypatch.setattr(b587, "run_validator_harness", lambda: {"ok": "true"})\n    monkeypatch.setattr(b587, "run_storage_harness", lambda: {"ok": True})\n    monkeypatch.setattr(b587, "run_reviewer_accountability", lambda: {"ok": True})\n    monkeypatch.setattr(\n        b587,\n        "run_helper_block_path",\n        lambda: {\n            "ok": True,\n            "production_block_path_state_root_equivalence_proven": True,\n            "mechanism_complete": True,\n        },\n    )\n    monkeypatch.setattr(b587, "run_locked_economics", lambda: {"ok": True})\n    result = b587.build()\n    assert result["component_harnesses_ok"] is False\n    assert result["ok"] is False\n\n\ndef test_release_critical_sources_have_no_bool_wrapped_ok_or_default_true_ok() -> None:\n    files = [\n        "scripts/gen_public_beta_blocker_report_v1_5.py",\n        "scripts/gen_b582_b586_readiness_truth_and_proof_v1_5.py",\n        "scripts/gen_b587_b594_testnet_mechanism_completion_v1_5.py",\n        "scripts/run_controlled_testnet_go_gate_v1_5.py",\n        "scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py",\n        "scripts/gen_release_evidence_manifest_v1_5.py",\n        "scripts/rehearse_public_api_write_lifecycle_v1_5.py",\n    ]\n    wrapped_ok = re.compile(r'bool\\([A-Za-z_][A-Za-z0-9_]*\\.get\\("ok"\\)\\)')\n    for rel in files:\n        text = (ROOT / rel).read_text(encoding="utf-8")\n        assert not wrapped_ok.search(text), rel\n        assert '.get("ok", True)' not in text, rel\n''',
    encoding="utf-8",
)
