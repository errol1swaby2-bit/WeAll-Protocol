from __future__ import annotations

import json
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


# The V2 compiler recognizes this compact source-mapping schema.
mapping_path = PROTO / "specs" / "v2" / "source" / "source_mappings.json"
mapping_doc = json.loads(mapping_path.read_text(encoding="utf-8"))
mappings = mapping_doc.get("mappings")
if not isinstance(mappings, list):
    raise SystemExit("source_mappings.json missing mappings list")
mapping = {
    "affected_registers": ["implementation_evidence"],
    "classification": "authoritative_or_launch_critical",
    "path": "scripts/release_evidence_contracts.py",
    "primary_mechanism_id": "M-076",
    "review_status": "mapped_current_snapshot",
}
if any(isinstance(item, dict) and item.get("path") == mapping["path"] for item in mappings):
    raise SystemExit("release evidence contract source mapping already exists")
mappings.append(mapping)
mapping_path.write_text(json.dumps(mapping_doc, indent=2) + "\n", encoding="utf-8")

# Serialized booleans crossing trust/readiness/authority boundaries must require
# exact JSON booleans. Strings such as "false" are truthy in Python.
testnet = PROTO / "src" / "weall" / "runtime" / "testnet_capabilities.py"
replace_once(
    testnet,
    '            "ok": bool(payload.get("ok", True)) if payload else False,\n',
    '            "ok": payload.get("ok") is True if payload else False,\n',
)
replace_once(
    testnet,
    '            "public_beta_ready": bool(blocker_report.get("public_beta_ready", False))\n            if blocker_report\n            else False,\n',
    '            "public_beta_ready": blocker_report.get("public_beta_ready") is True\n            if blocker_report\n            else False,\n',
)
replace_once(
    testnet,
    '            "mainnet_ready": bool(blocker_report.get("mainnet_ready", False))\n            if blocker_report\n            else False,\n',
    '            "mainnet_ready": blocker_report.get("mainnet_ready") is True\n            if blocker_report\n            else False,\n',
)

incident = PROTO / "src" / "weall" / "runtime" / "operator_incident_report.py"
replace_once(
    incident,
    '    if compatibility_contract and not bool(compatibility_contract.get("ok", True)):\n',
    '    if compatibility_contract and compatibility_contract.get("ok") is not True:\n',
)
replace_once(
    incident,
    '    if not bool(remote_forensics.get("ok", True)):\n',
    '    if remote_forensics.get("ok") is not True:\n',
)
replace_once(
    incident,
    '    stalled = bool(remote_forensics.get("stalled", False))\n',
    '    stalled = remote_forensics.get("stalled") is True\n',
)
replace_once(
    incident,
    '        "bootstrap_ok": bool(bootstrap.get("ok", False)),\n',
    '        "bootstrap_ok": bootstrap.get("ok") is True,\n',
)
replace_once(
    incident,
    '        "remote_ok": bool(remote.get("ok", True)) if remote else True,\n',
    '        "remote_ok": remote.get("ok") is True if remote else True,\n',
)
replace_once(
    incident,
    '        "remote_stalled": bool(remote.get("stalled", False)) if remote else False,\n',
    '        "remote_stalled": remote.get("stalled") is True if remote else False,\n',
)
replace_once(
    incident,
    '        "compatibility_contract_ok": bool(compatibility_contract.get("ok", True)),\n',
    '        "compatibility_contract_ok": compatibility_contract.get("ok") is True,\n',
)
replace_once(
    incident,
    '        "strict_runtime_authority_mode": bool(\n            authority_contract.get("strict_runtime_authority_mode", False)\n        ),\n',
    '        "strict_runtime_authority_mode": authority_contract.get("strict_runtime_authority_mode")\n        is True,\n',
)
replace_once(
    incident,
    '        "validator_effective": bool(authority_contract.get("validator_effective", False)),\n',
    '        "validator_effective": authority_contract.get("validator_effective") is True,\n',
)
replace_once(
    incident,
    '        "helper_effective": bool(authority_contract.get("helper_effective", False)),\n',
    '        "helper_effective": authority_contract.get("helper_effective") is True,\n',
)

security = PROTO / "src" / "weall" / "api" / "security.py"
replace_once(
    security,
    '    if not bool(srec.get("active", False)):\n',
    '    if srec.get("active") is not True:\n',
)

authority = PROTO / "src" / "weall" / "runtime" / "runtime_authority.py"
replace_once(
    authority,
    '    helper_requested = bool(lifecycle.get("helper_enabled_requested", cfg.helper_enabled_requested))\n    helper_effective = bool(lifecycle.get("helper_enabled_effective", False))\n    bft_requested = bool(lifecycle.get("bft_enabled_requested", cfg.bft_enabled_requested))\n    bft_effective = bool(lifecycle.get("bft_enabled_effective", False))\n',
    '    helper_requested_raw = lifecycle.get(\n        "helper_enabled_requested", cfg.helper_enabled_requested\n    )\n    bft_requested_raw = lifecycle.get("bft_enabled_requested", cfg.bft_enabled_requested)\n    helper_requested = (\n        helper_requested_raw\n        if isinstance(helper_requested_raw, bool)\n        else bool(cfg.helper_enabled_requested)\n    )\n    helper_effective = lifecycle.get("helper_enabled_effective") is True\n    bft_requested = (\n        bft_requested_raw\n        if isinstance(bft_requested_raw, bool)\n        else bool(cfg.bft_enabled_requested)\n    )\n    bft_effective = lifecycle.get("bft_enabled_effective") is True\n',
)
replace_once(
    authority,
    '            return bool(executor._bft_enabled_effective)\n',
    '            return executor._bft_enabled_effective is True\n',
)
replace_once(
    authority,
    '                        return bool(status.get("bft_enabled_effective", False))\n                    requested = bool(status.get("bft_enabled_requested", default))\n                    return bool(status.get("bft_enabled_effective", requested) or requested)\n',
    '                        return status.get("bft_enabled_effective") is True\n                    requested_raw = status.get("bft_enabled_requested", default)\n                    requested = (\n                        requested_raw if isinstance(requested_raw, bool) else bool(default)\n                    )\n                    effective = status.get("bft_enabled_effective") is True\n                    return effective or requested\n',
)

attester = PROTO / "src" / "weall" / "services" / "validator_attester.py"
attester_text = attester.read_text(encoding="utf-8")
before = attester_text
attester_text = re.sub(
    r'(?m)^(\s*)if not ([A-Za-z_][A-Za-z0-9_]*)\.get\("ok"\):$',
    r'\1if \2.get("ok") is not True:',
    attester_text,
)
attester_text = re.sub(
    r'(?m)^(\s*)if ([A-Za-z_][A-Za-z0-9_]*)\.get\("ok"\):$',
    r'\1if \2.get("ok") is True:',
    attester_text,
)
if attester_text == before:
    raise SystemExit("validator_attester ok-boundary audit made no replacements")
attester.write_text(attester_text, encoding="utf-8")

prod_smoke = PROTO / "scripts" / "prod_smoke.py"
replace_once(
    prod_smoke,
    '            assert bool(health.get("ok")) is True, (\n',
    '            assert health.get("ok") is True, (\n',
)
replay = PROTO / "scripts" / "replay_consistency_audit.py"
replace_once(
    replay,
    '    return 0 if bool(summary.get("ok")) else 1\n',
    '    return 0 if summary.get("ok") is True else 1\n',
)
manifest_check = PROTO / "scripts" / "prod_chain_manifest_check.sh"
replace_once(
    manifest_check,
    'if not status.get("ok"):\n',
    'if status.get("ok") is not True:\n',
)
docker_gate = PROTO / "scripts" / "docker_genesis_api_boot_gate.sh"
replace_once(
    docker_gate,
    '        if not payload.get("ok"):\n',
    '        if payload.get("ok") is not True:\n',
)

preflight = PROTO / "scripts" / "public_validator_preflight.py"
replace_once(
    preflight,
    '    signing_ready = bool(not deduped_issues and compatibility_contract.get("ok", True))\n',
    '    signing_ready = not deduped_issues and compatibility_contract.get("ok") is True\n',
)
replace_once(
    preflight,
    '        "ok": bool(\n            field_status.get("genesis_bootstrap_profile_payload", {}).get(\n                "ok", compatibility_contract.get("ok", True)\n            )\n        )\n        if isinstance(field_status.get("genesis_bootstrap_profile_payload"), dict)\n        else bool(compatibility_contract.get("ok", True)),\n',
    '        "ok": field_status.get("genesis_bootstrap_profile_payload", {}).get("ok")\n        is True\n        if isinstance(field_status.get("genesis_bootstrap_profile_payload"), dict)\n        else compatibility_contract.get("ok") is True,\n',
)
replace_once(
    preflight,
    '        "local_enabled": bool(local_genesis_bootstrap.get("enabled", False)),\n',
    '        "local_enabled": local_genesis_bootstrap.get("enabled") is True,\n',
)
replace_once(
    preflight,
    '        "bundle_enabled": bool(manifest_genesis_bootstrap.get("enabled", False)),\n',
    '        "bundle_enabled": manifest_genesis_bootstrap.get("enabled") is True,\n',
)
replace_once(
    preflight,
    '            or ("disabled" if not local_genesis_bootstrap.get("enabled", False) else "")\n',
    '            or ("disabled" if local_genesis_bootstrap.get("enabled") is not True else "")\n',
)
replace_once(
    preflight,
    '            or ("disabled" if not manifest_genesis_bootstrap.get("enabled", False) else "")\n',
    '            or ("disabled" if manifest_genesis_bootstrap.get("enabled") is not True else "")\n',
)

regression = PROTO / "tests" / "test_fail_closed_boolean_boundaries.py"
regression.write_text(
    '''from __future__ import annotations\n\nfrom pathlib import Path\n\nimport pytest\nfrom starlette.requests import Request\n\nfrom weall.api import security\nfrom weall.runtime import testnet_capabilities\nfrom weall.runtime.operator_incident_report import (\n    classify_local_severity,\n    classify_remote_severity,\n)\nfrom weall.runtime.runtime_authority import authority_contract_from_lifecycle\n\n\ndef test_serialized_false_does_not_pass_testnet_artifact_or_readiness_boundaries(monkeypatch) -> None:\n    def fake_load(rel: str) -> dict:\n        if rel == "generated/public_beta_blocker_report_v1_5.json":\n            return {\n                "schema": "weall.v1_5.public_beta_blocker_report",\n                "ok": "false",\n                "public_beta_ready": "false",\n                "mainnet_ready": "true",\n                "blocker_catalog_count": 15,\n                "blocker_count": 15,\n            }\n        return {"schema": "example", "ok": "true"}\n\n    monkeypatch.setattr(testnet_capabilities, "_load_artifact", fake_load)\n    surface = testnet_capabilities.build_testnet_capability_surface({})\n    assert all(item["ok"] is False for item in surface["required_artifacts"].values())\n    report = surface["public_beta_blocker_report"]\n    assert report["public_beta_ready"] is False\n    assert report["mainnet_ready"] is False\n\n\ndef test_operator_incident_external_boolean_fields_fail_closed() -> None:\n    assert classify_local_severity(\n        bootstrap_report={"issues": [], "release_manifest": {}},\n        manifest_report={"compatibility_contract": {"ok": "false"}},\n    ) == "critical"\n    assert classify_remote_severity(remote_forensics={"ok": "false"}) == "critical"\n    assert classify_remote_severity(\n        remote_forensics={\n            "ok": True,\n            "stalled": "false",\n            "pending_fetch_requests_count": 1,\n            "recent_rejection_summary": {"count": 0},\n        }\n    ) == "ok"\n\n\ndef test_session_active_requires_exact_true(monkeypatch) -> None:\n    request = Request({\n        "type": "http",\n        "method": "GET",\n        "path": "/",\n        "headers": [\n            (b"x-weall-account", b"acct"),\n            (b"x-weall-session-key", b"key"),\n        ],\n    })\n    state = {"accounts": {"acct": {"session_keys": {"key": {}}}}}\n    monkeypatch.setattr(\n        security,\n        "session_record_for",\n        lambda sessions, key: {"active": "false", "ttl_s": 0},\n    )\n    with pytest.raises(PermissionError, match="session_revoked"):\n        security.require_account_session(request, state)\n\n\ndef test_runtime_authority_rejects_truthy_effective_strings() -> None:\n    contract = authority_contract_from_lifecycle(\n        {\n            "helper_enabled_effective": "false",\n            "bft_enabled_effective": "true",\n            "service_roles_effective": [],\n        },\n        source="test",\n    )\n    assert contract["helper_effective"] is False\n    assert contract["bft_effective"] is False\n    assert contract["validator_effective"] is False\n\n\ndef test_public_validator_preflight_has_no_default_true_compatibility_gate() -> None:\n    text = (Path(__file__).resolve().parents[1] / "scripts" / "public_validator_preflight.py").read_text(encoding="utf-8")\n    assert 'compatibility_contract.get("ok", True)' not in text\n    assert 'bool(local_genesis_bootstrap.get("enabled", False))' not in text\n    assert 'bool(manifest_genesis_bootstrap.get("enabled", False))' not in text\n''',
    encoding="utf-8",
)
