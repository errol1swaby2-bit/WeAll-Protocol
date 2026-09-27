from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = ROOT / "Weall-Protocol/src/weall/runtime/apply/identity.py"
GOVERNANCE = ROOT / "Weall-Protocol/src/weall/runtime/apply/governance.py"
TESTS = ROOT / "Weall-Protocol/tests/test_p2_policy_enforcement.py"


def replace_once(text: str, old: str, new: str, label: str, marker: str) -> str:
    if marker in text:
        return text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def patch_identity() -> None:
    text = IDENTITY.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''    ttl_s = max(0, int(ttl_s))\n\n    sessions = a.get("session_keys")\n''',
        '''    ttl_s = max(0, int(ttl_s))\n\n    security_policy = (\n        a.get("security_policy") if isinstance(a.get("security_policy"), dict) else {}\n    )\n    policy_ttl_s = _as_int(security_policy.get("session_ttl_s"), 0)\n    if policy_ttl_s > 0:\n        # Account-owned security policy is authoritative: omitted/non-positive\n        # session TTLs default to the policy, while longer requests are capped.\n        ttl_s = policy_ttl_s if ttl_s <= 0 else min(ttl_s, policy_ttl_s)\n\n    sessions = a.get("session_keys")\n''',
        "P2-SEC-003 session TTL enforcement",
        "Account-owned security policy is authoritative",
    )
    text = replace_once(
        text,
        '''    for key in ("lock_on_recovery_request", "require_guardian_threshold_for_unlock"):\n        if key in p and p.get(key) is not None:\n            policy[key] = bool(p.get(key))\n    if p.get("session_ttl_s") is not None:\n        policy["session_ttl_s"] = _as_int(p.get("session_ttl_s"), 0)\n''',
        '''    explicit_lock_policy = (\n        p.get("lock_on_recovery_request")\n        if p.get("lock_on_recovery_request") is not None\n        else (raw_policy.get("lock_on_recovery_request") if isinstance(raw_policy, dict) else None)\n    )\n    if explicit_lock_policy is False:\n        raise ApplyError("invalid_tx", "mandatory_recovery_lock_cannot_be_disabled", {})\n    if explicit_lock_policy is not None:\n        policy["lock_on_recovery_request"] = True\n\n    guardian_unlock_explicit = p.get("require_guardian_threshold_for_unlock") is not None or (\n        isinstance(raw_policy, dict) and "require_guardian_threshold_for_unlock" in raw_policy\n    )\n    if guardian_unlock_explicit:\n        raise ApplyError("invalid_tx", "guardian_unlock_policy_retired", {})\n    policy.pop("require_guardian_threshold_for_unlock", None)\n\n    if p.get("session_ttl_s") is not None:\n        policy["session_ttl_s"] = p.get("session_ttl_s")\n    if "session_ttl_s" in policy:\n        policy_ttl_s = _as_int(policy.get("session_ttl_s"), 0)\n        if policy_ttl_s <= 0:\n            raise ApplyError("invalid_tx", "session_ttl_policy_must_be_positive", {})\n        policy["session_ttl_s"] = int(policy_ttl_s)\n''',
        "P2-SEC-003 security policy validation",
        "mandatory_recovery_lock_cannot_be_disabled",
    )
    IDENTITY.write_text(text, encoding="utf-8")


def patch_governance() -> None:
    text = GOVERNANCE.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''    rules = _d(p.get("rules"))\n    actions = _extract_actions(p)\n''',
        '''    rules = dict(_d(p.get("rules")))\n    governed_quorum = _d(_d(state.get("gov_config")).get("quorum"))\n    for quorum_key in sorted(_ALLOWED_GOV_QUORUM_KEYS):\n        if quorum_key not in rules and quorum_key in governed_quorum:\n            rules[quorum_key] = governed_quorum[quorum_key]\n    actions = _extract_actions(p)\n''',
        "P2-GOV-004 proposal quorum snapshot",
        "governed_quorum = _d(_d(state.get(\"gov_config\")).get(\"quorum\"))",
    )
    text = replace_once(
        text,
        '''    cfg = state.get("gov_config")\n    if isinstance(cfg, dict):\n        cfg["rules"] = _sorted_dict(dict(p))\n        cfg["rules"]["_height"] = int(rec["_height"])\n\n    return {"applied": True}\n''',
        '''    cfg = state.get("gov_config")\n    if isinstance(cfg, dict):\n        cfg["rules"] = _sorted_dict(dict(p))\n        cfg["rules"]["_height"] = int(rec["_height"])\n\n    params_blob = p.get("params")\n    if isinstance(params_blob, dict):\n        params_root = state.get("params")\n        if not isinstance(params_root, dict):\n            params_root = {}\n            state["params"] = params_root\n        for namespace in sorted(params_blob.keys(), key=lambda value: str(value)):\n            updates = params_blob[namespace]\n            if not isinstance(updates, dict):\n                continue\n            current = params_root.get(str(namespace))\n            if not isinstance(current, dict):\n                current = {}\n            for key in sorted(updates.keys(), key=lambda value: str(value)):\n                current[str(key)] = updates[key]\n            params_root[str(namespace)] = current\n\n    treasury_blob = p.get("treasury")\n    if isinstance(treasury_blob, dict):\n        treasury_root = state.get("treasury")\n        if not isinstance(treasury_root, dict):\n            treasury_root = {}\n            state["treasury"] = treasury_root\n        for namespace in sorted(treasury_blob.keys(), key=lambda value: str(value)):\n            updates = treasury_blob[namespace]\n            if not isinstance(updates, dict):\n                continue\n            current = treasury_root.get(str(namespace))\n            if not isinstance(current, dict):\n                current = {}\n            for key in sorted(updates.keys(), key=lambda value: str(value)):\n                current[str(key)] = updates[key]\n            treasury_root[str(namespace)] = current\n\n    return {"applied": True}\n''',
        "P2-GOV-003 operative governance rules",
        "params_blob = p.get(\"params\")",
    )
    GOVERNANCE.write_text(text, encoding="utf-8")


def write_tests() -> None:
    TESTS.write_text(
        '''from __future__ import annotations\n\nimport pytest\n\nfrom weall.runtime.apply.governance import apply_governance\nfrom weall.runtime.apply.identity import apply_identity\nfrom weall.runtime.errors import ApplyError\nfrom weall.runtime.session_keys import session_record_for\nfrom weall.runtime.tx_admission_types import TxEnvelope\n\n\ndef _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> TxEnvelope:\n    return TxEnvelope(\n        tx_type=tx_type,\n        signer=signer,\n        nonce=nonce,\n        payload=payload,\n        tx_id=f"p2:{tx_type}:{nonce}",\n        system=system,\n        parent="GOV_EXECUTE" if system else None,\n    )\n\n\ndef _identity_state() -> dict:\n    return {\n        "height": 10,\n        "time": 1000,\n        "accounts": {\n            "@alice": {\n                "nonce": 0,\n                "poh_tier": 2,\n                "banned": False,\n                "locked": False,\n                "keys": {"by_id": {"k1": {"pubkey": "pk1", "revoked": False}}},\n            }\n        },\n    }\n\n\ndef test_p2_sec003_session_policy_defaults_and_caps_ttl() -> None:\n    state = _identity_state()\n    state = apply_identity(\n        state,\n        _env("ACCOUNT_SECURITY_POLICY_SET", "@alice", 1, {"session_ttl_s": 120}),\n    )\n    state = apply_identity(\n        state,\n        _env("ACCOUNT_SESSION_KEY_ISSUE", "@alice", 2, {"session_key": "omitted"}),\n    )\n    assert session_record_for(state["accounts"]["@alice"]["session_keys"], "omitted")["ttl_s"] == 120\n\n    state = apply_identity(\n        state,\n        _env("ACCOUNT_SESSION_KEY_ISSUE", "@alice", 3, {"session_key": "short", "ttl_s": 60}),\n    )\n    assert session_record_for(state["accounts"]["@alice"]["session_keys"], "short")["ttl_s"] == 60\n\n    state = apply_identity(\n        state,\n        _env("ACCOUNT_SESSION_KEY_ISSUE", "@alice", 4, {"session_key": "capped", "ttl_s": 3600}),\n    )\n    assert session_record_for(state["accounts"]["@alice"]["session_keys"], "capped")["ttl_s"] == 120\n\n\ndef test_p2_sec003_rejects_misleading_or_retired_security_controls() -> None:\n    state = _identity_state()\n    with pytest.raises(ApplyError, match="mandatory_recovery_lock_cannot_be_disabled"):\n        apply_identity(state, _env("ACCOUNT_SECURITY_POLICY_SET", "@alice", 1, {"lock_on_recovery_request": False}))\n    with pytest.raises(ApplyError, match="guardian_unlock_policy_retired"):\n        apply_identity(state, _env("ACCOUNT_SECURITY_POLICY_SET", "@alice", 1, {"require_guardian_threshold_for_unlock": True}))\n    with pytest.raises(ApplyError, match="session_ttl_policy_must_be_positive"):\n        apply_identity(state, _env("ACCOUNT_SECURITY_POLICY_SET", "@alice", 1, {"session_ttl_s": 0}))\n\n\ndef _governance_state() -> dict:\n    return {\n        "height": 20,\n        "params": {\n            "poh": {"tier2_n_jurors": 5, "live_n_jurors": 5},\n            "gov_action_allowlist": ["GOV_RULES_SET", "GOV_QUORUM_SET"],\n        },\n        "treasury": {"params": {"timelock_blocks": 2}},\n        "accounts": {\n            "alice": {"poh_tier": 2, "banned": False, "locked": False},\n            "bob": {"poh_tier": 2, "banned": False, "locked": False},\n        },\n    }\n\n\ndef test_p2_gov003_rules_set_updates_operational_parameter_paths() -> None:\n    state = _governance_state()\n    apply_governance(\n        state,\n        _env(\n            "GOV_RULES_SET",\n            "SYSTEM",\n            1,\n            {\n                "params": {"poh": {"tier2_n_jurors": 7}},\n                "treasury": {"params": {"timelock_blocks": 9}},\n            },\n            system=True,\n        ),\n    )\n    assert state["params"]["poh"]["tier2_n_jurors"] == 7\n    assert state["params"]["poh"]["live_n_jurors"] == 5\n    assert state["treasury"]["params"]["timelock_blocks"] == 9\n    assert state["gov_config"]["rules"]["params"]["poh"]["tier2_n_jurors"] == 7\n\n\ndef test_p2_gov004_new_proposals_snapshot_governed_quorum_policy() -> None:\n    state = _governance_state()\n    apply_governance(state, _env("GOV_QUORUM_SET", "SYSTEM", 1, {"quorum_percent": 60}, system=True))\n    apply_governance(state, _env("GOV_PROPOSAL_CREATE", "alice", 1, {"proposal_id": "p:old", "rules": {}}))\n    assert state["gov_proposals_by_id"]["p:old"]["rules"]["quorum_percent"] == 60\n\n    apply_governance(state, _env("GOV_QUORUM_SET", "SYSTEM", 2, {"quorum_percent": 70}, system=True))\n    assert state["gov_proposals_by_id"]["p:old"]["rules"]["quorum_percent"] == 60\n\n    apply_governance(state, _env("GOV_PROPOSAL_CREATE", "alice", 2, {"proposal_id": "p:new", "rules": {}}))\n    assert state["gov_proposals_by_id"]["p:new"]["rules"]["quorum_percent"] == 70\n\n    apply_governance(\n        state,\n        _env("GOV_PROPOSAL_CREATE", "alice", 3, {"proposal_id": "p:explicit", "rules": {"quorum_percent": 40}}),\n    )\n    assert state["gov_proposals_by_id"]["p:explicit"]["rules"]["quorum_percent"] == 40\n''',
        encoding="utf-8",
    )


def main() -> None:
    patch_identity()
    patch_governance()
    write_tests()


if __name__ == "__main__":
    main()
