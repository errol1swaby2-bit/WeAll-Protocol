from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REWARDS = ROOT / "Weall-Protocol/src/weall/runtime/apply/rewards.py"
REWARD_TESTS = ROOT / "Weall-Protocol/tests/test_reward_issuance_invariants.py"
SQLITE = ROOT / "Weall-Protocol/src/weall/runtime/sqlite_db.py"
SQLITE_TESTS = ROOT / "Weall-Protocol/tests/test_p2_persistence_synchronous.py"
STATE_SYNC = ROOT / "Weall-Protocol/src/weall/net/state_sync.py"
STATE_SYNC_TESTS = ROOT / "Weall-Protocol/tests/test_p2_state_sync_hardening.py"
ROLES = ROOT / "Weall-Protocol/src/weall/runtime/apply/roles.py"
RESPONSIBILITIES = ROOT / "Weall-Protocol/src/weall/runtime/node_operator_responsibilities.py"
TREASURY = ROOT / "Weall-Protocol/src/weall/runtime/apply/treasury.py"
GROUPS = ROOT / "Weall-Protocol/src/weall/runtime/apply/groups.py"
SCOPED_TESTS = ROOT / "Weall-Protocol/tests/test_p2_scoped_authority_repairs.py"


def replace_once_or_already(
    text: str,
    old: str,
    new: str,
    *,
    label: str,
    already_marker: str,
) -> str:
    if already_marker in text:
        return text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one unpatched match, found {count}")
    return text.replace(old, new, 1)


def patch_rewards() -> None:
    text = REWARDS.read_text(encoding="utf-8")
    text = replace_once_or_already(
        text,
        """    # Optional but safer: explicit funding must cover explicit distributions.\n    if normalized_debits and debited_total < distributed_total:\n""",
        """    # Every positive distribution must be backed by canonical funding.\n    # An absent/empty debit list is not authority to create balances.\n    if distributed_total > 0 and debited_total < distributed_total:\n""",
        label="P2-ECON-002 funding guard",
        already_marker="if distributed_total > 0 and debited_total < distributed_total:",
    )
    text = replace_once_or_already(
        text,
        """        bal = _as_int(acct.get(\"balance\"), 0)\n        new_bal = bal - int(amount)\n        if new_bal < 0:\n            new_bal = 0\n        acct[\"balance\"] = int(new_bal)\n\n        forfeits[forfeit_id] = {\n""",
        """        bal = _as_int(acct.get(\"balance\"), 0)\n        if bal < int(amount):\n            raise RewardsApplyError(\n                \"forbidden\",\n                \"insufficient_balance_for_forfeiture\",\n                {\n                    \"account_id\": str(account_id),\n                    \"balance\": int(bal),\n                    \"amount\": int(amount),\n                },\n            )\n        acct[\"balance\"] = int(bal - int(amount))\n\n        forfeits[forfeit_id] = {\n""",
        label="P2-ECON-003 forfeiture guard",
        already_marker="insufficient_balance_for_forfeiture",
    )
    REWARDS.write_text(text, encoding="utf-8")


def patch_reward_tests() -> None:
    text = REWARD_TESTS.read_text(encoding="utf-8")
    marker = "def test_p2_econ002_distribution_without_debits_is_rejected()"
    if marker in text:
        return
    addition = r'''


def test_p2_econ002_distribution_without_debits_is_rejected() -> None:
    st = _active_state()
    before = st["accounts"]["@validator"]["balance"]
    with pytest.raises(RewardsApplyError) as ei:
        apply_rewards(
            st,
            _sys(
                "BLOCK_REWARD_DISTRIBUTE",
                {
                    "block_id": "issuance_epoch:no-debits",
                    "transfers": [{"to": "@validator", "amount": 100}],
                    "debits": [],
                },
            ),
        )
    assert ei.value.reason == "distribution_exceeds_debits"
    assert st["accounts"]["@validator"]["balance"] == before
    assert "issuance_epoch:no-debits" not in st.get("rewards", {}).get(
        "block_reward_distributions_by_id", {}
    )


def test_p2_econ003_forfeiture_fails_if_requested_amount_exceeds_balance() -> None:
    st = _active_state()
    st["accounts"]["@validator"]["balance"] = 25
    with pytest.raises(RewardsApplyError) as ei:
        apply_rewards(
            st,
            _sys(
                "FORFEITURE_APPLY",
                {
                    "account_id": "@validator",
                    "forfeit_id": "forfeit:p2-econ-003",
                    "amount": 40,
                },
            ),
        )
    assert ei.value.reason == "insufficient_balance_for_forfeiture"
    assert st["accounts"]["@validator"]["balance"] == 25
    assert "forfeit:p2-econ-003" not in st.get("rewards", {}).get("forfeitures_by_id", {})
    assert st.get("rewards", {}).get("stats", {}).get("forfeited_total", 0) == 0


def test_p2_econ003_forfeiture_records_exact_amount_removed() -> None:
    st = _active_state()
    st["accounts"]["@validator"]["balance"] = 100
    result = apply_rewards(
        st,
        _sys(
            "FORFEITURE_APPLY",
            {
                "account_id": "@validator",
                "forfeit_id": "forfeit:p2-econ-003-ok",
                "amount": 40,
            },
        ),
    )
    assert result["amount"] == 40
    assert st["accounts"]["@validator"]["balance"] == 60
    rec = st["rewards"]["forfeitures_by_id"]["forfeit:p2-econ-003-ok"]
    assert rec["amount"] == 40
    assert st["rewards"]["stats"]["forfeited_total"] == 40
'''
    REWARD_TESTS.write_text(text.rstrip() + addition.rstrip() + "\n", encoding="utf-8")


def patch_sqlite() -> None:
    text = SQLITE.read_text(encoding="utf-8")
    old = '''        Override with WEALL_SQLITE_SYNCHRONOUS in {OFF,NORMAL,FULL,EXTRA}.\n        """\n        mode = (os.environ.get("WEALL_MODE") or "prod").strip().lower()\n        default = "FULL" if mode == "prod" else "NORMAL"\n        raw = (os.environ.get("WEALL_SQLITE_SYNCHRONOUS") or default).strip().upper()\n\n        allowed = {"OFF", "NORMAL", "FULL", "EXTRA"}\n        if raw not in allowed:\n            # Fail-safe: never accept unknown values.\n            raw = default\n        return raw\n'''
    new = '''        Override with WEALL_SQLITE_SYNCHRONOUS in {NORMAL,FULL,EXTRA} in\n        production. ``OFF`` remains available only to explicit non-production\n        modes where crash durability is not a production claim.\n        """\n        mode = (os.environ.get("WEALL_MODE") or "prod").strip().lower()\n        default = "FULL" if mode == "prod" else "NORMAL"\n        raw = (os.environ.get("WEALL_SQLITE_SYNCHRONOUS") or default).strip().upper()\n\n        allowed = {"OFF", "NORMAL", "FULL", "EXTRA"}\n        if raw not in allowed:\n            # Fail-safe: never accept unknown values.\n            raw = default\n        if mode == "prod" and raw == "OFF":\n            raise ValueError("unsafe_sqlite_synchronous_off_in_prod")\n        return raw\n'''
    text = replace_once_or_already(
        text,
        old,
        new,
        label="P2-PERSIST-002 production synchronous guard",
        already_marker="unsafe_sqlite_synchronous_off_in_prod",
    )
    SQLITE.write_text(text, encoding="utf-8")


def patch_sqlite_tests() -> None:
    content = '''from __future__ import annotations\n\nimport pytest\n\nfrom weall.runtime.sqlite_db import SqliteDB\n\n\ndef test_p2_persist002_production_rejects_sqlite_synchronous_off(monkeypatch) -> None:\n    monkeypatch.setenv("WEALL_MODE", "prod")\n    monkeypatch.setenv("WEALL_SQLITE_SYNCHRONOUS", "OFF")\n    with pytest.raises(ValueError, match="unsafe_sqlite_synchronous_off_in_prod"):\n        SqliteDB._sqlite_synchronous_pragma()\n\n\ndef test_p2_persist002_nonproduction_can_explicitly_use_off(monkeypatch) -> None:\n    monkeypatch.setenv("WEALL_MODE", "dev")\n    monkeypatch.setenv("WEALL_SQLITE_SYNCHRONOUS", "OFF")\n    assert SqliteDB._sqlite_synchronous_pragma() == "OFF"\n\n\ndef test_p2_persist002_production_default_remains_full(monkeypatch) -> None:\n    monkeypatch.setenv("WEALL_MODE", "prod")\n    monkeypatch.delenv("WEALL_SQLITE_SYNCHRONOUS", raising=False)\n    assert SqliteDB._sqlite_synchronous_pragma() == "FULL"\n'''
    if SQLITE_TESTS.exists() and SQLITE_TESTS.read_text(encoding="utf-8") == content:
        return
    SQLITE_TESTS.write_text(content, encoding="utf-8")


def patch_state_sync() -> None:
    text = STATE_SYNC.read_text(encoding="utf-8")
    text = replace_once_or_already(
        text,
        '''    active = normalize_validator_ids(active_raw)\n''',
        '''    for member in active_raw:\n        if not isinstance(member, str):\n            raise StateSyncVerifyError(\n                "snapshot_validator_authority_invalid:active_set_member_not_string"\n            )\n    active = normalize_validator_ids(active_raw)\n''',
        label="P2-SYNC-002 validator member type guard",
        already_marker="snapshot_validator_authority_invalid:active_set_member_not_string",
    )
    text = replace_once_or_already(
        text,
        '''        if not resp.ok:\n            return\n\n        anchor = resp.snapshot_anchor\n''',
        '''        if not resp.ok:\n            return\n        if self.require_trusted_anchor and trusted_anchor is None:\n            raise StateSyncVerifyError("trusted_anchor_required")\n\n        anchor = resp.snapshot_anchor\n''',
        label="P2-SYNC-001 response trusted-anchor guard",
        already_marker='raise StateSyncVerifyError("trusted_anchor_required")',
    )
    STATE_SYNC.write_text(text, encoding="utf-8")


def patch_state_sync_tests() -> None:
    content = '''from __future__ import annotations\n\nimport pytest\n\nfrom weall.net.messages import MsgType, StateSyncResponseMsg, WireHeader\nfrom weall.net.state_sync import (\n    StateSyncService,\n    StateSyncVerifyError,\n    _validate_snapshot_validator_authority,\n)\nfrom weall.runtime.commitments import validator_set_hash\n\n\ndef _response() -> StateSyncResponseMsg:\n    return StateSyncResponseMsg(\n        header=WireHeader(\n            type=MsgType.STATE_SYNC_RESPONSE,\n            chain_id="chain",\n            schema_version="1",\n            tx_index_hash="tx-index",\n            sent_ts_ms=None,\n            corr_id="p2-sync",\n        ),\n        ok=True,\n        reason=None,\n        height=0,\n        snapshot=None,\n        snapshot_hash=None,\n        snapshot_anchor=None,\n        blocks=(),\n    )\n\n\ndef test_p2_sync001_required_anchor_is_enforced_on_response_verification(monkeypatch) -> None:\n    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")\n    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")\n    svc = StateSyncService(\n        chain_id="chain",\n        schema_version="1",\n        tx_index_hash="tx-index",\n        state_provider=lambda: {},\n    )\n    assert svc.require_trusted_anchor is True\n    with pytest.raises(StateSyncVerifyError, match="trusted_anchor_required"):\n        svc.verify_response(_response(), trusted_anchor=None)\n\n\ndef test_p2_sync002_numeric_validator_member_is_rejected_before_normalization() -> None:\n    snapshot = {\n        "params": {"validator_candidate_lifecycle_gate_enabled": True},\n        "consensus": {"validator_set": {"epoch": 1, "active_set": [1]}},\n    }\n    with pytest.raises(\n        StateSyncVerifyError,\n        match="snapshot_validator_authority_invalid:active_set_member_not_string",\n    ):\n        _validate_snapshot_validator_authority(snapshot)\n\n\ndef test_p2_sync002_canonical_string_validator_member_remains_valid() -> None:\n    active = ["@validator"]\n    snapshot = {\n        "params": {"validator_candidate_lifecycle_gate_enabled": True},\n        "consensus": {\n            "validator_set": {\n                "epoch": 1,\n                "active_set": active,\n                "set_hash": validator_set_hash(active),\n            },\n            "validators": {"registry": {"@validator": {"pubkey": "pk"}}},\n        },\n        "validators": {"registry": {"@validator": {"pubkey": "pk"}}},\n    }\n    _validate_snapshot_validator_authority(snapshot)\n'''
    if STATE_SYNC_TESTS.exists() and STATE_SYNC_TESTS.read_text(encoding="utf-8") == content:
        return
    STATE_SYNC_TESTS.write_text(content, encoding="utf-8")


def patch_helper_role_policy() -> None:
    text = ROLES.read_text(encoding="utf-8")
    old = '''    reputation_required = _as_int(\n        _payload_helper_field(payload, "reputation_required_milli", 2000), 2000\n    )\n    if reputation_required < 0:\n        reputation_required = 2000\n    reputation_actual = account_reputation_units(account, default=0)\n'''
    new = '''    # Helper eligibility is protocol policy, never an applicant-selected threshold.\n    reputation_required = 2000\n    asserted_required = _payload_helper_field(payload, "reputation_required_milli", None)\n    if asserted_required is not None and _as_int(asserted_required, -1) != reputation_required:\n        raise RolesApplyError(\n            "invalid_payload",\n            "helper_reputation_threshold_policy_mismatch",\n            {\n                "account_id": acct,\n                "required_milli": int(reputation_required),\n                "asserted_milli": asserted_required,\n            },\n        )\n    reputation_actual = account_reputation_units(account, default=0)\n'''
    text = replace_once_or_already(
        text,
        old,
        new,
        label="P2-ROLE-002 helper opt-in policy",
        already_marker="helper_reputation_threshold_policy_mismatch",
    )
    ROLES.write_text(text, encoding="utf-8")

    text = RESPONSIBILITIES.read_text(encoding="utf-8")
    text = replace_once_or_already(
        text,
        '''    required = _as_int(rec.get("reputation_required_milli"), 2000)\n    actual = account_reputation_units(account, default=0)\n''',
        '''    # Recompute helper reputation policy independently of persisted applicant data.\n    required = 2000\n    actual = account_reputation_units(account, default=0)\n''',
        label="P2-ROLE-002 helper evaluator policy",
        already_marker="Recompute helper reputation policy independently",
    )
    RESPONSIBILITIES.write_text(text, encoding="utf-8")


def patch_treasury_signer_authority() -> None:
    text = TREASURY.read_text(encoding="utf-8")
    text = replace_once_or_already(
        text,
        '''from weall.runtime.econ_phase import deny_if_econ_disabled, deny_if_econ_time_locked\n''',
        '''from weall.ledger.roles_schema import ensure_roles_schema, set_treasury_signers\nfrom weall.runtime.econ_phase import deny_if_econ_disabled, deny_if_econ_time_locked\n''',
        label="P2-TREAS-002 roles-schema import",
        already_marker="from weall.ledger.roles_schema import ensure_roles_schema, set_treasury_signers",
    )
    old_add = '''def _apply_treasury_signer_add(state: Json, env: TxEnvelope) -> Json:\n    payload = _as_dict(env.payload)\n    wallet_id = _as_str(\n        payload.get("wallet_id") or payload.get("treasury_id") or payload.get("id")\n    ).strip()\n    signer = _as_str(\n        payload.get("signer") or payload.get("account") or payload.get("account_id")\n    ).strip()\n    if not wallet_id or not signer:\n        raise TreasuryApplyError("invalid_payload", "missing_wallet_or_signer", {})\n\n    wallets = _ensure_wallets(state)\n    w = wallets.get(wallet_id)\n    if not isinstance(w, dict):\n        raise TreasuryApplyError("not_found", "wallet_not_found", {"wallet_id": wallet_id})\n\n    signers = w.get("signers")\n    if not isinstance(signers, list):\n        signers = []\n    had = signer in signers\n    if not had:\n        signers.append(signer)\n    w["signers"] = sorted({str(x).strip() for x in signers if str(x).strip()})\n    w["updated_at_nonce"] = int(env.nonce)\n    wallets[wallet_id] = w\n    return {\n        "applied": "TREASURY_SIGNER_ADD",\n        "wallet_id": wallet_id,\n        "signer": signer,\n        "deduped": had,\n    }\n'''
    new_add = '''def _apply_treasury_signer_add(state: Json, env: TxEnvelope) -> Json:\n    _require_system_env(env)\n    payload = _as_dict(env.payload)\n    wallet_id = _as_str(\n        payload.get("wallet_id") or payload.get("treasury_id") or payload.get("id")\n    ).strip()\n    signer = _as_str(\n        payload.get("signer") or payload.get("account") or payload.get("account_id")\n    ).strip()\n    if not wallet_id or not signer:\n        raise TreasuryApplyError("invalid_payload", "missing_wallet_or_signer", {})\n\n    wallets = _ensure_wallets(state)\n    w = wallets.get(wallet_id)\n    if not isinstance(w, dict):\n        raise TreasuryApplyError("not_found", "wallet_not_found", {"wallet_id": wallet_id})\n\n    roles = ensure_roles_schema(state)\n    treasuries = roles.get("treasuries_by_id")\n    authority = treasuries.get(wallet_id) if isinstance(treasuries, dict) else None\n    if not isinstance(authority, dict):\n        raise TreasuryApplyError(\n            "invalid_state", "treasury_signer_authority_missing", {"treasury_id": wallet_id}\n        )\n    signers = sorted(\n        {str(x).strip() for x in authority.get("signers", []) if str(x).strip()}\n    )\n    threshold = max(1, _as_int(authority.get("threshold"), 1))\n    if bool(authority.get("require_emissary_signers", False)) and signer not in _seated_emissaries(state):\n        raise TreasuryApplyError(\n            "forbidden", "signer_must_be_seated_emissary", {"treasury_id": wallet_id, "signer": signer}\n        )\n    had = signer in signers\n    if not had:\n        signers.append(signer)\n        signers = sorted(set(signers))\n    if threshold > len(signers):\n        raise TreasuryApplyError(\n            "invalid_state",\n            "threshold_exceeds_signer_set",\n            {"treasury_id": wallet_id, "threshold": threshold, "n_signers": len(signers)},\n        )\n    set_treasury_signers(state, wallet_id, signers, threshold=threshold)\n    w["signers"] = list(signers)\n    w["updated_at_nonce"] = int(env.nonce)\n    wallets[wallet_id] = w\n    return {\n        "applied": "TREASURY_SIGNER_ADD",\n        "wallet_id": wallet_id,\n        "signer": signer,\n        "deduped": had,\n    }\n'''
    text = replace_once_or_already(
        text,
        old_add,
        new_add,
        label="P2-TREAS-002 signer add authority",
        already_marker="treasury_signer_authority_missing",
    )
    old_remove = '''def _apply_treasury_signer_remove(state: Json, env: TxEnvelope) -> Json:\n    payload = _as_dict(env.payload)\n    wallet_id = _as_str(\n        payload.get("wallet_id") or payload.get("treasury_id") or payload.get("id")\n    ).strip()\n    signer = _as_str(\n        payload.get("signer") or payload.get("account") or payload.get("account_id")\n    ).strip()\n    if not wallet_id or not signer:\n        raise TreasuryApplyError("invalid_payload", "missing_wallet_or_signer", {})\n\n    wallets = _ensure_wallets(state)\n    w = wallets.get(wallet_id)\n    if not isinstance(w, dict):\n        raise TreasuryApplyError("not_found", "wallet_not_found", {"wallet_id": wallet_id})\n\n    signers = w.get("signers")\n    if not isinstance(signers, list):\n        signers = []\n    had = signer in signers\n    if had:\n        signers = [s for s in signers if _as_str(s).strip() != signer]\n    w["signers"] = sorted({str(x).strip() for x in signers if str(x).strip()})\n    w["updated_at_nonce"] = int(env.nonce)\n    wallets[wallet_id] = w\n    return {\n        "applied": "TREASURY_SIGNER_REMOVE",\n        "wallet_id": wallet_id,\n        "signer": signer,\n        "deduped": (not had),\n    }\n'''
    new_remove = '''def _apply_treasury_signer_remove(state: Json, env: TxEnvelope) -> Json:\n    _require_system_env(env)\n    payload = _as_dict(env.payload)\n    wallet_id = _as_str(\n        payload.get("wallet_id") or payload.get("treasury_id") or payload.get("id")\n    ).strip()\n    signer = _as_str(\n        payload.get("signer") or payload.get("account") or payload.get("account_id")\n    ).strip()\n    if not wallet_id or not signer:\n        raise TreasuryApplyError("invalid_payload", "missing_wallet_or_signer", {})\n\n    wallets = _ensure_wallets(state)\n    w = wallets.get(wallet_id)\n    if not isinstance(w, dict):\n        raise TreasuryApplyError("not_found", "wallet_not_found", {"wallet_id": wallet_id})\n\n    roles = ensure_roles_schema(state)\n    treasuries = roles.get("treasuries_by_id")\n    authority = treasuries.get(wallet_id) if isinstance(treasuries, dict) else None\n    if not isinstance(authority, dict):\n        raise TreasuryApplyError(\n            "invalid_state", "treasury_signer_authority_missing", {"treasury_id": wallet_id}\n        )\n    current = sorted(\n        {str(x).strip() for x in authority.get("signers", []) if str(x).strip()}\n    )\n    threshold = max(1, _as_int(authority.get("threshold"), 1))\n    had = signer in current\n    signers = [value for value in current if value != signer]\n    if had and threshold > len(signers):\n        raise TreasuryApplyError(\n            "forbidden",\n            "signer_removal_would_break_threshold",\n            {"treasury_id": wallet_id, "threshold": threshold, "n_signers_after": len(signers)},\n        )\n    if bool(authority.get("require_emissary_signers", False)):\n        seated = _seated_emissaries(state)\n        if any(value not in seated for value in signers):\n            raise TreasuryApplyError(\n                "invalid_state", "treasury_signer_not_seated_emissary", {"treasury_id": wallet_id}\n            )\n    set_treasury_signers(state, wallet_id, signers, threshold=threshold)\n    w["signers"] = list(signers)\n    w["updated_at_nonce"] = int(env.nonce)\n    wallets[wallet_id] = w\n    return {\n        "applied": "TREASURY_SIGNER_REMOVE",\n        "wallet_id": wallet_id,\n        "signer": signer,\n        "deduped": (not had),\n    }\n'''
    text = replace_once_or_already(
        text,
        old_remove,
        new_remove,
        label="P2-TREAS-002 signer remove authority",
        already_marker="signer_removal_would_break_threshold",
    )
    TREASURY.write_text(text, encoding="utf-8")


def patch_group_audit_anchor() -> None:
    text = GROUPS.read_text(encoding="utf-8")
    function = '''\n\ndef _apply_group_treasury_audit_anchor_set(state: Json, env: TxEnvelope) -> Json:\n    _require_system(env)\n    payload = _as_dict(env.payload)\n    group_id = _as_str(payload.get("group_id")).strip()\n    anchor = payload.get("anchor")\n    if not group_id:\n        raise GroupsApplyError("invalid_payload", "missing_group_id", {})\n    if not isinstance(anchor, dict) or not anchor:\n        raise GroupsApplyError("invalid_payload", "missing_anchor", {"group_id": group_id})\n    groups = _ensure_groups_root(state)\n    group = groups.get(group_id)\n    if not isinstance(group, dict):\n        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})\n    treasury_id = _as_str(group.get("treasury_id") or _group_treasury_id(group_id)).strip()\n    if not treasury_id:\n        raise GroupsApplyError("invalid_state", "missing_group_treasury_id", {"group_id": group_id})\n    anchors = group.get("treasury_audit_anchors")\n    if not isinstance(anchors, list):\n        anchors = []\n    record = {\n        "treasury_id": treasury_id,\n        "group_id": group_id,\n        "anchor": dict(anchor),\n        "set_at_nonce": int(env.nonce),\n    }\n    anchors.append(record)\n    group["treasury_audit_anchors"] = anchors\n    groups[group_id] = group\n    return {\n        "applied": "GROUP_TREASURY_AUDIT_ANCHOR_SET",\n        "group_id": group_id,\n        "treasury_id": treasury_id,\n    }\n'''
    text = replace_once_or_already(
        text,
        '''\ndef apply_groups(state: Json, env: TxEnvelope) -> Json | None:\n''',
        function + '''\n\ndef apply_groups(state: Json, env: TxEnvelope) -> Json | None:\n''',
        label="P2-GROUP-002 anchor function",
        already_marker="def _apply_group_treasury_audit_anchor_set(state: Json, env: TxEnvelope)",
    )
    text = replace_once_or_already(
        text,
        '''    if t == "GROUP_TREASURY_AUDIT_ANCHOR_SET":\n        _require_system(env)\n        return {"applied": "GROUP_TREASURY_AUDIT_ANCHOR_SET"}\n''',
        '''    if t == "GROUP_TREASURY_AUDIT_ANCHOR_SET":\n        return _apply_group_treasury_audit_anchor_set(state, env)\n''',
        label="P2-GROUP-002 anchor dispatch",
        already_marker='return _apply_group_treasury_audit_anchor_set(state, env)',
    )
    GROUPS.write_text(text, encoding="utf-8")


def patch_scoped_authority_tests() -> None:
    content = '''from __future__ import annotations\n\nimport pytest\n\nfrom weall.runtime.apply.groups import GroupsApplyError, apply_groups\nfrom weall.runtime.apply.roles import RolesApplyError, apply_roles\nfrom weall.runtime.apply.treasury import TreasuryApplyError, apply_treasury\nfrom weall.runtime.node_operator_responsibilities import evaluate_helper_responsibility\nfrom weall.runtime.tx_admission import TxEnvelope\n\n\ndef _env(tx_type: str, signer: str, payload: dict, *, nonce: int = 1, system: bool = False) -> TxEnvelope:\n    return TxEnvelope(\n        tx_type=tx_type,\n        signer=signer,\n        nonce=nonce,\n        payload=payload,\n        sig="sig",\n        system=system,\n        parent="gov:p2" if system else None,\n    )\n\n\ndef _helper_state(reputation: int) -> dict:\n    return {\n        "height": 1,\n        "accounts": {\n            "@op": {\n                "poh_tier": 2,\n                "reputation_milli": reputation,\n                "banned": False,\n                "locked": False,\n            }\n        },\n        "roles": {\n            "node_operators": {\n                "active_set": ["@op"],\n                "by_id": {\n                    "@op": {\n                        "account_id": "@op",\n                        "enrolled": True,\n                        "active": True,\n                        "status": "active",\n                        "responsibilities": {},\n                    }\n                },\n            }\n        },\n    }\n\n\ndef test_p2_role002_applicant_cannot_lower_helper_reputation_threshold() -> None:\n    state = _helper_state(1999)\n    with pytest.raises(RolesApplyError) as ei:\n        apply_roles(\n            state,\n            _env(\n                "NODE_OPERATOR_HELPER_OPT_IN",\n                "@op",\n                {"account_id": "@op", "reputation_required_milli": 0},\n            ),\n        )\n    assert ei.value.reason == "helper_reputation_threshold_policy_mismatch"\n\n    with pytest.raises(RolesApplyError) as ei2:\n        apply_roles(state, _env("NODE_OPERATOR_HELPER_OPT_IN", "@op", {"account_id": "@op"}))\n    assert ei2.value.reason == "helper_reputation_insufficient"\n\n\ndef test_p2_role002_evaluator_ignores_persisted_self_selected_threshold() -> None:\n    state = _helper_state(1999)\n    state["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"] = {\n        "helper": {\n            "opted_in": True,\n            "active": True,\n            "reputation_required_milli": 0,\n        }\n    }\n    result = evaluate_helper_responsibility(state, "@op")\n    assert result.eligible is False\n    assert "helper_reputation_insufficient" in result.reasons\n    assert result.details["reputation_required_milli"] == 2000\n\n\ndef test_p2_role002_canonical_minimum_allows_helper_opt_in() -> None:\n    state = _helper_state(2000)\n    result = apply_roles(state, _env("NODE_OPERATOR_HELPER_OPT_IN", "@op", {"account_id": "@op"}))\n    assert result["applied"] == "NODE_OPERATOR_HELPER_OPT_IN"\n    helper = state["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["helper"]\n    assert helper["reputation_required_milli"] == 2000\n\n\ndef _treasury_state(*, signers: list[str], threshold: int = 1) -> dict:\n    return {\n        "treasury_wallets": {"T": {"wallet_id": "T", "balance": 100, "signers": list(signers)}},\n        "roles": {\n            "treasuries_by_id": {\n                "T": {"signers": list(signers), "threshold": threshold, "require_emissary_signers": False}\n            }\n        },\n    }\n\n\ndef test_p2_treas002_add_remove_updates_canonical_authority_and_wallet_mirror() -> None:\n    state = _treasury_state(signers=["@a"], threshold=1)\n    add = apply_treasury(\n        state,\n        _env("TREASURY_SIGNER_ADD", "SYSTEM", {"wallet_id": "T", "signer": "@b"}, system=True),\n    )\n    assert add["deduped"] is False\n    assert state["roles"]["treasuries_by_id"]["T"]["signers"] == ["@a", "@b"]\n    assert state["treasury_wallets"]["T"]["signers"] == ["@a", "@b"]\n\n    remove = apply_treasury(\n        state,\n        _env(\n            "TREASURY_SIGNER_REMOVE",\n            "SYSTEM",\n            {"wallet_id": "T", "signer": "@a"},\n            nonce=2,\n            system=True,\n        ),\n    )\n    assert remove["deduped"] is False\n    assert state["roles"]["treasuries_by_id"]["T"]["signers"] == ["@b"]\n    assert state["treasury_wallets"]["T"]["signers"] == ["@b"]\n\n\ndef test_p2_treas002_remove_cannot_make_threshold_impossible() -> None:\n    state = _treasury_state(signers=["@a", "@b"], threshold=2)\n    with pytest.raises(TreasuryApplyError) as ei:\n        apply_treasury(\n            state,\n            _env("TREASURY_SIGNER_REMOVE", "SYSTEM", {"wallet_id": "T", "signer": "@a"}, system=True),\n        )\n    assert ei.value.reason == "signer_removal_would_break_threshold"\n    assert state["roles"]["treasuries_by_id"]["T"]["signers"] == ["@a", "@b"]\n\n\ndef test_p2_group002_audit_anchor_is_validated_and_bound_to_group_treasury() -> None:\n    state = {\n        "groups": {"G": {"group_id": "G", "treasury_id": "GT:G"}},\n    }\n    result = apply_groups(\n        state,\n        _env(\n            "GROUP_TREASURY_AUDIT_ANCHOR_SET",\n            "SYSTEM",\n            {"group_id": "G", "anchor": {"root": "sha256:abc"}},\n            system=True,\n        ),\n    )\n    assert result["treasury_id"] == "GT:G"\n    record = state["groups"]["G"]["treasury_audit_anchors"][0]\n    assert record["group_id"] == "G"\n    assert record["treasury_id"] == "GT:G"\n    assert record["anchor"] == {"root": "sha256:abc"}\n\n\ndef test_p2_group002_missing_anchor_fails_without_mutation() -> None:\n    state = {"groups": {"G": {"group_id": "G", "treasury_id": "GT:G"}}}\n    with pytest.raises(GroupsApplyError) as ei:\n        apply_groups(\n            state,\n            _env(\n                "GROUP_TREASURY_AUDIT_ANCHOR_SET",\n                "SYSTEM",\n                {"group_id": "G"},\n                system=True,\n            ),\n        )\n    assert ei.value.reason == "missing_anchor"\n    assert "treasury_audit_anchors" not in state["groups"]["G"]\n'''
    SCOPED_TESTS.write_text(content, encoding="utf-8")


def main() -> None:
    patch_rewards()
    patch_reward_tests()
    patch_sqlite()
    patch_sqlite_tests()
    patch_state_sync()
    patch_state_sync_tests()
    patch_helper_role_policy()
    patch_treasury_signer_authority()
    patch_group_audit_anchor()
    patch_scoped_authority_tests()


if __name__ == "__main__":
    main()