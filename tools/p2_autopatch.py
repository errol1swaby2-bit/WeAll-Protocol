from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REWARDS = ROOT / "Weall-Protocol/src/weall/runtime/apply/rewards.py"
REWARD_TESTS = ROOT / "Weall-Protocol/tests/test_reward_issuance_invariants.py"
SQLITE = ROOT / "Weall-Protocol/src/weall/runtime/sqlite_db.py"
SQLITE_TESTS = ROOT / "Weall-Protocol/tests/test_p2_persistence_synchronous.py"
STATE_SYNC = ROOT / "Weall-Protocol/src/weall/net/state_sync.py"
STATE_SYNC_TESTS = ROOT / "Weall-Protocol/tests/test_p2_state_sync_hardening.py"


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


def main() -> None:
    patch_rewards()
    patch_reward_tests()
    patch_sqlite()
    patch_sqlite_tests()
    patch_state_sync()
    patch_state_sync_tests()


if __name__ == "__main__":
    main()
