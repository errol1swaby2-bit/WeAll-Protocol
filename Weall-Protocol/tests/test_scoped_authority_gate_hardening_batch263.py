from __future__ import annotations

from weall.runtime.gate_expr import eval_gate


def test_signer_requires_tier2_account_even_when_listed() -> None:
    ledger = {
        "accounts": {"@alice": {"poh_tier": 1}},
        "roles": {"treasuries_by_id": {"t1": {"signers": ["@alice"]}}},
    }

    ok, _meta = eval_gate("Signer", signer="@alice", ledger=ledger, payload={"treasury_id": "t1"})

    assert ok is False


def test_treasury_signer_denies_suspended_signer_record() -> None:
    ledger = {
        "accounts": {"@alice": {"poh_tier": 2}},
        "roles": {
            "treasuries_by_id": {
                "t1": {
                    "signers": ["@alice"],
                    "signers_by_id": {"@alice": {"status": "suspended"}},
                }
            }
        },
    }

    ok, _meta = eval_gate("Signer", signer="@alice", ledger=ledger, payload={"treasury_id": "t1"})

    assert ok is False


def test_treasury_signer_allows_tier2_active_list_member() -> None:
    ledger = {
        "accounts": {"@alice": {"poh_tier": 2}},
        "roles": {"treasuries_by_id": {"t1": {"signers": ["@alice"]}}},
    }

    ok, _meta = eval_gate("Signer", signer="@alice", ledger=ledger, payload={"treasury_id": "t1"})

    assert ok is True


def test_group_signer_atom_is_supported_and_denies_suspended_record() -> None:
    ledger = {
        "accounts": {"@alice": {"poh_tier": 2}},
        "roles": {
            "groups_by_id": {
                "g1": {
                    "signers": ["@alice"],
                    "signers_by_id": {"@alice": {"revoked": True}},
                }
            }
        },
    }

    ok, _meta = eval_gate("GroupSigner", signer="@alice", ledger=ledger, payload={"group_id": "g1"})

    assert ok is False


def test_group_signer_atom_allows_tier2_active_group_signer() -> None:
    ledger = {
        "accounts": {"@alice": {"poh_tier": 2}},
        "roles": {"groups_by_id": {"g1": {"signers": ["@alice"]}}},
    }

    ok, _meta = eval_gate("GroupSigner", signer="@alice", ledger=ledger, payload={"group_id": "g1"})

    assert ok is True


def test_group_moderator_atom_requires_tier2_and_active_moderator() -> None:
    ledger = {
        "accounts": {"@mod": {"poh_tier": 2}, "@tier1": {"poh_tier": 1}},
        "roles": {"groups_by_id": {"g1": {"moderators": ["@mod", "@tier1"]}}},
    }

    ok, _meta = eval_gate("GroupModerator", signer="@mod", ledger=ledger, payload={"group_id": "g1"})
    low, _meta2 = eval_gate("GroupModerator", signer="@tier1", ledger=ledger, payload={"group_id": "g1"})

    assert ok is True
    assert low is False


def test_group_emissary_requires_tier2_and_denies_global_removal() -> None:
    ledger = {
        "accounts": {"@emi": {"poh_tier": 2}},
        "roles": {
            "groups_by_id": {"g1": {"emissaries": ["@emi"]}},
            "emissaries": {"by_id": {"@emi": {"removed": True}}},
        },
    }

    ok, _meta = eval_gate("Emissary", signer="@emi", ledger=ledger, payload={"group_id": "g1"})

    assert ok is False


def test_treasury_emissary_requires_emissary_controlled_treasury_signer_and_seated_emissary() -> None:
    ledger = {
        "accounts": {"@emi": {"poh_tier": 2}, "@outsider": {"poh_tier": 2}},
        "roles": {
            "emissaries": {"seated": ["@emi"], "by_id": {"@emi": {"active": True}}},
            "treasuries_by_id": {
                "t1": {
                    "require_emissary_signers": True,
                    "signers": ["@emi", "@outsider"],
                }
            },
        },
    }

    ok, _meta = eval_gate("Emissary", signer="@emi", ledger=ledger, payload={"treasury_id": "t1"})
    outsider, _meta2 = eval_gate("Emissary", signer="@outsider", ledger=ledger, payload={"treasury_id": "t1"})

    assert ok is True
    assert outsider is False
