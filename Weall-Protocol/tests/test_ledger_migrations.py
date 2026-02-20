from __future__ import annotations

import copy
import pytest

from weall.ledger.migrations import CURRENT_STATE_VERSION, migrate_state_dict


def _assert_minimal_shape(st: dict) -> None:
    assert isinstance(st, dict)
    assert st.get("state_version") == CURRENT_STATE_VERSION

    # Core chain keys
    assert isinstance(st.get("height"), int)
    assert isinstance(st.get("tip"), str)

    # Required roots
    assert isinstance(st.get("accounts"), dict)
    assert isinstance(st.get("roles"), dict)
    assert isinstance(st.get("blocks"), dict)
    assert isinstance(st.get("params"), dict)
    assert isinstance(st.get("block_attestations"), dict)

    # Finality root
    fin = st.get("finalized")
    assert isinstance(fin, dict)
    assert isinstance(fin.get("height"), int)
    assert isinstance(fin.get("block_id"), str)

    # Account normalization (if any accounts exist)
    for aid, acct in st["accounts"].items():
        assert isinstance(aid, str)
        assert isinstance(acct, dict)
        assert isinstance(acct.get("nonce"), int)
        assert isinstance(acct.get("poh_tier"), int)
        assert isinstance(acct.get("banned"), bool)
        assert isinstance(acct.get("locked"), bool)
        assert isinstance(acct.get("reputation"), float)


def test_migrate_non_dict_input_yields_current_skeleton() -> None:
    st = migrate_state_dict(None)
    _assert_minimal_shape(st)


def test_migrate_empty_dict_is_upgraded() -> None:
    st = migrate_state_dict({})
    _assert_minimal_shape(st)


def test_migrate_v0_missing_roots_backfills() -> None:
    v0 = {"height": "7", "tip": 123}  # wrong types that should be normalized by migration
    st = migrate_state_dict(v0)
    _assert_minimal_shape(st)
    assert st["height"] == 7
    assert st["tip"] == "123"


def test_migrate_v0_weird_root_shapes_are_normalized() -> None:
    v0 = {
        "height": 1,
        "tip": "abc",
        "accounts": ["not-a-dict"],
        "roles": "nope",
        "blocks": None,
        "params": 5,
        "block_attestations": [],
        "finalized": "bad",
    }
    st = migrate_state_dict(v0)
    _assert_minimal_shape(st)


def test_migrate_v0_accounts_are_normalized() -> None:
    v0 = {
        "height": 2,
        "tip": "t",
        "accounts": {
            "alice": {"nonce": "3", "poh_tier": "2", "banned": "false", "locked": 0, "reputation": "0.25"},
            "bob": "bad",
        },
        # omit other roots on purpose
    }
    st = migrate_state_dict(v0)
    _assert_minimal_shape(st)

    assert st["accounts"]["alice"]["nonce"] == 3
    assert st["accounts"]["alice"]["poh_tier"] == 2
    assert st["accounts"]["alice"]["banned"] is False
    assert st["accounts"]["alice"]["locked"] is False
    assert st["accounts"]["alice"]["reputation"] == pytest.approx(0.25)

    assert isinstance(st["accounts"]["bob"], dict)
    assert st["accounts"]["bob"]["nonce"] == 0
    assert st["accounts"]["bob"]["poh_tier"] == 0


def test_migrate_is_idempotent_at_current_version() -> None:
    raw = migrate_state_dict({})
    raw2 = migrate_state_dict(copy.deepcopy(raw))
    assert raw2 == raw


def test_future_state_version_is_rejected() -> None:
    raw = migrate_state_dict({})
    raw["state_version"] = CURRENT_STATE_VERSION + 1
    with pytest.raises(ValueError):
        migrate_state_dict(raw)
