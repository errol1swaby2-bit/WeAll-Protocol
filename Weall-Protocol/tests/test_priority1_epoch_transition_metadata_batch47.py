from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _seed_validator_set(
    ex: WeAllExecutor, *, validators: List[str], pub: Dict[str, str], epoch: int
) -> None:
    st = ex.read_state()
    st.setdefault("roles", {})
    st["roles"].setdefault("validators", {})
    st["roles"]["validators"]["active_set"] = list(validators)

    st.setdefault("validators", {})
    st["validators"].setdefault("registry", {})

    st.setdefault("consensus", {})
    st["consensus"].setdefault("validators", {})
    st["consensus"]["validators"].setdefault("registry", {})
    st["consensus"].setdefault("epochs", {})
    st["consensus"]["epochs"]["current"] = int(epoch)
    st["consensus"].setdefault("validator_set", {})
    st["consensus"]["validator_set"]["active_set"] = list(validators)
    st["consensus"]["validator_set"]["epoch"] = int(epoch)
    st["consensus"]["validator_set"].pop("set_hash", None)

    for v in validators:
        st["consensus"]["validators"]["registry"].setdefault(v, {})
        st["consensus"]["validators"]["registry"][v]["pubkey"] = pub[v]
        st["validators"]["registry"].setdefault(v, {})
        st["validators"]["registry"][v]["pubkey"] = pub[v]

    ex.state = st
    ex._ledger_store.write(ex.state)

    st = ex.read_state()
    st["consensus"]["validator_set"]["set_hash"] = ex._current_validator_set_hash()
    ex.state = st
    ex._ledger_store.write(ex.state)


def test_epoch_transition_persists_current_epoch_and_set_hash_batch47(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    validators = ["v1", "v2", "v3", "v4"]
    pub = {v: f"pk-{v}" for v in validators}

    db_path = str(tmp_path / "epoch.db")
    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch47-epoch",
        tx_index_path=tx_index_path,
    )

    _seed_validator_set(ex, validators=validators, pub=pub, epoch=1)
    st1 = ex.read_state()
    hash1 = str(st1["consensus"]["validator_set"]["set_hash"])
    assert int(st1["consensus"]["epochs"]["current"]) == 1
    assert int(st1["consensus"]["validator_set"]["epoch"]) == 1

    _seed_validator_set(ex, validators=validators, pub=pub, epoch=2)
    st2 = ex.read_state()
    hash2 = str(st2["consensus"]["validator_set"]["set_hash"])
    assert int(st2["consensus"]["epochs"]["current"]) == 2
    assert int(st2["consensus"]["validator_set"]["epoch"]) == 2
    assert hash2 == hash1

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch47-epoch",
        tx_index_path=tx_index_path,
    )
    st3 = ex2.read_state()
    assert int(st3["consensus"]["epochs"]["current"]) == 2
    assert int(st3["consensus"]["validator_set"]["epoch"]) == 2
    assert str(st3["consensus"]["validator_set"]["set_hash"]) == hash2


def test_epoch_transition_with_membership_change_persists_new_hash_batch47(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    pub = {
        "v1": "pk-v1",
        "v2": "pk-v2",
        "v3": "pk-v3",
        "v4": "pk-v4",
        "v5": "pk-v5",
    }

    db_path = str(tmp_path / "membership.db")
    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch47-membership",
        tx_index_path=tx_index_path,
    )

    _seed_validator_set(ex, validators=["v1", "v2", "v3", "v4"], pub=pub, epoch=4)
    st_before = ex.read_state()
    hash_before = str(st_before["consensus"]["validator_set"]["set_hash"])

    _seed_validator_set(ex, validators=["v1", "v2", "v3", "v4", "v5"], pub=pub, epoch=5)
    st_after = ex.read_state()
    hash_after = str(st_after["consensus"]["validator_set"]["set_hash"])

    assert int(st_after["consensus"]["epochs"]["current"]) == 5
    assert int(st_after["consensus"]["validator_set"]["epoch"]) == 5
    assert st_after["consensus"]["validator_set"]["active_set"] == ["v1", "v2", "v3", "v4", "v5"]
    assert hash_before
    assert hash_after
    assert hash_after != hash_before

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch47-membership",
        tx_index_path=tx_index_path,
    )
    st_reload = ex2.read_state()
    assert int(st_reload["consensus"]["epochs"]["current"]) == 5
    assert int(st_reload["consensus"]["validator_set"]["epoch"]) == 5
    assert st_reload["consensus"]["validator_set"]["active_set"] == ["v1", "v2", "v3", "v4", "v5"]
    assert str(st_reload["consensus"]["validator_set"]["set_hash"]) == hash_after


def test_epoch_metadata_does_not_regress_across_multiple_reloads_batch47(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    validators = ["v1", "v2", "v3", "v4"]
    pub = {v: f"pk-{v}" for v in validators}
    db_path = str(tmp_path / "reloads.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch47-reloads",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(ex, validators=validators, pub=pub, epoch=7)

    expected_hash = str(ex.read_state()["consensus"]["validator_set"]["set_hash"])

    for _ in range(3):
        ex = WeAllExecutor(
            db_path=db_path,
            node_id="v3",
            chain_id="batch47-reloads",
            tx_index_path=tx_index_path,
        )
        st = ex.read_state()
        assert int(st["consensus"]["epochs"]["current"]) == 7
        assert int(st["consensus"]["validator_set"]["epoch"]) == 7
        assert str(st["consensus"]["validator_set"]["set_hash"]) == expected_hash
        assert st["consensus"]["validator_set"]["active_set"] == validators


def test_epoch_and_validator_set_metadata_remain_aligned_batch47(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    validators = ["v1", "v2", "v3", "v4"]
    pub = {v: f"pk-{v}" for v in validators}

    ex = WeAllExecutor(
        db_path=str(tmp_path / "aligned.db"),
        node_id="v4",
        chain_id="batch47-aligned",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(ex, validators=validators, pub=pub, epoch=9)

    st = ex.read_state()
    assert (
        int(st["consensus"]["epochs"]["current"])
        == int(st["consensus"]["validator_set"]["epoch"])
        == 9
    )

    _seed_validator_set(ex, validators=validators, pub=pub, epoch=10)
    st2 = ex.read_state()
    assert (
        int(st2["consensus"]["epochs"]["current"])
        == int(st2["consensus"]["validator_set"]["epoch"])
        == 10
    )
