from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from weall.runtime.bft_hotstuff import quorum_threshold
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _seed_validator_set(
    ex: WeAllExecutor, *, validators: List[str], pub: Dict[str, str], epoch: int = 1
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
    # Clear any previous persisted set hash before recomputing.
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


def test_validator_set_hash_is_canonical_across_input_order(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    pub = {
        "v1": "pk-v1",
        "v2": "pk-v2",
        "v3": "pk-v3",
        "v4": "pk-v4",
    }

    ex_a = WeAllExecutor(
        db_path=str(tmp_path / "a.db"),
        node_id="v1",
        chain_id="batch42-canonical-a",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(ex_a, validators=["v1", "v2", "v3", "v4"], pub=pub, epoch=1)
    hash_a = str(ex_a.read_state()["consensus"]["validator_set"]["set_hash"])

    ex_b = WeAllExecutor(
        db_path=str(tmp_path / "b.db"),
        node_id="v1",
        chain_id="batch42-canonical-b",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(ex_b, validators=["v4", "v2", "v1", "v3"], pub=pub, epoch=1)
    hash_b = str(ex_b.read_state()["consensus"]["validator_set"]["set_hash"])

    assert hash_a
    assert hash_b
    assert hash_a == hash_b


def test_validator_epoch_and_set_hash_survive_restart(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    validators = ["v1", "v2", "v3", "v4"]
    pub = {v: f"pk-{v}" for v in validators}

    db_path = str(tmp_path / "restart.db")
    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch42-restart",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(ex, validators=validators, pub=pub, epoch=3)

    st = ex.read_state()
    expected_hash = str(st["consensus"]["validator_set"]["set_hash"])
    assert int(st["consensus"]["validator_set"]["epoch"]) == 3
    assert st["consensus"]["validator_set"]["active_set"] == validators

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch42-restart",
        tx_index_path=tx_index_path,
    )
    st2 = ex2.read_state()

    assert int(st2["consensus"]["validator_set"]["epoch"]) == 3
    assert st2["consensus"]["validator_set"]["active_set"] == validators
    assert str(st2["consensus"]["validator_set"]["set_hash"]) == expected_hash


def test_validator_set_change_produces_new_hash_and_persists(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_path = str(tmp_path / "change.db")
    pub = {
        "v1": "pk-v1",
        "v2": "pk-v2",
        "v3": "pk-v3",
        "v4": "pk-v4",
        "v5": "pk-v5",
    }

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch42-change",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(ex, validators=["v1", "v2", "v3", "v4"], pub=pub, epoch=1)
    hash_before = str(ex.read_state()["consensus"]["validator_set"]["set_hash"])

    _seed_validator_set(ex, validators=["v1", "v2", "v3", "v4", "v5"], pub=pub, epoch=2)
    st_after = ex.read_state()
    hash_after = str(st_after["consensus"]["validator_set"]["set_hash"])

    assert hash_before
    assert hash_after
    assert hash_after != hash_before
    assert int(st_after["consensus"]["validator_set"]["epoch"]) == 2
    assert st_after["consensus"]["validator_set"]["active_set"] == ["v1", "v2", "v3", "v4", "v5"]

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch42-change",
        tx_index_path=tx_index_path,
    )
    st2 = ex2.read_state()
    assert int(st2["consensus"]["validator_set"]["epoch"]) == 2
    assert st2["consensus"]["validator_set"]["active_set"] == ["v1", "v2", "v3", "v4", "v5"]
    assert str(st2["consensus"]["validator_set"]["set_hash"]) == hash_after


def test_quorum_threshold_tracks_validator_set_sizes() -> None:
    assert quorum_threshold(1) == 1
    assert quorum_threshold(4) == 3
    assert quorum_threshold(5) == 4
    assert quorum_threshold(7) == 5
