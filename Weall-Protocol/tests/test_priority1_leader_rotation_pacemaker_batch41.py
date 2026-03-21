from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

import pytest

from weall.runtime.bft_hotstuff import HotStuffBFT
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _mk_keypair_hex() -> tuple[str, str]:
    import os

    return os.urandom(32).hex(), os.urandom(32).hex()


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


def leader_for_view(validators: List[str], view: int) -> str:
    return validators[view % len(validators)]


def test_bft_drive_timeouts_emit_only_for_non_leaders_across_rotating_views(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]

    vpub: Dict[str, str] = {}
    vpriv: Dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    monkeypatch.setenv("WEALL_AUTOTIMEOUT", "1")
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_BFT_ALLOW_UNSIGNED_TIMEOUTS", "1")

    for view in range(4):
        expected_leader = leader_for_view(validators, view)

        for signer in validators:
            monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", signer)
            monkeypatch.setenv("WEALL_NODE_PUBKEY", vpub[signer])
            monkeypatch.setenv("WEALL_NODE_PRIVKEY", vpriv[signer])

            ex = WeAllExecutor(
                db_path=str(tmp_path / f"{signer}-{view}.db"),
                node_id=signer,
                chain_id="batch41-timeouts",
                tx_index_path=tx_index_path,
            )
            _seed_validator_set(ex, validators=validators, pub=vpub)

            ex.bft_set_view(view)
            out = ex.bft_drive_timeouts(now_ms=0)

            if signer == expected_leader:
                assert out == []
            else:
                assert isinstance(out, list) and len(out) == 1
                assert int(out[0].get("view", -1)) == view
                assert str(out[0].get("signer") or "") == signer


def test_timeout_quorum_survives_restart_and_advances_to_next_rotating_leader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]

    vpub: Dict[str, str] = {}
    vpriv: Dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    monkeypatch.setenv("WEALL_AUTOTIMEOUT", "1")
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_BFT_ALLOW_UNSIGNED_TIMEOUTS", "1")

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", vpub["v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", vpriv["v2"])

    db_path = str(tmp_path / "v2.db")
    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch41-timeout-restart",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(ex, validators=validators, pub=vpub)

    ex.bft_set_view(0)
    out = ex.bft_drive_timeouts(now_ms=0)
    assert isinstance(out, list) and len(out) == 1
    assert str(out[0].get("signer") or "") == "v2"
    assert int(out[0].get("view", -1)) == 0

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch41-timeout-restart",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(ex2, validators=validators, pub=vpub)

    ex2.bft_set_view(1)
    out2 = ex2.bft_drive_timeouts(now_ms=0)
    assert out2 == []  # v2 is leader for view 1

    ex2.bft_set_view(2)
    out3 = ex2.bft_drive_timeouts(now_ms=0)
    assert isinstance(out3, list) and len(out3) == 1
    assert int(out3[0].get("view", -1)) == 2
    assert str(out3[0].get("signer") or "") == "v2"


def test_pacemaker_backoff_persists_across_restart_and_resets_on_progress() -> None:
    hs = HotStuffBFT(chain_id="batch41")
    hs.timeout_base_ms = 1000

    assert hs.pacemaker_timeout_ms() == 1000
    hs.note_timeout_emitted(view=0)
    hs.note_timeout_emitted(view=1)
    assert hs.pacemaker_timeout_ms() == 4000

    persisted = hs.export_state()
    hs2 = HotStuffBFT(chain_id="batch41")
    hs2.load_from_state({"bft": persisted})
    assert hs2.pacemaker_timeout_ms() == 4000
    assert int(hs2.export_state().get("last_timeout_view", -1)) == 1

    hs2.note_progress()
    assert hs2.pacemaker_timeout_ms() == 1000

    hs3 = HotStuffBFT(chain_id="batch41")
    hs3.load_from_state({"bft": hs2.export_state()})
    assert hs3.pacemaker_timeout_ms() == 1000
    assert int(hs3.export_state().get("timeout_backoff_exp", 99)) == 0


def test_bft_adversarial_matrix_cli_runs_all_scenarios(tmp_path: Path) -> None:
    env = {"PYTHONPATH": str(_repo_root() / "src")}

    proc = subprocess.run(
        [
            sys.executable,
            str(_repo_root() / "scripts" / "bft_adversarial_matrix.py"),
            "--work-dir",
            str(tmp_path),
            "--chain-id-prefix",
            "bft-batch18-matrix",
        ],
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert int(payload["scenario_count"]) == 4
