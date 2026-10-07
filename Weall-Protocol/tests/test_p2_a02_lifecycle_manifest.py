from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from weall.runtime import tx_contracts
from weall.runtime.domain_apply import apply_tx_atomic_meta_bounded_rollback
from weall.runtime.errors import ApplyError
from weall.runtime.sqlite_db import SqliteDB, SqliteLedgerStore
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_id import compute_tx_id_from_envelope

ROOT = Path(__file__).resolve().parents[1]
LIFECYCLE_SCRIPT = ROOT / "scripts" / "gen_tx_lifecycle_assurance_v1_5.py"


def _load_lifecycle_module():
    spec = importlib.util.spec_from_file_location(
        "gen_tx_lifecycle_assurance_v1_5_testmod",
        LIFECYCLE_SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_LIFECYCLE = _load_lifecycle_module()
OUTPUT_PATH = _LIFECYCLE.OUTPUT_PATH
build_manifest = _LIFECYCLE.build_manifest
load_fixture_module = _LIFECYCLE.load_fixture_module
load_semantic_manifest = _LIFECYCLE.load_semantic_manifest


def _rows_by_type(payload: dict) -> dict[str, dict]:
    rows = payload.get("rows")
    assert isinstance(rows, list)
    return {str(row["tx_type"]): row for row in rows}


def test_a02_lifecycle_manifest_is_current_complete_and_exact() -> None:
    tracked = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
    rebuilt = build_manifest()

    assert tracked == rebuilt
    assert tracked["schema"] == "weall.tx_lifecycle_assurance.v1"
    assert tracked["summary"]["tx_count"] == 236
    assert tracked["summary"]["successful_apply_count"] == 236
    assert tracked["summary"]["successful_admission_count"] == 236
    assert tracked["summary"]["failure_stage_vector_count"] == 236
    assert tracked["summary"]["receipt_expectation_count"] == 236
    assert tracked["summary"]["duplicate_replay_expectation_count"] == 236

    semantic = load_semantic_manifest()
    semantic_types = {str(row["tx_type"]) for row in semantic["rows"]}
    lifecycle = _rows_by_type(tracked)

    assert len(lifecycle) == 236
    assert set(lifecycle) == semantic_types

    tx_ids: list[str] = []
    for tx_type in sorted(lifecycle):
        row = lifecycle[tx_type]
        success = row["successful_execution"]

        env = TxEnvelope.from_json(success["admission_envelope"])
        tx_id = compute_tx_id_from_envelope(str(env.chain_id or ""), env)
        assert tx_id == success["tx_id"]

        signature = success["signature_evidence"]
        assert signature["admission_verified"] is True
        if bool(env.system):
            assert signature["required"] is False
        else:
            assert signature["required"] is True
            assert signature["sig_profile"] == "pq-mldsa-v1"
            assert signature["algorithm"] == "ML-DSA"
            assert signature["pubkey"]
            assert signature["signature_bytes"] > 0
            assert signature["signature_bytes_omitted_from_manifest"] is True

        assert success["success_receipt"] == {
            "tx_id": tx_id,
            "tx_type": str(env.tx_type or ""),
            "signer": str(env.signer or ""),
            "nonce": int(env.nonce or 0),
            "ok": True,
        }
        assert row["failure_expectation"]["stage"] == "schema_validation"
        assert row["failure_expectation"]["vector"]
        assert row["failure_expectation"]["rollback"] == "exact_pre_state_restoration"
        assert row["duplicate_replay_expectation"] == {
            "tx_id_scope": "global_one_shot",
            "pending_duplicate": "already_known_without_second_mempool_row",
            "committed_duplicate": "block_commit_duplicate_tx_id",
            "restart_replay": "rejected_after_confirmed_restart",
            "evidence_tests": [
                "tests/test_tx_replay_rejected_after_confirmed_restart.py",
                "tests/test_nonce_failure_block_progression.py",
            ],
        }
        tx_ids.append(tx_id)

    assert len(set(tx_ids)) == 236


def test_a02_state_writing_vectors_survive_sqlite_reopen_with_same_root(
    tmp_path: Path,
) -> None:
    fixture = load_fixture_module()
    semantic = load_semantic_manifest()
    lifecycle = _rows_by_type(build_manifest())

    checked = 0
    for index, semantic_row in enumerate(semantic["rows"]):
        tx_type = str(semantic_row["tx_type"])
        state = fixture._base_state()
        env = fixture._prepared_envelope(state, semantic_row)
        apply_tx_atomic_meta_bounded_rollback(state, env)

        expected = lifecycle[tx_type]
        expected_root = expected["successful_execution"]["state_root_after"]
        assert compute_state_root(state) == expected_root

        if not expected["persistence_restart_expectation"]["required"]:
            continue

        db_path = tmp_path / f"{index:03d}-{tx_type}.db"
        db = SqliteDB(path=str(db_path))
        db.init_schema()
        SqliteLedgerStore(db=db).write(state)

        reopened_db = SqliteDB(path=str(db_path))
        reopened_db.init_schema()
        restored = SqliteLedgerStore(db=reopened_db).read()

        assert restored == state
        assert compute_state_root(restored) == expected_root
        checked += 1

    assert checked == build_manifest()["summary"]["persistence_required_count"]
    assert checked > 0


def test_a02_matrix_detects_intentionally_broken_registered_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tx_type = "PROFILE_UPDATE"
    assert tx_type in tx_contracts._HANDLER_BY_TX_TYPE

    def _broken_handler(_state, _env):
        raise ApplyError("mutation_probe", "intentionally_broken_handler", {})

    handler_name, _original = tx_contracts._HANDLER_BY_TX_TYPE[tx_type]
    monkeypatch.setitem(
        tx_contracts._HANDLER_BY_TX_TYPE,
        tx_type,
        (handler_name, _broken_handler),
    )

    with pytest.raises(ApplyError) as exc:
        build_manifest()

    assert exc.value.code == "mutation_probe"
    assert exc.value.reason == "intentionally_broken_handler"
