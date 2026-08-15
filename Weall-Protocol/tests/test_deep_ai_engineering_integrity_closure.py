from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from weall.net.net_loop import NetStateSnapshotError
from weall.runtime.block_hash import compute_receipts_root
from weall.runtime.bft_hotstuff import validator_set_hash as bft_validator_set_hash
from weall.runtime.commitments import receipts_root, validator_set_hash
from weall.runtime.executor import WeAllExecutor
from weall.runtime.helper_certificates import hash_receipts
from weall.runtime.helper_lane_journal import (
    HelperLaneJournal,
    HelperLaneJournalCorruptionError,
)
from weall.runtime.helper_merge_admission import canonical_receipts_root
from weall.runtime.poh.eligibility import ACTION_REQUIRED_POH_TIER, get_required_poh_tier
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_index import load_tx_index

ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = ROOT / "generated" / "tx_index.json"


def test_poh_minimum_tier_adapter_is_derived_from_canonical_tx_index() -> None:
    index = load_tx_index(TX_INDEX)
    expected = {}
    for name, spec in index.by_name.items():
        gate = str(spec.get("subject_gate") or "")
        if gate in {"Tier0+", "Tier1+", "Tier2+"}:
            expected[name] = int(gate[4])

    assert dict(ACTION_REQUIRED_POH_TIER) == dict(sorted(expected.items()))
    assert get_required_poh_tier("CONTENT_COMMENT_CREATE") == 0
    assert get_required_poh_tier("CONTENT_FLAG") == 1
    assert get_required_poh_tier("DISPUTE_OPEN") == 1
    assert "GOV_DELEGATION_SET" not in ACTION_REQUIRED_POH_TIER


def test_real_executor_persisted_read_failure_does_not_return_stale_state(tmp_path: Path) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="read-fail-node",
        chain_id="read-fail-chain",
        tx_index_path=str(TX_INDEX),
    )
    cached_before = copy.deepcopy(ex.state)

    def _boom():
        raise OSError("simulated durable read failure")

    ex._ledger_store.read = _boom  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="persisted_ledger_state_read_failed"):
        ex.read_state()

    assert ex.read_cached_state() == cached_before
    assert compute_state_root(ex.read_cached_state()) == compute_state_root(cached_before)


def test_net_state_snapshot_fail_closed_branch_is_reachable_with_real_executor(
    tmp_path: Path,
) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="net-read-fail-node",
        chain_id="net-read-fail-chain",
        tx_index_path=str(TX_INDEX),
    )

    def _boom():
        raise OSError("simulated durable read failure")

    ex._ledger_store.read = _boom  # type: ignore[method-assign]

    # Exercise the real executor through the production net-loop snapshot method
    # without constructing a fake read_state implementation.
    from weall.net.net_loop import NetMeshLoop

    loop = object.__new__(NetMeshLoop)
    loop._executor = ex
    old_mode = os.environ.get("WEALL_MODE")
    os.environ["WEALL_MODE"] = "prod"
    try:
        with pytest.raises(NetStateSnapshotError, match="state_snapshot_failed"):
            loop._state_snapshot()
    finally:
        if old_mode is None:
            os.environ.pop("WEALL_MODE", None)
        else:
            os.environ["WEALL_MODE"] = old_mode


def _run_clean_import(tmp_path: Path, code: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("WEALL_API_BOOT_RUNTIME", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_importing_app_factory_is_runtime_storage_pure(tmp_path: Path) -> None:
    proc = _run_clean_import(tmp_path, "from weall.api.app import create_app; print(create_app)")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (tmp_path / "data").exists()


def test_importing_prod_smoke_is_runtime_storage_pure(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "prod_smoke.py"
    proc = _run_clean_import(
        tmp_path,
        f"import runpy; runpy.run_path({str(script)!r}, run_name='weall_prod_smoke_import')",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (tmp_path / "data").exists()


def test_production_asgi_entrypoint_is_separate_from_import_safe_factory() -> None:
    app_src = (ROOT / "src" / "weall" / "api" / "app.py").read_text(encoding="utf-8")
    asgi_src = (ROOT / "src" / "weall" / "api" / "asgi.py").read_text(encoding="utf-8")
    run_node = (ROOT / "scripts" / "run_node.sh").read_text(encoding="utf-8")
    assert "app = create_app(boot_runtime=False)" in app_src
    assert "app = create_app(boot_runtime=_module_app_boot_runtime_default())" in asgi_src
    assert "weall.api.asgi:app" in run_node
    assert "weall.api.app:app" not in run_node


def test_helper_journal_rejects_corrupt_json_and_truncation(tmp_path: Path) -> None:
    path = tmp_path / "helper.jsonl"
    journal = HelperLaneJournal(str(path))
    journal.append_receipt_accept(
        plan_id="plan-1",
        lane_id="lane-1",
        helper_id="helper-1",
        receipt_fingerprint="fp-1",
    )
    path.write_text(path.read_text(encoding="utf-8") + "{broken}\n", encoding="utf-8")
    with pytest.raises(HelperLaneJournalCorruptionError, match="invalid_json"):
        journal.load_resolution_state()

    journal = HelperLaneJournal(str(path))
    path.unlink()
    journal.append_receipt_accept(
        plan_id="plan-2",
        lane_id="lane-2",
        helper_id="helper-2",
        receipt_fingerprint="fp-2",
    )
    obj = json.loads(path.read_text(encoding="utf-8"))
    obj["helper_id"] = "tampered-helper"
    path.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    with pytest.raises(HelperLaneJournalCorruptionError, match="checksum_mismatch"):
        journal.load_resolution_state()

    path.write_text('{"kind":"helper_plan","plan_id":"legacy"}\n', encoding="utf-8")
    with pytest.raises(HelperLaneJournalCorruptionError, match="integrity_fields_missing"):
        journal.load()

    path.write_text('{"kind":"helper_plan","plan_id":"p"}', encoding="utf-8")
    with pytest.raises(HelperLaneJournalCorruptionError, match="truncated_final_record"):
        journal.load()


def test_commitment_primitives_are_shared_across_bft_block_and_helper_domains() -> None:
    validators = [" v2 ", "v1", "v2", "", "v3"]
    assert bft_validator_set_hash(validators) == validator_set_hash(validators)

    receipts = [
        {"tx_id": "tx-1", "ok": True},
        {"tx_id": "tx-2", "ok": False, "error": "denied"},
    ]
    canonical = receipts_root(receipts)
    assert hash_receipts(receipts) == canonical
    assert canonical_receipts_root(receipts) == canonical
    assert compute_receipts_root(receipts=receipts) == canonical


def test_shadow_helper_planner_is_not_a_runtime_module_or_mechanism_authority() -> None:
    assert not (ROOT / "src" / "weall" / "runtime" / "helper_planner.py").exists()
    assert not (ROOT / "src" / "weall" / "runtime" / "conflict_lanes.py").exists()
    assert (ROOT / "src" / "weall" / "testing" / "helper_planner.py").exists()
    assert (ROOT / "src" / "weall" / "testing" / "conflict_lanes.py").exists()

    from v2_spec_validation import apply_authoritative_mechanism_bindings

    mechanisms = json.loads(
        (ROOT / "specs" / "v2" / "source" / "mechanisms.json").read_text(encoding="utf-8")
    )["mechanisms"]
    apply_authoritative_mechanism_bindings(ROOT, mechanisms)
    by_id = {row["id"]: row for row in mechanisms}
    helper_paths = set(by_id["M-067"]["repository_evidence_paths"])
    poh_paths = set(by_id["M-032"]["repository_evidence_paths"])
    assert "src/weall/runtime/helper_planner.py" not in helper_paths
    assert "src/weall/runtime/parallel_execution.py" in helper_paths
    assert "src/weall/runtime/helper_execution_runtime.py" in helper_paths
    assert "src/weall/runtime/poh/eligibility.py" not in poh_paths


def test_mechanism_authority_map_rejects_reintroduced_shadow_evidence() -> None:
    from v2_spec_validation import (
        apply_authoritative_mechanism_bindings,
        validate_mechanism_evidence,
    )

    mechanisms = json.loads(
        (ROOT / "specs" / "v2" / "source" / "mechanisms.json").read_text(encoding="utf-8")
    )["mechanisms"]
    apply_authoritative_mechanism_bindings(ROOT, mechanisms)
    report = validate_mechanism_evidence(ROOT, copy.deepcopy(mechanisms))
    assert report["explicit_authority_bindings_validated"] >= 3
    assert "existence, not call-path authority" in report["authority_claim_scope"]

    tampered = copy.deepcopy(mechanisms)
    row = next(item for item in tampered if item["id"] == "M-067")
    row["repository_evidence"].append(
        {"kind": "current_path", "path": "src/weall/runtime/helper_planner.py", "status": "present"}
    )
    # The removed runtime path fails path resolution before it can masquerade as authority.
    with pytest.raises(ValueError):
        validate_mechanism_evidence(ROOT, tampered)
