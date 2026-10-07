from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
FIXTURE_PATH = ROOT / "tests" / "test_p2_a02_success_lifecycle_baseline.py"
SEMANTIC_PATH = ROOT / "generated" / "tx_semantic_assurance_v1_5.json"
OUTPUT_PATH = ROOT / "generated" / "tx_lifecycle_assurance_v1_5.json"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# This is a hermetic contract-evidence generator, not a production node boot.
# Match tests/conftest.py so operator shell WEALL_* exports cannot change the
# 236-vector fixture semantics or the tracked manifest bytes.
for _name in list(os.environ):
    if _name.startswith("WEALL_"):
        os.environ.pop(_name, None)
os.environ["WEALL_MODE"] = "test"
os.environ["WEALL_CRYPTO_MODE"] = "closed-testnet"
os.environ["WEALL_API_BOOT_RUNTIME"] = "0"

from weall.runtime.domain_apply import apply_tx_atomic_meta_bounded_rollback
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_contracts import handler_name_for_tx_type, load_default_tx_index
from weall.runtime.tx_id import compute_tx_id_from_envelope
from weall.testing.sigtools import ensure_account_has_test_key, sign_tx_dict


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_fixture_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_weall_a02_lifecycle_fixture", FIXTURE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable_to_load_a02_lifecycle_fixture")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_semantic_manifest() -> dict[str, Any]:
    payload = json.loads(SEMANTIC_PATH.read_text(encoding="utf-8"))
    rows = payload.get("rows")
    if not isinstance(rows, list) or len(rows) != 236:
        raise RuntimeError("semantic_manifest_must_contain_exactly_236_rows")
    return payload


def _nonce(state: dict[str, Any], signer: str) -> int | None:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return None
    account = accounts.get(signer)
    if not isinstance(account, dict):
        return None
    try:
        return int(account.get("nonce") or 0)
    except Exception:
        return None


def _changed_top_level_keys(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    keys = set(before) | set(after)
    return sorted(key for key in keys if before.get(key) != after.get(key))


def _receipt(tx_id: str, env: TxEnvelope) -> dict[str, Any]:
    return {
        "tx_id": tx_id,
        "tx_type": str(env.tx_type or ""),
        "signer": str(env.signer or ""),
        "nonce": int(env.nonce or 0),
        "ok": True,
    }


def _stable_admission_envelope(env: TxEnvelope) -> dict[str, Any]:
    """Return admission semantics without randomized signature bytes."""

    payload = copy.deepcopy(env.to_json())
    payload.pop("sig", None)
    signature = payload.get("signature")
    if isinstance(signature, dict):
        signature = dict(signature)
        signature.pop("sig", None)
        if signature:
            payload["signature"] = signature
        else:
            payload.pop("signature", None)
    return payload


def _signature_evidence(env: TxEnvelope) -> dict[str, Any]:
    payload = env.to_json()
    signature = payload.get("signature") if isinstance(payload.get("signature"), dict) else {}
    sig_hex = str(payload.get("sig") or signature.get("sig") or "")
    return {
        "required": not bool(env.system),
        "admission_verified": True,
        "sig_profile": str(payload.get("sig_profile") or ""),
        "algorithm": str(signature.get("alg") or ""),
        "pubkey": str(payload.get("pubkey") or signature.get("pubkey") or ""),
        "signature_bytes": len(bytes.fromhex(sig_hex)) if sig_hex else 0,
        "signature_bytes_omitted_from_manifest": bool(sig_hex),
    }


def _admitted_envelope(
    fixture: ModuleType,
    state: dict[str, Any],
    row: dict[str, Any],
    env: TxEnvelope,
) -> tuple[TxEnvelope, str]:
    tx_type = str(row["tx_type"])
    context = str(row.get("context") or "mempool").strip().lower() or "mempool"
    fixture._seed_a02_admission_authority(state, tx_type, env.signer, env.payload)

    admitted = TxEnvelope.from_json(env.to_json())
    if not bool(admitted.system):
        ensure_account_has_test_key(
            state.setdefault("accounts", {}), account_id=admitted.signer
        )
        admitted = TxEnvelope.from_json(
            sign_tx_dict(admitted.to_json(), label=admitted.signer)
        )

    verdict = admit_tx(admitted, state, canon=load_default_tx_index(), context=context)
    if not verdict.ok:
        raise RuntimeError(
            f"lifecycle_admission_failed:{tx_type}:{context}:{verdict.code}:{verdict.reason}"
        )
    return admitted, context


def _build_row(
    fixture: ModuleType,
    semantic_row: dict[str, Any],
) -> dict[str, Any]:
    tx_type = str(semantic_row["tx_type"])

    apply_state = fixture._base_state()
    prepared = fixture._prepared_envelope(apply_state, semantic_row)

    admission_state = copy.deepcopy(apply_state)
    admitted, context = _admitted_envelope(
        fixture,
        admission_state,
        semantic_row,
        prepared,
    )

    before = copy.deepcopy(apply_state)
    before_root = compute_state_root(before)
    nonce_before = _nonce(before, prepared.signer)

    meta = apply_tx_atomic_meta_bounded_rollback(apply_state, prepared)

    after_root = compute_state_root(apply_state)
    nonce_after = _nonce(apply_state, prepared.signer)
    tx_id = compute_tx_id_from_envelope(str(prepared.chain_id or ""), admitted)
    state_writing = before_root != after_root

    failure_vector = copy.deepcopy(semantic_row.get("required_mutation") or {})
    if not failure_vector:
        raise RuntimeError(f"lifecycle_missing_failure_vector:{tx_type}")

    return {
        "tx_type": tx_type,
        "domain": str(semantic_row.get("domain") or ""),
        "origin": str(semantic_row.get("origin") or ""),
        "context": context,
        "receipt_only": bool(semantic_row.get("receipt_only", False)),
        "handler": handler_name_for_tx_type(tx_type),
        "successful_execution": {
            "envelope": prepared.to_json(),
            "admission_envelope": _stable_admission_envelope(admitted),
            "signature_evidence": _signature_evidence(admitted),
            "admission_expected": {
                "ok": True,
                "context": context,
            },
            "apply_expected": {
                "ok": True,
                "metadata": copy.deepcopy(meta),
            },
            "state_root_before": before_root,
            "state_root_after": after_root,
            "changed_top_level_keys": _changed_top_level_keys(before, apply_state),
            "state_writing": state_writing,
            "nonce": {
                "before": nonce_before,
                "after": nonce_after,
                "delta": (
                    None
                    if nonce_before is None or nonce_after is None
                    else nonce_after - nonce_before
                ),
            },
            "tx_id": tx_id,
            "success_receipt": _receipt(tx_id, admitted),
        },
        "failure_expectation": {
            "stage": "schema_validation",
            "vector": failure_vector,
            "rollback": "exact_pre_state_restoration",
            "evidence_test": "tests/test_a16_f006_all_tx_semantic_assurance.py",
        },
        "duplicate_replay_expectation": {
            "tx_id_scope": "global_one_shot",
            "pending_duplicate": "already_known_without_second_mempool_row",
            "committed_duplicate": "block_commit_duplicate_tx_id",
            "restart_replay": "rejected_after_confirmed_restart",
            "evidence_tests": [
                "tests/test_tx_replay_rejected_after_confirmed_restart.py",
                "tests/test_nonce_failure_block_progression.py",
            ],
        },
        "persistence_restart_expectation": {
            "required": state_writing,
            "assertion": (
                "sqlite_reopen_preserves_exact_state_root"
                if state_writing
                else "not_state_writing"
            ),
            "evidence_test": "tests/test_p2_a02_lifecycle_manifest.py",
        },
    }


def build_manifest() -> dict[str, Any]:
    fixture = load_fixture_module()
    semantic = load_semantic_manifest()
    rows = [_build_row(fixture, row) for row in semantic["rows"]]
    rows.sort(key=lambda row: str(row["tx_type"]))

    if len(rows) != 236 or len({row["tx_type"] for row in rows}) != 236:
        raise RuntimeError("lifecycle_manifest_requires_exactly_236_unique_types")

    return {
        "schema": "weall.tx_lifecycle_assurance.v1",
        "harness_environment": {
            "WEALL_MODE": "test",
            "WEALL_CRYPTO_MODE": "closed-testnet",
            "WEALL_API_BOOT_RUNTIME": "0",
        },
        "source_inputs": {
            "semantic_manifest_sha256": _sha256(SEMANTIC_PATH),
            "lifecycle_fixture_sha256": _sha256(FIXTURE_PATH),
        },
        "summary": {
            "tx_count": len(rows),
            "successful_apply_count": sum(
                1 for row in rows if row["successful_execution"]["apply_expected"]["ok"]
            ),
            "successful_admission_count": sum(
                1 for row in rows if row["successful_execution"]["admission_expected"]["ok"]
            ),
            "failure_stage_vector_count": sum(
                1 for row in rows if row["failure_expectation"]["vector"]
            ),
            "receipt_expectation_count": sum(
                1 for row in rows if row["successful_execution"]["success_receipt"]
            ),
            "duplicate_replay_expectation_count": sum(
                1 for row in rows if row["duplicate_replay_expectation"]
            ),
            "persistence_required_count": sum(
                1
                for row in rows
                if row["persistence_restart_expectation"]["required"]
            ),
        },
        "shared_contract_evidence": {
            "success_receipt_shape": "src/weall/runtime/block_builder.py",
            "global_duplicate_commit_guard": "src/weall/runtime/block_commit.py",
            "restart_replay_regression": "tests/test_tx_replay_rejected_after_confirmed_restart.py",
            "failure_rollback_matrix": "tests/test_a16_f006_all_tx_semantic_assurance.py",
        },
        "rows": rows,
    }


def render_manifest() -> str:
    return json.dumps(build_manifest(), indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    rendered = render_manifest()
    if args.check:
        if not OUTPUT_PATH.exists() or OUTPUT_PATH.read_text(encoding="utf-8") != rendered:
            print(f"stale_lifecycle_manifest:{OUTPUT_PATH}")
            return 1
        payload = json.loads(rendered)
        print(
            "OK: "
            f"{payload['summary']['tx_count']} transaction lifecycle vectors are current"
        )
        return 0

    OUTPUT_PATH.write_text(rendered, encoding="utf-8")
    print(f"wrote:{OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
