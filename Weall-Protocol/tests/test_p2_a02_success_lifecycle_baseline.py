from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from weall.runtime.domain_apply import apply_tx_atomic_meta_bounded_rollback
from weall.runtime.tx_admission_types import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "generated" / "tx_semantic_assurance_v1_5.json"


def _base_state() -> dict[str, Any]:
    return {
        "height": 10,
        "time": 1_000_000,
        "chain_id": "weall-testnet-v1",
        "network_id": "weall-testnet-v1",
        "params": {
            "chain_id": "weall-testnet-v1",
            "economics_enabled": False,
            "genesis_time": 0,
            "economic_unlock_time": 9_999_999_999,
        },
        "accounts": {
            "@tester": {
                "nonce": 0,
                "balance": 1_000_000,
                "poh_tier": 2,
                "reputation": "10.000",
                "reputation_milli": 10_000,
                "banned": False,
                "locked": False,
            },
            "@target": {
                "nonce": 0,
                "balance": 0,
                "poh_tier": 2,
                "reputation": "10.000",
                "reputation_milli": 10_000,
                "banned": False,
                "locked": False,
            },
            "@juror1": {
                "nonce": 0,
                "balance": 0,
                "poh_tier": 2,
                "reputation": "10.000",
                "reputation_milli": 10_000,
                "banned": False,
                "locked": False,
            },
            "@validator1": {
                "nonce": 0,
                "balance": 0,
                "poh_tier": 2,
                "reputation": "10.000",
                "reputation_milli": 10_000,
                "banned": False,
                "locked": False,
            },
        },
        "roles": {},
        "social": {},
        "content": {},
        "groups": {},
        "notifications": {},
        "storage": {},
        "networking": {},
        "economics": {},
        "rewards": {},
        "treasury": {},
        "governance": {},
        "disputes": {},
        "protocol": {},
        "consensus": {},
    }


def _envelope(row: dict[str, Any]) -> TxEnvelope:
    system = str(row.get("origin") or "").upper() == "SYSTEM"
    block_only = str(row.get("context") or "").lower() == "block"
    receipt_only = bool(row.get("receipt_only"))
    return TxEnvelope(
        tx_type=str(row["tx_type"]),
        signer="SYSTEM" if system else "@tester",
        nonce=1,
        payload=copy.deepcopy(row["baseline_payload"]),
        parent="PARENT-A02" if block_only or receipt_only else None,
        system=system,
        chain_id="weall-testnet-v1",
    )


def test_a02_f003_all_canon_baselines_have_successful_apply_fixture() -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = payload["rows"]
    assert len(rows) == 236

    failures: list[tuple[str, str, str]] = []
    successes: list[str] = []

    for row in rows:
        tx_type = str(row["tx_type"])
        state = _base_state()
        try:
            apply_tx_atomic_meta_bounded_rollback(state, _envelope(row))
        except Exception as exc:  # domain error families intentionally vary.
            failures.append(
                (
                    tx_type,
                    str(getattr(exc, "code", "") or type(exc).__name__),
                    str(getattr(exc, "reason", "") or str(exc)),
                )
            )
        else:
            successes.append(tx_type)

    if failures:
        detail = "\n".join(f"{tx_type}\t{code}\t{reason}" for tx_type, code, reason in failures)
        raise AssertionError(
            f"A02-F003 successful-baseline gap: "
            f"success_count={len(successes)} failure_count={len(failures)}\n{detail}"
        )
