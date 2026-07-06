from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.state_hash import compute_state_root

ROOT = Path(__file__).resolve().parents[1]
Json = dict[str, Any]


def _env(
    tx_type: str,
    payload: Json | None = None,
    *,
    signer: str = "alice",
    nonce: int = 1,
    system: bool = False,
    parent: str | None = None,
) -> Json:
    out: Json = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "sig": "",
        "payload": payload or {},
        "system": bool(system),
    }
    if parent is not None:
        out["parent"] = parent
    return out


def _load_json(path: str) -> Json:
    with (ROOT / path).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_m1_to_m10_mechanics_register_is_complete_and_truth_bounded() -> None:
    data = _load_json("generated/v15_mechanics_gap_register.json")
    assert data["schema"] == "weall.v1_5.mechanics_gap_register"
    assert data["truth_boundaries"] == {
        "automatic_protocol_upgrade_apply_enabled": False,
        "live_economics_enabled": False,
        "production_helper_execution_claimed": False,
        "public_validators_enabled": False,
    }
    mechanics = data["mechanics"]
    assert [m["id"] for m in mechanics] == [f"M-{i:02d}" for i in range(1, 11)]
    by_id = {m["id"]: m for m in mechanics}
    assert "public_multi_validator_bft" in by_id["M-01"].get("locked_features", [])
    assert "live_economics" in by_id["M-08"].get("locked_features", [])
    assert by_id["M-10"]["status"] == "locked_or_serial_only_until_proven"


def test_m03_slash_execute_records_non_economic_validator_accountability() -> None:
    state: Json = {
        "state_version": 1,
        "validators": {
            "registry": {
                "alice": {"status": "active", "active": True, "pubkey": "mldsa:alice"}
            }
        },
        "roles": {"validators": {"active_set": ["alice"]}},
    }

    out = apply_tx(
        state,
        _env(
            "SLASH_EXECUTE",
            {"slash_id": "slash-alice-1", "account": "alice", "reason": "equivocation"},
            signer="SYSTEM",
            nonce=1,
            system=True,
            parent="consensus:slash:proposal:1",
        ),
    )

    assert out["applied"] == "SLASH_EXECUTE"
    assert out["consequence"]["economic_penalty_applied"] is False
    rec = state["validators"]["registry"]["alice"]
    assert rec["accountability_status"] == "slashed_non_economic"
    slash = rec["accountability"]["slashes"]["slash-alice-1"]
    assert slash["economic_penalty_applied"] is False
    assert slash["validator_set_mutation_applied"] is False
    assert slash["requires_explicit_validator_suspend_or_remove"] is True
    assert state["roles"]["validators"]["active_set"] == ["alice"]


def test_m05_upheld_poh_challenge_revokes_poh_status() -> None:
    state: Json = {
        "state_version": 1,
        "height": 42,
        "accounts": {"bob": {"nonce": 0, "poh_tier": 2, "poh_status": "active"}},
        "poh": {
            "account_status": {
                "bob": {
                    "account_id": "bob",
                    "poh_tier": 2,
                    "status": "active",
                    "verified_at_height": 10,
                    "expires_at_height": 0,
                }
            }
        },
    }

    opened = apply_tx(
        state,
        _env("POH_CHALLENGE_OPEN", {"account_id": "bob", "reason": "duplicate-human"}, signer="alice", nonce=1),
    )
    challenge_id = opened["challenge_id"]

    resolved = apply_tx(
        state,
        _env(
            "POH_CHALLENGE_RESOLVE",
            {"challenge_id": challenge_id, "resolution": "upheld", "note": "review complete"},
            signer="SYSTEM",
            nonce=2,
            system=True,
            parent="dispute:resolve:1",
        ),
    )

    assert resolved["resolution"] == "upheld"
    assert resolved["consequence"]["applied"] is True
    assert resolved["consequence"]["type"] == "poh_status_revoked"
    assert state["accounts"]["bob"]["poh_tier"] == 0
    assert state["accounts"]["bob"]["poh_status"] == "revoked"
    assert state["poh"]["account_status"]["bob"]["revocation_reason"] == "challenge_upheld"
    assert state["poh"]["challenges"][challenge_id]["consequence"]["type"] == "poh_status_revoked"


def test_m05_dismissed_poh_challenge_does_not_revoke() -> None:
    state: Json = {
        "state_version": 1,
        "accounts": {"bob": {"nonce": 0, "poh_tier": 2, "poh_status": "active"}},
    }
    opened = apply_tx(
        state,
        _env("POH_CHALLENGE_OPEN", {"account_id": "bob", "reason": "mistake"}, signer="alice", nonce=1),
    )
    resolved = apply_tx(
        state,
        _env(
            "POH_CHALLENGE_RESOLVE",
            {"challenge_id": opened["challenge_id"], "resolution": "dismissed"},
            signer="SYSTEM",
            nonce=2,
            system=True,
            parent="dispute:resolve:2",
        ),
    )
    assert resolved["consequence"] == {"type": "none", "applied": False}
    assert state["accounts"]["bob"]["poh_tier"] == 2
    assert state["accounts"]["bob"]["poh_status"] == "active"


def test_m08_tokenomics_simulation_artifact_keeps_economics_locked_boundary() -> None:
    data = _load_json("generated/tokenomics_simulation_v1_5.json")
    assert data["schema"] == "weall.v1_5.tokenomics_simulation"
    assert data["truth_boundaries"] == {
        "balance_transfer_enabled": False,
        "live_economics_enabled": False,
        "reward_issuance_enabled": False,
        "treasury_spend_enabled": False,
    }
    assert data["constants"]["issuance_epoch_blocks"] == 30
    assert data["sample_epochs"][0]["due_height"] == 30
    assert data["cap_sample"]["remaining_after_atomic"] == 0


def test_m10_state_root_vectors_encode_canonicalization_contract() -> None:
    data = _load_json("generated/state_root_vectors_v1_5.json")
    assert data["schema"] == "weall.v1_5.state_root_vectors"
    vectors = {v["name"]: v for v in data["vectors"]}
    assert vectors["base"]["state_root"] == vectors["reordered_dicts_same_semantics"]["state_root"]
    assert vectors["base"]["state_root"] == vectors["with_ephemeral_fields_same_semantics"]["state_root"]
    assert vectors["list_order_reference"]["state_root"] != vectors["list_order_changed"]["state_root"]
    assert compute_state_root({"a": 1, "meta": {"local": True}}) == compute_state_root({"a": 1})


def test_m1_to_m10_generators_are_fresh() -> None:
    commands = [
        [sys.executable, "scripts/gen_mechanics_gap_register_v1_5.py", "--check"],
        [sys.executable, "scripts/gen_state_root_vectors_v1_5.py", "--check"],
        [sys.executable, "scripts/gen_tokenomics_simulation_v1_5.py", "--check"],
    ]
    for cmd in commands:
        subprocess.run(cmd, cwd=ROOT, check=True)
