from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from weall.api.routes_public_parts.poh import _as_live_session
from weall.runtime.apply.poh import poh_bootstrap_policy_summary
from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]
OUTER_ROOT = ROOT.parent


def _env(tx_type: str, payload: dict, signer: str = "alice", nonce: int = 1, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    if system and not parent:
        parent = "parent"
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="sig", parent=parent, system=system)


def _run_authority_gate(extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "WEALL_MODE": "prod",
        "WEALL_CHAIN_MANIFEST_PATH": str(ROOT / "configs" / "chains" / "weall-genesis.json"),
        "WEALL_OBSERVER_MODE": "1",
        "WEALL_VALIDATOR_SIGNING_ENABLED": "0",
        "WEALL_BFT_ENABLED": "0",
        "WEALL_HELPER_MODE_ENABLED": "0",
        "WEALL_BLOCK_LOOP_AUTOSTART": "0",
        "WEALL_SERVICE_ROLES": "",
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", "scripts/external_observer_authority_lock_gate.sh"],
        cwd=str(ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def test_batch437_authority_lock_gate_passes_minimal_observer_posture() -> None:
    result = _run_authority_gate()
    assert result.returncode == 0, result.stdout
    assert "external observer authority lock gate passed" in result.stdout
    assert "validator signing, BFT, helper mode, and block-loop autostart are forced off" in result.stdout


@pytest.mark.parametrize(
    "key,value,expected",
    [
        ("WEALL_VALIDATOR_SIGNING_ENABLED", "1", "refuses WEALL_VALIDATOR_SIGNING_ENABLED=1"),
        ("WEALL_BFT_ENABLED", "1", "refuses WEALL_BFT_ENABLED=1"),
        ("WEALL_HELPER_MODE_ENABLED", "1", "refuses WEALL_HELPER_MODE_ENABLED=1"),
        ("WEALL_BLOCK_LOOP_AUTOSTART", "1", "refuses WEALL_BLOCK_LOOP_AUTOSTART=1"),
        ("WEALL_SERVICE_ROLES", "validator", "refuses service authority roles"),
        ("WEALL_VALIDATOR_ACCOUNT", "@observer", "refuses WEALL_VALIDATOR_ACCOUNT"),
    ],
)
def test_batch437_authority_lock_gate_refuses_observer_authority_leaks(key: str, value: str, expected: str) -> None:
    result = _run_authority_gate({key: value})
    assert result.returncode != 0
    assert expected in result.stdout


def _live_state() -> dict:
    accounts = {"alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False}}
    for jid in ("j1", "j2", "j3", "j4", "j5"):
        accounts[jid] = {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 5000}
    return {"chain_id": "test", "height": 1, "accounts": accounts, "params": {"poh": {"live_min_rep_milli": 0}}}


def test_batch441_live_session_init_never_stores_raw_join_url() -> None:
    st = _live_state()
    created = apply_tx(
        st,
        _env(
            "POH_LIVE_REQUEST_OPEN",
            {"account_id": "alice", "session_commitment": "sc:join", "room_commitment": "room:commit", "prompt_commitment": "prompt:commit"},
            signer="alice",
            nonce=1,
        ),
    )
    case_id = str(created["case_id"])
    apply_tx(
        st,
        _env(
            "POH_LIVE_SESSION_INIT",
            {"case_id": case_id, "account_id": "alice", "session_commitment": "sc:join", "join_url": "https://relay.example/private-room"},
            signer="SYSTEM",
            nonce=2,
            system=True,
            parent="POH_LIVE_REQUEST_OPEN",
        ),
    )
    case = st["poh"]["live_cases"][case_id]
    session = st["poh"]["live_sessions"][f"session:{case_id}"]
    assert "join_url" not in case
    assert "join_url" not in session
    assert case["relay_commitment"]
    assert session["relay_commitment"] == case["relay_commitment"]


def test_batch441_live_session_serializer_redacts_legacy_join_url() -> None:
    model = _as_live_session(
        "session:poh_live:alice:1",
        {
            "case_id": "poh_live:alice:1",
            "status": "open",
            "session_commitment": "sc:legacy",
            "join_url": "https://legacy.example/should-never-leak",
        },
    )
    assert model.join_url is None
    assert model.session_commitment == "sc:legacy"


def test_batch440_poh_bootstrap_policy_summary_exposes_mode_bounds_and_auto_lock() -> None:
    st = {
        "height": 4,
        "params": {"poh_bootstrap_mode": "open", "poh_bootstrap_open": True, "poh_bootstrap_max_height": 5, "poh": {"live_poh_policy_mode": "production"}},
        "roles": {"validators": {"active_set": []}},
    }
    summary = poh_bootstrap_policy_summary(st)
    assert summary["mode"] == "open"
    assert summary["open_max_height"] == 5
    assert summary["open_expired"] is False
    assert summary["production_live_quorum_required"] is True

    st["height"] = 6
    summary = poh_bootstrap_policy_summary(st)
    assert summary["open_expired"] is True

    st["roles"] = {"validators": {"active_set": ["v1", "v2", "v3", "v4"]}}
    summary = poh_bootstrap_policy_summary(st)
    assert summary["auto_locked_by_validator_quorum"] is True


def test_batch440_open_bootstrap_without_max_height_still_fails_apply_time() -> None:
    st = {
        "height": 1,
        "accounts": {"alice": {"nonce": 0, "poh_tier": 0, "pubkey": "pk1", "banned": False, "locked": False}},
        "params": {"poh_bootstrap_mode": "open", "poh_bootstrap_open": True},
    }
    with pytest.raises(ApplyError) as exc:
        apply_tx(st, _env("POH_BOOTSTRAP_TIER2_GRANT", {"account_id": "alice", "pubkey": "pk1"}, signer="alice", nonce=1))
    assert exc.value.reason == "bootstrap_open_requires_max_height"


def test_batch438_node_manager_uses_manifest_or_build_baseline_before_current_node_fallback() -> None:
    src = (OUTER_ROOT / "web" / "src" / "lib" / "nodeConnectionManager.ts").read_text(encoding="utf-8")
    assert "buildConfiguredCompatibilityBaseline" in src
    assert "baselineFromPayload" in src
    assert "loadExpectedCompatibilityBaseline" in src
    assert "source: \"build\"" in src
    assert "source: \"seed-manifest\"" in src
    assert "source: \"current-node\"" in src
    assert "publicTestnetBaselineErrors" in src
    assert "public_testnet_config_missing:pinned_commitments_required" in src
    assert "const explicitBaseline = await loadExpectedCompatibilityBaseline();" in src
    assert "explicitBaseline === null && !config.publicTestnet ? undefined : explicitBaseline" in src
    assert "explicitBaseline === null ? undefined : explicitBaseline" not in src
    assert src.index("const explicitBaseline = await loadExpectedCompatibilityBaseline();") < src.index("const rawProbes = await Promise.all")
    assert src.index("const rawProbes = await Promise.all") < src.index("applyCompatibilityBaseline(rawProbes")


def test_batch442_status_surface_exposes_constitution_and_limited_testnet_posture() -> None:
    src = (ROOT / "src" / "weall" / "api" / "routes_public_parts" / "status.py").read_text(encoding="utf-8")
    assert "active_constitution_commitment" in src
    assert "testnet_readiness" in src
    assert "poh_bootstrap_policy_summary" in src
    assert "full_public_governance_ready" in src
    assert "full_public_moderation_ready" in src
    assert "economics" in src and "locked" in src


def test_batch443_no_prod_api_path_imports_stale_ledger_gate_resolver() -> None:
    api_root = ROOT / "src" / "weall" / "api"
    runtime_root = ROOT / "src" / "weall" / "runtime"
    offenders: list[str] = []
    for base in (api_root, runtime_root):
        for path in base.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if "ledger.gate_resolver" in text or "from weall.ledger.gate_resolver" in text:
                offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []
