from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NESTED = ROOT / "Weall-Protocol"
WEB = ROOT / "web"


def test_profile_posting_uses_shared_onboarding_thresholds_batch495() -> None:
    src = (WEB / "src" / "pages" / "Account.tsx").read_text(encoding="utf-8")

    assert 'POSTING_MIN_REPUTATION' in src
    assert 'POSTING_MIN_TIER' in src
    assert 'reputation >= 0.75' not in src
    assert 'tier >= POSTING_MIN_TIER' in src
    assert 'reputation >= POSTING_MIN_REPUTATION' in src


def test_observer_readthrough_sync_helper_is_gated_batch495() -> None:
    src = (NESTED / "src" / "weall" / "api" / "routes_public_parts" / "observer_sync.py").read_text(encoding="utf-8")

    assert 'WEALL_OBSERVER_READ_THROUGH_SYNC' in src
    assert 'WEALL_OBSERVER_EDGE_MODE' in src
    assert 'WEALL_TX_UPSTREAM_URLS' in src
    assert 'apply_state_sync_response' in src
    assert 'allow_snapshot_bootstrap=False' in src


def test_account_and_content_reads_attempt_observer_catchup_batch495() -> None:
    accounts = (NESTED / "src" / "weall" / "api" / "routes_public_parts" / "accounts.py").read_text(encoding="utf-8")
    content = (NESTED / "src" / "weall" / "api" / "routes_public_parts" / "content.py").read_text(encoding="utf-8")

    assert 'sync_observer_from_upstream_if_enabled(request, reason="account_get")' in accounts
    assert 'sync_observer_from_upstream_if_enabled(request, reason="account_registered")' in accounts
    assert 'sync_observer_from_upstream_if_enabled(request, reason="account_feed")' in accounts
    assert 'sync_observer_from_upstream_if_enabled(request, reason="public_feed")' in content
    assert 'sync_observer_from_upstream_if_enabled(request, reason="content_get")' in content


def test_local_rehearsal_enables_observer_readthrough_and_sync_on_submit_batch495() -> None:
    src = (NESTED / "scripts" / "devnet_local_two_frontend_rehearsal.sh").read_text(encoding="utf-8")

    assert 'export WEALL_TX_UPSTREAM_SYNC_ON_SUBMIT=1' in src
    assert 'export WEALL_OBSERVER_READ_THROUGH_SYNC=1' in src
    assert 'WEALL_LOCAL_REHEARSAL_DOWNSTREAM_SYNC_MAX_ROUNDS:-8' in src
