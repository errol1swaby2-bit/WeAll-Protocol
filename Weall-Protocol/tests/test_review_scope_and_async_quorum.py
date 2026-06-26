from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NESTED = ROOT / "Weall-Protocol"
WEB = ROOT / "web"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_dispute_detail_exposes_only_viewer_juror_scope() -> None:
    api = _read(NESTED / "src/weall/api/routes_public_parts/disputes.py")
    surface = _read(WEB / "src/lib/disputeSurface.ts")

    assert "require_account_session" in api
    assert "viewer_juror" in api
    assert "current_juror" in api
    assert "juror_self" in api
    assert "Keep the global juror map redacted" in api
    assert "_redact_dispute_detail_maps(obj, viewer=viewer)" in api

    assert "current_juror" in surface
    assert "viewer_juror" in surface
    assert "juror_self" in surface
    assert "selfScopedJurorRecord" in surface


def test_local_rehearsal_sets_one_reviewer_async_quorum() -> None:
    script = _read(NESTED / "scripts/devnet_local_two_frontend_rehearsal.sh")
    executor = _read(NESTED / "src/weall/runtime/executor.py")

    assert 'export WEALL_POH_ASYNC_N_JURORS="${WEALL_POH_ASYNC_N_JURORS:-1}"' in script
    assert 'export WEALL_POH_ASYNC_MIN_REVIEWS="${WEALL_POH_ASYNC_MIN_REVIEWS:-1}"' in script
    assert 'export WEALL_POH_ASYNC_APPROVAL_THRESHOLD="${WEALL_POH_ASYNC_APPROVAL_THRESHOLD:-1}"' in script
    assert 'export WEALL_POH_ASYNC_REJECTION_THRESHOLD="${WEALL_POH_ASYNC_REJECTION_THRESHOLD:-1}"' in script
    assert 'export WEALL_POH_ASYNC_MIN_REP_MILLI="${WEALL_POH_ASYNC_MIN_REP_MILLI:-0}"' in script

    assert '"async_n_jurors": "WEALL_POH_ASYNC_N_JURORS"' in executor
    assert '"async_min_reviews": "WEALL_POH_ASYNC_MIN_REVIEWS"' in executor
    assert '"async_approval_threshold": "WEALL_POH_ASYNC_APPROVAL_THRESHOLD"' in executor
    assert '"async_rejection_threshold": "WEALL_POH_ASYNC_REJECTION_THRESHOLD"' in executor
    assert '"async_min_rep_milli": "WEALL_POH_ASYNC_MIN_REP_MILLI"' in executor
