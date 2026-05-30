from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import load_tx_index_json


def _load_index():
    repo_root = Path(__file__).resolve().parents[1]
    return load_tx_index_json(repo_root / "generated" / "tx_index.json")


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system, parent=parent)


def _content_state() -> dict:
    return {
        "height": 0,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10},
            "bob": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation": 10},
        },
        "roles": {"validators": {"active_set": ["alice"]}},
        "system_queue": [],
        "content": {
            "posts": {
                "p1": {
                    "post_id": "p1",
                    "id": "p1",
                    "author": "alice",
                    "body": "flagged content",
                    "visibility": "public",
                    "deleted": False,
                    "locked": False,
                }
            },
            "comments": {},
            "reactions": {},
            "flags": {},
            "media": {},
            "media_bindings": {},
            "moderation": {"receipts": [], "targets": {}},
        },
    }


def test_content_author_cannot_be_assigned_or_vote_on_own_dispute_batch490() -> None:
    st = _content_state()
    apply_tx(st, _env("DISPUTE_OPEN", "bob", 1, {"dispute_id": "d1", "target_type": "content", "target_id": "p1"}))

    with pytest.raises(ApplyError) as assign_err:
        apply_tx(st, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 1, {"dispute_id": "d1", "juror": "alice"}, system=True, parent="tx:bob:1"))
    assert assign_err.value.code == "forbidden"
    assert assign_err.value.reason == "target_owner_cannot_review"

    st["disputes_by_id"]["d1"]["jurors"]["alice"] = {"status": "assigned"}
    st["disputes_by_id"]["d1"]["assigned_jurors"] = ["alice"]
    st["disputes_by_id"]["d1"]["eligible_juror_ids"] = ["alice"]

    with pytest.raises(ApplyError) as accept_err:
        apply_tx(st, _env("DISPUTE_JUROR_ACCEPT", "alice", 2, {"dispute_id": "d1"}))
    assert accept_err.value.code == "forbidden"
    assert accept_err.value.reason == "target_owner_cannot_review"

    with pytest.raises(ApplyError) as vote_err:
        apply_tx(st, _env("DISPUTE_VOTE_SUBMIT", "alice", 3, {"dispute_id": "d1", "vote": "yes"}))
    assert vote_err.value.code == "forbidden"
    assert vote_err.value.reason == "target_owner_cannot_review"


def test_content_flag_assigns_reporter_when_bootstrap_reviewer_is_target_owner_batch490() -> None:
    idx = _load_index()
    st = _content_state()

    apply_tx(st, _env("CONTENT_FLAG", "bob", 1, {"target_type": "content", "target_id": "p1", "reason": "policy"}))

    post_h1 = system_tx_emitter(st, canon=idx, next_height=1, phase="post")
    assert "CONTENT_ESCALATE_TO_DISPUTE" in [env.tx_type for env in post_h1]
    for env in post_h1:
        apply_tx(st, env)

    disputes = st["disputes_by_id"]
    dispute = next(iter(disputes.values()))

    assert dispute["target_owner"] == "alice"
    assert dispute["flagged_by"] == "bob"
    assert dispute["eligible_juror_ids"] == ["bob"]
    assert dispute["assigned_jurors"] == ["bob"]
    assert "bob" in dispute["jurors"]
    assert "alice" not in dispute["jurors"]

    apply_tx(st, _env("DISPUTE_JUROR_ACCEPT", "bob", 2, {"dispute_id": dispute["id"]}))
    apply_tx(st, _env("DISPUTE_VOTE_SUBMIT", "bob", 3, {"dispute_id": dispute["id"], "vote": "yes"}))

    assert dispute["resolved"] is True
    assert st["content"]["posts"]["p1"]["deleted"] is True


def test_run_node_exports_repo_src_pythonpath_batch490() -> None:
    script = Path("scripts/run_node.sh").read_text(encoding="utf-8")

    assert 'REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"' in script
    assert 'export PYTHONPATH="${REPO_ROOT}/src:${PYTHONPATH}"' in script
    assert 'export PYTHONPATH="${REPO_ROOT}/src"' in script
    assert "gunicorn weall.api.app:app" in script


def test_two_machine_rehearsal_help_is_available_batch490() -> None:
    result = subprocess.run(
        ["bash", "scripts/rehearse_external_observer_two_machine.sh", "--help"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0
    assert "Usage: scripts/rehearse_external_observer_two_machine.sh" in result.stdout
    assert "Truth boundary" in result.stdout
