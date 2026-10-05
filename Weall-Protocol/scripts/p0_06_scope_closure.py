#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(os.environ["WEALL_REPO_ROOT"]).resolve()
PROTO = ROOT / "Weall-Protocol"


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"replace_once_failed:{rel}:count={count}:needle={old[:120]!r}")
    write(rel, text.replace(old, new, 1))


# 1) Consensus-visible human-authority scope mode.  This is intentionally a
# scope closure, not a claim that human uniqueness or unbiased threshold
# randomness has been invented.
state_rel = "Weall-Protocol/src/weall/runtime/poh/state.py"
replace_once(
    state_rel,
    "MAX_USER_FACING_POH_TIER = 2\n",
    "MAX_USER_FACING_POH_TIER = 2\n\n"
    "POH_HUMAN_AUTHORITY_MODE_COMPATIBILITY = \"compatibility\"\n"
    "POH_HUMAN_AUTHORITY_MODE_SCOPE_CLOSED = \"scope_closed_pending_uniqueness_entropy\"\n\n\n"
    "def poh_human_authority_mode(state: Json) -> str:\n"
    "    \"\"\"Return the chain-committed new-human-authority mode.\n\n"
    "    Historical/dev chains default to compatibility.  The canonical production\n"
    "    genesis explicitly commits the scope-closed mode until a separately reviewed\n"
    "    global uniqueness authority and post-commit unpredictable reviewer entropy\n"
    "    protocol are implemented.\n"
    "    \"\"\"\n\n"
    "    params = state.get(\"params\") if isinstance(state, dict) else None\n"
    "    params = params if isinstance(params, dict) else {}\n"
    "    poh = params.get(\"poh\") if isinstance(params.get(\"poh\"), dict) else {}\n"
    "    mode = _as_str(poh.get(\"human_authority_mode\") or \"\").lower()\n"
    "    if mode == POH_HUMAN_AUTHORITY_MODE_SCOPE_CLOSED:\n"
    "        return POH_HUMAN_AUTHORITY_MODE_SCOPE_CLOSED\n"
    "    return POH_HUMAN_AUTHORITY_MODE_COMPATIBILITY\n\n\n"
    "def poh_human_authority_scope_closed(state: Json) -> bool:\n"
    "    return poh_human_authority_mode(state) == POH_HUMAN_AUTHORITY_MODE_SCOPE_CLOSED\n",
)

# 2) Canonical apply boundary.  Challenge/revocation and evidence-deletion
# attestations remain available.  All positive authority creation/advancement
# paths fail before case/reviewer state can be mutated.
poh_rel = "Weall-Protocol/src/weall/runtime/apply/poh.py"
replace_once(
    poh_rel,
    "    POH_STATUS_ACTIVE,\n    TIER2_VALIDITY_BLOCKS,\n    require_valid_poh_tier,\n",
    "    POH_STATUS_ACTIVE,\n    TIER2_VALIDITY_BLOCKS,\n    poh_human_authority_mode,\n    poh_human_authority_scope_closed,\n    require_valid_poh_tier,\n",
)
replace_once(
    poh_rel,
    "Json = dict[str, Any]\n\n_COMMITMENT_RE = re.compile(\n",
    "Json = dict[str, Any]\n\n"
    "_P0_06_SCOPE_CLOSED_AUTHORITY_TX_TYPES: frozenset[str] = frozenset(\n"
    "    {\n"
    "        \"POH_APPLICATION_SUBMIT\",\n"
    "        \"POH_ASYNC_REQUEST_OPEN\",\n"
    "        \"POH_ASYNC_EVIDENCE_DECLARE\",\n"
    "        \"POH_ASYNC_EVIDENCE_BIND\",\n"
    "        \"POH_ASYNC_JUROR_ASSIGN\",\n"
    "        \"POH_ASYNC_JUROR_ACCEPT\",\n"
    "        \"POH_ASYNC_JUROR_DECLINE\",\n"
    "        \"POH_ASYNC_REVIEW_SUBMIT\",\n"
    "        \"POH_ASYNC_FINALIZE\",\n"
    "        \"POH_ASYNC_RECEIPT\",\n"
    "        \"POH_TIER_SET\",\n"
    "        \"POH_BOOTSTRAP_TIER2_GRANT\",\n"
    "        \"POH_TIER2_REQUEST_OPEN\",\n"
    "        \"POH_TIER2_JUROR_ASSIGN\",\n"
    "        \"POH_TIER2_JUROR_ACCEPT\",\n"
    "        \"POH_TIER2_JUROR_DECLINE\",\n"
    "        \"POH_TIER2_REVIEW_SUBMIT\",\n"
    "        \"POH_TIER2_FINALIZE\",\n"
    "        \"POH_TIER2_RECEIPT\",\n"
    "        \"POH_LIVE_REQUEST_OPEN\",\n"
    "        \"POH_LIVE_SESSION_INIT\",\n"
    "        \"POH_LIVE_JUROR_ASSIGN\",\n"
    "        \"POH_LIVE_JUROR_ACCEPT\",\n"
    "        \"POH_LIVE_JUROR_DECLINE\",\n"
    "        \"POH_LIVE_JUROR_REPLACE\",\n"
    "        \"POH_LIVE_ATTENDANCE_MARK\",\n"
    "        \"POH_LIVE_VERDICT_SUBMIT\",\n"
    "        \"POH_LIVE_FINALIZE\",\n"
    "        \"POH_LIVE_RECEIPT\",\n"
    "    }\n"
    ")\n\n"
    "_COMMITMENT_RE = re.compile(\n",
)
replace_once(
    poh_rel,
    "    acct = _require_registered_account(state, account_id)\n    duplicate_identity = _active_duplicate_identity_record(state, account_id)\n",
    "    if poh_human_authority_scope_closed(state):\n"
    "        raise ApplyError(\n"
    "            \"forbidden\",\n"
    "            \"poh_human_authority_scope_closed\",\n"
    "            {\"account_id\": account_id, \"mode\": poh_human_authority_mode(state)},\n"
    "        )\n"
    "    acct = _require_registered_account(state, account_id)\n"
    "    duplicate_identity = _active_duplicate_identity_record(state, account_id)\n",
)
replace_once(
    poh_rel,
    "def apply_poh(state: Json, env: Any) -> Json | None:\n    t = _tx_type(env)\n\n",
    "def apply_poh(state: Json, env: Any) -> Json | None:\n"
    "    t = _tx_type(env)\n\n"
    "    if poh_human_authority_scope_closed(state) and t in _P0_06_SCOPE_CLOSED_AUTHORITY_TX_TYPES:\n"
    "        raise ApplyError(\n"
    "            \"forbidden\",\n"
    "            \"poh_human_authority_scope_closed\",\n"
    "            {\"tx_type\": t, \"mode\": poh_human_authority_mode(state)},\n"
    "        )\n\n",
)

# 3) Every PoH authority scheduler independently refuses to assign/finalize in
# scope-closed production state.  The check occurs before helper accessors that
# can materialize missing state containers.
for rel, import_anchor, body_anchor in (
    (
        "Weall-Protocol/src/weall/runtime/poh/async_scheduler.py",
        "from weall.runtime.reputation_units import threshold_to_units\n",
        "    enq = 0\n    cases = _async_cases(state)\n",
    ),
    (
        "Weall-Protocol/src/weall/runtime/poh/tier2_scheduler.py",
        "from weall.runtime.reputation_units import threshold_to_units\n",
        "    enq = 0\n\n    n_jurors = max(1, _param_int(state, \"tier2_n_jurors\", DEFAULT_TIER2_N_JURORS))\n",
    ),
    (
        "Weall-Protocol/src/weall/runtime/poh/live_scheduler.py",
        "from weall.runtime.reputation_units import threshold_to_units\n",
        "    enq = 0\n    cases = _live_cases(state)\n",
    ),
):
    replace_once(
        rel,
        import_anchor,
        import_anchor + "from weall.runtime.poh.state import poh_human_authority_scope_closed\n",
    )
    if "tier2_scheduler.py" in rel:
        replacement = (
            "    if poh_human_authority_scope_closed(state):\n"
            "        return 0\n\n"
            "    enq = 0\n\n"
            "    n_jurors = max(1, _param_int(state, \"tier2_n_jurors\", DEFAULT_TIER2_N_JURORS))\n"
        )
    elif "async_scheduler.py" in rel:
        replacement = (
            "    if poh_human_authority_scope_closed(state):\n"
            "        return 0\n\n"
            "    enq = 0\n"
            "    cases = _async_cases(state)\n"
        )
    else:
        replacement = (
            "    if poh_human_authority_scope_closed(state):\n"
            "        return 0\n\n"
            "    enq = 0\n"
            "    cases = _live_cases(state)\n"
        )
    replace_once(rel, body_anchor, replacement)

# 4) Canonical production genesis explicitly commits the scope closure.  This
# keeps dev/test compatibility intact while preventing the checked production
# chain from silently treating PoH account review as a uniqueness authority.
gen_rel = "Weall-Protocol/scripts/build_production_genesis_manifest.py"
replace_once(
    gen_rel,
    "            \"poh\": {\n                \"live_partial_panels_enabled\": True,\n",
    "            \"poh\": {\n"
    "                \"human_authority_mode\": \"scope_closed_pending_uniqueness_entropy\",\n"
    "                \"live_partial_panels_enabled\": True,\n",
)

# 5) Focused regression matrix.
test_rel = "Weall-Protocol/tests/test_p0_06_production_scope_closure.py"
write(
    test_rel,
    '''from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.runtime.apply.poh import _grant_active_poh_tier, apply_poh
from weall.runtime.errors import ApplyError
from weall.runtime.poh.async_scheduler import schedule_poh_async_system_txs
from weall.runtime.poh.live_scheduler import schedule_poh_live_system_txs
from weall.runtime.poh.state import (
    POH_HUMAN_AUTHORITY_MODE_SCOPE_CLOSED,
    poh_human_authority_mode,
    poh_human_authority_scope_closed,
)
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs

ROOT = Path(__file__).resolve().parents[1]


def _env(tx_type: str, *, signer: str = "subject", system: bool = False) -> dict[str, object]:
    return {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": 1,
        "sig": "",
        "system": system,
        "payload": {},
    }


def _state(*, closed: bool = True) -> dict[str, object]:
    poh_params: dict[str, object] = {}
    if closed:
        poh_params["human_authority_mode"] = POH_HUMAN_AUTHORITY_MODE_SCOPE_CLOSED
    return {
        "chain_id": "weall-prod" if closed else "dev-chain",
        "height": 100,
        "tip": "tip",
        "params": {"poh": poh_params},
        "accounts": {
            "subject": {"nonce": 0, "poh_tier": 0, "poh_status": "expired"},
            "primary": {"nonce": 0, "poh_tier": 2, "poh_status": "active"},
            "challenger": {"nonce": 0, "poh_tier": 2, "poh_status": "active"},
            "reviewer": {"nonce": 0, "poh_tier": 2, "poh_status": "active"},
        },
        "poh": {
            "account_status": {
                "primary": {"account_id": "primary", "poh_tier": 2, "status": "active"},
                "challenger": {"account_id": "challenger", "poh_tier": 2, "status": "active"},
                "reviewer": {"account_id": "reviewer", "poh_tier": 2, "status": "active"},
            },
            "async_cases": {"a": {"case_id": "a", "account_id": "subject", "status": "open", "evidence_binds": {"e": {"followup_round": 0}}}},
            "tier2_cases": {"t": {"case_id": "t", "account_id": "subject", "status": "open"}},
            "live_cases": {"l": {"case_id": "l", "account_id": "subject", "status": "requested", "session_commitment": "a" * 64, "room_commitment": "b" * 64, "prompt_commitment": "c" * 64}},
        },
        "system_tx_queue": [],
    }


@pytest.mark.parametrize(
    "tx_type",
    [
        "POH_APPLICATION_SUBMIT",
        "POH_ASYNC_REQUEST_OPEN",
        "POH_ASYNC_JUROR_ASSIGN",
        "POH_ASYNC_FINALIZE",
        "POH_TIER_SET",
        "POH_BOOTSTRAP_TIER2_GRANT",
        "POH_TIER2_REQUEST_OPEN",
        "POH_TIER2_JUROR_ASSIGN",
        "POH_TIER2_FINALIZE",
        "POH_LIVE_REQUEST_OPEN",
        "POH_LIVE_JUROR_ASSIGN",
        "POH_LIVE_FINALIZE",
    ],
)
def test_scope_closed_apply_boundary_rejects_positive_human_authority(tx_type: str) -> None:
    state = _state()
    with pytest.raises(ApplyError) as excinfo:
        apply_poh(state, _env(tx_type, signer="SYSTEM" if "ASSIGN" in tx_type or "FINALIZE" in tx_type or tx_type in {"POH_TIER_SET", "POH_BOOTSTRAP_TIER2_GRANT"} else "subject", system=("ASSIGN" in tx_type or "FINALIZE" in tx_type or tx_type in {"POH_TIER_SET", "POH_BOOTSTRAP_TIER2_GRANT"})))
    assert excinfo.value.reason == "poh_human_authority_scope_closed"


def test_scope_closed_direct_award_helper_fails_closed() -> None:
    state = _state()
    with pytest.raises(ApplyError) as excinfo:
        _grant_active_poh_tier(state, account_id="subject", tier=2)
    assert excinfo.value.reason == "poh_human_authority_scope_closed"
    assert state["accounts"]["subject"]["poh_tier"] == 0


def test_scope_closed_schedulers_do_not_select_or_enqueue_reviewers() -> None:
    state = _state()
    before = list(state["system_tx_queue"])
    assert schedule_poh_async_system_txs(state, next_height=101) == 0
    assert schedule_poh_tier2_system_txs(state, next_height=101) == 0
    assert schedule_poh_live_system_txs(state, next_height=101) == 0
    assert state["system_tx_queue"] == before


def test_duplicate_challenge_remains_available_for_existing_authority() -> None:
    state = _state()
    env = _env("POH_CHALLENGE_OPEN", signer="challenger")
    env["payload"] = {
        "account_id": "primary",
        "reference_account_id": "reviewer",
        "reason": "duplicate-human-suspected",
    }
    out = apply_poh(state, env)
    assert out and out["applied"] == "POH_CHALLENGE_OPEN"


def test_nonproduction_compatibility_lane_is_not_silently_disabled() -> None:
    state = _state(closed=False)
    assert poh_human_authority_scope_closed(state) is False
    env = _env("POH_APPLICATION_SUBMIT")
    env["payload"] = {"account_id": "subject", "application_id": "dev-app"}
    out = apply_poh(state, env)
    assert out == {"applied": "POH_APPLICATION_SUBMIT", "application_id": "dev-app"}


def test_checked_production_genesis_commits_scope_closed_mode_and_only_bootstrap_tier2() -> None:
    ledger = json.loads((ROOT / "configs" / "genesis.ledger.prod.json").read_text(encoding="utf-8"))
    assert poh_human_authority_mode(ledger) == POH_HUMAN_AUTHORITY_MODE_SCOPE_CLOSED
    assert poh_human_authority_scope_closed(ledger) is True
    tier2_accounts = sorted(
        account_id
        for account_id, rec in ledger["accounts"].items()
        if isinstance(rec, dict) and int(rec.get("poh_tier") or 0) >= 2
    )
    assert tier2_accounts == ["@errol-genesis"]
    grant = ledger["poh"]["bootstrap_grants"]["by_id"]
    assert len(grant) == 1
    assert next(iter(grant.values()))["transitional"] is True
''',
)

# 6) Bind scope closure into the existing P0 mutation gate.
assurance_rel = "Weall-Protocol/tests/p0_assurance.py"
anchor = '''    MutationSpec(
        mutation_id="P0-07-PRODUCTION-CHAIN-MODE",
'''
insert = '''    MutationSpec(
        mutation_id="P0-06-PRODUCTION-AUTHORITY-SCOPE",
        track="P0-06",
        description="Bypass the canonical production PoH human-authority scope lock.",
        edits=(
            _edit(
                "src/weall/runtime/apply/poh.py",
                "    if poh_human_authority_scope_closed(state) and t in _P0_06_SCOPE_CLOSED_AUTHORITY_TX_TYPES:\\n",
                "    if False and poh_human_authority_scope_closed(state) and t in _P0_06_SCOPE_CLOSED_AUTHORITY_TX_TYPES:\\n",
            ),
        ),
        tests=("tests/test_p0_06_production_scope_closure.py",),
    ),
    MutationSpec(
        mutation_id="P0-06-PRODUCTION-ASYNC-SCHEDULER-SCOPE",
        track="P0-06",
        description="Re-enable async reviewer scheduling while the production human-authority scope is closed.",
        edits=(
            _edit(
                "src/weall/runtime/poh/async_scheduler.py",
                "    if poh_human_authority_scope_closed(state):\\n        return 0\\n",
                "    if False and poh_human_authority_scope_closed(state):\\n        return 0\\n",
            ),
        ),
        tests=("tests/test_p0_06_production_scope_closure.py",),
    ),
'''
replace_once(assurance_rel, anchor, insert + anchor)

# 7) Same-tree audit truth.  This explicitly records scope closure and does not
# claim global uniqueness or unpredictable entropy is implemented.
status_rel = "docs/audit/WeAll-A01-A20-P0-Closure-Status-20260930.md"
replace_once(
    status_rel,
    "| P0-06 Human uniqueness / reviewer anti-grinding | A08-F001, A20-F001 | DESIGN BLOCKER | Must define protocol-level global uniqueness authority and commit-before-unpredictable-entropy reviewer selection. Applicant-controlled case ID cannot remain selection entropy. |",
    "| P0-06 Human uniqueness / reviewer anti-grinding | A08-F001, A20-F001 | CLOSED — SCOPE-CLOSED AND PROVEN | The repository does **not** claim to have invented global human uniqueness or an unbiasable randomness beacon. Instead, the canonical production genesis commits `params.poh.human_authority_mode=scope_closed_pending_uniqueness_entropy`. At the canonical apply boundary all positive PoH authority creation/advancement families fail closed with `poh_human_authority_scope_closed`; async/Tier-2/Live schedulers independently enqueue nothing under that mode; direct award helpers fail closed; challenge/revocation remain available; and non-production compatibility remains testable. This removes both A08-F001 and A20-F001 from reachable production authority until a separately reviewed uniqueness/privacy/adjudication protocol and commit-before-unpredictable-entropy selection protocol are defined. The P0 assurance gate contains dedicated mutants for bypassing both the apply lock and async scheduler lock. |",
)
replace_once(
    status_rel,
    "These exact-head passes prove the current source/evidence tree. P0-10 A15-F001/F002 are now closed by the bounded-history/state-sync architecture plus the dedicated long-height/large-state proof run; P0-06 remains the only open P0 track.",
    "These exact-head passes prove the pre-P0-06 source/evidence tree. P0-10 A15-F001/F002 are closed by the bounded-history/state-sync architecture plus the dedicated long-height/large-state proof run. P0-06 is scope-closed on the successor candidate only after its focused regressions, expanded P0 assurance gate, generated-artifact checks, full backend/web suites, and exact-head normal PR gates are green.",
)
replace_once(
    status_rel,
    "## Next implementation order\n\n1. Adjudicate P0-06 A08/A20 together so global human uniqueness and reviewer anti-grinding share one coherent protocol trust model.\n2. After P0-06 closes, capture the final closure SHA/tree, regenerate final same-tree public evidence, and require all four normal exact-head gates plus the P0 assurance gate to remain green.",
    "## Next implementation order\n\n1. Prove the P0-06 production scope closure on an exact workflow-free tree without claiming the missing uniqueness/randomness primitives.\n2. Capture the final closure SHA/tree, regenerate final same-tree public evidence, and require all four normal exact-head gates plus the expanded P0 assurance gate to remain green.\n3. Treat any future re-enablement of production PoH human authority as a new protocol feature requiring a separately reviewed uniqueness/privacy/adjudication design and post-commit unpredictable reviewer-entropy design before activation.",
)

print("P0-06 bounded production scope closure patch applied")
