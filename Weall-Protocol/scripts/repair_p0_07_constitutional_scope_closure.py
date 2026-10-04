from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{rel}: expected one anchor, found {count}: {old[:120]!r}")
    write(rel, text.replace(old, new, 1))


# ---------------------------------------------------------------------------
# A09-F004: remove constitutional mutation authority from strict civic profiles.
# ---------------------------------------------------------------------------

gov_anchor = '''def _assert_governance_actions_allowed(state: Json, actions: list[dict[str, Any]]) -> None:
    allowed = _allowed_gov_action_types(state)
    for action in actions:
        tx_type = _s(action.get("tx_type")).strip().upper()
        if not tx_type:
            continue
        if tx_type not in allowed:
            raise ApplyError("forbidden", "governance_action_not_allowed", {"tx_type": tx_type})
        _validate_governance_action_payload(tx_type, _d(action.get("payload")))
'''

gov_replacement = '''def _assert_governance_actions_allowed(state: Json, actions: list[dict[str, Any]]) -> None:
    allowed = _allowed_gov_action_types(state)
    for action in actions:
        tx_type = _s(action.get("tx_type")).strip().upper()
        if not tx_type:
            continue
        if strict_civic_governance_enabled(state) and tx_type in {
            "CONSTITUTION_UPGRADE_DECLARE",
            "CONSTITUTION_UPGRADE_ACTIVATE",
        }:
            raise ApplyError(
                "forbidden",
                "constitutional_amendment_process_not_enabled",
                {
                    "tx_type": tx_type,
                    "scope": "strict_civic_governance",
                    "reason": (
                        "The Genesis Constitution requires an exact amendment diff, independent "
                        "constitutional review, a challenge window, protected-right handling, and "
                        "an unamendable-floor check. The exact stricter protected-right process and "
                        "challenge duration are not yet normatively specified, so production civic "
                        "governance fails closed instead of inventing amendment authority."
                    ),
                },
            )
        if tx_type not in allowed:
            raise ApplyError("forbidden", "governance_action_not_allowed", {"tx_type": tx_type})
        _validate_governance_action_payload(tx_type, _d(action.get("payload")))
'''
replace_once("src/weall/runtime/apply/governance.py", gov_anchor, gov_replacement)

replace_once(
    "src/weall/runtime/apply/protocol.py",
    "from weall.runtime.tx_admission import TxEnvelope\n",
    "from weall.runtime.ballot_policy import strict_civic_governance_enabled\n"
    "from weall.runtime.tx_admission import TxEnvelope\n",
)

protocol_helper_anchor = '''def _ensure_constitution(state: Json) -> Json:
    c = _ensure_root_dict(state, "constitution")
    if not isinstance(c.get("upgrades"), dict):
        c["upgrades"] = {}
    if not isinstance(c.get("scheduled_upgrades"), dict):
        c["scheduled_upgrades"] = {}
    return c
'''

protocol_helper_replacement = '''def _ensure_constitution(state: Json) -> Json:
    c = _ensure_root_dict(state, "constitution")
    if not isinstance(c.get("upgrades"), dict):
        c["upgrades"] = {}
    if not isinstance(c.get("scheduled_upgrades"), dict):
        c["scheduled_upgrades"] = {}
    return c


def _require_constitution_upgrade_scope_enabled(
    state: Json, *, tx_type: str, constitution_id: str
) -> None:
    """Fail closed on strict civic chains until amendment authority is complete.

    A09-F004 established that a record representing the Active Constitution could
    otherwise become effective through generic governance without mechanically
    proving the Article XIII amendment procedure.  The Genesis Constitution does
    not yet supply an exact stricter protected-right threshold/process or an exact
    challenge-window duration.  Strict civic profiles therefore have no
    constitutional mutation authority.  Non-strict/dev replay compatibility keeps
    the existing record-only path, but that path is outside the production civic
    authority contract.
    """

    if not strict_civic_governance_enabled(state):
        return
    raise ProtocolApplyError(
        "forbidden",
        "constitutional_activation_scope_disabled_pending_normative_process",
        {
            "tx_type": str(tx_type),
            "constitution_id": str(constitution_id),
            "scope": "strict_civic_governance",
            "missing_normative_prerequisites": [
                "independent_constitutional_review_semantics",
                "challenge_window_duration",
                "protected_right_amendment_process",
                "unamendable_floor_semantic_validation",
            ],
        },
    )
'''
replace_once("src/weall/runtime/apply/protocol.py", protocol_helper_anchor, protocol_helper_replacement)

replace_once(
    "src/weall/runtime/apply/protocol.py",
    '''    cid = _constitution_id(payload, env)
    version = _target_constitution_version(payload)
''',
    '''    cid = _constitution_id(payload, env)
    _require_constitution_upgrade_scope_enabled(
        state, tx_type=env.tx_type, constitution_id=cid
    )
    version = _target_constitution_version(payload)
''',
)

replace_once(
    "src/weall/runtime/apply/protocol.py",
    '''    cid = _constitution_id(payload, env)
    _validate_constitution_payload_public(payload, constitution_id=cid)
    constitution = _ensure_constitution(state)
''',
    '''    cid = _constitution_id(payload, env)
    _require_constitution_upgrade_scope_enabled(
        state, tx_type=env.tx_type, constitution_id=cid
    )
    _validate_constitution_payload_public(payload, constitution_id=cid)
    constitution = _ensure_constitution(state)
''',
)

# ---------------------------------------------------------------------------
# Focused closure regressions.
# ---------------------------------------------------------------------------

test_path = ROOT / "tests/test_p0_07_constitutional_scope_closure.py"
test_path.write_text(
    '''from __future__ import annotations

import pytest

from weall.runtime.apply.governance import _apply_gov_proposal_create
from weall.runtime.apply.protocol import ProtocolApplyError, apply_protocol
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope

DOC_HASH = "sha256:" + "a" * 64
TRACE_HASH = "sha256:" + "b" * 64
RIGHTS_HASH = "sha256:" + "c" * 64


def _strict_state() -> dict:
    return {
        "chain_id": "weall-prod",
        "height": 100,
        "accounts": {
            "@alice": {"poh_tier": 2},
            "@bob": {"poh_tier": 2},
        },
    }


def _constitution_action(tx_type: str) -> dict:
    if tx_type == "CONSTITUTION_UPGRADE_DECLARE":
        payload = {
            "constitution_id": "const-v0-2",
            "constitution_version": "v0.2",
            "document_hash": DOC_HASH,
            "traceability_hash": TRACE_HASH,
            "rights_floor_hash": RIGHTS_HASH,
        }
    else:
        payload = {
            "constitution_id": "const-v0-2",
            "constitution_version": "v0.2",
            "document_hash": DOC_HASH,
            "traceability_hash": TRACE_HASH,
            "activation_height": 200,
        }
    return {"tx_type": tx_type, "payload": payload}


def test_strict_governance_cannot_author_constitution_upgrade_actions() -> None:
    state = _strict_state()
    for tx_type in ("CONSTITUTION_UPGRADE_DECLARE", "CONSTITUTION_UPGRADE_ACTIVATE"):
        env = TxEnvelope(
            tx_type="GOV_PROPOSAL_CREATE",
            signer="@alice",
            nonce=1,
            payload={
                "proposal_id": f"constitutional-{tx_type.lower()}",
                "title": "Constitution amendment attempt",
                "rules": {"start_stage": "draft"},
                "actions": [_constitution_action(tx_type)],
            },
            chain_id="weall-prod",
        )
        with pytest.raises(ApplyError) as exc_info:
            _apply_gov_proposal_create(state, env)
        assert exc_info.value.code == "forbidden"
        assert exc_info.value.reason == "constitutional_amendment_process_not_enabled"


def test_strict_protocol_apply_rejects_direct_system_constitution_mutation() -> None:
    state = _strict_state()
    env = TxEnvelope(
        tx_type="CONSTITUTION_UPGRADE_DECLARE",
        signer="SYSTEM",
        nonce=1,
        payload=_constitution_action("CONSTITUTION_UPGRADE_DECLARE")["payload"],
        sig="",
        system=True,
        parent="gov:proposal:approved",
        chain_id="weall-prod",
    )
    with pytest.raises(ProtocolApplyError) as exc_info:
        apply_protocol(state, env)
    assert exc_info.value.code == "forbidden"
    assert exc_info.value.reason == (
        "constitutional_activation_scope_disabled_pending_normative_process"
    )
    assert state.get("constitution") is None


def test_non_strict_record_only_compatibility_remains_non_authoritative() -> None:
    state = {"height": 10, "params": {"mode": "dev"}}
    env = TxEnvelope(
        tx_type="CONSTITUTION_UPGRADE_DECLARE",
        signer="SYSTEM",
        nonce=1,
        payload=_constitution_action("CONSTITUTION_UPGRADE_DECLARE")["payload"],
        sig="",
        system=True,
        parent="GOV_EXECUTE",
    )
    out = apply_protocol(state, env)
    assert out is not None
    assert out["applied"] == "CONSTITUTION_UPGRADE_DECLARE"
    rec = state["constitution"]["upgrades"]["const-v0-2"]
    assert rec["record_only_boundary"]["automatic_constitution_apply_supported"] is False
    assert rec["record_only_boundary"]["operator_action_required"] is True
''',
    encoding="utf-8",
)

# ---------------------------------------------------------------------------
# Same-tree audit ledger: make the canonical status match the proven branch.
# ---------------------------------------------------------------------------

status_rel = "../docs/audit/WeAll-A01-A20-P0-Closure-Status-20260930.md"
status_path = ROOT / status_rel
status = status_path.read_text(encoding="utf-8")
status = status.replace("Canonical closure PR: #36", "Canonical closure PR: #38", 1)
status = status.replace(
    "| P0-03 HotStuff highQC parent / validator transition certificates | A05-F001, A05-F002, A16-F004 | IMPLEMENTATION BLOCKER | Requires chained-HotStuff leader parent rule and authenticated transition-certificate bridge across activation/validator generations plus adversarial multinode mutation evidence. No cosmetic patch applied. |",
    "| P0-03 HotStuff highQC parent / validator transition certificates | A05-F001, A05-F002, A16-F004 | CLOSED — PATCHED AND PROVEN | The production-composition closure chain now requires highQC-parent extension, preserves the authenticated validator-transition bridge across highQC advance/restart, reconstructs certified pending ancestry without admitting unauthenticated alternates, and proves delayed finality/replay behavior. The focused closure matrix and full backend/reviewer gates were green on the preserved exact closure lineage. |",
    1,
)
status = status.replace(
    "| P0-05 P2P mutual auth / frame sizing | A07-F001, A07-F002 | IMPLEMENTATION BLOCKER | Requires fresh session-bound mutual peer authentication and a single protocol-valid wire-size contract/chunking strategy. Audit explicitly rejects a boolean-only or limit-only cosmetic fix. |",
    "| P0-05 P2P mutual auth / frame sizing | A07-F001, A07-F002 | CLOSED — PATCHED AND PROVEN | Mutual authentication now uses fresh receiver challenge material with signed acknowledgements, recipient/correlation binding, stale-proof rejection and replay rejection. A single finite production wire budget now governs peer payloads/frames, BFT proposal block sizing and chunked state-sync transfer bounds. The dedicated closure run passed 17 focused regressions plus 4,685 backend tests (1 skipped), and the unchanged exact tree at `65329c71df7a2f029760d49fc57b21beffd650cc` passed Backend CI, Reviewer Readiness, Web CI and Secrets Guard. |",
    1,
)
status = status.replace(
    "| P0-07 Governance electorate / proposal binding / constitutional authority | A09-F001..F004, A16-F005 | PARTIAL | A09-F001 patched: `weall-prod` is strict production civic governance. A09-F002 patched/evidence-pending: strict executable governance uses a snapshotted Tier-2 human electorate, with a regression proving a Tier-0 validator is excluded while a non-validator Tier-2 human is included. A09-F003 patched/evidence-pending: voting-stage mutation is rejected on strict chains and `GOV_EXECUTE` must execute the exact proposal action snapshot rather than substituted SYSTEM payload actions. A09-F004 remains open, but the normative ambiguity is narrower than previously recorded: Genesis Constitution Article XIII explicitly requires a public amendment proposal, exact diff, deliberation, constitutional review, eligible verified-user participation, quorum, supermajority, activation delay, public receipt, challenge window, and at least 75% approval for ordinary amendments; it also defines an explicit unamendable anti-domination floor. The stricter protected-right process is not numerically specified, so production code must fail closed rather than inventing its threshold/process. Broader mutation/property/restart evidence remains required for A16-F005. |",
    "| P0-07 Governance electorate / proposal binding / constitutional authority | A09-F001..F004, A16-F005 | PARTIAL — RUNTIME ROOTS CLOSED / ASSURANCE PENDING | A09-F001 through A09-F003 remain patched: production civic governance fails closed, executable proposals use the Tier-2 human electorate, and votes bind an immutable executable proposal version. A09-F004 is scope-closed rather than supplied with invented constitutional rules: strict civic profiles reject `CONSTITUTION_UPGRADE_DECLARE`/`ACTIVATE` at proposal authoring and independently reject direct SYSTEM protocol application. The non-strict record-only compatibility path remains outside production civic authority. This explicitly removes the unsafe constitutional activation capability until independent review semantics, challenge-window duration, protected-right procedure and unamendable-floor semantic validation are normatively defined. A16-F005 remains open until the P0-11 property/mutation gate proves the governance lifecycle against targeted mutants. |",
    1,
)
status = status.replace("PR #36 remains the single canonical closure PR", "PR #38 remains the single canonical closure PR", 1)
status = status.replace(
    "1. Finish P0-07 A09-F004 only where Genesis Constitution Article XIII is mechanically explicit; protected-right amendments remain fail-closed until the stricter normative threshold/process is defined.\n2. Implement the architecture-heavy P0-03 HotStuff transition, P0-05 P2P session/frame, and P0-10 bounded-state/state-sync tracks with adversarial multinode or stress evidence.\n3. Adjudicate P0-06 A08/A20 together so global human uniqueness and reviewer anti-grinding share one coherent protocol trust model.\n4. Install P0-11's locked property/mutation gate with deterministic seeds and survivor artifacts across the closed and remaining P0 surfaces.\n5. After the remaining implementation/design tracks close, capture the final closure SHA/tree and regenerate final exact-head public evidence.",
    "1. Complete P0-10 bounded-state/state-sync/permanent-state architecture with adversarial stress evidence.\n2. Adjudicate P0-06 A08/A20 together so global human uniqueness and reviewer anti-grinding share one coherent protocol trust model.\n3. Install P0-11's locked property/mutation gate with deterministic seeds and survivor artifacts across the closed and remaining P0 surfaces; this is also the remaining assurance gate for A16-F005/P0-07.\n4. After the remaining implementation/design/assurance tracks close, capture the final closure SHA/tree and regenerate final exact-head public evidence.",
    1,
)
if status == status_path.read_text(encoding="utf-8"):
    raise SystemExit("closure status ledger was not updated")
status_path.write_text(status, encoding="utf-8")

print("P0-07 constitutional strict-profile scope closure staged")
