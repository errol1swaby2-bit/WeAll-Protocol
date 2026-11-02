"""PR77 nine-role/reviewer V2 semantic-drift execution adjudication.

The archived V2 scanner recorded literal error codes from duplicated guards.
The current implementation calls a shared, versioned pure predicate that raises
dynamic RolesApplyError(code, reason). Missing AST strings are NOT proof that
the old runtime rejection disappeared. No semantic digest is approved here.
"""

from __future__ import annotations

import copy

import pytest

from scripts.pr77_v2_semantic_review_packet import build_packet
from weall.ledger.state import LedgerView
from weall.runtime.apply.roles import RolesApplyError, apply_roles
from weall.runtime.bounded_rollback import run_with_bounded_rollback
from weall.runtime.reputation_events import append_reputation_event
from weall.runtime.reputation_role_gate import role_activation_reputation_decision
from weall.runtime.tx_admission import TxEnvelope, admit_tx
from weall.tx.canon import TxIndex

# All nine stale role/reviewer contracts use the same implementation module,
# but one of them (OPT_OUT) deliberately does NOT invoke the activation gate.
GATED_TX_ROLES = (
    ("ROLE_JUROR_ENROLL", "juror"),
    ("ROLE_JUROR_ACTIVATE", "juror"),
    ("ROLE_JUROR_REINSTATE", "juror"),
    ("ROLE_VALIDATOR_ACTIVATE", "validator"),
    ("ROLE_NODE_OPERATOR_ACTIVATE", "node_operator"),
    ("ROLE_EMISSARY_SEAT", "emissary"),
    ("ROLE_GOV_EXECUTOR_SET", "gov_executor"),
    ("REVIEWER_LANE_OPT_IN", "juror"),
)
ALL_REVIEWED_TX_TYPES = tuple(tx for tx, _role in GATED_TX_ROLES) + ("REVIEWER_LANE_OPT_OUT",)
SYSTEM_ORIGIN_TX_TYPES = frozenset(
    {
        "ROLE_VALIDATOR_ACTIVATE",
        "ROLE_NODE_OPERATOR_ACTIVATE",
        "ROLE_EMISSARY_SEAT",
        "ROLE_GOV_EXECUTOR_SET",
    }
)


def _state(*, gate_version: int | None) -> dict:
    state: dict = {
        "height": 21,
        "accounts": {
            "@alice": {
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation": "6",
                "reputation_milli": 6000,
                "nonce": 0,
            }
        },
        "roles": {
            "jurors": {
                "by_id": {
                    "@alice": {
                        "enrolled": True,
                        "active": True,
                        "responsibilities": {
                            "reviewer": {
                                "dispute_review": {
                                    "active": True,
                                    "opted_in": True,
                                }
                            }
                        },
                    }
                },
                "active_set": ["@alice"],
            },
            "node_operators": {
                "by_id": {"@alice": {"enrolled": True, "active": True}},
                "active_set": ["@alice"],
            },
        },
    }
    if gate_version is not None:
        state["params"] = {"reputation_role_gate_version": gate_version}
    return state


def _envelope(tx_type: str) -> TxEnvelope:
    system = tx_type in SYSTEM_ORIGIN_TX_TYPES
    payload = {"account_id": "@alice", "reputation_required_milli": 5000}
    if tx_type.startswith("REVIEWER_LANE_"):
        payload["reviewer_lanes"] = ["dispute_review"]
    return TxEnvelope(
        tx_type=tx_type,
        signer="SYSTEM" if system else "@alice",
        nonce=24,
        payload=payload,
        sig="synthetic-no-cryptographic-identity",
        parent="synthetic-parent" if system else None,
        system=system,
    )


def _apply_atomically(state: dict, tx_type: str) -> dict:
    return run_with_bounded_rollback(state, lambda ledger: apply_roles(ledger, _envelope(tx_type)))[
        0
    ]


@pytest.mark.parametrize("tx_type", ALL_REVIEWED_TX_TYPES)
def test_each_stale_role_contract_compiler_delta_is_scanner_visibility(
    tx_type: str,
) -> None:
    packet = build_packet()
    row = next(row for row in packet["transactions"] if row["tx_type"] == tx_type)
    assert row["archive_matches_accepted_digest"] is True
    assert row["archived_implementation_source"] == row["current_implementation_source"]
    assert row["current_material_digest"] != row["accepted_review_digest"]
    assert row["changed_field_names"] == ["failure_codes", "state_reads", "state_writes"]
    assert row["failure_code_deltas"] == {
        "added": [{"code": "RolesApplyError", "reason": "runtime_apply_failure"}],
        "removed": [
            {"code": "forbidden", "reason": "account_restricted"},
            {"code": "forbidden", "reason": "live_verification_required"},
            {"code": "forbidden", "reason": "reputation_insufficient"},
            {"code": "forbidden", "reason": "role_eligibility_revoked"},
        ],
    }
    assert row["signed_off_for_current_digest"] is False
    assert row["historical_replay_proven"] is False
    assert packet["must_not_update_semantic_reviews_automatically"] is True


@pytest.mark.parametrize("tx_type,role", GATED_TX_ROLES)
@pytest.mark.parametrize("gate_version", [None, 1, 2], ids=["legacy-default", "v1", "v2"])
@pytest.mark.parametrize(
    ("restriction", "reason"),
    [
        ("banned", "account_restricted"),
        ("locked", "account_restricted"),
        ("tier1", "live_verification_required"),
        ("revoked", "role_eligibility_revoked"),
        ("low_reputation", "reputation_insufficient"),
    ],
)
def test_shared_role_gate_rejections_retain_exact_runtime_code_and_atomicity(
    tx_type: str, role: str, gate_version: int | None, restriction: str, reason: str
) -> None:
    state = _state(gate_version=gate_version)
    account = state["accounts"]["@alice"]
    if restriction == "banned":
        account["banned"] = True
    elif restriction == "locked":
        account["locked"] = True
    elif restriction == "tier1":
        account["poh_tier"] = 1
    elif restriction == "revoked":
        state["reputation"] = {"role_eligibility": {"@alice": {"roles": {role: False}}}}
    else:
        account["reputation"] = "1"
        account["reputation_milli"] = 1000
    predicted = role_activation_reputation_decision(
        state, "@alice", role=role, minimum_reputation_milli=5000
    )
    assert predicted["eligible"] is False
    assert predicted["code"] == "forbidden"
    assert predicted["reason"] == reason

    before = copy.deepcopy(state)
    with pytest.raises(RolesApplyError) as error:
        _apply_atomically(state, tx_type)
    assert (error.value.code, error.value.reason) == ("forbidden", reason)
    assert state == before


@pytest.mark.parametrize("tx_type,role", GATED_TX_ROLES)
@pytest.mark.parametrize("bad_version", [0, 3, True, "2"])
def test_malformed_role_gate_version_cannot_activate_role(
    tx_type: str, role: str, bad_version: object
) -> None:
    state = _state(gate_version=1)
    state["params"]["reputation_role_gate_version"] = bad_version
    expected = role_activation_reputation_decision(
        state, "@alice", role=role, minimum_reputation_milli=5000
    )
    assert expected["reason"] == "policy_unknown"
    before = copy.deepcopy(state)
    with pytest.raises(RolesApplyError) as error:
        _apply_atomically(state, tx_type)
    assert error.value.code == "forbidden"
    assert error.value.reason == "policy_unknown"
    assert state == before


@pytest.mark.parametrize(
    "tx_type,role,event_code",
    [
        ("ROLE_JUROR_ENROLL", "juror", "DISPUTE_JUROR_TIMED_OUT"),
        ("ROLE_JUROR_ACTIVATE", "juror", "DISPUTE_JUROR_TIMED_OUT"),
        ("ROLE_JUROR_REINSTATE", "juror", "DISPUTE_JUROR_TIMED_OUT"),
        ("REVIEWER_LANE_OPT_IN", "juror", "DISPUTE_JUROR_TIMED_OUT"),
        ("ROLE_VALIDATOR_ACTIVATE", "validator", "VALIDATOR_DOUBLE_SIGN"),
    ],
)
def test_canonical_penalty_only_blocks_explicit_v2_gate(
    tx_type: str, role: str, event_code: str
) -> None:
    state = _state(gate_version=2)
    append_reputation_event(
        state,
        actor_id="@alice",
        event_code=event_code,
        source_flow="validator" if role == "validator" else "dispute",
        source_tx_id=f"pr77:{event_code}",
        source_object_id="synthetic-case",
        occurred_at_block=21,
    )
    expected = role_activation_reputation_decision(
        state, "@alice", role=role, minimum_reputation_milli=5000
    )
    assert expected["reason"] == "canonical_role_reputation_ineligible"
    before = copy.deepcopy(state)
    with pytest.raises(RolesApplyError) as exc:
        _apply_atomically(state, tx_type)
    assert exc.value.reason == "canonical_role_reputation_ineligible"
    assert state == before


@pytest.mark.parametrize("gate_version", [None, 1, 2], ids=["legacy-default", "v1", "v2"])
@pytest.mark.parametrize("restriction", ["banned", "tier1", "revoked", "malformed_version"])
def test_reviewer_opt_out_stays_possible_when_activation_gate_rejects(
    gate_version: int | None, restriction: str
) -> None:
    state = _state(gate_version=gate_version)
    if restriction == "banned":
        state["accounts"]["@alice"]["banned"] = True
    elif restriction == "tier1":
        state["accounts"]["@alice"]["poh_tier"] = 1
    elif restriction == "revoked":
        state["reputation"] = {"role_eligibility": {"@alice": {"roles": {"juror": False}}}}
    else:
        state.setdefault("params", {})["reputation_role_gate_version"] = "2"
    assert (
        role_activation_reputation_decision(
            state, "@alice", role="juror", minimum_reputation_milli=5000
        )["eligible"]
        is False
    )
    old = copy.deepcopy(state)
    result = _apply_atomically(state, "REVIEWER_LANE_OPT_OUT")
    assert result["applied"] == "REVIEWER_LANE_OPT_OUT"
    assert result["account_id"] == "@alice"
    lane = state["roles"]["jurors"]["by_id"]["@alice"]["responsibilities"]["reviewer"][
        "dispute_review"
    ]
    assert lane["opted_in"] is False
    assert lane["active"] is False
    assert state["roles"]["jurors"]["active_set"] == ["@alice"]
    # Opt-out must not modify the user's account restriction or role event history.
    assert state["accounts"] == old["accounts"]
    assert state.get("reputation") == old.get("reputation")


def test_reviewer_opt_out_is_not_pretend_activation_rejection() -> None:
    """The AST's four removed errors never governed the withdrawal path."""
    state = _state(gate_version=2)
    state["accounts"]["@alice"]["banned"] = True
    result = _apply_atomically(state, "REVIEWER_LANE_OPT_OUT")
    assert result["applied"] == "REVIEWER_LANE_OPT_OUT"
    assert state["accounts"]["@alice"]["banned"] is True


@pytest.mark.parametrize(("account_flag", "reason"), [
    ("banned", "banned"),
    ("locked", "locked"),
])
def test_public_reviewer_opt_out_reaches_admission_restriction_before_applier(
    monkeypatch: pytest.MonkeyPatch, account_flag: str, reason: str
) -> None:
    """Do not claim a banned/locked user can withdraw through public ingress.

    The domain handler intentionally permits opting out, but public admission
    enforces the signer's ban/lock before any domain apply. This is an explicit
    architecture/product-policy review item, not permission to change admission.
    """
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    state = _state(gate_version=2)
    state["accounts"]["@alice"][account_flag] = True
    ledger = LedgerView(
        accounts=state["accounts"],
        roles=state["roles"],
        params=state["params"],
    )
    tx_index = TxIndex.load_from_file(
        str(__import__("pathlib").Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")
    )
    tx = TxEnvelope(
        tx_type="REVIEWER_LANE_OPT_OUT",
        signer="@alice",
        nonce=1,
        payload={"account_id": "@alice", "reviewer_lanes": ["dispute_review"]},
        sig="synthetic-not-authenticated",
    )
    before = copy.deepcopy(state)
    verdict = admit_tx(tx.to_json(), ledger, tx_index, context="mempool")
    assert verdict.ok is False
    assert verdict.code == "gate_denied"
    assert verdict.reason == reason
    assert state == before
