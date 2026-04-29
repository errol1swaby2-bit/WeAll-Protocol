from weall.runtime.conflict_lanes import plan_conflict_lanes
from weall.runtime.read_write_sets import build_tx_access_set
from weall.runtime.tx_conflict_audit_samples import build_conflict_probe_tx


ROLE_IDENTITY_SERIAL_TYPES = {
    "ROLE_EMISSARY_NOMINATE",
    "ROLE_EMISSARY_VOTE",
    "ROLE_GOV_EXECUTOR_SET",
    "ROLE_JUROR_ACTIVATE",
    "ROLE_JUROR_ENROLL",
    "ROLE_JUROR_REINSTATE",
    "ROLE_JUROR_SUSPEND",
    "ROLE_NODE_OPERATOR_ACTIVATE",
    "ROLE_NODE_OPERATOR_ENROLL",
    "ROLE_NODE_OPERATOR_SUSPEND",
    "ROLE_VALIDATOR_ACTIVATE",
    "ROLE_VALIDATOR_SUSPEND",
}


def test_role_identity_bridge_txs_fail_closed_to_serial_batch141() -> None:
    for tx_type in sorted(ROLE_IDENTITY_SERIAL_TYPES):
        access = build_tx_access_set(build_conflict_probe_tx(tx_type, seed="1"))
        assert access.lane_hint == "SERIAL", tx_type
        assert any(key.startswith("roles:") for key in access.writes), tx_type
        assert any(key.startswith("identity:") for key in access.writes), tx_type



def test_role_validator_activation_promotes_to_serial_when_consensus_membership_changes_batch141() -> None:
    access = build_tx_access_set(
        build_conflict_probe_tx(
            "ROLE_VALIDATOR_ACTIVATE",
            seed="2",
            payload_overrides={"validator": "acct-validator", "validator_id": "acct-validator", "account_id": "acct-validator"},
        )
    )
    assert access.lane_hint == "SERIAL"
    assert any(key.startswith("consensus:") for key in access.writes)
    assert any(key.startswith("identity:") for key in access.writes)
    assert any(key.startswith("roles:") for key in access.writes)



def test_role_enrollment_is_not_parallelized_with_identity_mutation_for_same_account_batch141() -> None:
    account_id = "acct-shared"
    plan = plan_conflict_lanes(
        [
            build_conflict_probe_tx(
                "ROLE_JUROR_ENROLL",
                seed="3",
                payload_overrides={"account_id": account_id, "juror": account_id},
            ),
            build_conflict_probe_tx(
                "ACCOUNT_KEY_ADD",
                seed="4",
                payload_overrides={"account_id": account_id, "key_id": "key-shared"},
            ),
        ]
    )
    lane_map = {lane.lane_id: lane.tx_ids for lane in plan.lanes}
    assert any(
        lane_id.startswith("SERIAL") and "role_juror_enroll-3" in tx_ids
        for lane_id, tx_ids in lane_map.items()
    )
