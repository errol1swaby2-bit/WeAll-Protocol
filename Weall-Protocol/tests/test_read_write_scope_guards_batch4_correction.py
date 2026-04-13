from weall.runtime.read_write_sets import build_tx_access_set


def test_explicit_authority_scope_materialized_in_writes_stays_family_lane_batch4_correction() -> None:
    tx = {
        "tx_id": "t-auth-ok",
        "tx_type": "GROUP_TREASURY_POLICY_SET",
        "read_set": ["groups:group:alpha"],
        "write_set": ["groups:group:alpha", "authority:groups:group:alpha"],
        "authority_set": ["authority:groups:group:alpha"],
        "family": "GROUPS",
        "barrier_class": "AUTHORITY_BARRIER",
    }
    access = build_tx_access_set(tx)
    assert access.fail_closed_serial is False
    assert access.lane_hint == "GOVERNANCE"
    assert access.authority_keys == ("authority:groups:group:alpha",)


def test_explicit_authority_scope_missing_from_writes_fails_closed_batch4_correction() -> None:
    tx = {
        "tx_id": "t-auth-missing",
        "tx_type": "ROLE_JUROR_ACTIVATE",
        "read_set": ["roles:user:@alice"],
        "write_set": ["roles:user:@alice"],
        "authority_set": ["authority:roles"],
    }
    access = build_tx_access_set(tx)
    assert access.lane_hint == "SERIAL"
    assert access.fail_closed_serial is True
    assert access.authority_keys == ("authority:roles",)
