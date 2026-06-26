from weall.runtime.read_write_sets import build_tx_access_set


def test_explicit_authority_scope_forces_fail_closed_serial_batch4() -> None:
    tx = {
        "tx_id": "t-auth",
        "tx_type": "ROLE_JUROR_ACTIVATE",
        "read_set": ["roles:user:@alice"],
        "write_set": ["roles:user:@alice"],
        "authority_set": ["authority:roles"],
    }
    access = build_tx_access_set(tx)
    assert access.lane_hint == "SERIAL"
    assert access.fail_closed_serial is True
    assert access.authority_keys == ("authority:roles",)



def test_explicit_subject_scope_missing_from_writes_fails_closed_batch4() -> None:
    tx = {
        "tx_id": "t-subject",
        "tx_type": "FOLLOW_SET",
        "read_set": ["social:profile:@alice"],
        "write_set": ["social:follow:@alice:@bob"],
        "subject_set": ["social:profile:@alice"],
    }
    access = build_tx_access_set(tx)
    assert access.lane_hint == "SERIAL"
    assert access.fail_closed_serial is True
    assert access.subject_keys == ("social:profile:@alice",)



def test_explicit_scoped_writes_remain_parallel_when_scope_is_materialized_batch4() -> None:
    tx = {
        "tx_id": "t-ok",
        "tx_type": "CONTENT_POST_CREATE",
        "read_set": ["content:post:1"],
        "write_set": ["content:post:1", "content:post:1:scope"],
        "subject_set": ["content:post:1:scope"],
    }
    access = build_tx_access_set(tx)
    assert access.fail_closed_serial is False
    assert access.lane_hint == "CONTENT"
