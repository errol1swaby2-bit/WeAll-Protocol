from weall.runtime.read_write_sets import build_tx_access_set


def test_explicit_read_write_sets_are_preserved() -> None:
    tx = {
        "tx_id": "t1",
        "tx_type": "CONTENT_POST_CREATE",
        "read_set": ["identity:user:@alice"],
        "write_set": ["content:post:1"],
    }
    access = build_tx_access_set(tx)
    assert access.reads == ("identity:user:@alice",)
    assert access.writes == ("content:post:1",)
    assert access.fail_closed_serial is False


def test_inferred_content_prefixes_are_deterministic() -> None:
    tx = {
        "tx_id": "t2",
        "tx_type": "CONTENT_POST_CREATE",
        "signer": "@alice",
        "payload": {"post_id": "p-1"},
    }
    access1 = build_tx_access_set(tx)
    access2 = build_tx_access_set(tx)
    assert access1 == access2
    assert "content:post:p-1" in access1.writes


def test_unknown_tx_fails_closed_to_serial() -> None:
    tx = {"tx_id": "t3", "tx_type": "MYSTERY_TX"}
    access = build_tx_access_set(tx)
    assert access.lane_hint == "SERIAL"
    assert access.fail_closed_serial is True
