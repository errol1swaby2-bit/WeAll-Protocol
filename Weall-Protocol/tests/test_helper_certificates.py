from weall.runtime.helper_certificates import HelperCertificate


def test_tx_order_hash_consistency():
    cert = HelperCertificate(
        chain_id="test",
        block_height=1,
        view=1,
        leader_id="leader",
        helper_id="helper",
        validator_epoch=1,
        validator_set_hash="hash",

        lane_id="LANE_X",

        tx_ids=["a", "b", "c"],
        tx_order_hash="",

        receipts_root="r",
        write_set_hash="w",
        read_set_hash="r2",

        state_delta_hash="s",
        namespace_hash="n",

        signature="sig"
    )

    correct_hash = cert.compute_tx_order_hash()

    cert = HelperCertificate(**{**cert.__dict__, "tx_order_hash": correct_hash})

    assert cert.verify_internal_consistency()


def test_invalid_hash_detected():
    cert = HelperCertificate(
        chain_id="test",
        block_height=1,
        view=1,
        leader_id="leader",
        helper_id="helper",
        validator_epoch=1,
        validator_set_hash="hash",

        lane_id="LANE_X",

        tx_ids=["a", "b"],
        tx_order_hash="wrong",

        receipts_root="r",
        write_set_hash="w",
        read_set_hash="r2",

        state_delta_hash="s",
        namespace_hash="n",

        signature="sig"
    )

    assert not cert.verify_internal_consistency()
