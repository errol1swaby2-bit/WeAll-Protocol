from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_a05_f004_production_closure_is_not_the_legacy_batch539_rehearsal() -> None:
    legacy = (ROOT / "scripts" / "rehearse_production_bft_path_v1_5.py").read_text(
        encoding="utf-8"
    )
    prod = (ROOT / "tests" / "test_p0_03_production_composition.py").read_text(
        encoding="utf-8"
    )

    # Preserve the audit truth: Batch 539 still contains testnet/dev allowances
    # and cannot be treated as the A05-F004 production proof.
    assert '"WEALL_MODE": "testnet"' in legacy
    assert '"WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "1"' in legacy
    assert '"WEALL_SIGVERIFY": "0"' in legacy

    # The closure gate is the true production composition suite.
    for required in (
        '"WEALL_MODE": "prod"',
        '"WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "0"',
        '"WEALL_SIGVERIFY": "1"',
        '"WEALL_UNSAFE_DEV": "0"',
        "bft_on_proposal(copy.deepcopy(proposal))",
        "_form_qc(",
        "_broadcast_qc(",
        "finalized_block_id",
        "mark_clean_shutdown()",
        "NetMeshLoop(",
        "_on_bft_proposal(leader, msg)",
    ):
        assert required in prod
