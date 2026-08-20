from __future__ import annotations

from collections.abc import Iterator

import pytest

from weall.runtime import vrf_sig


def _proofs() -> Iterator[str]:
    yield "11" * 64
    yield "22" * 64


def test_randomized_mldsa_proofs_cannot_grind_beacon_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proofs = _proofs()
    monkeypatch.setattr(vrf_sig, "sign_mldsa", lambda **_kwargs: next(proofs))

    kwargs = {
        "chain_id": "weall-test",
        "height": 8,
        "prev_block_hash": "parent-hash",
        "pubkey": "canonical-proposer-key",
        "privkey": "unused-test-private-key",
    }
    first = vrf_sig.make_vrf_record(**kwargs)
    second = vrf_sig.make_vrf_record(**kwargs)

    assert first["scheme"] == "mldsa_beacon_v2"
    assert first["proof"] != second["proof"]
    assert first["output"] == second["output"]


def test_beacon_output_binds_parent_height_chain_and_proposer_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(vrf_sig, "sign_mldsa", lambda **_kwargs: "33" * 64)

    base = vrf_sig.make_vrf_record(
        chain_id="chain-a",
        height=9,
        prev_block_hash="parent-a",
        pubkey="proposer-a",
        privkey="unused",
    )
    changed_key = vrf_sig.make_vrf_record(
        chain_id="chain-a",
        height=9,
        prev_block_hash="parent-a",
        pubkey="proposer-b",
        privkey="unused",
    )
    changed_parent = vrf_sig.make_vrf_record(
        chain_id="chain-a",
        height=9,
        prev_block_hash="parent-b",
        pubkey="proposer-a",
        privkey="unused",
    )

    assert base["output"] != changed_key["output"]
    assert base["output"] != changed_parent["output"]


def test_verify_beacon_checks_signature_and_deterministic_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(vrf_sig, "sign_mldsa", lambda **_kwargs: "44" * 64)
    monkeypatch.setattr(vrf_sig, "verify_mldsa_signature", lambda **_kwargs: True)

    rec = vrf_sig.make_vrf_record(
        chain_id="chain-a",
        height=10,
        prev_block_hash="parent-a",
        pubkey="proposer-a",
        privkey="unused",
    )
    ok, reason = vrf_sig.verify_vrf_record(
        vrf=rec,
        chain_id="chain-a",
        height=10,
        prev_block_hash="parent-a",
    )
    assert ok is True
    assert reason == ""

    tampered = dict(rec)
    tampered["output"] = "00" * 32
    ok2, reason2 = vrf_sig.verify_vrf_record(
        vrf=tampered,
        chain_id="chain-a",
        height=10,
        prev_block_hash="parent-a",
    )
    assert ok2 is False
    assert reason2 == "vrf_output_mismatch"


def test_bft_vrf_authority_requires_exact_canonical_proposer_key() -> None:
    from weall.runtime.block_replay import _vrf_validator_authority_reason

    class _FakeExecutor:
        def _active_validators(self) -> list[str]:
            return ["canonical"]

        def _validator_pubkeys(self) -> dict[str, str]:
            return {"canonical": "canonical-key", "stale": "stale-key"}

    ex = _FakeExecutor()
    assert (
        _vrf_validator_authority_reason(
            ex,
            vrf_pubkey="canonical-key",
            proposer="canonical",
            bft_enabled=True,
        )
        == ""
    )
    assert (
        _vrf_validator_authority_reason(
            ex,
            vrf_pubkey="stale-key",
            proposer="canonical",
            bft_enabled=True,
        )
        == "not_canonical_proposer_key"
    )
    assert (
        _vrf_validator_authority_reason(
            ex,
            vrf_pubkey="stale-key",
            proposer="stale",
            bft_enabled=True,
        )
        == "not_canonical_proposer"
    )


def test_canonical_rand_state_excludes_randomized_proof_bytes(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pathlib import Path

    from weall.runtime import block_builder
    from weall.runtime.executor import WeAllExecutor
    from weall.testing.prod_fixtures import next_constitutional_block_time_ms

    tx_index = str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")
    ex_a = WeAllExecutor(
        db_path=str(tmp_path / "a.db"),
        node_id="a",
        chain_id="beacon-state",
        tx_index_path=tx_index,
    )
    ex_b = WeAllExecutor(
        db_path=str(tmp_path / "b.db"),
        node_id="b",
        chain_id="beacon-state",
        tx_index_path=tx_index,
    )

    monkeypatch.setenv("WEALL_NODE_PUBKEY", "test-pubkey")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "test-private")
    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: True)

    proofs = iter(("proof-a", "proof-b"))

    def _fake_record(**kwargs):
        message = vrf_sig.vrf_message(
            chain_id=kwargs["chain_id"],
            height=kwargs["height"],
            prev_block_hash=kwargs["prev_block_hash"],
            pubkey=kwargs["pubkey"],
        )
        return {
            "scheme": vrf_sig.SCHEME,
            "pubkey": kwargs["pubkey"],
            "proof": next(proofs),
            "output": vrf_sig.vrf_output_from_message(message),
        }

    monkeypatch.setattr(block_builder, "make_vrf_record", _fake_record)

    common_ts = next_constitutional_block_time_ms(ex_a)
    block_a, state_a, _, _, err_a = ex_a.build_block_candidate(
        max_txs=0, allow_empty=True, force_ts_ms=common_ts
    )
    block_b, state_b, _, _, err_b = ex_b.build_block_candidate(
        max_txs=0, allow_empty=True, force_ts_ms=common_ts
    )

    assert err_a == err_b == ""
    assert isinstance(block_a, dict) and isinstance(block_b, dict)
    assert isinstance(state_a, dict) and isinstance(state_b, dict)
    assert block_a["header"]["vrf"]["proof"] != block_b["header"]["vrf"]["proof"]
    assert state_a["rand"]["vrf"] == state_b["rand"]["vrf"]
    assert "proof" not in state_a["rand"]["vrf"]
    assert block_a["header"]["state_root"] == block_b["header"]["state_root"]
