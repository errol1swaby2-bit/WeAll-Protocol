"""Single-runner *synthetic* positive signed DISPUTE_OPEN offline replay.

Only a deterministic explicit genesis-bootstrap test account is granted PoH.
This is not historical provenance, verified global PoH, or BFT finality.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.pr77_retained_history_replay import (
    ReplayEvidenceError,
    file_sha256,
    replay_offline_source,
)
from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.executor import WeAllExecutor
from weall.runtime.replay_consistency import _deterministic_replay_fixture_keypair
from weall.runtime.tx_id import compute_tx_id_from_dict

CHAIN = "weall-controlled-devnet"
CASE_ID = "dispute:@alice:1"


def _generate_test_only_opening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, str]:
    """Create actual committed blocks, using only the executor and signed TXs."""
    alice_pub, alice_priv = _deterministic_replay_fixture_keypair(label="@alice")
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", "@alice")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", alice_pub)
    monkeypatch.delenv("WEALL_GENESIS_MODE", raising=False)
    monkeypatch.delenv("WEALL_POH_BOOTSTRAP_OPEN", raising=False)
    monkeypatch.delenv("WEALL_NODE_ID", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)

    index = Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"
    source_db = tmp_path / "recorded-synthetic-dispute.sqlite"
    executor = WeAllExecutor(
        db_path=str(source_db),
        node_id="pr77-synthetic-source",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    genesis = executor.read_state()
    assert genesis["height"] == 0
    assert genesis["accounts"]["@alice"]["poh_tier"] == 2
    assert genesis["params"]["block_tx_signature_policy"] == "required"

    bob_pub, bob_priv = _deterministic_replay_fixture_keypair(label="@bob")
    register = sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN,
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@bob",
            "nonce": 1,
            "payload": {"pubkey": bob_pub},
        },
        privkey=bob_priv,
        encoding="hex",
    )
    submitted = executor.submit_tx(register)
    assert submitted["ok"] is True, submitted
    first = executor.produce_block(max_txs=1)
    assert first.ok is True, first.error
    assert executor.read_state()["height"] == 1

    opening = sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN,
            "tx_type": "DISPUTE_OPEN",
            "signer": "@alice",
            "nonce": 1,
            "payload": {
                "target_type": "ACCOUNT",
                "target_id": "  @bob ",
                "reason": " Synthetic signed dispute ",
            },
        },
        privkey=alice_priv,
        encoding="hex",
    )
    opening_id = compute_tx_id_from_dict(CHAIN, opening)
    submitted = executor.submit_tx(opening)
    assert submitted["ok"] is True, submitted
    second = executor.produce_block(max_txs=1)
    assert second.ok is True, second.error
    state = executor.read_state()
    assert state["height"] == 2
    case = state["disputes_by_id"][CASE_ID]
    assert case["opened_at_height"] == 1
    assert case["target_type"] == "account"
    assert case["target_id"] == "@bob"
    assert case["reason"] == "Synthetic signed dispute"
    block = executor.get_block_by_height(2)
    assert opening_id in block["header"]["tx_ids"]
    return source_db, opening_id


def test_synthetic_executor_opening_replays_with_source_bound_witness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_db, opening_id = _generate_test_only_opening(tmp_path, monkeypatch)
    index = Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()

    scratch = tmp_path / "positive-replay"
    scratch.mkdir()
    result = replay_offline_source(
        source=source_db,
        source_sha256=file_sha256(source_db),
        chain_id=CHAIN,
        scratch_dir=scratch,
        tx_index=index,
        tx_index_sha256=file_sha256(index),
        expected_commit=sha,
        opening_tx_id=opening_id,
        opening_case_id=CASE_ID,
    )
    assert result["ok"] is True
    assert result["block_count"] == 2
    witness = result["signed_opening_witness"]
    assert witness["height"] == 2
    assert witness["opening_tx_id"] == opening_id
    assert witness["case_id"] == CASE_ID
    assert all(witness["observations"].values())
    assert witness["pre_state_root"] == result["per_height_commitments"][0]["state_root"]
    assert witness["post_state_root"] == result["per_height_commitments"][1]["state_root"]
    assert witness["constitutional_authorization"] == "NOT_ESTABLISHED"
    assert witness["may_classify_canonical_case"] is False
    assert witness["may_enqueue_account_ban"] is False
    assert result["historical_provenance_verified"] is False
    assert result["old_version_compatibility_proven"] is False
    assert result["independent_two_node_consensus_proven"] is False

    wrong_scratch = tmp_path / "wrong-case-replay"
    wrong_scratch.mkdir()
    with pytest.raises(ReplayEvidenceError, match="opening_witness_case_not_in_replayed_state"):
        replay_offline_source(
            source=source_db,
            source_sha256=file_sha256(source_db),
            chain_id=CHAIN,
            scratch_dir=wrong_scratch,
            tx_index=index,
            tx_index_sha256=file_sha256(index),
            expected_commit=sha,
            opening_tx_id=opening_id,
            opening_case_id="substituted-case",
        )
