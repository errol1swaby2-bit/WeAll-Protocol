from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.block_admission import admit_bft_block, admit_bft_commit_block


def _state() -> dict:
    return {
        "chain_id": "weall-test",
        "roles": {"validators": {"active_set": ["@v1", "@v2", "@v3", "@v4"]}},
        "consensus": {
            "validators": {
                "registry": {
                    "@v1": {"pubkey": "pk1"},
                    "@v2": {"pubkey": "pk2"},
                    "@v3": {"pubkey": "pk3"},
                    "@v4": {"pubkey": "pk4"},
                }
            }
        },
        "blocks": {"genesis": {"prev_block_id": ""}},
    }


def _block() -> dict:
    return {
        "block_id": "b1",
        "prev_block_id": "genesis",
        "header": {
            "chain_id": "weall-test",
            "height": 1,
            "prev_block_hash": "00" * 32,
            "block_ts_ms": 1000,
            "tx_ids": [],
            "receipts_root": "r",
            "state_root": "s",
        },
    }


def test_block_admission_respects_explicit_bft_disable_even_when_env_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    ok, rej = admit_bft_block(block=_block(), state=_state(), bft_enabled=False)
    assert ok is True
    assert rej is None


def test_block_commit_admission_respects_explicit_bft_disable_even_when_env_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    ok, rej = admit_bft_commit_block(block=_block(), state=_state(), bft_enabled=False)
    assert ok is True
    assert rej is None


def test_block_admission_default_env_behavior_unchanged_when_no_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    ok, rej = admit_bft_block(block=_block(), state=_state())
    assert ok is False
    assert rej is not None
    assert rej.code == "bft_missing_qc"
