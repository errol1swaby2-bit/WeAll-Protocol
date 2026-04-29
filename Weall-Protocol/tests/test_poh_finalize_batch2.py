from __future__ import annotations

from weall.poh.apply import deterministic_token_id
from weall.poh.finalize import finalize_poh_and_mint_gate_nfts


def _base_ledger() -> dict:
    return {
        "accounts": {},
        "poh": {
            "finalizations": [],
            "processed_finalizations": {},
        },
    }


def test_poh_finalize_upgrade_mints_gate_nft_and_marks_processed() -> None:
    state = _base_ledger()

    state["poh"]["finalizations"] = [
        {
            "finalization_id": "email:abc123",
            "account": "@alice",
            "tier": 1,
            "action": "upgrade",
        }
    ]

    receipts = finalize_poh_and_mint_gate_nfts(
        state,
        ctx={"chain_id": "chain-A", "height": 7, "ts": 123456},
    )

    assert len(receipts) == 2
    assert receipts[0]["tx_type"] == "POH_TIER_SET"
    assert receipts[1]["tx_type"] == "POF_NFT_MINT"

    acct = state["accounts"]["@alice"]
    assert acct["poh_tier"] == 1
    assert acct["gate_raw"] == "PoH1"
    assert acct["gate"] == "PoH1"

    token_id = deterministic_token_id(
        chain_id="chain-A",
        owner="@alice",
        tier=1,
        source_id="email:abc123",
    )

    tok = state["pof_nfts"]["tokens"][token_id]
    assert tok["owner"] == "@alice"
    assert tok["tier"] == 1
    assert tok["banned"] is False

    processed = state["poh"]["processed_finalizations"]["email:abc123"]
    assert processed["done"] is True
    assert processed["action"] == "upgrade"
    assert processed["height"] == 7


def test_poh_finalize_revoke_bans_exact_token_and_does_not_import_dead_module() -> None:
    state = _base_ledger()

    # First simulate an upgrade to mint the NFT
    state["poh"]["finalizations"] = [
        {
            "finalization_id": "video:case-9",
            "account": "@bob",
            "tier": 2,
            "action": "upgrade",
        }
    ]

    finalize_poh_and_mint_gate_nfts(
        state,
        ctx={"chain_id": "chain-A", "height": 10, "ts": 1000},
    )

    token_id = deterministic_token_id(
        chain_id="chain-A",
        owner="@bob",
        tier=2,
        source_id="video:case-9",
    )

    tok = state["pof_nfts"]["tokens"][token_id]
    assert tok["banned"] is False

    # Now simulate a fresh revoke-only replay context
    state["poh"]["finalizations"] = [
        {
            "finalization_id": "video:case-9",
            "account": "@bob",
            "tier": 2,
            "action": "revoke",
            "reason": "fraud",
        }
    ]

    state["poh"]["processed_finalizations"] = {}

    receipts = finalize_poh_and_mint_gate_nfts(
        state,
        ctx={"chain_id": "chain-A", "height": 11, "ts": 2000},
    )

    ban_receipts = [r for r in receipts if r.get("tx_type") == "POF_NFT_BAN"]
    assert len(ban_receipts) == 1

    tok = state["pof_nfts"]["tokens"][token_id]
    assert tok["banned"] is True
    assert tok["banned_height"] == 11
    assert tok["ban_reason"] == "fraud"

    acct = state["accounts"]["@bob"]
    assert acct["poh_tier"] == 0
    assert acct["gate_raw"] == "Tier0"
    assert acct["gate"] == "Tier0"


def test_poh_finalize_is_idempotent_for_same_finalization_id() -> None:
    state = _base_ledger()

    state["poh"]["finalizations"] = [
        {
            "finalization_id": "ceremony:xyz",
            "account": "@carol",
            "tier": 3,
            "action": "upgrade",
        }
    ]

    first = finalize_poh_and_mint_gate_nfts(
        state,
        ctx={"chain_id": "chain-A", "height": 20, "ts": 3000},
    )

    second = finalize_poh_and_mint_gate_nfts(
        state,
        ctx={"chain_id": "chain-A", "height": 21, "ts": 4000},
    )

    assert len(first) == 2
    assert second == []

    token_id = deterministic_token_id(
        chain_id="chain-A",
        owner="@carol",
        tier=3,
        source_id="ceremony:xyz",
    )

    tokens = state["pof_nfts"]["tokens"]
    assert list(tokens.keys()) == [token_id]
    assert tokens[token_id]["minted_height"] == 20
