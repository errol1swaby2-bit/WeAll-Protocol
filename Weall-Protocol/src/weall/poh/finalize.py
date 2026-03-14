# src/weall/poh/finalize.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from weall.ledger.state import LedgerView
from weall.poh.apply import apply_pof_nft_mint, apply_pof_nft_ban


class PoHFinalizeError(Exception):
    pass


def _now(ctx: Dict[str, Any]) -> Optional[int]:
    v = ctx.get("ts")
    if isinstance(v, int):
        return v
    v = ctx.get("block_ts")
    if isinstance(v, int):
        return v
    return None


def _height(ctx: Dict[str, Any]) -> int:
    v = ctx.get("height")
    if isinstance(v, int):
        return v
    return 0


def _chain_id(ctx: Dict[str, Any]) -> str:
    v = ctx.get("chain_id")
    return str(v) if isinstance(v, str) and v else "weall-dev"


def ensure_poh_roots(ledger: LedgerView) -> None:
    poh = ledger.poh()
    if "finalizations" not in poh or poh["finalizations"] is None:
        poh["finalizations"] = []
    if "processed_finalizations" not in poh or poh["processed_finalizations"] is None:
        poh["processed_finalizations"] = {}
    if not isinstance(poh["finalizations"], list):
        raise PoHFinalizeError("poh.finalizations must be a list")
    if not isinstance(poh["processed_finalizations"], dict):
        raise PoHFinalizeError("poh.processed_finalizations must be a dict")


def finalize_poh_and_mint_gate_nfts(ledger: LedgerView, *, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Block-only finalizer.
    Reads poh.finalizations and performs deterministic SYSTEM mutations:
      - sets accounts[user].gate raw to PoH{tier}
      - mints PoF gate NFT for that tier (Tier1/2/3)
      - on revocation: marks the relevant NFT as banned (does not burn)

    Input contract: each finalization entry is a dict like:
      {
        "finalization_id": "email:abc123" | "video:..." | "ceremony:...",
        "account": "@alice",
        "tier": 1|2|3,
        "action": "upgrade" | "revoke",
        "reason": "optional",
      }

    Idempotency:
      - processed_finalizations[finalization_id] prevents double-processing
      - mint is itself idempotent by deterministic token id
    """
    ensure_poh_roots(ledger)
    poh = ledger.poh()
    finals = poh["finalizations"]
    processed = poh["processed_finalizations"]

    height = _height(ctx)
    ts = _now(ctx)
    chain_id = _chain_id(ctx)

    receipts: List[Dict[str, Any]] = []

    # Process in order, but only once per finalization_id
    for entry in list(finals):
        if not isinstance(entry, dict):
            continue
        fid = str(entry.get("finalization_id") or "").strip()
        acct = str(entry.get("account") or "").strip()
        action = str(entry.get("action") or "upgrade").strip().lower()
        try:
            tier = int(entry.get("tier", 0))
        except Exception:
            tier = 0
        reason = str(entry.get("reason") or "").strip()

        if not fid or not acct or tier not in (1, 2, 3):
            continue
        if processed.get(fid):
            continue

        ledger.ensure_account(acct)

        if action == "upgrade":
            # 1) set raw gate to PoH{tier}
            ledger.set_account_gate_raw(acct, f"PoH{tier}")

            # 2) mint PoF gate NFT (tier)
            mint_rcpt = apply_pof_nft_mint(
                ledger,
                chain_id=chain_id,
                owner=acct,
                tier=tier,
                source_id=fid,
                height=height,
                ts=ts,
            )

            receipts.append(
                {
                    "ok": True,
                    "tx_type": "POH_TIER_SET",
                    "account": acct,
                    "tier": tier,
                    "source_id": fid,
                    "height": height,
                    "ts": ts,
                }
            )
            receipts.append(
                {
                    "ok": True,
                    "tx_type": "POF_NFT_MINT",
                    "account": acct,
                    "tier": tier,
                    "token_id": mint_rcpt.get("token_id"),
                    "source_id": fid,
                    "height": height,
                    "ts": ts,
                }
            )

        elif action == "revoke":
            # Mark the user's *current tier NFT* banned.
            # We deterministically compute token_id from same scheme:
            # token_id = sha256(chain_id|POF_GATE|owner|tier|finalization_id)
            # If you want revocation to ban *all* tiers, iterate tier=1..3 here.
            from weall.pof_nft.apply import deterministic_token_id  # local import to avoid cycles

            token_id = deterministic_token_id(chain_id=chain_id, owner=acct, tier=tier, source_id=fid)
            ban_rcpt = apply_pof_nft_ban(
                ledger,
                token_id=token_id,
                height=height,
                ts=ts,
                reason=reason or "revoked",
            )

            receipts.append(
                {
                    "ok": True,
                    "tx_type": "POF_NFT_BAN",
                    "account": acct,
                    "tier": tier,
                    "token_id": ban_rcpt.get("token_id"),
                    "reason": reason or "revoked",
                    "source_id": fid,
                    "height": height,
                    "ts": ts,
                }
            )
        else:
            # unknown action, skip
            continue

        processed[fid] = True

    return receipts
