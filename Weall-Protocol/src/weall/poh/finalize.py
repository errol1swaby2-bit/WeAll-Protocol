from __future__ import annotations

from typing import Any, Dict, List, MutableMapping, Optional

from weall.poh.apply import canonical_metadata_cid_placeholder, deterministic_token_id

Json = Dict[str, Any]


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


def _root_dict(ledger: Any) -> MutableMapping[str, Any]:
    if isinstance(ledger, MutableMapping):
        return ledger
    data = getattr(ledger, "_data", None)
    if isinstance(data, MutableMapping):
        return data
    raise PoHFinalizeError("ledger must be a mutable mapping or expose mutable _data")


def _accounts_root(ledger: Any) -> MutableMapping[str, Any]:
    root = _root_dict(ledger)
    accounts = root.get("accounts")
    if not isinstance(accounts, MutableMapping):
        accounts = {}
        root["accounts"] = accounts
    return accounts


def _poh_root(ledger: Any) -> MutableMapping[str, Any]:
    root = _root_dict(ledger)
    poh = root.get("poh")
    if not isinstance(poh, MutableMapping):
        poh = {}
        root["poh"] = poh
    return poh


def _pof_root(ledger: Any) -> MutableMapping[str, Any]:
    root = _root_dict(ledger)
    pof = root.get("pof_nfts")
    if not isinstance(pof, MutableMapping):
        pof = {}
        root["pof_nfts"] = pof
    return pof


def _pof_tokens_root(ledger: Any) -> MutableMapping[str, Any]:
    pof = _pof_root(ledger)
    tokens = pof.get("tokens")
    if not isinstance(tokens, MutableMapping):
        tokens = {}
        pof["tokens"] = tokens
    return tokens


def _pof_by_owner_root(ledger: Any) -> MutableMapping[str, Any]:
    pof = _pof_root(ledger)
    by_owner = pof.get("by_owner")
    if not isinstance(by_owner, MutableMapping):
        by_owner = {}
        pof["by_owner"] = by_owner
    return by_owner


def _ensure_account(ledger: Any, account_id: str) -> MutableMapping[str, Any]:
    if not isinstance(account_id, str) or not account_id.strip():
        raise PoHFinalizeError("account_id required")
    accounts = _accounts_root(ledger)
    acct = accounts.get(account_id)
    if not isinstance(acct, MutableMapping):
        acct = {
            "nonce": 0,
            "poh_tier": 0,
            "banned": False,
            "locked": False,
            "reputation": 0,
        }
        accounts[account_id] = acct
    acct.setdefault("nonce", 0)
    acct.setdefault("poh_tier", 0)
    acct.setdefault("banned", False)
    acct.setdefault("locked", False)
    acct.setdefault("reputation", 0)
    return acct


def _set_account_gate_raw(ledger: Any, account_id: str, gate: str) -> None:
    acct = _ensure_account(ledger, account_id)
    acct["gate_raw"] = str(gate)
    # Keep a simple mirror field for any older consumers that look for "gate".
    acct["gate"] = str(gate)


def ensure_poh_roots(ledger: Any) -> None:
    poh = _poh_root(ledger)
    if "finalizations" not in poh or poh["finalizations"] is None:
        poh["finalizations"] = []
    if "processed_finalizations" not in poh or poh["processed_finalizations"] is None:
        poh["processed_finalizations"] = {}
    if not isinstance(poh["finalizations"], list):
        raise PoHFinalizeError("poh.finalizations must be a list")
    if not isinstance(poh["processed_finalizations"], MutableMapping):
        raise PoHFinalizeError("poh.processed_finalizations must be a dict")

    _pof_tokens_root(ledger)
    _pof_by_owner_root(ledger)


def _mint_gate_nft(
    ledger: Any,
    *,
    chain_id: str,
    owner: str,
    tier: int,
    source_id: str,
    height: int,
    ts: Optional[int],
) -> Json:
    if int(tier) not in (1, 2, 3):
        raise PoHFinalizeError("tier must be 1, 2, or 3")
    acct = _ensure_account(ledger, owner)
    acct["poh_tier"] = max(int(acct.get("poh_tier") or 0), int(tier))

    token_id = deterministic_token_id(
        chain_id=chain_id,
        owner=owner,
        tier=int(tier),
        source_id=source_id,
    )

    tokens = _pof_tokens_root(ledger)
    by_owner = _pof_by_owner_root(ledger)

    existing = tokens.get(token_id)
    if isinstance(existing, MutableMapping):
        bucket = by_owner.get(owner)
        if not isinstance(bucket, MutableMapping):
            bucket = {}
            by_owner[owner] = bucket
        bucket[token_id] = True
        return {
            "ok": True,
            "token_id": token_id,
            "status": "exists",
            "tier": int(existing.get("tier", tier) or tier),
        }

    tokens[token_id] = {
        "token_id": token_id,
        "owner": owner,
        "tier": int(tier),
        "minted_height": int(height),
        "minted_ts": ts,
        "source_id": source_id,
        "metadata": {"cid": canonical_metadata_cid_placeholder(tier=int(tier))},
        "banned": False,
        "banned_height": None,
        "banned_ts": None,
        "ban_reason": None,
    }

    bucket = by_owner.get(owner)
    if not isinstance(bucket, MutableMapping):
        bucket = {}
        by_owner[owner] = bucket
    bucket[token_id] = True

    return {"ok": True, "token_id": token_id, "status": "minted", "tier": int(tier)}


def _ban_gate_nft(
    ledger: Any,
    *,
    chain_id: str,
    owner: str,
    tier: int,
    source_id: str,
    height: int,
    ts: Optional[int],
    reason: str,
) -> Json:
    token_id = deterministic_token_id(
        chain_id=chain_id,
        owner=owner,
        tier=int(tier),
        source_id=source_id,
    )
    tokens = _pof_tokens_root(ledger)
    tok = tokens.get(token_id)

    if not isinstance(tok, MutableMapping):
        tok = {
            "token_id": token_id,
            "owner": owner,
            "tier": int(tier),
            "minted_height": None,
            "minted_ts": None,
            "source_id": source_id,
            "metadata": {"cid": canonical_metadata_cid_placeholder(tier=int(tier))},
            "banned": False,
            "banned_height": None,
            "banned_ts": None,
            "ban_reason": None,
        }
        tokens[token_id] = tok

    by_owner = _pof_by_owner_root(ledger)
    bucket = by_owner.get(owner)
    if not isinstance(bucket, MutableMapping):
        bucket = {}
        by_owner[owner] = bucket
    bucket[token_id] = True

    tok["banned"] = True
    tok["banned_height"] = int(height)
    tok["banned_ts"] = ts
    tok["ban_reason"] = str(reason or "revoked")

    acct = _ensure_account(ledger, owner)
    if int(acct.get("poh_tier") or 0) <= int(tier):
        acct["poh_tier"] = 0
        acct["gate_raw"] = "Tier0"
        acct["gate"] = "Tier0"

    return {"ok": True, "token_id": token_id, "status": "banned", "tier": int(tier)}


def finalize_poh_and_mint_gate_nfts(ledger: Any, *, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Block-only finalizer.

    Reads poh.finalizations and performs deterministic SYSTEM mutations:
      - sets accounts[user].poh_tier and gate_raw/gate
      - mints deterministic PoH gate NFT for that tier
      - on revocation: bans the deterministic NFT for that exact finalization source

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
      - token ids are deterministic and replay-safe
    """
    ensure_poh_roots(ledger)
    poh = _poh_root(ledger)
    finals = poh["finalizations"]
    processed = poh["processed_finalizations"]

    height = _height(ctx)
    ts = _now(ctx)
    chain_id = _chain_id(ctx)

    receipts: List[Dict[str, Any]] = []

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
        if bool(processed.get(fid)):
            continue

        _ensure_account(ledger, acct)

        if action == "upgrade":
            _set_account_gate_raw(ledger, acct, f"PoH{tier}")
            acct_rec = _ensure_account(ledger, acct)
            acct_rec["poh_tier"] = max(int(acct_rec.get("poh_tier") or 0), int(tier))

            mint_rcpt = _mint_gate_nft(
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
                    "status": mint_rcpt.get("status"),
                    "source_id": fid,
                    "height": height,
                    "ts": ts,
                }
            )

        elif action == "revoke":
            ban_rcpt = _ban_gate_nft(
                ledger,
                chain_id=chain_id,
                owner=acct,
                tier=tier,
                source_id=fid,
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
            continue

        processed[fid] = {
            "done": True,
            "action": action,
            "account": acct,
            "tier": tier,
            "height": height,
            "ts": ts,
        }

    return receipts
