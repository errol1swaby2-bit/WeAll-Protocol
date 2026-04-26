from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Callable

from weall.runtime.apply.consensus import CONSENSUS_TX_TYPES, apply_consensus
from weall.runtime.apply.content import CONTENT_TX_TYPES, apply_content
from weall.runtime.apply.dispute import DISPUTE_TX_TYPES, apply_dispute
from weall.runtime.apply.economics import ECON_TX_TYPES, apply_economics
from weall.runtime.apply.governance import apply_governance
from weall.runtime.apply.groups import GROUPS_TX_TYPES, apply_groups
from weall.runtime.apply.identity import apply_identity
from weall.runtime.apply.indexing import INDEXING_TX_TYPES, apply_indexing
from weall.runtime.apply.messaging import MESSAGING_TX_TYPES, apply_messaging
from weall.runtime.apply.networking import apply_networking
from weall.runtime.apply.notifications import NOTIFICATION_TX_TYPES, apply_notifications
from weall.runtime.apply.poh import apply_poh
from weall.runtime.apply.protocol import PROTOCOL_TX_TYPES, apply_protocol
from weall.runtime.apply.reputation import REPUTATION_TX_TYPES, apply_reputation
from weall.runtime.apply.rewards import REWARDS_TX_TYPES, apply_rewards
from weall.runtime.apply.roles import ROLES_TX_TYPES, apply_roles
from weall.runtime.apply.social import SOCIAL_TX_TYPES, apply_social
from weall.runtime.apply.storage import apply_storage
from weall.runtime.apply.treasury import TREASURY_TX_TYPES, apply_treasury
from weall.runtime.tx_schema import model_for_tx_type
from weall.tx.canon import TxIndex

Json = dict[str, Any]
ApplyFn = Callable[[Json, Any], Json | None]


# NOTE:
# These explicit sets are intentionally kept close to the actual router logic in
# the corresponding apply modules. They let CI assert that every canon tx is
# claimed by exactly one domain applier, while also permitting a few legacy
# aliases that are intentionally not part of the canonical tx index.
IDENTITY_TX_TYPES: frozenset[str] = frozenset(
    {
        "ACCOUNT_REGISTER",
        "ACCOUNT_KEY_ADD",
        "ACCOUNT_KEY_REVOKE",
        "ACCOUNT_DEVICE_REGISTER",
        "ACCOUNT_DEVICE_REVOKE",
        "ACCOUNT_SESSION_KEY_ISSUE",
        "ACCOUNT_SESSION_KEY_REVOKE",
        "ACCOUNT_GUARDIAN_ADD",
        "ACCOUNT_GUARDIAN_REMOVE",
        "ACCOUNT_SECURITY_POLICY_SET",
        "ACCOUNT_LOCK",
        "ACCOUNT_UNLOCK",
        # Legacy/non-canon identity aliases intentionally kept routable.
        "ACCOUNT_UNBAN",
        "ACCOUNT_RECOVERY_CONFIG_SET",
        "ACCOUNT_RECOVERY_PROPOSE",
        "ACCOUNT_RECOVERY_APPROVE",
        "ACCOUNT_RECOVERY_EXECUTE",
        "ACCOUNT_RECOVERY_REQUEST",
        "ACCOUNT_RECOVERY_CANCEL",
        "ACCOUNT_RECOVERY_FINALIZE",
        "ACCOUNT_RECOVERY_RECEIPT",
        "ACCOUNT_RECOVERY_VOTE",
    }
)

POH_TX_TYPES: frozenset[str] = frozenset(
    {
        "POH_APPLICATION_SUBMIT",
        "POH_EVIDENCE_DECLARE",
        "POH_EVIDENCE_BIND",
        "POH_EMAIL_RECEIPT_SUBMIT",
        "POH_TIER_SET",
        "POH_BOOTSTRAP_TIER3_GRANT",
        "POH_CHALLENGE_OPEN",
        "POH_CHALLENGE_RESOLVE",
        "POH_TIER2_REQUEST_OPEN",
        "POH_TIER3_REQUEST_OPEN",
        "POH_TIER2_JUROR_ASSIGN",
        "POH_TIER2_JUROR_ACCEPT",
        "POH_TIER2_JUROR_DECLINE",
        "POH_TIER2_REVIEW_SUBMIT",
        "POH_TIER2_FINALIZE",
        "POH_TIER2_RECEIPT",
        "POH_TIER3_INIT",
        "POH_TIER3_JUROR_ASSIGN",
        "POH_TIER3_JUROR_ACCEPT",
        "POH_TIER3_JUROR_DECLINE",
        "POH_TIER3_JUROR_REPLACE",
        "POH_TIER3_ATTENDANCE_MARK",
        "POH_TIER3_VERDICT_SUBMIT",
        "POH_TIER3_FINALIZE",
        "POH_TIER3_RECEIPT",
    }
)

GOVERNANCE_TX_TYPES: frozenset[str] = frozenset(
    {
        "GOV_PROPOSAL_CREATE",
        "GOV_PROPOSAL_EDIT",
        "GOV_PROPOSAL_WITHDRAW",
        "GOV_VOTE_CAST",
        "GOV_VOTE_REVOKE",
        "GOV_VOTING_CLOSE",
        "GOV_TALLY_PUBLISH",
        "GOV_STAGE_SET",
        "GOV_QUORUM_SET",
        "GOV_RULES_SET",
        "GOV_EXECUTE",
        "GOV_EXECUTION_RECEIPT",
        "GOV_PROPOSAL_FINALIZE",
        "GOV_PROPOSAL_RECEIPT",
    }
)

NETWORKING_TX_TYPES: frozenset[str] = frozenset(
    {
        "PEER_ADVERTISE",
        "PEER_RENDEZVOUS_TICKET_CREATE",
        "PEER_RENDEZVOUS_TICKET_REVOKE",
        "PEER_REQUEST_CONNECT",
        "PEER_BAN_SET",
        "PEER_REPUTATION_SIGNAL",
    }
)

STORAGE_TX_TYPES: frozenset[str] = frozenset(
    {
        "STORAGE_OFFER_CREATE",
        "STORAGE_OFFER_WITHDRAW",
        "STORAGE_LEASE_CREATE",
        "STORAGE_LEASE_RENEW",
        "STORAGE_LEASE_REVOKE",
        "STORAGE_PROOF_SUBMIT",
        "STORAGE_CHALLENGE_ISSUE",
        "STORAGE_CHALLENGE_RESPOND",
        "STORAGE_PAYOUT_EXECUTE",
        "STORAGE_REPORT_ANCHOR",
        "IPFS_PIN_REQUEST",
        "IPFS_PIN_CONFIRM",
    }
)

# Ordered for readability in generated artifacts.
HANDLER_REGISTRY: tuple[tuple[str, ApplyFn, frozenset[str]], ...] = (
    ("identity", apply_identity, IDENTITY_TX_TYPES),
    ("poh", apply_poh, POH_TX_TYPES),
    ("roles", apply_roles, frozenset(ROLES_TX_TYPES)),
    # Reputation canonically owns ACCOUNT_BAN; identity keeps only legacy ACCOUNT_UNBAN.
    ("reputation", apply_reputation, frozenset(REPUTATION_TX_TYPES)),
    ("content", apply_content, frozenset(CONTENT_TX_TYPES)),
    ("social", apply_social, frozenset(SOCIAL_TX_TYPES)),
    ("groups", apply_groups, frozenset(GROUPS_TX_TYPES)),
    ("messaging", apply_messaging, frozenset(MESSAGING_TX_TYPES)),
    ("notifications", apply_notifications, frozenset(NOTIFICATION_TX_TYPES)),
    ("storage", apply_storage, STORAGE_TX_TYPES),
    ("networking", apply_networking, NETWORKING_TX_TYPES),
    ("indexing", apply_indexing, frozenset(INDEXING_TX_TYPES)),
    ("economics", apply_economics, frozenset(ECON_TX_TYPES)),
    ("rewards", apply_rewards, frozenset(REWARDS_TX_TYPES)),
    ("treasury", apply_treasury, frozenset(TREASURY_TX_TYPES)),
    ("governance", apply_governance, GOVERNANCE_TX_TYPES),
    ("dispute", apply_dispute, frozenset(DISPUTE_TX_TYPES)),
    ("protocol", apply_protocol, frozenset(PROTOCOL_TX_TYPES)),
    ("consensus", apply_consensus, frozenset(CONSENSUS_TX_TYPES)),
)

_HANDLER_BY_TX_TYPE: dict[str, tuple[str, ApplyFn]] = {}

for _handler_name, _fn, _tx_types in HANDLER_REGISTRY:
    for _tx_type in _tx_types:
        _tt = str(_tx_type or "").strip().upper()
        if _tt and _tt not in _HANDLER_BY_TX_TYPE:
            _HANDLER_BY_TX_TYPE[_tt] = (_handler_name, _fn)


def handler_claims_for_tx_type(tx_type: str) -> list[str]:
    t = str(tx_type or "").strip().upper()
    if not t:
        return []
    out: list[str] = []
    for handler_name, _fn, tx_types in HANDLER_REGISTRY:
        if t in tx_types:
            out.append(handler_name)
    return out


def handler_name_for_tx_type(tx_type: str) -> str | None:
    t = str(tx_type or "").strip().upper()
    if not t:
        return None
    rec = _HANDLER_BY_TX_TYPE.get(t)
    return None if rec is None else rec[0]


def resolve_applier_for_tx_type(tx_type: str) -> ApplyFn | None:
    t = str(tx_type or "").strip().upper()
    if not t:
        return None
    rec = _HANDLER_BY_TX_TYPE.get(t)
    return None if rec is None else rec[1]


def duplicate_handler_claims(canon: TxIndex | Json) -> dict[str, list[str]]:
    idx = canon if isinstance(canon, TxIndex) else TxIndex.from_raw(canon)
    out: dict[str, list[str]] = {}
    for tx_type in idx.list_types():
        claims = handler_claims_for_tx_type(tx_type)
        if len(claims) > 1:
            out[tx_type] = claims
    return dict(sorted(out.items()))


def unclaimed_canon_tx_types(canon: TxIndex | Json) -> list[str]:
    idx = canon if isinstance(canon, TxIndex) else TxIndex.from_raw(canon)
    out = [tx_type for tx_type in idx.list_types() if not handler_claims_for_tx_type(tx_type)]
    return sorted(out)


def noncanon_registry_tx_types(canon: TxIndex | Json) -> list[str]:
    idx = canon if isinstance(canon, TxIndex) else TxIndex.from_raw(canon)
    canon_types = set(idx.list_types())
    reg_types = {tx_type for _name, _fn, tx_types in HANDLER_REGISTRY for tx_type in tx_types}
    return sorted(reg_types - canon_types)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _default_tx_index_path() -> Path:
    return _repo_root() / "generated" / "tx_index.json"


def load_default_tx_index() -> TxIndex:
    return TxIndex.load_from_file(_default_tx_index_path())


def build_tx_contract_map(canon: TxIndex | Json | None = None) -> list[Json]:
    idx = load_default_tx_index() if canon is None else (canon if isinstance(canon, TxIndex) else TxIndex.from_raw(canon))
    rows: list[Json] = []
    for tx_type in idx.list_types():
        txdef = idx.get(tx_type, {})
        txdef = txdef if isinstance(txdef, dict) else {}
        claims = handler_claims_for_tx_type(tx_type)
        rows.append(
            {
                "tx_type": tx_type,
                "domain": str(txdef.get("domain") or ""),
                "origin": str(txdef.get("origin") or ""),
                "context": str(txdef.get("context") or ""),
                "receipt_only": bool(txdef.get("receipt_only", False)),
                "handler": claims[0] if len(claims) == 1 else None,
                "claim_count": len(claims),
                "claim_handlers": claims,
                "schema_covered": model_for_tx_type(tx_type) is not None,
                "subject_gate": str(txdef.get("subject_gate") or ""),
            }
        )
    rows.sort(key=lambda row: str(row["tx_type"]))
    return rows


def tx_contract_summary(canon: TxIndex | Json | None = None) -> Json:
    rows = build_tx_contract_map(canon)
    claim_counter = Counter(int(row["claim_count"]) for row in rows)
    return {
        "tx_count": len(rows),
        "schema_covered_count": sum(1 for row in rows if bool(row["schema_covered"])),
        "unclaimed_count": int(claim_counter.get(0, 0)),
        "single_claim_count": int(claim_counter.get(1, 0)),
        "duplicate_claim_count": sum(v for k, v in claim_counter.items() if k > 1),
        "rows": rows,
    }


__all__ = [
    "ApplyFn",
    "GOVERNANCE_TX_TYPES",
    "HANDLER_REGISTRY",
    "IDENTITY_TX_TYPES",
    "NETWORKING_TX_TYPES",
    "POH_TX_TYPES",
    "STORAGE_TX_TYPES",
    "build_tx_contract_map",
    "duplicate_handler_claims",
    "handler_claims_for_tx_type",
    "handler_name_for_tx_type",
    "load_default_tx_index",
    "noncanon_registry_tx_types",
    "resolve_applier_for_tx_type",
    "tx_contract_summary",
    "unclaimed_canon_tx_types",
]
