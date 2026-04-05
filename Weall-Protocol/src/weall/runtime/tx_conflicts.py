from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping


JsonDict = dict[str, Any]


class TxFamily(str, Enum):
    CONSENSUS = "CONSENSUS"
    GOVERNANCE = "GOVERNANCE"
    ROLES = "ROLES"
    POH = "POH"
    IDENTITY = "IDENTITY"
    TREASURY = "TREASURY"
    ECONOMICS = "ECONOMICS"
    GROUPS = "GROUPS"
    CONTENT = "CONTENT"
    DISPUTE = "DISPUTE"
    CASES = "CASES"
    MODERATION = "MODERATION"
    MESSAGING = "MESSAGING"
    NETWORKING = "NETWORKING"
    NOTIFICATIONS = "NOTIFICATIONS"
    INDEXING = "INDEXING"
    REPUTATION = "REPUTATION"
    REWARDS = "REWARDS"
    PERFORMANCE = "PERFORMANCE"
    SOCIAL = "SOCIAL"
    STORAGE = "STORAGE"
    UNKNOWN = "UNKNOWN"


class BarrierClass(str, Enum):
    GLOBAL_BARRIER = "GLOBAL_BARRIER"
    AUTHORITY_BARRIER = "AUTHORITY_BARRIER"
    SUBJECT_BARRIER = "SUBJECT_BARRIER"
    SCOPED_PARALLEL = "SCOPED_PARALLEL"


@dataclass(frozen=True)
class TxConflictRule:
    tx_type: str
    family: TxFamily
    barrier_class: BarrierClass
    derived_only: bool = False
    serial_only_on_missing_fields: bool = False


@dataclass(frozen=True)
class ConflictDescriptor:
    tx_id: str
    tx_type: str
    family: TxFamily
    barrier_class: BarrierClass
    subject_keys: tuple[str, ...]
    read_keys: tuple[str, ...]
    write_keys: tuple[str, ...]
    authority_keys: tuple[str, ...]
    derived_only: bool
    serial_only_on_missing_fields: bool


LANE_BY_FAMILY: dict[TxFamily, str] = {
    TxFamily.UNKNOWN: "SERIAL",
    TxFamily.CONSENSUS: "SERIAL",
    TxFamily.IDENTITY: "IDENTITY",
    TxFamily.POH: "IDENTITY",
    TxFamily.CONTENT: "CONTENT",
    TxFamily.SOCIAL: "SOCIAL",
    TxFamily.MESSAGING: "SOCIAL",
    TxFamily.NOTIFICATIONS: "SOCIAL",
    TxFamily.REPUTATION: "SOCIAL",
    TxFamily.GOVERNANCE: "GOVERNANCE",
    TxFamily.ROLES: "GOVERNANCE",
    TxFamily.GROUPS: "GOVERNANCE",
    TxFamily.DISPUTE: "GOVERNANCE",
    TxFamily.CASES: "GOVERNANCE",
    TxFamily.MODERATION: "GOVERNANCE",
    TxFamily.TREASURY: "ECONOMICS",
    TxFamily.ECONOMICS: "ECONOMICS",
    TxFamily.REWARDS: "ECONOMICS",
    TxFamily.STORAGE: "STORAGE",
    TxFamily.INDEXING: "CONTENT",
    TxFamily.NETWORKING: "STORAGE",
    TxFamily.PERFORMANCE: "SOCIAL",
}


def _norm_str(value: Any) -> str:
    return str(value or "").strip()


def _tx_type(tx: Mapping[str, Any]) -> str:
    return _norm_str(tx.get("tx_type") or tx.get("type")).upper()


def _payload(tx: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = tx.get("payload")
    if isinstance(payload, Mapping):
        return payload
    return {}


def _field(tx: Mapping[str, Any], *names: str) -> str:
    payload = _payload(tx)
    for name in names:
        value = payload.get(name)
        if value not in (None, ""):
            return _norm_str(value)
    for name in names:
        value = tx.get(name)
        if value not in (None, ""):
            return _norm_str(value)
    return ""


def _field_many(tx: Mapping[str, Any], *names: str) -> tuple[str, ...]:
    payload = _payload(tx)
    out: list[str] = []
    for name in names:
        for source in (payload, tx):
            value = source.get(name)
            if isinstance(value, (list, tuple, set)):
                out.extend(_norm_str(v) for v in value if _norm_str(v))
            elif value not in (None, ""):
                out.append(_norm_str(value))
    return tuple(sorted(set(v for v in out if v)))


def _stable_tx_id(tx: Mapping[str, Any]) -> str:
    value = _field(tx, "tx_id")
    if value:
        return value
    return f"anon:{_tx_type(tx) or 'UNKNOWN'}"


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({str(v) for v in values if str(v).strip()}))


def _key(prefix: str, value: str) -> str:
    value = _norm_str(value)
    return f"{prefix}:{value}" if value else ""


def _signer(tx: Mapping[str, Any]) -> str:
    return _field(tx, "signer", "account_id", "user_id", "actor_id")


def _account_subject(tx: Mapping[str, Any]) -> str:
    return _field(tx, "account_id", "user_id", "subject_id", "actor_id", "target_account_id") or _signer(tx)


def _proposal_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "proposal_id", "governance_proposal_id", "upgrade_id") or _stable_tx_id(tx)


def _group_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "group_id") or _stable_tx_id(tx)


def _wallet_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "wallet_id", "treasury_id", "program_wallet_id") or _stable_tx_id(tx)


def _spend_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "spend_id", "payment_id") or _stable_tx_id(tx)


def _dispute_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "dispute_id", "case_id", "challenge_id") or _stable_tx_id(tx)


def _content_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "post_id", "content_id", "object_id") or _stable_tx_id(tx)


def _comment_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "comment_id") or _stable_tx_id(tx)


def _media_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "media_id", "cid") or _stable_tx_id(tx)


def _thread_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "thread_id", "conversation_id") or _stable_tx_id(tx)


def _peer_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "peer_id", "node_id") or _stable_tx_id(tx)


def _lease_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "lease_id", "offer_id", "challenge_id", "cid") or _stable_tx_id(tx)


def _receipt_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "receipt_id") or _stable_tx_id(tx)


def _case_type_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "case_type_id") or _stable_tx_id(tx)


def _election_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "election_id") or _stable_tx_id(tx)


def _validator_id(tx: Mapping[str, Any]) -> str:
    return _field(tx, "validator_id", "subject_id", "account_id") or _signer(tx) or _stable_tx_id(tx)


def _object_account_keys(tx: Mapping[str, Any]) -> tuple[str, ...]:
    values = _field_many(
        tx,
        "account_id",
        "user_id",
        "subject_id",
        "actor_id",
        "target_account_id",
        "target_user_id",
    )
    if not values:
        signer = _signer(tx)
        if signer:
            values = (signer,)
    return tuple(f"identity:user:{value}" for value in values)


def _object_relationship_keys(tx: Mapping[str, Any]) -> tuple[str, ...]:
    actor = _field(tx, "actor_id") or _signer(tx)
    target = _field(tx, "target_id", "target_user_id", "followee_id")
    if actor and target:
        return (f"social:edge:{actor}:{target}",)
    return ()


def _rule(tx_type: str, family: TxFamily, barrier: BarrierClass, *, derived_only: bool = False, serial_only_on_missing_fields: bool = False) -> TxConflictRule:
    return TxConflictRule(
        tx_type=tx_type,
        family=family,
        barrier_class=barrier,
        derived_only=derived_only,
        serial_only_on_missing_fields=serial_only_on_missing_fields,
    )


REGISTRY: dict[str, TxConflictRule] = {}


def _register_many(names: Iterable[str], family: TxFamily, barrier: BarrierClass, *, derived_only: bool = False, serial_only_on_missing_fields: bool = False) -> None:
    for name in names:
        REGISTRY[name] = _rule(name, family, barrier, derived_only=derived_only, serial_only_on_missing_fields=serial_only_on_missing_fields)


_register_many(
    [
        "VALIDATOR_REGISTER",
        "VALIDATOR_CANDIDATE_REGISTER",
        "VALIDATOR_CANDIDATE_APPROVE",
        "VALIDATOR_DEREGISTER",
        "VALIDATOR_SET_UPDATE",
        "BLOCK_PROPOSE",
        "BLOCK_ATTEST",
        "BLOCK_FINALIZE",
        "EPOCH_OPEN",
        "EPOCH_CLOSE",
        "SLASH_PROPOSE",
        "SLASH_VOTE",
        "SLASH_EXECUTE",
    ],
    TxFamily.CONSENSUS,
    BarrierClass.GLOBAL_BARRIER,
    serial_only_on_missing_fields=True,
)
_register_many(
    [
        "VALIDATOR_HEARTBEAT",
        "VALIDATOR_CANDIDATE_APPROVE",
        "VALIDATOR_SUSPEND",
        "VALIDATOR_REMOVE",
    ],
    TxFamily.CONSENSUS,
    BarrierClass.SUBJECT_BARRIER,
    serial_only_on_missing_fields=True,
)

_register_many(
    [
        "GOV_PROPOSAL_CREATE",
        "GOV_PROPOSAL_EDIT",
        "GOV_PROPOSAL_WITHDRAW",
        "GOV_VOTE_CAST",
        "GOV_DELEGATION_SET",
        "GOV_VOTE_REVOKE",
        "GOV_EXECUTION_RECEIPT",
        "GOV_PROPOSAL_RECEIPT",
    ],
    TxFamily.GOVERNANCE,
    BarrierClass.SUBJECT_BARRIER,
    serial_only_on_missing_fields=True,
)
_register_many(
    [
        "GOV_STAGE_SET",
        "GOV_QUORUM_SET",
        "GOV_RULES_SET",
        "GOV_VOTING_CLOSE",
        "GOV_TALLY_PUBLISH",
        "GOV_PROPOSAL_FINALIZE",
    ],
    TxFamily.GOVERNANCE,
    BarrierClass.AUTHORITY_BARRIER,
    serial_only_on_missing_fields=True,
)
_register_many(["GOV_EXECUTE", "PROTOCOL_UPGRADE_DECLARE", "PROTOCOL_UPGRADE_ACTIVATE"], TxFamily.GOVERNANCE, BarrierClass.GLOBAL_BARRIER, serial_only_on_missing_fields=True)

_register_many(
    [
        "ROLE_JUROR_ENROLL",
        "ROLE_JUROR_ACTIVATE",
        "ROLE_JUROR_SUSPEND",
        "ROLE_JUROR_REINSTATE",
        "ROLE_VALIDATOR_ACTIVATE",
        "ROLE_VALIDATOR_SUSPEND",
        "ROLE_NODE_OPERATOR_ENROLL",
        "ROLE_NODE_OPERATOR_ACTIVATE",
        "ROLE_NODE_OPERATOR_SUSPEND",
        "ROLE_EMISSARY_NOMINATE",
        "ROLE_EMISSARY_VOTE",
        "ROLE_EMISSARY_SEAT",
        "ROLE_EMISSARY_REMOVE",
        "ROLE_GOV_EXECUTOR_SET",
    ],
    TxFamily.ROLES,
    BarrierClass.AUTHORITY_BARRIER,
    serial_only_on_missing_fields=True,
)

_register_many(
    [
        "POH_APPLICATION_SUBMIT",
        "POH_EVIDENCE_DECLARE",
        "POH_EVIDENCE_BIND",
        "POH_CHALLENGE_OPEN",
        "POH_TIER2_REQUEST_OPEN",
        "POH_TIER2_JUROR_ACCEPT",
        "POH_TIER2_JUROR_DECLINE",
        "POH_TIER2_REVIEW_SUBMIT",
        "POH_TIER2_RECEIPT",
        "POH_TIER3_JUROR_ACCEPT",
        "POH_TIER3_JUROR_DECLINE",
        "POH_TIER3_ATTENDANCE_MARK",
        "POH_TIER3_VERDICT_SUBMIT",
        "POH_TIER3_RECEIPT",
    ],
    TxFamily.POH,
    BarrierClass.SUBJECT_BARRIER,
    serial_only_on_missing_fields=True,
)
_register_many(
    [
        "POH_CHALLENGE_RESOLVE",
        "POH_TIER_SET",
        "POH_TIER2_JUROR_ASSIGN",
        "POH_TIER2_FINALIZE",
        "POH_TIER3_INIT",
        "POH_TIER3_JUROR_ASSIGN",
        "POH_TIER3_FINALIZE",
        "POH_BOOTSTRAP_TIER3_GRANT",
    ],
    TxFamily.POH,
    BarrierClass.AUTHORITY_BARRIER,
    serial_only_on_missing_fields=True,
)

_register_many(
    [
        "ACCOUNT_REGISTER",
        "ACCOUNT_KEY_ADD",
        "ACCOUNT_KEY_REVOKE",
        "ACCOUNT_DEVICE_REGISTER",
        "ACCOUNT_DEVICE_REVOKE",
        "ACCOUNT_SESSION_KEY_ISSUE",
        "ACCOUNT_SESSION_KEY_REVOKE",
        "ACCOUNT_SECURITY_POLICY_SET",
        "ACCOUNT_RECOVERY_CONFIG_SET",
        "ACCOUNT_GUARDIAN_ADD",
        "ACCOUNT_GUARDIAN_REMOVE",
        "ACCOUNT_RECOVERY_REQUEST",
        "ACCOUNT_RECOVERY_APPROVE",
        "ACCOUNT_RECOVERY_CANCEL",
        "ACCOUNT_RECOVERY_RECEIPT",
    ],
    TxFamily.IDENTITY,
    BarrierClass.SUBJECT_BARRIER,
    serial_only_on_missing_fields=True,
)
_register_many(["ACCOUNT_LOCK", "ACCOUNT_UNLOCK", "ACCOUNT_RECOVERY_FINALIZE"], TxFamily.IDENTITY, BarrierClass.AUTHORITY_BARRIER, serial_only_on_missing_fields=True)

_register_many(
    [
        "TREASURY_WALLET_CREATE",
        "TREASURY_SPEND_PROPOSE",
        "TREASURY_SPEND_SIGN",
        "TREASURY_SPEND_CANCEL",
        "TREASURY_SPEND_EXPIRE",
        "TREASURY_SPEND_EXECUTE",
        "TREASURY_PROGRAM_CREATE",
        "TREASURY_PROGRAM_UPDATE",
        "TREASURY_PROGRAM_CLOSE",
        "TREASURY_AUDIT_ANCHOR_SET",
        "TREASURY_CREATE",
        "TREASURY_SIGNERS_SET",
    ],
    TxFamily.TREASURY,
    BarrierClass.SUBJECT_BARRIER,
    serial_only_on_missing_fields=True,
)
_register_many(["TREASURY_SIGNER_ADD", "TREASURY_SIGNER_REMOVE", "TREASURY_POLICY_SET"], TxFamily.TREASURY, BarrierClass.AUTHORITY_BARRIER, serial_only_on_missing_fields=True)

_register_many(["BALANCE_TRANSFER", "FEE_PAY"], TxFamily.ECONOMICS, BarrierClass.SCOPED_PARALLEL, serial_only_on_missing_fields=True)
_register_many(["ECONOMICS_ACTIVATION", "FEE_POLICY_SET", "RATE_LIMIT_POLICY_SET"], TxFamily.ECONOMICS, BarrierClass.GLOBAL_BARRIER, serial_only_on_missing_fields=True)
_register_many(["RATE_LIMIT_STRIKE_APPLY"], TxFamily.ECONOMICS, BarrierClass.AUTHORITY_BARRIER, serial_only_on_missing_fields=True)
_register_many(["MEMPOOL_REJECT_RECEIPT"], TxFamily.ECONOMICS, BarrierClass.SUBJECT_BARRIER, serial_only_on_missing_fields=True)

_register_many(
    [
        "GROUP_CREATE",
        "GROUP_UPDATE",
        "GROUP_ROLE_GRANT",
        "GROUP_ROLE_REVOKE",
        "GROUP_MEMBERSHIP_REQUEST",
        "GROUP_MEMBERSHIP_DECIDE",
        "GROUP_MEMBERSHIP_REMOVE",
        "GROUP_TREASURY_CREATE",
        "GROUP_TREASURY_SPEND_PROPOSE",
        "GROUP_TREASURY_SPEND_SIGN",
        "GROUP_TREASURY_SPEND_CANCEL",
        "GROUP_TREASURY_SPEND_EXPIRE",
        "GROUP_TREASURY_SPEND_EXECUTE",
        "GROUP_TREASURY_AUDIT_ANCHOR_SET",
        "GROUP_EMISSARY_ELECTION_CREATE",
        "GROUP_EMISSARY_BALLOT_CAST",
        "GROUP_EMISSARY_ELECTION_FINALIZE",
        "GROUP_SIGNERS_SET",
        "GROUP_MODERATORS_SET",
    ],
    TxFamily.GROUPS,
    BarrierClass.SUBJECT_BARRIER,
    serial_only_on_missing_fields=True,
)
_register_many(["GROUP_TREASURY_POLICY_SET"], TxFamily.GROUPS, BarrierClass.AUTHORITY_BARRIER, serial_only_on_missing_fields=True)

_register_many(
    [
        "CONTENT_POST_CREATE",
        "CONTENT_POST_EDIT",
        "CONTENT_POST_DELETE",
        "CONTENT_MEDIA_DECLARE",
        "CONTENT_MEDIA_BIND",
        "CONTENT_MEDIA_REPLACE",
        "CONTENT_MEDIA_UNBIND",
    ],
    TxFamily.CONTENT,
    BarrierClass.SCOPED_PARALLEL,
    serial_only_on_missing_fields=True,
)
_register_many(
    [
        "CONTENT_COMMENT_CREATE",
        "CONTENT_COMMENT_DELETE",
        "CONTENT_REACTION_SET",
        "CONTENT_FLAG",
        "CONTENT_ESCALATE_TO_DISPUTE",
    ],
    TxFamily.CONTENT,
    BarrierClass.SUBJECT_BARRIER,
    serial_only_on_missing_fields=True,
)
_register_many(["CONTENT_LABEL_SET", "CONTENT_VISIBILITY_SET", "CONTENT_THREAD_LOCK_SET"], TxFamily.CONTENT, BarrierClass.AUTHORITY_BARRIER, serial_only_on_missing_fields=True)

_register_many(
    [
        "DISPUTE_OPEN",
        "DISPUTE_EVIDENCE_DECLARE",
        "DISPUTE_EVIDENCE_BIND",
        "DISPUTE_JUROR_ACCEPT",
        "DISPUTE_JUROR_DECLINE",
        "DISPUTE_VOTE_SUBMIT",
        "DISPUTE_APPEAL",
        "DISPUTE_FINAL_RECEIPT",
    ],
    TxFamily.DISPUTE,
    BarrierClass.SUBJECT_BARRIER,
    serial_only_on_missing_fields=True,
)
_register_many(["DISPUTE_STAGE_SET", "DISPUTE_JUROR_ASSIGN", "DISPUTE_JUROR_ATTENDANCE", "DISPUTE_RESOLVE"], TxFamily.DISPUTE, BarrierClass.AUTHORITY_BARRIER, serial_only_on_missing_fields=True)

_register_many(["CASE_TYPE_REGISTER", "CASE_BIND_TO_DISPUTE", "CASE_OUTCOME_RECEIPT"], TxFamily.CASES, BarrierClass.SUBJECT_BARRIER, serial_only_on_missing_fields=True)
_register_many(["MOD_ACTION_RECEIPT", "FLAG_ESCALATION_RECEIPT"], TxFamily.MODERATION, BarrierClass.AUTHORITY_BARRIER, serial_only_on_missing_fields=True)
_register_many(["DIRECT_MESSAGE_SEND", "DIRECT_MESSAGE_REDACT"], TxFamily.MESSAGING, BarrierClass.SUBJECT_BARRIER, serial_only_on_missing_fields=True)
_register_many(["PEER_ADVERTISE", "PEER_REQUEST_CONNECT", "PEER_RENDEZVOUS_TICKET_CREATE", "PEER_RENDEZVOUS_TICKET_REVOKE"], TxFamily.NETWORKING, BarrierClass.SCOPED_PARALLEL, serial_only_on_missing_fields=True)
_register_many(["PEER_BAN_SET"], TxFamily.NETWORKING, BarrierClass.AUTHORITY_BARRIER, serial_only_on_missing_fields=True)
_register_many(["PEER_REPUTATION_SIGNAL"], TxFamily.NETWORKING, BarrierClass.SUBJECT_BARRIER, serial_only_on_missing_fields=True)
_register_many(["NOTIFICATION_SUBSCRIBE", "NOTIFICATION_UNSUBSCRIBE"], TxFamily.NOTIFICATIONS, BarrierClass.SCOPED_PARALLEL, serial_only_on_missing_fields=True)
_register_many(["NOTIFICATION_EMIT_RECEIPT"], TxFamily.NOTIFICATIONS, BarrierClass.SUBJECT_BARRIER, serial_only_on_missing_fields=True)
_register_many(
    [
        "INDEX_ANCHOR_SET",
        "STATE_SNAPSHOT_DECLARE",
        "STATE_SNAPSHOT_ACCEPT",
        "COLD_SYNC_REQUEST",
        "COLD_SYNC_COMPLETE",
        "INDEX_TOPIC_REGISTER",
        "INDEX_TOPIC_ANCHOR_SET",
        "TX_RECEIPT_EMIT",
    ],
    TxFamily.INDEXING,
    BarrierClass.SUBJECT_BARRIER,
    serial_only_on_missing_fields=True,
)
_register_many(["REPUTATION_DELTA_APPLY", "REPUTATION_THRESHOLD_CROSS"], TxFamily.REPUTATION, BarrierClass.SUBJECT_BARRIER, serial_only_on_missing_fields=True)
_register_many(["ROLE_ELIGIBILITY_SET", "ROLE_ELIGIBILITY_REVOKE", "ACCOUNT_BAN", "ACCOUNT_REINSTATE"], TxFamily.REPUTATION, BarrierClass.AUTHORITY_BARRIER, serial_only_on_missing_fields=True)
_register_many(["REWARD_POOL_OPT_IN_SET", "BLOCK_REWARD_MINT", "BLOCK_REWARD_DISTRIBUTE", "CREATOR_REWARD_ALLOCATE", "TREASURY_REWARD_ALLOCATE", "FORFEITURE_APPLY"], TxFamily.REWARDS, BarrierClass.SCOPED_PARALLEL, serial_only_on_missing_fields=True)
_register_many(["VALIDATOR_PERFORMANCE_REPORT", "NODE_OPERATOR_PERFORMANCE_REPORT", "CREATOR_PERFORMANCE_REPORT"], TxFamily.PERFORMANCE, BarrierClass.SCOPED_PARALLEL, serial_only_on_missing_fields=True)
_register_many(["PERFORMANCE_EVALUATE", "PERFORMANCE_SCORE_APPLY"], TxFamily.PERFORMANCE, BarrierClass.SUBJECT_BARRIER, serial_only_on_missing_fields=True)
_register_many(["PROFILE_UPDATE", "CONTENT_SHARE_CREATE"], TxFamily.SOCIAL, BarrierClass.SCOPED_PARALLEL, serial_only_on_missing_fields=True)
_register_many(["FOLLOW_SET", "BLOCK_SET", "MUTE_SET"], TxFamily.SOCIAL, BarrierClass.SUBJECT_BARRIER, serial_only_on_missing_fields=True)
_register_many(["IPFS_PIN_REQUEST", "STORAGE_OFFER_CREATE", "STORAGE_OFFER_WITHDRAW", "STORAGE_LEASE_CREATE", "STORAGE_LEASE_RENEW", "STORAGE_LEASE_REVOKE", "STORAGE_PROOF_SUBMIT", "STORAGE_CHALLENGE_RESPOND"], TxFamily.STORAGE, BarrierClass.SCOPED_PARALLEL, serial_only_on_missing_fields=True)
_register_many(["IPFS_PIN_CONFIRM", "STORAGE_CHALLENGE_ISSUE", "STORAGE_PAYOUT_EXECUTE", "STORAGE_REPORT_ANCHOR"], TxFamily.STORAGE, BarrierClass.SUBJECT_BARRIER, serial_only_on_missing_fields=True)


def lookup_rule(tx_type: str) -> TxConflictRule | None:
    return REGISTRY.get(_norm_str(tx_type).upper())


def lane_hint_for_family(family: TxFamily, barrier_class: BarrierClass) -> str:
    if barrier_class == BarrierClass.GLOBAL_BARRIER:
        return "SERIAL"
    return LANE_BY_FAMILY.get(family, "SERIAL")


def _barrier_keys(rule: TxConflictRule, tx: Mapping[str, Any]) -> tuple[str, ...]:
    out: list[str] = []
    if rule.barrier_class == BarrierClass.GLOBAL_BARRIER:
        out.append("barrier:global")
    elif rule.barrier_class == BarrierClass.AUTHORITY_BARRIER:
        if rule.family == TxFamily.GOVERNANCE:
            out.append("authority:governance")
        elif rule.family == TxFamily.ROLES:
            out.append("authority:roles")
        elif rule.family == TxFamily.POH:
            out.append("authority:poh")
        elif rule.family == TxFamily.IDENTITY:
            out.append("authority:identity")
        elif rule.family == TxFamily.TREASURY:
            out.append(f"authority:treasury:{_wallet_id(tx)}")
        elif rule.family == TxFamily.GROUPS:
            out.append(f"authority:groups:{_group_id(tx)}")
        elif rule.family == TxFamily.DISPUTE:
            out.append(f"authority:dispute:{_dispute_id(tx)}")
        elif rule.family == TxFamily.ECONOMICS:
            out.append("authority:economics")
        elif rule.family == TxFamily.MODERATION:
            out.append("authority:moderation")
        elif rule.family == TxFamily.NETWORKING:
            out.append(f"authority:network:{_peer_id(tx)}")
        elif rule.family == TxFamily.REPUTATION:
            out.append("authority:reputation")
        else:
            out.append(f"authority:{rule.family.value.lower()}")
    return _sorted_unique(out)


def _base_keys(rule: TxConflictRule, tx: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    subject: list[str] = []
    reads: list[str] = []
    writes: list[str] = []
    authority: list[str] = list(_barrier_keys(rule, tx))
    tx_id = _stable_tx_id(tx)

    if rule.family == TxFamily.CONSENSUS:
        vid = _validator_id(tx)
        subject.extend([_key("consensus:validator", vid)])
        writes.extend([_key("consensus:block", _field(tx, "block_id") or tx_id)])
        if rule.barrier_class == BarrierClass.GLOBAL_BARRIER:
            writes.extend(["consensus:validator_set", "consensus:validator_epoch"])
            authority.extend(["consensus:validator_set", "consensus:validator_epoch"])

    elif rule.family == TxFamily.GOVERNANCE:
        proposal_id = _proposal_id(tx)
        subject.append(_key("gov:proposal", proposal_id))
        writes.append(_key("gov:proposal", proposal_id))
        voter_id = _field(tx, "voter_id") or _signer(tx)
        if voter_id:
            writes.append(_key("gov:vote", f"{proposal_id}:{voter_id}"))
        if rule.barrier_class != BarrierClass.SUBJECT_BARRIER:
            authority.append("authority:governance")

    elif rule.family == TxFamily.ROLES:
        account_id = _account_subject(tx)
        subject.extend(_object_account_keys(tx))
        if account_id:
            writes.append(_key("roles:user", account_id))
        capability = _field(tx, "role", "capability", "role_name") or _tx_type(tx)
        writes.append(_key("roles:capability", capability))
        authority.append("authority:roles")
        if "VALIDATOR" in _tx_type(tx):
            authority.extend(["consensus:validator_set", "consensus:validator_epoch"])

    elif rule.family == TxFamily.POH:
        account_id = _account_subject(tx)
        case_id = _field(tx, "application_id", "case_id", "challenge_id") or tx_id
        if account_id:
            subject.append(_key("poh:user", account_id))
            reads.append(_key("identity:user", account_id))
            writes.append(_key("poh:user", account_id))
        subject.append(_key("poh:application", case_id))
        writes.append(_key("poh:application", case_id))
        if rule.barrier_class == BarrierClass.AUTHORITY_BARRIER and account_id:
            authority.extend([f"authority:poh:{account_id}", f"authority:identity:{account_id}"])

    elif rule.family == TxFamily.IDENTITY:
        account_id = _account_subject(tx)
        if account_id:
            subject.append(_key("identity:user", account_id))
            writes.append(_key("identity:user", account_id))
            authority.append(_key("authority:identity", account_id)) if rule.barrier_class == BarrierClass.AUTHORITY_BARRIER else None
        key_id = _field(tx, "key_id", "device_id", "session_key", "guardian_id", "request_id")
        if key_id:
            writes.append(_key("identity:subobject", f"{account_id}:{key_id}"))

    elif rule.family == TxFamily.TREASURY:
        wallet_id = _wallet_id(tx)
        spend_id = _spend_id(tx)
        subject.append(_key("treasury:wallet", wallet_id))
        writes.append(_key("treasury:wallet", wallet_id))
        if spend_id:
            writes.append(_key("treasury:spend", spend_id))
            subject.append(_key("treasury:spend", spend_id))
        if rule.barrier_class == BarrierClass.AUTHORITY_BARRIER:
            authority.append(_key("treasury:policy", wallet_id))

    elif rule.family == TxFamily.ECONOMICS:
        src = _field(tx, "from_account_id", "source_account_id", "account_id") or _signer(tx)
        dst = _field(tx, "to_account_id", "destination_account_id", "recipient_id")
        if src:
            subject.append(_key("economics:balance", src))
            writes.append(_key("economics:balance", src))
        if dst:
            subject.append(_key("economics:balance", dst))
            writes.append(_key("economics:balance", dst))
        if rule.barrier_class == BarrierClass.GLOBAL_BARRIER:
            writes.append("economics:activation")
            authority.append("economics:activation")
        elif rule.barrier_class == BarrierClass.AUTHORITY_BARRIER and src:
            authority.append(_key("economics:rate_limit_strike", src))
        elif "RECEIPT" in _tx_type(tx):
            writes.append(_key("economics:mempool_reject", _receipt_id(tx)))

    elif rule.family == TxFamily.GROUPS:
        group_id = _group_id(tx)
        subject.append(_key("groups:group", group_id))
        writes.append(_key("groups:group", group_id))
        member_id = _field(tx, "member_id", "account_id", "user_id")
        if member_id:
            writes.append(_key("groups:member", f"{group_id}:{member_id}"))
        election_id = _election_id(tx)
        if election_id and "ELECTION" in _tx_type(tx):
            writes.append(_key("groups:emissary_election", f"{group_id}:{election_id}"))
        if rule.barrier_class == BarrierClass.AUTHORITY_BARRIER:
            authority.append(_key("groups:treasury_policy", group_id))

    elif rule.family == TxFamily.CONTENT:
        content_id = _content_id(tx)
        subject.append(_key("content:post", content_id))
        writes.append(_key("content:post", content_id))
        comment_id = _field(tx, "comment_id")
        if comment_id:
            writes.append(_key("content:comment", comment_id))
        media_id = _field(tx, "media_id", "cid")
        if media_id:
            writes.append(_key("content:media", media_id))
        if rule.barrier_class == BarrierClass.AUTHORITY_BARRIER:
            authority.append(_key("content:visibility", content_id))
        if "ESCALATE" in _tx_type(tx):
            writes.append(_key("dispute:case", _dispute_id(tx)))

    elif rule.family == TxFamily.DISPUTE:
        dispute_id = _dispute_id(tx)
        subject.append(_key("dispute:case", dispute_id))
        writes.append(_key("dispute:case", dispute_id))
        juror_id = _field(tx, "juror_id")
        if juror_id:
            writes.append(_key("dispute:juror", f"{dispute_id}:{juror_id}"))
        if rule.barrier_class == BarrierClass.AUTHORITY_BARRIER:
            authority.append(_key("authority:dispute", dispute_id))

    elif rule.family == TxFamily.CASES:
        case_id = _field(tx, "case_id") or _stable_tx_id(tx)
        case_type_id = _case_type_id(tx)
        subject.append(_key("cases:binding", case_id))
        writes.extend([_key("cases:binding", case_id), _key("cases:type", case_type_id)])

    elif rule.family == TxFamily.MODERATION:
        action_id = _field(tx, "action_id", "escalation_id") or tx_id
        subject.append(_key("moderation:action", action_id))
        writes.append(_key("moderation:action", action_id))
        authority.append("authority:moderation")

    elif rule.family == TxFamily.MESSAGING:
        thread_id = _thread_id(tx)
        message_id = _field(tx, "message_id") or tx_id
        subject.append(_key("messaging:thread", thread_id))
        writes.extend([_key("messaging:thread", thread_id), _key("messaging:message", message_id)])

    elif rule.family == TxFamily.NETWORKING:
        peer_id = _peer_id(tx)
        subject.append(_key("network:peer", peer_id))
        writes.append(_key("network:peer", peer_id))
        if rule.barrier_class == BarrierClass.AUTHORITY_BARRIER:
            authority.append(_key("network:ban", peer_id))

    elif rule.family == TxFamily.NOTIFICATIONS:
        account_id = _account_subject(tx)
        topic = _field(tx, "topic") or "default"
        subject.append(_key("notifications:subscription", f"{account_id}:{topic}"))
        writes.append(_key("notifications:subscription", f"{account_id}:{topic}"))
        if "RECEIPT" in _tx_type(tx):
            writes.append(_key("notifications:emit", _receipt_id(tx)))

    elif rule.family == TxFamily.INDEXING:
        anchor = _field(tx, "anchor_id", "snapshot_id", "topic", "request_id") or tx_id
        subject.append(_key("index:anchor", anchor))
        writes.append(_key("index:anchor", anchor))

    elif rule.family == TxFamily.REPUTATION:
        account_id = _account_subject(tx)
        if account_id:
            subject.append(_key("reputation:user", account_id))
            writes.append(_key("reputation:user", account_id))
        if rule.barrier_class == BarrierClass.AUTHORITY_BARRIER and account_id:
            authority.append(_key("reputation:eligibility", account_id))

    elif rule.family == TxFamily.REWARDS:
        account_id = _field(tx, "recipient_id", "account_id", "creator_id") or _signer(tx)
        height = _field(tx, "height", "block_height")
        if account_id:
            subject.append(_key("rewards:recipient", account_id))
            writes.append(_key("rewards:recipient", account_id))
        if height:
            writes.append(_key("rewards:block", height))

    elif rule.family == TxFamily.PERFORMANCE:
        subject_id = _field(tx, "subject_id", "validator_id", "account_id") or tx_id
        subject.append(_key("performance:subject", subject_id))
        writes.append(_key("performance:score", subject_id))

    elif rule.family == TxFamily.SOCIAL:
        account_id = _account_subject(tx)
        if _tx_type(tx) in {"FOLLOW_SET", "BLOCK_SET", "MUTE_SET"}:
            subject.extend(_object_relationship_keys(tx))
            writes.extend(_object_relationship_keys(tx))
        else:
            subject.append(_key("social:profile", account_id or tx_id))
            writes.append(_key("social:profile", account_id or tx_id))

    elif rule.family == TxFamily.STORAGE:
        lease_id = _lease_id(tx)
        cid = _field(tx, "cid")
        subject.append(_key("storage:lease", lease_id))
        writes.append(_key("storage:lease", lease_id))
        if cid:
            writes.append(_key("storage:pin", cid))

    return _sorted_unique(subject), _sorted_unique(reads), _sorted_unique(writes), _sorted_unique(authority)


def build_conflict_descriptor(tx: Mapping[str, Any]) -> ConflictDescriptor:
    tx_type = _tx_type(tx)
    rule = lookup_rule(tx_type)
    tx_id = _stable_tx_id(tx)
    if rule is None:
        return ConflictDescriptor(
            tx_id=tx_id,
            tx_type=tx_type,
            family=TxFamily.UNKNOWN,
            barrier_class=BarrierClass.GLOBAL_BARRIER,
            subject_keys=(),
            read_keys=(),
            write_keys=(),
            authority_keys=("barrier:global",),
            derived_only=False,
            serial_only_on_missing_fields=True,
        )

    subject, reads, writes, authority = _base_keys(rule, tx)
    if rule.serial_only_on_missing_fields and not (subject or writes or authority):
        authority = ("barrier:global",)
    return ConflictDescriptor(
        tx_id=tx_id,
        tx_type=tx_type,
        family=rule.family,
        barrier_class=rule.barrier_class,
        subject_keys=subject,
        read_keys=reads,
        write_keys=writes,
        authority_keys=authority,
        derived_only=rule.derived_only,
        serial_only_on_missing_fields=rule.serial_only_on_missing_fields,
    )


__all__ = [
    "BarrierClass",
    "ConflictDescriptor",
    "LANE_BY_FAMILY",
    "REGISTRY",
    "TxConflictRule",
    "TxFamily",
    "build_conflict_descriptor",
    "lane_hint_for_family",
    "lookup_rule",
]
