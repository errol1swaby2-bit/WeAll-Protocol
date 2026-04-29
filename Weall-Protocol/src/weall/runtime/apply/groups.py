# src/weall/runtime/apply/groups.py
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from weall.ledger.roles_schema import ensure_roles_schema, set_treasury_signers
from weall.runtime.econ_phase import deny_if_econ_disabled, deny_if_econ_time_locked
from weall.runtime.group_treasury_scheduler import (
    maybe_enqueue_group_spend_execute,
    maybe_enqueue_group_spend_expire,
)
from weall.runtime.tx_admission import TxEnvelope

Json = dict[str, Any]


@dataclass
class GroupsApplyError(Exception):
    code: str
    reason: str
    details: Json | None = None

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}"


def _as_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def _as_dict(v: Any) -> Json:
    return v if isinstance(v, dict) else {}


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _strict_positive_int_from_state(value: Any, *, field_name: str) -> int:
    try:
        parsed = int(value)
    except Exception as exc:
        raise GroupsApplyError(
            "invalid_state",
            "state_param_not_integer",
            {"field": field_name, "value": value},
        ) from exc
    if parsed <= 0:
        raise GroupsApplyError(
            "invalid_state",
            "state_param_not_positive",
            {"field": field_name, "value": value},
        )
    return parsed


def _ensure_roles_root(state: Json) -> Json:
    ensure_roles_schema(state)
    roles = state.get("roles")
    if not isinstance(roles, dict):
        roles = {}
        state["roles"] = roles
    return roles


def _ensure_groups_root(state: Json) -> Json:
    """Canonical group storage.

    IMPORTANT: authorization gates (GroupSigner/GroupModerator/Signer(group scope))
    read groups from roles.groups_by_id.

    We also mirror the dict at state['groups_by_id'] for API convenience.
    """
    roles = _ensure_roles_root(state)
    gbid = roles.get("groups_by_id")
    if not isinstance(gbid, dict):
        gbid = {}
        roles["groups_by_id"] = gbid
        state["roles"] = roles

    state["groups_by_id"] = gbid
    return gbid


def _ensure_group_spends(state: Json) -> Json:
    root = state.get("group_treasury_spends")
    if not isinstance(root, dict):
        root = {}
        state["group_treasury_spends"] = root
    return root


def _ensure_treasury_wallets(state: Json) -> Json:
    root = state.get("treasury_wallets")
    if not isinstance(root, dict):
        root = {}
        state["treasury_wallets"] = root
    return root


def _group_treasury_id(group_id: str) -> str:
    gid = _as_str(group_id).strip()
    return f"TREASURY_GROUP::{gid}"


def _active_emissary_election_for_group(state: Json, group_id: str) -> Json | None:
    elections = _ensure_group_emissary_elections(state)
    gid = _as_str(group_id).strip()
    for election in elections.values():
        if not isinstance(election, dict):
            continue
        if _as_str(election.get("group_id")).strip() != gid:
            continue
        if _as_str(election.get("status")).strip().lower() == "open":
            return election
    return None




def _active_group_treasury_spend_for_group(state: Json, group_id: str) -> Json | None:
    spends = _ensure_group_spends(state)
    gid = _as_str(group_id).strip()
    for spend in spends.values():
        if not isinstance(spend, dict):
            continue
        if _as_str(spend.get("group_id")).strip() != gid:
            continue
        status = _as_str(spend.get("status")).strip().lower()
        if status in ("executed", "canceled", "cancelled", "expired"):
            continue
        return spend
    return None

def _height_hint(state: Json, env: TxEnvelope) -> int:
    """Return the block height currently applying.

    - For system txs, system_tx_engine injects _due_height.
    - For normal txs, assume apply occurs at state.height + 1.
    """
    p = _as_dict(env.payload)
    dh = p.get("_due_height")
    if isinstance(dh, int) and dh > 0:
        return int(dh)
    return int(_as_int(state.get("height"), 0) + 1)


def _majority_threshold(n: int) -> int:
    n2 = int(n)
    if n2 <= 0:
        return 1
    return (n2 // 2) + 1


def _group_treasury_timelock_blocks(state: Json) -> int:
    """Timelock for group treasury spends.

    Priority:
      1) state.params.group_treasury_timelock_blocks
      2) state.treasury.params.timelock_blocks
      3) 0
    """
    params = state.get("params")
    if isinstance(params, dict) and "group_treasury_timelock_blocks" in params:
        v = params.get("group_treasury_timelock_blocks")
        if v is None or v == "":
            return 0
        return _strict_positive_int_from_state(
            v, field_name="params.group_treasury_timelock_blocks"
        )

    tre = state.get("treasury")
    if isinstance(tre, dict):
        tparams = tre.get("params")
        if isinstance(tparams, dict) and "timelock_blocks" in tparams:
            v2 = tparams.get("timelock_blocks")
            if v2 is None or v2 == "":
                return 0
            return _strict_positive_int_from_state(
                v2, field_name="treasury.params.timelock_blocks"
            )

    return 0


GROUPS_TX_TYPES: set[str] = {
    "GROUP_CREATE",
    "GROUP_UPDATE",
    "GROUP_ROLE_GRANT",
    "GROUP_ROLE_REVOKE",
    "GROUP_MEMBERSHIP_REQUEST",
    "GROUP_MEMBERSHIP_DECIDE",
    "GROUP_MEMBERSHIP_REMOVE",
    "GROUP_SIGNERS_SET",
    "GROUP_MODERATORS_SET",
    "GROUP_TREASURY_CREATE",
    "GROUP_TREASURY_SPEND_PROPOSE",
    "GROUP_TREASURY_SPEND_SIGN",
    "GROUP_TREASURY_SPEND_CANCEL",
    "GROUP_TREASURY_SPEND_EXECUTE",
    "GROUP_TREASURY_AUDIT_ANCHOR_SET",
    "GROUP_TREASURY_POLICY_SET",
    "GROUP_TREASURY_SPEND_EXPIRE",
    "GROUP_EMISSARY_ELECTION_CREATE",
    "GROUP_EMISSARY_BALLOT_CAST",
    "GROUP_EMISSARY_ELECTION_FINALIZE",
}


def _ensure_group_emissary_elections(state: Json) -> Json:
    root = state.get("group_emissary_elections")
    if not isinstance(root, dict):
        root = {}
        state["group_emissary_elections"] = root
    return root


def _ensure_group_emissary_ballots(state: Json) -> Json:
    root = state.get("group_emissary_ballots")
    if not isinstance(root, dict):
        root = {}
        state["group_emissary_ballots"] = root
    return root


def _uniq_sorted_accounts(xs: Any) -> list[str]:
    if not isinstance(xs, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for x in xs:
        s = _as_str(x).strip()
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return sorted(out)


def _group_member_snapshot(g: Json) -> list[str]:
    members = g.get("members")
    if not isinstance(members, dict):
        return []
    return sorted([_as_str(k).strip() for k in members.keys() if _as_str(k).strip()])


def _group_is_private(g: Json) -> bool:
    if bool(g.get("is_private", False)):
        return True

    visibility = _as_str(g.get("visibility") or g.get("privacy")).strip().lower()
    if visibility in {"private", "closed", "members"}:
        return True

    meta = g.get("meta")
    if isinstance(meta, dict):
        if bool(meta.get("is_private", False)):
            return True
        visibility = _as_str(meta.get("visibility") or meta.get("privacy")).strip().lower()
        if visibility in {"private", "closed", "members"}:
            return True

    return False


def _default_emissary_election_window_blocks(state: Json) -> int:
    """Default election window length in blocks.

    Default = 1008 blocks (~7 days at 10-minute blocks).
    Override via state.params.group_emissary_election_window_blocks.
    """
    params = state.get("params")
    if isinstance(params, dict) and "group_emissary_election_window_blocks" in params:
        v = params.get("group_emissary_election_window_blocks")
        if v is None or v == "":
            return 1008
        return _strict_positive_int_from_state(
            v, field_name="params.group_emissary_election_window_blocks"
        )
    return 1008


def _stv_winners(
    *, ballots_by_voter: dict[str, list[str]], candidates: list[str], seats: int
) -> list[str]:
    """Deterministic STV (Droop quota) with Fraction weights."""
    cands = sorted([c for c in candidates if isinstance(c, str) and c.strip()])
    if seats <= 0 or not cands:
        return []

    class _Ballot:
        __slots__ = ("prefs", "w")

        def __init__(self, prefs: list[str], w: Fraction):
            self.prefs = prefs
            self.w = w

        def next_choice(self, active: set[str]) -> str | None:
            for p in self.prefs:
                if p in active:
                    return p
            return None

    ballots: list[_Ballot] = []
    for _v, prefs in ballots_by_voter.items():
        if not isinstance(prefs, list):
            continue
        seen: set[str] = set()
        norm: list[str] = []
        for p in prefs:
            s = _as_str(p).strip()
            if not s or s not in cands or s in seen:
                continue
            seen.add(s)
            norm.append(s)
        if norm:
            ballots.append(_Ballot(norm, Fraction(1, 1)))

    active: set[str] = set(cands)
    winners: list[str] = []

    total_votes = sum((b.w for b in ballots), Fraction(0, 1))
    quota = int(total_votes / Fraction(seats + 1, 1)) + 1
    if quota <= 0:
        quota = 1

    piles: dict[str, list[_Ballot]] = {c: [] for c in active}

    def _reassign_all() -> None:
        for c in list(piles.keys()):
            piles[c] = []
        for b in ballots:
            ch = b.next_choice(active)
            if ch is None:
                continue
            piles.setdefault(ch, []).append(b)

    def _tally() -> dict[str, Fraction]:
        return {c: sum((b.w for b in piles.get(c, [])), Fraction(0, 1)) for c in active}

    _reassign_all()

    while active and len(winners) < seats:
        if len(active) <= (seats - len(winners)):
            winners.extend(sorted(active))
            active.clear()
            break

        tally = _tally()

        met = [c for c in active if tally.get(c, Fraction(0, 1)) >= Fraction(quota, 1)]
        if met:
            met.sort(key=lambda c: (-tally.get(c, Fraction(0, 1)), c))
            elect = met[0]
            winners.append(elect)

            elect_total = tally.get(elect, Fraction(0, 1))
            surplus = elect_total - Fraction(quota, 1)

            if surplus > 0 and elect_total > 0:
                tv = surplus / elect_total
                new_ballots: list[_Ballot] = []
                for b in piles.get(elect, []):
                    transfer_w = b.w * tv
                    b.w = b.w - transfer_w
                    if transfer_w > 0:
                        new_ballots.append(_Ballot(list(b.prefs), transfer_w))
                ballots.extend(new_ballots)

            active.discard(elect)
            piles.pop(elect, None)
            _reassign_all()
            continue

        low = sorted(active, key=lambda c: (tally.get(c, Fraction(0, 1)), c))[0]
        active.discard(low)
        piles.pop(low, None)
        _reassign_all()

    out: list[str] = []
    seen_out: set[str] = set()
    for w in winners:
        if w in seen_out:
            continue
        seen_out.add(w)
        out.append(w)
        if len(out) >= seats:
            break
    return out


def _apply_group_create(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    if not group_id:
        raise GroupsApplyError("invalid_payload", "missing_group_id", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    if group_id in groups:
        raise GroupsApplyError("already_exists", "group_exists", {"group_id": group_id})

    roles = _ensure_roles_root(state)
    treasuries_by_id = roles.get("treasuries_by_id")
    if not isinstance(treasuries_by_id, dict):
        treasuries_by_id = {}
        roles["treasuries_by_id"] = treasuries_by_id

    treasury_id = _group_treasury_id(group_id)
    creator = _as_str(env.signer).strip()

    # Default signer set for GroupSigner gate.
    signers = [creator] if creator else []
    threshold = 1

    if treasury_id not in treasuries_by_id:
        set_treasury_signers(state, treasury_id, signers, threshold=threshold)
        obj = treasuries_by_id.get(treasury_id)
        if isinstance(obj, dict):
            obj.setdefault("require_emissary_signers", False)
            obj.setdefault("label", "group")
            obj.setdefault("group_id", group_id)
            treasuries_by_id[treasury_id] = obj
        roles["treasuries_by_id"] = treasuries_by_id
        state["roles"] = roles

    wallets = _ensure_treasury_wallets(state)
    if treasury_id not in wallets:
        wallets[treasury_id] = {
            "wallet_id": treasury_id,
            "kind": "group",
            "group_id": group_id,
            "created_by": creator,
            "created_at_nonce": int(env.nonce),
        }
        state["treasury_wallets"] = wallets

    groups[group_id] = {
        "group_id": group_id,
        "created_by": creator,
        "charter": _as_str(payload.get("charter")).strip(),
        "meta": payload,
        "treasury_id": treasury_id,
        "signers": signers,
        "threshold": int(threshold),
        "moderators": [],
        "emissaries": [],
        "members": {creator: {"account": creator, "joined_at_nonce": int(env.nonce), "role": "creator"}} if creator else {},
    }
    return {"applied": "GROUP_CREATE", "group_id": group_id, "treasury_id": treasury_id}


def _apply_group_update(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    if not group_id:
        raise GroupsApplyError("invalid_payload", "missing_group_id", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    g["charter"] = _as_str(payload.get("charter", g.get("charter"))).strip()
    g["meta"] = payload
    groups[group_id] = g
    return {"applied": "GROUP_UPDATE", "group_id": group_id}


def _apply_group_role_grant(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    account = _as_str(payload.get("account")).strip()
    role = _as_str(payload.get("role")).strip().lower()
    if not group_id or not account or not role:
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    roles = g.get("roles")
    if not isinstance(roles, dict):
        roles = {}
    r = roles.get(role)
    if not isinstance(r, list):
        r = []
    if account not in r:
        r.append(account)
    roles[role] = sorted(set([_as_str(x).strip() for x in r if _as_str(x).strip()]))
    g["roles"] = roles
    groups[group_id] = g
    return {"applied": "GROUP_ROLE_GRANT", "group_id": group_id, "role": role, "account": account}


def _apply_group_role_revoke(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    account = _as_str(payload.get("account")).strip()
    role = _as_str(payload.get("role")).strip().lower()
    if not group_id or not account or not role:
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    roles = g.get("roles")
    if not isinstance(roles, dict):
        roles = {}
    r = roles.get(role)
    if not isinstance(r, list):
        r = []
    r2 = [x for x in r if _as_str(x).strip() != account]
    roles[role] = sorted(set([_as_str(x).strip() for x in r2 if _as_str(x).strip()]))
    g["roles"] = roles
    groups[group_id] = g
    return {"applied": "GROUP_ROLE_REVOKE", "group_id": group_id, "role": role, "account": account}


def _apply_group_membership_request(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    if not group_id:
        raise GroupsApplyError("invalid_payload", "missing_group_id", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    account = _as_str(env.signer).strip()
    members = g.get("members")
    if not isinstance(members, dict):
        members = {}

    if account in members:
        return {
            "applied": "GROUP_MEMBERSHIP_REQUEST",
            "group_id": group_id,
            "membership": "already_member",
            "account": account,
            "deduped": True,
        }

    # Public/demo groups should behave like an actual join surface, not a moderation queue.
    # Private groups still retain the explicit request -> moderator decision pipeline.
    if not _group_is_private(g):
        members[account] = {"joined_at_nonce": int(env.nonce), "joined_via": "request_auto_accept"}
        g["members"] = members
        reqs = g.get("membership_requests")
        if isinstance(reqs, dict) and account in reqs:
            reqs.pop(account, None)
            g["membership_requests"] = reqs
        groups[group_id] = g
        return {
            "applied": "GROUP_MEMBERSHIP_REQUEST",
            "group_id": group_id,
            "membership": "accepted",
            "account": account,
            "auto_accepted": True,
        }

    reqs = g.get("membership_requests")
    if not isinstance(reqs, dict):
        reqs = {}
    reqs[account] = {"requested_at_nonce": int(env.nonce), "payload": payload}
    g["membership_requests"] = reqs
    groups[group_id] = g
    return {
        "applied": "GROUP_MEMBERSHIP_REQUEST",
        "group_id": group_id,
        "membership": "pending",
        "account": account,
    }


def _apply_group_membership_decide(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    account = _as_str(payload.get("account")).strip()
    decision = _as_str(payload.get("decision")).strip().lower()
    if not group_id or not account or decision not in ("accept", "reject"):
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    reqs = g.get("membership_requests")
    if not isinstance(reqs, dict):
        reqs = {}

    if decision == "accept":
        mem = g.get("members")
        if not isinstance(mem, dict):
            mem = {}
        mem[account] = {"joined_at_nonce": int(env.nonce)}
        g["members"] = mem

    if account in reqs:
        reqs.pop(account, None)
    g["membership_requests"] = reqs
    groups[group_id] = g
    return {
        "applied": "GROUP_MEMBERSHIP_DECIDE",
        "group_id": group_id,
        "account": account,
        "decision": decision,
    }


def _apply_group_membership_remove(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    account = _as_str(payload.get("account")).strip()
    if not group_id or not account:
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    mem = g.get("members")
    if not isinstance(mem, dict):
        mem = {}
    mem.pop(account, None)
    g["members"] = mem
    groups[group_id] = g
    return {"applied": "GROUP_MEMBERSHIP_REMOVE", "group_id": group_id, "account": account}


def _apply_group_signers_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    signers_raw = payload.get("signers")
    threshold_raw = payload.get("threshold")

    if not group_id or not isinstance(signers_raw, list):
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    signers = sorted({str(s).strip() for s in signers_raw if str(s).strip()})
    if not signers:
        raise GroupsApplyError(
            "invalid_payload", "signers_required", {"tx_type": env.tx_type, "group_id": group_id}
        )

    threshold = _as_int(threshold_raw, 0)
    if threshold <= 0:
        threshold = _majority_threshold(len(signers))
    if threshold > len(signers):
        raise GroupsApplyError(
            "bad_payload",
            "threshold_exceeds_signers",
            {"group_id": group_id, "threshold": int(threshold), "n_signers": len(signers)},
        )

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    active_election = _active_emissary_election_for_group(state, group_id)
    if isinstance(active_election, dict):
        raise GroupsApplyError(
            "forbidden",
            "group_emissary_election_open",
            {
                "group_id": group_id,
                "election_id": _as_str(active_election.get("election_id") or active_election.get("id")).strip(),
            },
        )

    active_spend = _active_group_treasury_spend_for_group(state, group_id)
    if isinstance(active_spend, dict):
        raise GroupsApplyError(
            "forbidden",
            "group_treasury_spend_open",
            {
                "group_id": group_id,
                "spend_id": _as_str(active_spend.get("spend_id")).strip(),
                "status": _as_str(active_spend.get("status")).strip().lower() or "proposed",
            },
        )

    g["signers"] = list(signers)
    g["threshold"] = int(threshold)
    groups[group_id] = g

    treasury_id = _as_str(g.get("treasury_id") or _group_treasury_id(group_id)).strip()
    if treasury_id:
        try:
            set_treasury_signers(state, treasury_id, list(signers), threshold=int(threshold))
        except Exception as exc:
            raise GroupsApplyError(
                "internal_error",
                "treasury_signer_sync_failed",
                {"group_id": group_id, "treasury_id": treasury_id},
            ) from exc

    return {
        "applied": "GROUP_SIGNERS_SET",
        "group_id": group_id,
        "n_signers": len(signers),
        "threshold": int(threshold),
    }


def _apply_group_moderators_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    moderators = payload.get("moderators")

    if not group_id or not isinstance(moderators, list):
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    active_election = _active_emissary_election_for_group(state, group_id)
    if isinstance(active_election, dict):
        raise GroupsApplyError(
            "forbidden",
            "group_emissary_election_open",
            {
                "group_id": group_id,
                "election_id": _as_str(active_election.get("election_id") or active_election.get("id")).strip(),
            },
        )

    g["moderators"] = [str(m).strip() for m in moderators if str(m).strip()]
    groups[group_id] = g
    return {"applied": "GROUP_MODERATORS_SET", "group_id": group_id}


def _apply_group_treasury_create(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    treasury_id = _as_str(payload.get("treasury_id")).strip()
    if not treasury_id:
        raise GroupsApplyError("invalid_payload", "missing_treasury_id", {"tx_type": env.tx_type})
    return {"applied": "GROUP_TREASURY_CREATE", "treasury_id": treasury_id}


def _require_system(env: TxEnvelope) -> None:
    if bool(getattr(env, "system", False)) or _as_str(getattr(env, "signer", "")) == "SYSTEM":
        return
    raise GroupsApplyError(
        "forbidden", "system_tx_required", {"tx_type": env.tx_type, "signer": env.signer}
    )


def _apply_group_treasury_spend_propose(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)

    spend_id = _as_str(payload.get("spend_id")).strip()
    group_id = _as_str(payload.get("group_id")).strip()
    to = _as_str(payload.get("to")).strip()
    amount = payload.get("amount")

    if not spend_id:
        raise GroupsApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})
    if not group_id:
        raise GroupsApplyError("invalid_payload", "missing_group_id", {"tx_type": env.tx_type})
    if not to or amount is None:
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    treasury_id = _as_str(g.get("treasury_id") or _group_treasury_id(group_id)).strip()
    if not treasury_id:
        raise GroupsApplyError("invalid_state", "missing_group_treasury_id", {"group_id": group_id})

    spends = _ensure_group_spends(state)
    if spend_id in spends:
        raise GroupsApplyError("already_exists", "spend_exists", {"spend_id": spend_id})

    # Snapshot signer policy at propose-time for deterministic execution.
    signers = g.get("signers")
    if not isinstance(signers, list):
        signers = []
    allowed = sorted({str(x).strip() for x in signers if str(x).strip()})

    # If signers not initialized, allow emissary set as fallback (still deterministic).
    if not allowed:
        em = g.get("emissaries")
        if isinstance(em, list):
            allowed = sorted({str(x).strip() for x in em if str(x).strip()})

    if not allowed:
        raise GroupsApplyError(
            "forbidden", "no_authorized_signers", {"group_id": group_id, "treasury_id": treasury_id}
        )

    threshold = _as_int(g.get("threshold"), 0)
    if threshold <= 0:
        threshold = _majority_threshold(len(allowed))
    if threshold > len(allowed):
        raise GroupsApplyError(
            "forbidden",
            "threshold_exceeds_signer_set",
            {
                "group_id": group_id,
                "treasury_id": treasury_id,
                "threshold": int(threshold),
                "n_allowed": len(allowed),
            },
        )

    now_h = _height_hint(state, env)
    delay = _group_treasury_timelock_blocks(state)
    earliest = int(now_h + int(delay))

    spends[spend_id] = {
        "spend_id": spend_id,
        "group_id": group_id,
        "treasury_id": treasury_id,
        "proposed_by": _as_str(env.signer).strip(),
        "to": to,
        "amount": int(amount),
        "status": "proposed",
        "signatures": {},
        "allowed_signers": allowed,
        "threshold": int(threshold),
        "created_at_nonce": int(env.nonce),
        "created_at_height": int(now_h),
        "earliest_execute_height": int(earliest),
        "payload": payload,
    }

    # Optional expiry scheduling (off unless params.group_treasury_spend_expiry_blocks > 0)
    try:
        maybe_enqueue_group_spend_expire(state, spend=spends[spend_id])
    except Exception as exc:
        raise GroupsApplyError(
            "internal_error",
            "group_spend_expire_enqueue_failed",
            {"group_id": group_id, "spend_id": spend_id},
        ) from exc

    return {
        "applied": "GROUP_TREASURY_SPEND_PROPOSE",
        "spend_id": spend_id,
        "group_id": group_id,
        "treasury_id": treasury_id,
        "threshold": int(threshold),
        "earliest_execute_height": int(earliest),
    }


def _apply_group_treasury_spend_sign(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    signer = _as_str(env.signer).strip()

    if not spend_id or not signer:
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    spends = _ensure_group_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise GroupsApplyError("not_found", "spend_not_found", {"spend_id": spend_id})

    status = _as_str(s.get("status")).strip().lower()
    if status in ("canceled", "cancelled"):
        raise GroupsApplyError("forbidden", "spend_canceled", {"spend_id": spend_id})
    if status == "executed":
        raise GroupsApplyError("forbidden", "spend_executed", {"spend_id": spend_id})
    if status == "expired":
        raise GroupsApplyError("forbidden", "spend_expired", {"spend_id": spend_id})

    allowed = s.get("allowed_signers")
    if not isinstance(allowed, list):
        allowed = []
    allowed_set = {str(x).strip() for x in allowed if str(x).strip()}

    if signer not in allowed_set:
        raise GroupsApplyError(
            "forbidden", "not_authorized_signer", {"spend_id": spend_id, "signer": signer}
        )

    sigs = s.get("signatures")
    if not isinstance(sigs, dict):
        sigs = {}
    had = signer in {str(k).strip() for k in sigs.keys() if str(k).strip()}
    sigs[signer] = {"at_nonce": int(env.nonce), "payload": payload}
    s["signatures"] = sigs
    spends[spend_id] = s

    # If threshold now satisfied, schedule EXECUTE at earliest_execute_height.
    try:
        maybe_enqueue_group_spend_execute(state, spend=spends[spend_id])
    except Exception as exc:
        raise GroupsApplyError(
            "internal_error",
            "group_spend_execute_enqueue_failed",
            {"spend_id": spend_id, "signer": signer},
        ) from exc

    return {
        "applied": "GROUP_TREASURY_SPEND_SIGN",
        "spend_id": spend_id,
        "signer": signer,
        "deduped": had,
    }


def _apply_group_treasury_spend_cancel(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise GroupsApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})

    spends = _ensure_group_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise GroupsApplyError("not_found", "spend_not_found", {"spend_id": spend_id})

    status = _as_str(s.get("status")).strip().lower()
    if status == "executed":
        raise GroupsApplyError("forbidden", "spend_executed", {"spend_id": spend_id})
    if status == "expired":
        raise GroupsApplyError("forbidden", "spend_expired", {"spend_id": spend_id})
    if status in ("canceled", "cancelled"):
        return {"applied": "GROUP_TREASURY_SPEND_CANCEL", "spend_id": spend_id, "deduped": True}

    s["status"] = "canceled"
    s["canceled_by"] = _as_str(env.signer).strip()
    s["canceled_at_nonce"] = int(env.nonce)
    spends[spend_id] = s
    return {"applied": "GROUP_TREASURY_SPEND_CANCEL", "spend_id": spend_id}


def _apply_group_treasury_spend_execute(state: Json, env: TxEnvelope) -> Json:
    # Canon: SYSTEM-only receipt (via gov executor / system queue).
    _require_system(env)

    # Economic subsystem gating: treasury spends are economic.
    try:
        deny_if_econ_time_locked(state)
        deny_if_econ_disabled(state, tx_type="GROUP_TREASURY_SPEND_EXECUTE")
    except ValueError as e:
        raise GroupsApplyError(
            "forbidden", "economics_disabled", {"tx_type": env.tx_type, "error": str(e)}
        )

    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise GroupsApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})

    spends = _ensure_group_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise GroupsApplyError("not_found", "spend_not_found", {"spend_id": spend_id})

    status = _as_str(s.get("status")).strip().lower()
    if status == "executed":
        return {"applied": "GROUP_TREASURY_SPEND_EXECUTE", "spend_id": spend_id, "deduped": True}
    if status in ("canceled", "cancelled"):
        raise GroupsApplyError("forbidden", "spend_canceled", {"spend_id": spend_id})
    if status == "expired":
        raise GroupsApplyError("forbidden", "spend_expired", {"spend_id": spend_id})

    now_h = _height_hint(state, env)
    earliest = _as_int(s.get("earliest_execute_height"), 0)
    if earliest > 0 and int(now_h) < int(earliest):
        raise GroupsApplyError(
            "forbidden",
            "timelock_not_expired",
            {
                "spend_id": spend_id,
                "earliest_execute_height": int(earliest),
                "now_height": int(now_h),
            },
        )

    allowed = s.get("allowed_signers")
    if not isinstance(allowed, list):
        allowed = []
    allowed_set = {str(x).strip() for x in allowed if str(x).strip()}

    threshold = _as_int(s.get("threshold"), 1)
    if threshold <= 0:
        threshold = 1

    sigs = s.get("signatures")
    if not isinstance(sigs, dict):
        sigs = {}
    signed_by = {str(k).strip() for k in sigs.keys() if str(k).strip()}
    valid = {a for a in signed_by if a in allowed_set}

    if len(valid) < int(threshold):
        raise GroupsApplyError(
            "forbidden",
            "insufficient_multisig",
            {
                "spend_id": spend_id,
                "threshold": int(threshold),
                "valid_signatures": len(valid),
                "signed_by": sorted(valid),
            },
        )

    s["status"] = "executed"
    s["executed_by"] = _as_str(env.signer).strip()
    s["executed_at_nonce"] = int(env.nonce)
    s["executed_at_height"] = int(now_h)
    spends[spend_id] = s
    return {"applied": "GROUP_TREASURY_SPEND_EXECUTE", "spend_id": spend_id}


def _apply_group_treasury_policy_set(state: Json, env: TxEnvelope) -> Json:
    _require_system(env)
    payload = _as_dict(env.payload)
    gid = _as_str(payload.get("group_id")).strip()
    if not gid:
        raise GroupsApplyError("invalid_payload", "missing_group_id", {})
    groups = _ensure_groups_root(state)
    g = groups.get(gid)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": gid})
    active_spend = _active_group_treasury_spend_for_group(state, gid)
    if isinstance(active_spend, dict):
        raise GroupsApplyError(
            "forbidden",
            "group_treasury_spend_open",
            {
                "group_id": gid,
                "spend_id": _as_str(active_spend.get("spend_id")).strip(),
                "status": _as_str(active_spend.get("status")).strip().lower() or "proposed",
            },
        )

    g["treasury_policy"] = (
        payload.get("policy") if isinstance(payload.get("policy"), dict) else payload
    )
    g["treasury_policy_set_at_nonce"] = int(env.nonce)
    groups[gid] = g
    return {"applied": "GROUP_TREASURY_POLICY_SET", "group_id": gid}


def _ensure_group_spends_expired(state: Json) -> Json:
    root = state.get("group_treasury_spends_expired")
    if not isinstance(root, dict):
        root = {}
        state["group_treasury_spends_expired"] = root
    return root


def _apply_group_treasury_spend_expire(state: Json, env: TxEnvelope) -> Json:
    # Canon: SYSTEM-only receipt.
    _require_system(env)

    payload = _as_dict(env.payload)
    gid = _as_str(payload.get("group_id")).strip()
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not gid or not spend_id:
        raise GroupsApplyError(
            "invalid_payload", "missing_group_or_spend_id", {"group_id": gid, "spend_id": spend_id}
        )

    spends = _ensure_group_spends(state)
    s = spends.get(spend_id)
    if isinstance(s, dict):
        status = _as_str(s.get("status")).strip().lower()
        if status not in ("executed", "canceled", "cancelled", "expired"):
            s["status"] = "expired"
            s["expired_at_nonce"] = int(env.nonce)
            s["expired_at_height"] = int(_height_hint(state, env))
            spends[spend_id] = s

    expired = _ensure_group_spends_expired(state)
    lst = expired.get(gid)
    if not isinstance(lst, list):
        lst = []
    lst.append({"spend_id": spend_id, "at_nonce": int(env.nonce), "payload": payload})
    expired[gid] = lst
    return {"applied": "GROUP_TREASURY_SPEND_EXPIRE", "group_id": gid, "spend_id": spend_id}


def _apply_group_emissary_election_create(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    election_id = _as_str(payload.get("election_id") or payload.get("id")).strip()
    seats = _as_int(payload.get("seats") or 5, 5)
    candidates = _uniq_sorted_accounts(payload.get("candidates"))

    if not group_id:
        raise GroupsApplyError("invalid_payload", "missing_group_id", {"tx_type": env.tx_type})
    if not election_id:
        raise GroupsApplyError("invalid_payload", "missing_election_id", {"tx_type": env.tx_type})
    if seats < 5:
        seats = 5
    if not candidates:
        raise GroupsApplyError("invalid_payload", "missing_candidates", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    elections = _ensure_group_emissary_elections(state)
    if election_id in elections:
        raise GroupsApplyError("already_exists", "election_exists", {"election_id": election_id})

    now_h = _height_hint(state, env)

    start_h = _as_int(payload.get("start_height"), now_h)
    if start_h < now_h:
        start_h = now_h

    end_h = _as_int(payload.get("end_height"), 0)
    duration = _as_int(payload.get("duration_blocks"), 0)
    if end_h <= 0:
        if duration > 0:
            end_h = start_h + duration
        else:
            end_h = start_h + _default_emissary_election_window_blocks(state)

    if end_h <= start_h:
        end_h = start_h + 1

    snapshot = _group_member_snapshot(g)

    elections[election_id] = {
        "election_id": election_id,
        "group_id": group_id,
        "seats": int(seats),
        "candidates": candidates,
        "voter_snapshot": snapshot,
        "created_by": _as_str(env.signer).strip(),
        "created_at_nonce": int(env.nonce),
        "created_at_height": int(now_h),
        "start_height": int(start_h),
        "end_height": int(end_h),
        "status": "open",
        "winners": [],
        "payload": payload,
    }

    ballots_root = _ensure_group_emissary_ballots(state)
    ballots_root[election_id] = {}

    return {
        "applied": "GROUP_EMISSARY_ELECTION_CREATE",
        "group_id": group_id,
        "election_id": election_id,
        "seats": int(seats),
        "start_height": int(start_h),
        "end_height": int(end_h),
        "n_candidates": len(candidates),
        "n_voters": len(snapshot),
    }


def _apply_group_emissary_ballot_cast(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    election_id = _as_str(payload.get("election_id") or payload.get("id")).strip()
    ranking = payload.get("ranking")

    if not election_id:
        raise GroupsApplyError("invalid_payload", "missing_election_id", {"tx_type": env.tx_type})
    if not isinstance(ranking, list) or not ranking:
        raise GroupsApplyError("invalid_payload", "missing_ranking", {"tx_type": env.tx_type})

    elections = _ensure_group_emissary_elections(state)
    e = elections.get(election_id)
    if not isinstance(e, dict):
        raise GroupsApplyError("not_found", "election_not_found", {"election_id": election_id})
    if _as_str(e.get("status")).strip().lower() != "open":
        raise GroupsApplyError("forbidden", "election_not_open", {"election_id": election_id})

    now_h = _height_hint(state, env)
    start_h = _as_int(e.get("start_height"), 0)
    end_h = _as_int(e.get("end_height"), 0)
    if start_h and now_h < start_h:
        raise GroupsApplyError(
            "forbidden",
            "election_not_started",
            {"election_id": election_id, "now": now_h, "start": start_h},
        )
    if end_h and now_h >= end_h:
        raise GroupsApplyError(
            "forbidden", "election_closed", {"election_id": election_id, "now": now_h, "end": end_h}
        )

    voter = _as_str(env.signer).strip()
    snapshot = e.get("voter_snapshot")
    if isinstance(snapshot, list) and voter not in [str(x) for x in snapshot]:
        raise GroupsApplyError(
            "forbidden", "voter_not_in_snapshot", {"election_id": election_id, "voter": voter}
        )

    candidates = e.get("candidates")
    cand_set = set([str(x) for x in candidates]) if isinstance(candidates, list) else set()
    norm_rank: list[str] = []
    seen: set[str] = set()
    for x in ranking:
        s = _as_str(x).strip()
        if not s or s not in cand_set or s in seen:
            continue
        seen.add(s)
        norm_rank.append(s)
    if not norm_rank:
        raise GroupsApplyError(
            "invalid_payload", "ranking_has_no_valid_candidates", {"election_id": election_id}
        )

    ballots_root = _ensure_group_emissary_ballots(state)
    ballots = ballots_root.get(election_id)
    if not isinstance(ballots, dict):
        ballots = {}
        ballots_root[election_id] = ballots

    had = voter in ballots
    ballots[voter] = {
        "ranking": norm_rank,
        "cast_at_nonce": int(env.nonce),
        "cast_at_height": int(now_h),
        "payload": payload,
    }
    ballots_root[election_id] = ballots

    return {
        "applied": "GROUP_EMISSARY_BALLOT_CAST",
        "election_id": election_id,
        "voter": voter,
        "deduped": had,
        "n_ranked": len(norm_rank),
    }


def _apply_group_emissary_election_finalize(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    election_id = _as_str(payload.get("election_id") or payload.get("id")).strip()
    if not election_id:
        raise GroupsApplyError("invalid_payload", "missing_election_id", {"tx_type": env.tx_type})

    elections = _ensure_group_emissary_elections(state)
    e = elections.get(election_id)
    if not isinstance(e, dict):
        raise GroupsApplyError("not_found", "election_not_found", {"election_id": election_id})

    status = _as_str(e.get("status")).strip().lower()
    if status == "finalized":
        return {
            "applied": "GROUP_EMISSARY_ELECTION_FINALIZE",
            "election_id": election_id,
            "group_id": _as_str(e.get("group_id")).strip(),
            "winners": e.get("winners") if isinstance(e.get("winners"), list) else [],
            "deduped": True,
        }
    if status != "open":
        raise GroupsApplyError(
            "forbidden", "election_not_open", {"election_id": election_id, "status": status}
        )

    now_h = _height_hint(state, env)
    end_h = _as_int(e.get("end_height"), 0)
    if end_h and now_h < end_h:
        raise GroupsApplyError(
            "forbidden",
            "election_still_open",
            {"election_id": election_id, "now": now_h, "end": end_h},
        )

    group_id = _as_str(e.get("group_id")).strip()
    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    seats = _as_int(e.get("seats"), 5)
    if seats < 5:
        seats = 5
    candidates = _uniq_sorted_accounts(e.get("candidates"))

    ballots_root = _ensure_group_emissary_ballots(state)
    raw_ballots = ballots_root.get(election_id)
    ballots_by_voter: dict[str, list[str]] = {}
    if isinstance(raw_ballots, dict):
        for voter, b in raw_ballots.items():
            if isinstance(b, dict) and isinstance(b.get("ranking"), list):
                ballots_by_voter[str(voter)] = [str(x) for x in b.get("ranking")]

    winners = _stv_winners(ballots_by_voter=ballots_by_voter, candidates=candidates, seats=seats)

    if len(winners) < 5:
        remaining = [c for c in candidates if c not in winners]
        for c in remaining:
            winners.append(c)
            if len(winners) >= 5:
                break
    if len(winners) > seats:
        winners = winners[:seats]

    g["emissaries"] = winners
    g["emissaries_set_at_nonce"] = int(env.nonce)
    g["emissaries_set_at_height"] = int(now_h)

    # Align GroupSigner set with seated emissaries (canon uses GroupSigner on spend signing).
    g["signers"] = list(winners)
    g["threshold"] = int(_majority_threshold(len(winners)))

    groups[group_id] = g

    treasury_id = _as_str(g.get("treasury_id") or _group_treasury_id(group_id)).strip()
    if treasury_id:
        roles = _ensure_roles_root(state)
        treasuries_by_id = roles.get("treasuries_by_id")
        if not isinstance(treasuries_by_id, dict):
            treasuries_by_id = {}
            roles["treasuries_by_id"] = treasuries_by_id
        t_obj = treasuries_by_id.get(treasury_id)
        if isinstance(t_obj, dict):
            t_obj["require_emissary_signers"] = True
            treasuries_by_id[treasury_id] = t_obj
            roles["treasuries_by_id"] = treasuries_by_id
            state["roles"] = roles

        threshold = (len(winners) // 2) + 1
        if threshold < 2:
            threshold = 2
        set_treasury_signers(state, treasury_id, winners, threshold=threshold)

    e["status"] = "finalized"
    e["finalized_by"] = _as_str(env.signer).strip()
    e["finalized_at_nonce"] = int(env.nonce)
    e["finalized_at_height"] = int(now_h)
    e["winners"] = winners
    elections[election_id] = e

    return {
        "applied": "GROUP_EMISSARY_ELECTION_FINALIZE",
        "election_id": election_id,
        "group_id": group_id,
        "n_ballots": len(ballots_by_voter),
        "n_candidates": len(candidates),
        "seats": int(seats),
        "winners": winners,
        "treasury_id": treasury_id,
    }


def apply_groups(state: Json, env: TxEnvelope) -> Json | None:
    t = _as_str(env.tx_type).strip().upper()
    if t not in GROUPS_TX_TYPES:
        return None

    if t == "GROUP_CREATE":
        return _apply_group_create(state, env)
    if t == "GROUP_UPDATE":
        return _apply_group_update(state, env)
    if t == "GROUP_ROLE_GRANT":
        return _apply_group_role_grant(state, env)
    if t == "GROUP_ROLE_REVOKE":
        return _apply_group_role_revoke(state, env)
    if t == "GROUP_MEMBERSHIP_REQUEST":
        return _apply_group_membership_request(state, env)
    if t == "GROUP_MEMBERSHIP_DECIDE":
        return _apply_group_membership_decide(state, env)
    if t == "GROUP_MEMBERSHIP_REMOVE":
        return _apply_group_membership_remove(state, env)
    if t == "GROUP_SIGNERS_SET":
        return _apply_group_signers_set(state, env)
    if t == "GROUP_MODERATORS_SET":
        return _apply_group_moderators_set(state, env)

    if t == "GROUP_TREASURY_CREATE":
        return _apply_group_treasury_create(state, env)
    if t == "GROUP_TREASURY_SPEND_PROPOSE":
        return _apply_group_treasury_spend_propose(state, env)
    if t == "GROUP_TREASURY_SPEND_SIGN":
        return _apply_group_treasury_spend_sign(state, env)
    if t == "GROUP_TREASURY_SPEND_CANCEL":
        return _apply_group_treasury_spend_cancel(state, env)
    if t == "GROUP_TREASURY_SPEND_EXECUTE":
        return _apply_group_treasury_spend_execute(state, env)
    if t == "GROUP_TREASURY_POLICY_SET":
        return _apply_group_treasury_policy_set(state, env)
    if t == "GROUP_TREASURY_SPEND_EXPIRE":
        return _apply_group_treasury_spend_expire(state, env)

    if t == "GROUP_TREASURY_AUDIT_ANCHOR_SET":
        _require_system(env)
        return {"applied": "GROUP_TREASURY_AUDIT_ANCHOR_SET"}

    if t == "GROUP_EMISSARY_ELECTION_CREATE":
        return _apply_group_emissary_election_create(state, env)
    if t == "GROUP_EMISSARY_BALLOT_CAST":
        return _apply_group_emissary_ballot_cast(state, env)
    if t == "GROUP_EMISSARY_ELECTION_FINALIZE":
        return _apply_group_emissary_election_finalize(state, env)

    return None


__all__ = ["GroupsApplyError", "apply_groups"]
