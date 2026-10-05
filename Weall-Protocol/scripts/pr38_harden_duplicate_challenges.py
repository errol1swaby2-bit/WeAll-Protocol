from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POH = ROOT / "Weall-Protocol" / "src" / "weall" / "runtime" / "apply" / "poh.py"
TEST = ROOT / "Weall-Protocol" / "tests" / "test_p0_06a_duplicate_account_adjudication.py"


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def patch_poh() -> None:
    text = POH.read_text(encoding="utf-8")

    old_helpers = '''def _challenges(state: Json) -> Json:
    poh = _poh_root(state)
    challenges = poh.get("challenges")
    if not isinstance(challenges, dict):
        challenges = {}
        poh["challenges"] = challenges
    return challenges


def _duplicate_identity_adjudications_root(state: Json) -> Json:
'''
    new_helpers = '''def _challenges(state: Json) -> Json:
    poh = _poh_root(state)
    challenges = poh.get("challenges")
    if not isinstance(challenges, dict):
        challenges = {}
        poh["challenges"] = challenges
    return challenges


def _duplicate_identity_pair_key(account_id: str, reference_account_id: str) -> str:
    pair = sorted({_as_str(account_id).strip(), _as_str(reference_account_id).strip()})
    if len(pair) != 2 or not all(pair):
        raise ApplyError(
            "invalid_tx",
            "invalid_duplicate_identity_pair",
            {"account_id": account_id, "reference_account_id": reference_account_id},
        )
    material = json.dumps(
        {"domain": "weall.poh.duplicate_identity_pair.v1", "accounts": pair},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "poh-duplicate-pair:" + _sha256_hex(material)


def _duplicate_identity_challenge_pairs_root(state: Json) -> Json:
    poh = _poh_root(state)
    root = poh.get("duplicate_identity_challenge_pairs")
    if not isinstance(root, dict):
        root = {"active": {}, "events": []}
        poh["duplicate_identity_challenge_pairs"] = root
    active = root.get("active")
    if not isinstance(active, dict):
        active = {}
        root["active"] = active
    events = root.get("events")
    if not isinstance(events, list):
        events = []
        root["events"] = events
    return root


def _reserve_duplicate_identity_pair_challenge(
    state: Json,
    *,
    challenge_id: str,
    account_id: str,
    reference_account_id: str,
    opened_by: str,
) -> str:
    pair_key = _duplicate_identity_pair_key(account_id, reference_account_id)
    root = _duplicate_identity_challenge_pairs_root(state)
    active = _require_dict_invariant(root.get("active"), field="duplicate_identity_challenge_pairs.active")
    events = _require_list_invariant(root.get("events"), field="duplicate_identity_challenge_pairs.events")
    existing = active.get(pair_key)
    if isinstance(existing, dict):
        raise ApplyError(
            "conflict",
            "duplicate_identity_challenge_already_open",
            {
                "pair_key": pair_key,
                "challenge_id": existing.get("challenge_id"),
                "account_id": account_id,
                "reference_account_id": reference_account_id,
            },
        )
    pair_accounts = sorted([account_id, reference_account_id])
    rec: Json = {
        "pair_key": pair_key,
        "pair_accounts": pair_accounts,
        "challenge_id": challenge_id,
        "opened_by": opened_by,
        "status": "pending_adjudication",
        "opened_height": int(state.get("height") or 0),
    }
    active[pair_key] = rec
    events.append({"event": "duplicate_identity_pair_challenge_reserved", **rec})
    return pair_key


def _release_duplicate_identity_pair_challenge(
    state: Json,
    *,
    challenge: Json,
    outcome: str,
) -> None:
    pair_key = _as_str(challenge.get("identity_pair_key") or "").strip()
    if not pair_key:
        return
    root = _duplicate_identity_challenge_pairs_root(state)
    active = _require_dict_invariant(root.get("active"), field="duplicate_identity_challenge_pairs.active")
    events = _require_list_invariant(root.get("events"), field="duplicate_identity_challenge_pairs.events")
    challenge_id = _as_str(challenge.get("challenge_id") or "").strip()
    current = active.get(pair_key)
    if isinstance(current, dict) and _as_str(current.get("challenge_id") or "").strip() == challenge_id:
        active.pop(pair_key, None)
    events.append(
        {
            "event": "duplicate_identity_pair_challenge_released",
            "pair_key": pair_key,
            "challenge_id": challenge_id,
            "outcome": _as_str(outcome).strip().lower(),
            "height": int(state.get("height") or 0),
        }
    )


def _duplicate_identity_adjudications_root(state: Json) -> Json:
'''
    text = replace_once(text, old_helpers, new_helpers, label="pair helpers")

    old_open = '''def apply_poh_challenge_open(state: Json, env: Any) -> Json:
    p = _payload(env)
    account_id = _as_str(p.get("account_id") or "").strip()
    reference_account_id = _as_str(p.get("reference_account_id") or "").strip()
    reason = _as_str(p.get("reason") or "").strip()
    if not account_id:
        raise ApplyError("invalid_tx", "missing_account_id", {})

    if reference_account_id:
        if reference_account_id == account_id:
            raise ApplyError(
                "invalid_tx",
                "duplicate_reference_matches_target",
                {"account_id": account_id},
            )
        _require_registered_account(state, account_id)
        _require_registered_account(
            state,
            reference_account_id,
            reason="reference_account_not_registered",
        )
        if _active_duplicate_identity_record(state, reference_account_id) is not None:
            raise ApplyError(
                "invalid_tx",
                "reference_account_is_confirmed_duplicate",
                {"reference_account_id": reference_account_id},
            )

    cid = _challenge_id(account_id=account_id, nonce=_as_int(_get_env(env, "nonce", 0)))
    ch = {
        "challenge_id": cid,
        "account_id": account_id,
        "opened_by": _signer(env),
        "reason": reason,
        "status": "open",
    }
    if reference_account_id:
        ch["reference_account_id"] = reference_account_id
        ch["challenge_kind"] = "duplicate_identity"
    case_id = _as_str(p.get("case_id") or p.get("target_case_id") or "").strip()
    if case_id:
        ch["case_id"] = case_id

    challenges = _challenges(state)
    challenges[cid] = ch

    return {"applied": "POH_CHALLENGE_OPEN", "challenge_id": cid}
'''
    new_open = '''def apply_poh_challenge_open(state: Json, env: Any) -> Json:
    p = _payload(env)
    account_id = _as_str(p.get("account_id") or "").strip()
    reference_account_id = _as_str(p.get("reference_account_id") or "").strip()
    reason = _as_str(p.get("reason") or "").strip()
    if not account_id:
        raise ApplyError("invalid_tx", "missing_account_id", {})

    cid = _challenge_id(account_id=account_id, nonce=_as_int(_get_env(env, "nonce", 0)))
    challenger = _signer(env)
    pair_key = ""
    if reference_account_id:
        _require_account_min_tier(
            state,
            challenger,
            min_tier=1,
            reason="duplicate_challenge_requires_verified_human",
        )
        if reference_account_id == account_id:
            raise ApplyError(
                "invalid_tx",
                "duplicate_reference_matches_target",
                {"account_id": account_id},
            )
        _require_registered_account(state, account_id)
        _require_registered_account(
            state,
            reference_account_id,
            reason="reference_account_not_registered",
        )
        if _active_duplicate_identity_record(state, account_id) is not None:
            raise ApplyError(
                "conflict",
                "challenged_account_is_confirmed_duplicate",
                {"account_id": account_id},
            )
        if _active_duplicate_identity_record(state, reference_account_id) is not None:
            raise ApplyError(
                "invalid_tx",
                "reference_account_is_confirmed_duplicate",
                {"reference_account_id": reference_account_id},
            )
        pair_key = _reserve_duplicate_identity_pair_challenge(
            state,
            challenge_id=cid,
            account_id=account_id,
            reference_account_id=reference_account_id,
            opened_by=challenger,
        )

    ch = {
        "challenge_id": cid,
        "account_id": account_id,
        "opened_by": challenger,
        "reason": reason,
        "status": "open",
    }
    if reference_account_id:
        ch["reference_account_id"] = reference_account_id
        ch["challenge_kind"] = "duplicate_identity"
        ch["identity_pair_key"] = pair_key
        ch["adjudication_status"] = "pending_unpredictable_entropy"
        ch["reviewer_selection_status"] = "deferred_pending_a20_entropy"
        ch["authority_effect"] = "none_pending_adjudication"
    case_id = _as_str(p.get("case_id") or p.get("target_case_id") or "").strip()
    if case_id:
        ch["case_id"] = case_id

    challenges = _challenges(state)
    challenges[cid] = ch

    return {"applied": "POH_CHALLENGE_OPEN", "challenge_id": cid}
'''
    text = replace_once(text, old_open, new_open, label="challenge open")

    old_resolve_head = '''def apply_poh_challenge_resolve(state: Json, env: Any) -> Json:
    p = _payload(env)
'''
    new_resolve_head = '''def apply_poh_challenge_resolve(state: Json, env: Any) -> Json:
    _require_system_tx(env, "POH_CHALLENGE_RESOLVE")
    p = _payload(env)
'''
    text = replace_once(text, old_resolve_head, new_resolve_head, label="system-only resolve")

    old_overturn = '''        ch["status"] = "resolved_overturned"
        ch["resolution"] = "dismissed"
        ch["consequence"] = {
'''
    new_overturn = '''        ch["status"] = "resolved_overturned"
        ch["resolution"] = "dismissed"
        ch["adjudication_status"] = "adjudicated_overturned"
        _release_duplicate_identity_pair_challenge(
            state,
            challenge=ch,
            outcome="overturned",
        )
        ch["consequence"] = {
'''
    text = replace_once(text, old_overturn, new_overturn, label="overturn pair release")

    old_final = '''    return {
        "applied": "POH_CHALLENGE_RESOLVE",
        "challenge_id": cid,
        "resolution": resolution,
        "consequence": consequence,
    }


ASYNC_SENSITIVE_IDENTITY_FIELD_DENYLIST'''
    new_final = '''    if reference_account_id:
        ch["adjudication_status"] = f"adjudicated_{resolution}"
        _release_duplicate_identity_pair_challenge(
            state,
            challenge=ch,
            outcome=resolution,
        )

    return {
        "applied": "POH_CHALLENGE_RESOLVE",
        "challenge_id": cid,
        "resolution": resolution,
        "consequence": consequence,
    }


ASYNC_SENSITIVE_IDENTITY_FIELD_DENYLIST'''
    text = replace_once(text, old_final, new_final, label="resolved pair release")

    POH.write_text(text, encoding="utf-8")


def patch_tests() -> None:
    text = TEST.read_text(encoding="utf-8")
    addition = '''


def test_duplicate_challenge_requires_verified_human_challenger() -> None:
    state = _state()
    state["accounts"]["unverified"] = {"nonce": 0, "poh_tier": 0, "poh_status": "none"}  # type: ignore[index]

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _env(
                "POH_CHALLENGE_OPEN",
                {
                    "account_id": "duplicate",
                    "reference_account_id": "primary",
                    "reason": "duplicate-human-suspected",
                },
                signer="unverified",
                nonce=1,
            ),
        )
    assert excinfo.value.reason == "duplicate_challenge_requires_verified_human"


def test_duplicate_challenge_open_is_non_punitive_and_entropy_deferred() -> None:
    state = _state()
    challenge_id = _open_duplicate_challenge(state)

    challenge = state["poh"]["challenges"][challenge_id]  # type: ignore[index]
    assert challenge["adjudication_status"] == "pending_unpredictable_entropy"
    assert challenge["reviewer_selection_status"] == "deferred_pending_a20_entropy"
    assert challenge["authority_effect"] == "none_pending_adjudication"
    assert state["accounts"]["duplicate"]["poh_tier"] == 2  # type: ignore[index]
    assert state["accounts"]["duplicate"]["poh_status"] == "active"  # type: ignore[index]


def test_duplicate_pair_allows_only_one_active_direction_and_reopens_after_dismissal() -> None:
    state = _state()
    challenge_id = _open_duplicate_challenge(state)

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _env(
                "POH_CHALLENGE_OPEN",
                {
                    "account_id": "primary",
                    "reference_account_id": "duplicate",
                    "reason": "same-pair-reversed",
                },
                signer="challenger",
                nonce=2,
            ),
        )
    assert excinfo.value.reason == "duplicate_identity_challenge_already_open"

    _resolve(state, challenge_id, "dismissed")
    reopened = apply_tx(
        state,
        _env(
            "POH_CHALLENGE_OPEN",
            {
                "account_id": "primary",
                "reference_account_id": "duplicate",
                "reason": "new-evidence-after-dismissal",
            },
            signer="challenger",
            nonce=3,
        ),
    )
    assert reopened["challenge_id"] != challenge_id


def test_duplicate_challenge_resolution_is_apply_layer_system_only() -> None:
    state = _state()
    challenge_id = _open_duplicate_challenge(state)

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _env(
                "POH_CHALLENGE_RESOLVE",
                {"challenge_id": challenge_id, "resolution": "upheld"},
                signer="challenger",
                nonce=2,
                system=False,
                parent="poh:duplicate-identity-adjudication",
            ),
        )
    assert excinfo.value.reason == "system_only"
'''
    if "test_duplicate_challenge_requires_verified_human_challenger" in text:
        raise RuntimeError("tests already patched")
    TEST.write_text(text.rstrip() + addition + "\n", encoding="utf-8")


def main() -> None:
    patch_poh()
    patch_tests()


if __name__ == "__main__":
    main()
