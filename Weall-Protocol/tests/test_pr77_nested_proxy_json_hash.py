"""PR77 nested JSON hash parity with journal-backed inputs.

Current-version synthetic parity does not establish archived chain replay.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

import pytest

from weall.runtime.apply import content, dispute, governance, groups
from weall.runtime.bounded_rollback import (
    materialize_journaled,
    run_with_bounded_rollback,
)

HASHERS: tuple[Callable[[Any], str], ...] = (
    content._canonical_hash,
    dispute._canonical_hash,
    governance._canonical_json_hash,
    groups._group_ballot_hash,
)
_HASH_IDS = ("content", "dispute", "governance", "groups")


def test_materialization_is_safe_for_nested_json_hash_inputs() -> None:
    state = {"payload": {"vote": "yes", "details": {"stage": "final"}}}
    original = copy.deepcopy(state)

    def check(proxy: dict[str, Any]) -> tuple[str, str]:
        record = proxy["payload"]
        materialized = materialize_journaled(record)
        assert materialized == original["payload"]
        assert type(materialized) is dict
        assert type(materialized["details"]) is dict
        raw = json.dumps({"record": original["payload"]}, sort_keys=True)
        corrected = json.dumps({"record": materialized}, sort_keys=True)
        return raw, corrected

    (raw, corrected), journal_records = run_with_bounded_rollback(state, check)
    assert raw == corrected
    assert journal_records == 0
    assert state == original


@pytest.mark.parametrize("hasher", HASHERS, ids=_HASH_IDS)
def test_nested_journal_dict_hash_matches_ordinary_dict(
    hasher: Callable[[Any], str],
) -> None:
    state = {"payload": {"vote": "yes", "details": {"stage": "final"}}}

    def check(proxy: dict[str, Any]) -> tuple[str, str]:
        proxied = {"record": proxy["payload"]}
        detached = {"record": materialize_journaled(proxy["payload"])}
        return hasher(proxied), hasher(detached)

    (proxied_hash, detached_hash), records = run_with_bounded_rollback(state, check)
    assert records == 0
    assert proxied_hash == detached_hash


def test_legacy_dispute_resolution_commitment_matches_plain_state() -> None:
    initial = {
        "dispute": {},
        "resolution": {
            "action": "restore",
            "details": {"source": "preexisting-ballot", "reason": "corrected"},
        },
    }
    raw = copy.deepcopy(initial)
    bounded = copy.deepcopy(initial)

    dispute._record_deattributed_resolution_option(
        raw["dispute"], choice="yes", resolution=raw["resolution"], summary=""
    )

    def apply(proxy: dict[str, Any]) -> None:
        dispute._record_deattributed_resolution_option(
            proxy["dispute"],
            choice="yes",
            resolution=proxy["resolution"],
            summary="",
        )

    _, journal_records = run_with_bounded_rollback(bounded, apply)
    assert journal_records > 0
    assert bounded == raw
