# tests/test_gov_engine_rules_source_strict.py
from __future__ import annotations

from weall.runtime import gov_engine


def test_gov_engine_proposal_rules_never_from_payload_strict() -> None:
    """
    Strict mode invariant:
      _proposal_rules() MUST ONLY read stored proposal rules (prop["rules"])
      and MUST NEVER fall back to user-supplied payload.rules.
    """
    prop = {
        "proposal_id": "p1",
        "stage": "voting",
        "created_at_height": 1,
        # Stored rules missing/empty:
        "rules": {},
        # Attacker/user tries to override via payload.rules:
        "payload": {
            "rules": {"auto_lifecycle": False, "quorum": 999, "voting_period_blocks": 1_000_000},
        },
    }

    rules = gov_engine._proposal_rules(prop)  # pylint: disable=protected-access
    assert isinstance(rules, dict)
    assert rules == {}

    # And if stored rules exist, they win.
    prop2 = dict(prop)
    prop2["rules"] = {"auto_lifecycle": True, "quorum": 1}
    rules2 = gov_engine._proposal_rules(prop2)  # pylint: disable=protected-access
    assert rules2 == {"auto_lifecycle": True, "quorum": 1}
