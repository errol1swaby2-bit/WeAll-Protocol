"""Fail-closed severe-sanction finalization signals; never authorization.

DISPUTE_OPEN does not yet bind canonical severe-sanction classification.
The only purpose of these signals is to HOLD finalization. All ACCOUNT_BAN
receipts remain independently blocked in constitutional-clock mode.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def is_explicit_severe_account_sanction(dispute: Any) -> bool:
    """True only for explicitly marked account-targeted severe/S4 cases."""
    if not isinstance(dispute, Mapping):
        return False
    target_type = dispute.get("target_type")
    if not isinstance(target_type, str) or target_type.strip().lower() != "account":
        return False
    rules = dispute.get("rules")
    rules = rules if isinstance(rules, Mapping) else {}
    # Inspect both levels independently: an explicit top-level "low" must not
    # override a conflicting severe/critical rule or S4 sanction class.
    severities = (dispute.get("severity"), rules.get("severity"))
    classes = (dispute.get("sanction_class"), rules.get("sanction_class"))
    return any(
        isinstance(value, str) and value.strip().lower() in {"severe", "critical"}
        for value in severities
    ) or any(
        isinstance(value, str) and value.strip().upper() == "S4"
        for value in classes
    )


def _has_explicit_account_ban_action(resolution: Any) -> bool:
    """Recognize an ACCOUNT_BAN action without treating it as valid enforcement."""
    if not isinstance(resolution, Mapping):
        return False
    actions = resolution.get("actions")
    if not isinstance(actions, list):
        return False
    return any(
        isinstance(action, Mapping)
        and isinstance(action.get("tx_type"), str)
        and action["tx_type"].strip().upper() == "ACCOUNT_BAN"
        for action in actions
    )


def requires_severe_sanction_finality_hold(
    dispute: Any, *, receipt_payload: Any = None
) -> bool:
    """Hold final receipt when explicit severe class OR ban intent is present.

    Ban intent is inspected in the submitted final receipt as well as the
    previously recorded resolutions. This does NOT verify its source, panel,
    votes, timing, appeal or constitutional validity. Unmarked/undetected
    severe cases remain a known limitation pending canonical case admission.
    """
    if is_explicit_severe_account_sanction(dispute):
        return True
    case = dispute if isinstance(dispute, Mapping) else {}
    receipt = receipt_payload if isinstance(receipt_payload, Mapping) else {}
    panel_result = case.get("appeal_panel_result")
    panel_result = panel_result if isinstance(panel_result, Mapping) else {}
    surfaces = (
        case.get("resolution"),
        case.get("final_resolution"),
        panel_result.get("resolution"),
        receipt.get("resolution"),
        receipt.get("appeal_resolution"),
    )
    return any(_has_explicit_account_ban_action(item) for item in surfaces)
