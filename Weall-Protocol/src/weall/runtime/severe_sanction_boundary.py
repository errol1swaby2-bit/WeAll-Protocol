"""Conservative severe-account-sanction classification, no authorization.

Only explicitly represented severe account sanctions are recognized. DISPUTE_OPEN
does not yet bind a canonical sanction class; missing classification therefore
cannot establish authorization or imply constitutional coverage. All explicit
ACCOUNT_BAN receipts remain blocked in constitutional-clock mode separately.
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
    severity = dispute.get("severity") or rules.get("severity")
    sanction_class = dispute.get("sanction_class") or rules.get("sanction_class")
    severity = severity.strip().lower() if isinstance(severity, str) else ""
    sanction_class = sanction_class.strip().upper() if isinstance(sanction_class, str) else ""
    return severity in {"severe", "critical"} or sanction_class == "S4"
