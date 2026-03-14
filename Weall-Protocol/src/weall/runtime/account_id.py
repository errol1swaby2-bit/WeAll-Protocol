# src/weall/runtime/account_id.py
from __future__ import annotations

"""Account / signer id validation.

Production policy (default):
  - User/validator accounts are identified by an @-prefixed handle.

Why this exists
--------------
Multiple layers (HTTP boundary, mempool admission, apply-time) need to agree on
what a "valid" signer/account id looks like. Centralizing the rule prevents
inconsistent bypasses (e.g. nonce checks only applying to some ids).

Environment
-----------
- In WEALL_MODE=prod: we enforce the strict @handle format.
- In WEALL_MODE=testnet: we allow legacy ids (looser) to keep dev/test tooling
  usable, but you can still force strictness by setting WEALL_STRICT_ACCOUNT_ID=1.
"""

import os
import re

# Conservative, URL/UI friendly handle:
#   @ + 1..32 of lowercase letters, digits, underscore
_ACCOUNT_ID_RE = re.compile(r"^@[a-z0-9_]{1,32}$")


def strict_account_ids_enabled() -> bool:
    mode = (os.environ.get("WEALL_MODE") or "testnet").strip().lower()
    if (os.environ.get("WEALL_STRICT_ACCOUNT_ID") or "").strip() == "1":
        return True
    return bool(mode == "prod")


def is_valid_account_id(s: str) -> bool:
    """Return True if s is a valid account id under the current policy."""
    s2 = str(s or "").strip()
    if not s2:
        return False

    if strict_account_ids_enabled():
        return bool(_ACCOUNT_ID_RE.match(s2))

    # Testnet/dev: tolerate legacy ids to avoid breaking existing tools/tests.
    # Still reject obvious junk.
    if len(s2) > 128:
        return False
    if any(ch.isspace() for ch in s2):
        return False
    return True


def require_valid_account_id(s: str) -> str:
    """Return normalized id if valid; raise ValueError otherwise."""
    s2 = str(s or "").strip()
    if not is_valid_account_id(s2):
        raise ValueError("invalid_account_id")
    return s2
