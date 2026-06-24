from __future__ import annotations

"""Public-only messaging apply guard.

WeAll no longer supports protocol-native direct/private messaging, encrypted
message threads, or encrypted social payloads.  The module is retained only as a
stable dispatcher/contract hook for legacy ``DIRECT_MESSAGE_*`` transaction
names.  Every legacy messaging transaction is rejected deterministically before
any messaging state can be created.
"""

from dataclasses import dataclass
from typing import Any

from weall.runtime.tx_admission import TxEnvelope

Json = dict[str, Any]

PRIVATE_MESSAGING_UNSUPPORTED = "PRIVATE_MESSAGING_UNSUPPORTED"
PRIVATE_MESSAGING_REASON = "protocol_native_direct_messages_are_unsupported"


@dataclass
class MessagingApplyError(RuntimeError):
    code: str
    reason: str
    details: Json

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}:{self.details}"


MESSAGING_TX_TYPES: set[str] = {
    "DIRECT_MESSAGE_SEND",
    "DIRECT_MESSAGE_REDACT",
}


def apply_messaging(state: Json, env: TxEnvelope) -> Json | None:
    """Reject legacy direct-message transactions deterministically.

    The shared public-only policy rejects these txs at admission and replay.
    This direct applier guard closes bypasses from test harnesses, migrations,
    import/replay tools, or future dispatcher changes that might call the domain
    applier directly.
    """

    t = str(env.tx_type or "").strip().upper()
    if t not in MESSAGING_TX_TYPES:
        return None
    raise MessagingApplyError(
        PRIVATE_MESSAGING_UNSUPPORTED,
        PRIVATE_MESSAGING_REASON,
        {"tx_type": t},
    )
