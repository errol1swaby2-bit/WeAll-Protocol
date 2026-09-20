from __future__ import annotations

from dataclasses import dataclass, field

from weall.net.messages import JsonObject, WireMessage
from weall.net.messages import WireHeader as _WireHeader

# Dataclass-generated subclass __init__ annotations inherit the base field name
# and resolve it against this module at runtime. Keep the name available here.
WireHeader = _WireHeader


@dataclass(frozen=True, slots=True)
class HelperExecRequestMsg(WireMessage):
    block_height: int
    view: int
    leader_id: str
    helper_id: str
    validator_epoch: int
    validator_set_hash: str
    lane_id: str
    request_id: str
    lane_tx_ids: tuple[str, ...] = field(default_factory=tuple)
    txs: tuple[JsonObject, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class HelperExecCertificateMsg(WireMessage):
    block_height: int
    view: int
    lane_id: str
    helper_id: str
    request_id: str
    certificate: JsonObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HelperExecRejectMsg(WireMessage):
    block_height: int
    view: int
    lane_id: str
    helper_id: str
    request_id: str
    reason: str
    details: JsonObject | None = None
