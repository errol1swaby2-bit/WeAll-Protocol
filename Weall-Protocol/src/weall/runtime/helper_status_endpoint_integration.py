from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from weall.runtime.helper_status_surface import HelperStatusSurface


Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class NodeStatusEnvelope:
    ok: bool
    chain_id: str
    mode: str
    helper: Json

    def to_json(self) -> Json:
        return {
            "ok": self.ok,
            "chain_id": self.chain_id,
            "mode": self.mode,
            "helper": dict(self.helper),
        }


@dataclass(frozen=True, slots=True)
class ReadyzEnvelope:
    ready: bool
    chain_id: str
    helper_status: str
    helper_severity: str
    helper_summary: str

    def to_json(self) -> Json:
        return {
            "ready": self.ready,
            "chain_id": self.chain_id,
            "helper_status": self.helper_status,
            "helper_severity": self.helper_severity,
            "helper_summary": self.helper_summary,
        }


def build_node_status_envelope(
    *,
    chain_id: str,
    base_ok: bool,
    base_mode: str,
    helper_surface: HelperStatusSurface,
) -> NodeStatusEnvelope:
    """
    Repo-native integration surface for node status endpoints.

    This does not define the entire status schema of the node. It provides a
    stable helper-aware sub-envelope that can be merged into an existing status
    response without changing the helper safety boundary.
    """
    return NodeStatusEnvelope(
        ok=bool(base_ok),
        chain_id=str(chain_id),
        mode=str(base_mode),
        helper=helper_surface.to_json(),
    )


def build_readyz_envelope(
    *,
    chain_id: str,
    base_ready: bool,
    helper_surface: HelperStatusSurface,
) -> ReadyzEnvelope:
    """
    Repo-native integration surface for readyz-style probes.

    Policy:
    - if the base node is not ready, readyz must fail regardless of helper state
    - if base node is ready, helper status is surfaced but does not block readyz
      unless startup was already blocked upstream
    """
    helper_payload = helper_surface.to_json()
    helper_status = str(helper_payload.get("helper_status") or "")
    helper_severity = str(helper_payload.get("helper_severity") or "")
    helper_summary = str(helper_payload.get("helper_summary") or "")

    ready = bool(base_ready)
    if helper_status == "blocked":
        ready = False

    return ReadyzEnvelope(
        ready=ready,
        chain_id=str(chain_id),
        helper_status=helper_status,
        helper_severity=helper_severity,
        helper_summary=helper_summary,
    )
