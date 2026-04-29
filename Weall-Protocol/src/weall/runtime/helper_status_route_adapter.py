from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from weall.runtime.helper_status_endpoint_integration import (
    build_node_status_envelope,
    build_readyz_envelope,
)
from weall.runtime.helper_status_surface import HelperStatusSurface


Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class ApiStatusResponseShape:
    status_payload: Json
    readyz_payload: Json

    def to_json(self) -> Json:
        return {
            "status_payload": dict(self.status_payload),
            "readyz_payload": dict(self.readyz_payload),
        }


def merge_helper_surface_into_status_payload(
    *,
    base_status_payload: Mapping[str, Any],
    helper_surface: HelperStatusSurface,
) -> Json:
    """
    Repo-native helper/status route merge utility.

    This function is intentionally schema-light so it can be adapted into the
    existing API routes without forcing a full route rewrite. It appends a
    stable `helper` object while preserving the existing payload keys.
    """
    payload = dict(base_status_payload)
    payload["helper"] = helper_surface.to_json()
    return payload


def merge_helper_surface_into_readyz_payload(
    *,
    base_readyz_payload: Mapping[str, Any],
    helper_surface: HelperStatusSurface,
) -> Json:
    """
    Repo-native readyz merge utility.

    Policy:
    - preserve existing readyz fields
    - add helper posture fields
    - if helper is blocked, force `ready=False`
    """
    payload = dict(base_readyz_payload)
    helper_payload = helper_surface.to_json()
    payload["helper_status"] = str(helper_payload.get("helper_status") or "")
    payload["helper_severity"] = str(helper_payload.get("helper_severity") or "")
    payload["helper_summary"] = str(helper_payload.get("helper_summary") or "")
    if payload["helper_status"] == "blocked":
        payload["ready"] = False
    return payload


def build_api_status_response_shape(
    *,
    chain_id: str,
    base_ok: bool,
    base_mode: str,
    base_ready: bool,
    base_status_payload: Mapping[str, Any],
    base_readyz_payload: Mapping[str, Any],
    helper_surface: HelperStatusSurface,
) -> ApiStatusResponseShape:
    """
    Repo-native adapter showing how helper posture can be merged into an
    existing status/readyz API shape.

    This does not replace the main API routes. It provides the exact merged
    payloads those routes can emit after helper startup posture is computed.
    """
    status_envelope = build_node_status_envelope(
        chain_id=chain_id,
        base_ok=base_ok,
        base_mode=base_mode,
        helper_surface=helper_surface,
    ).to_json()

    readyz_envelope = build_readyz_envelope(
        chain_id=chain_id,
        base_ready=base_ready,
        helper_surface=helper_surface,
    ).to_json()

    status_payload = merge_helper_surface_into_status_payload(
        base_status_payload={**dict(base_status_payload), **status_envelope},
        helper_surface=helper_surface,
    )
    readyz_payload = merge_helper_surface_into_readyz_payload(
        base_readyz_payload={**dict(base_readyz_payload), **readyz_envelope},
        helper_surface=helper_surface,
    )

    return ApiStatusResponseShape(
        status_payload=status_payload,
        readyz_payload=readyz_payload,
    )
