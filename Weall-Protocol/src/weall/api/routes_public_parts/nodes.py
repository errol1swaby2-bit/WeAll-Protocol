from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.routes_nodes import _known_peers_response, _seeds_response, _validator_endpoints_response

Json = dict[str, Any]

router = APIRouter()


@router.get("/nodes")
def nodes(request: Request) -> Json:
    raise ApiError.gone(
        "legacy_endpoint_removed",
        "/v1/nodes has been removed; use /v1/nodes/seeds or /v1/nodes/known",
        {"canonical_endpoints": ["/v1/nodes/seeds", "/v1/nodes/known", "/v1/nodes/validators"]},
    )


@router.get("/nodes/seeds")
def nodes_seeds(request: Request) -> Json:
    return _seeds_response(request)


@router.get("/nodes/known")
def nodes_known(request: Request) -> Json:
    return _known_peers_response(request)


@router.get("/nodes/validators")
def nodes_validators(request: Request) -> Json:
    return _validator_endpoints_response(request)
