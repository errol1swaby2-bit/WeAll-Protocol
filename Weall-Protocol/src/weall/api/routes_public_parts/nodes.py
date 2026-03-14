from __future__ import annotations

from fastapi import APIRouter, Request

from weall.api.routes_nodes import v1_nodes as _v1_nodes
from weall.api.routes_nodes import v1_nodes_known as _v1_nodes_known
from weall.api.routes_nodes import v1_nodes_seeds as _v1_nodes_seeds

router = APIRouter()


@router.get("/nodes")
def nodes(request: Request):
    return _v1_nodes(request)


@router.get("/nodes/seeds")
def nodes_seeds(request: Request):
    return _v1_nodes_seeds(request)


@router.get("/nodes/known")
def nodes_known(request: Request):
    return _v1_nodes_known(request)
