from fastapi import APIRouter, Request
from weall.api.routes_public_parts.common import _snapshot
from weall.api.security import require_account_session

router = APIRouter()

@router.get("/v1/social/{account}/following")
def following(account: str, request: Request):
    st = _snapshot(request)
    social = st.get("social", {})
    edges = social.get("follows_by_edge", {})
    out = []
    for _, obj in edges.items():
        if obj.get("from") == account and obj.get("active", True):
            out.append(obj)
    return {"ok": True, "following": out}

@router.get("/v1/social/me")
def me(request: Request):
    st = _snapshot(request)
    viewer = require_account_session(request, st)
    return {"ok": True, "account": viewer}
