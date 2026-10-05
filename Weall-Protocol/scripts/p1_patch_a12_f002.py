from __future__ import annotations

from pathlib import Path


path = Path("src/weall/api/routes_public_parts/status.py")
text = path.read_text(encoding="utf-8")
start_marker = '@router.get("/status/mempool")\ndef status_mempool(request: Request) -> dict[str, Any]:\n'
end_marker = '\n\n@router.get("/status/attestations")\n'
start = text.find(start_marker)
if start < 0:
    raise SystemExit("A12-F002 start anchor missing")
end = text.find(end_marker, start)
if end < 0:
    raise SystemExit("A12-F002 end anchor missing")
if text.find(start_marker, start + 1) >= 0:
    raise SystemExit("A12-F002 start anchor is not unique")

replacement = '''@router.get("/status/mempool")
def status_mempool(request: Request) -> dict[str, Any]:
    limit = _env_int("WEALL_STATUS_MEMPOOL_LIMIT", 50)
    ex = getattr(request.app.state, "executor", None)
    mp = getattr(ex, "mempool", None)
    raw_items: list[Any] = []
    if mp is not None:
        peek = getattr(mp, "peek", None)
        if callable(peek):
            try:
                out = peek(limit=limit)
                if isinstance(out, list):
                    raw_items = out
            except Exception:
                raw_items = []

    # A12-F002: this route is anonymous/public. Never return the internal
    # pending envelope shape: payloads and signatures may never become chain
    # public if a transaction is later rejected or expires. Keep a small,
    # explicit metadata projection instead of attempting a payload denylist.
    items: list[dict[str, Any]] = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            continue
        items.append(
            {
                "tx_id": _safe_str(raw.get("tx_id"), ""),
                "tx_type": _safe_str(raw.get("tx_type"), ""),
                "signer": _safe_str(raw.get("signer"), ""),
                "nonce": _safe_int(raw.get("nonce"), 0),
                "received_ms": _safe_int(raw.get("received_ms"), 0),
                "mempool_admitted_height": _safe_int(raw.get("mempool_admitted_height"), 0),
                "mempool_expires_height": _safe_int(raw.get("mempool_expires_height"), 0),
            }
        )

    selection_diag: dict[str, Any] = {}
    fn = getattr(ex, "mempool_selection_diagnostics", None)
    if callable(fn):
        try:
            out = fn(preview_limit=limit)
            if isinstance(out, dict):
                selection_diag = dict(out)
        except Exception:
            selection_diag = {}
    return {
        "ok": True,
        "limit": limit,
        "size": _safe_int(getattr(mp, "size", lambda: 0)(), 0) if mp is not None else 0,
        "items": items,
        "selection_diagnostics": selection_diag,
    }
'''

path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")
