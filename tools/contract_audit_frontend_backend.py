#!/usr/bin/env python3
"""
Contract Audit: Frontend (projects/web) ↔ Backend (projects/Weall-Protocol)

What it does
------------
- Extracts backend public FastAPI routes mounted under /v1 from:
    projects/Weall-Protocol/src/weall/api/routes_public_parts/*.py
  (These modules define paths WITHOUT /v1; we add /v1 during collection.)

- Extracts frontend API paths from:
    projects/web/src/api/weall.ts
  plus any other /v1/... string literals anywhere under projects/web/src.

- Produces:
  - a markdown report (default: ./frontend_backend_contract_audit.md)
  - a JSON report (default: ./frontend_backend_contract_audit.json)

How to run
----------
From the "projects" directory (or pass --root to point at it):

    python3 tools/contract_audit_frontend_backend.py --root . --out ./audit

This script is intentionally "static":
- It does NOT import your FastAPI app.
- It does NOT run TypeScript parsing.
- It relies on simple regex extraction for speed and robustness.

Limitations
-----------
- It won't catch routes built dynamically.
- It won't validate request/response JSON shapes (just method+path congruity).
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple


ROUTE_DECORATOR_RE = re.compile(
    r"@router\.(get|post|put|delete|patch|head|options)\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

# In weall.ts we can infer method from helper used
FRONT_HELPER_METHOD = {
    "apiGet": "GET",
    "apiPostRaw": "POST",
    "apiPostMultipart": "POST",
}

# Generic scan: any "/v1/..." string literal
FRONT_V1_LITERAL_RE = re.compile(r"[\"'](\/v1\/[^\"']+)[\"']")


def canon(path: str) -> str:
    """Canonicalize paths so /v1/content/{id} matches /v1/content/${enc}."""
    p = re.sub(r"\{[^}]+\}", "{param}", path)
    p = re.sub(r"\$\{[^}]+\}", "{param}", p)
    # Strip query
    p = p.split("?", 1)[0]
    return p


def read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def collect_backend_routes(projects_root: Path) -> List[dict]:
    routes_dir = projects_root / "Weall-Protocol" / "src" / "weall" / "api" / "routes_public_parts"
    if not routes_dir.exists():
        raise SystemExit(f"Backend routes directory not found: {routes_dir}")

    out: List[dict] = []
    for fp in sorted(routes_dir.glob("*.py")):
        rel = fp.relative_to(projects_root).as_posix()
        txt = read_text(fp)
        for m in ROUTE_DECORATOR_RE.finditer(txt):
            method = m.group(1).upper()
            path = m.group(2)
            full = "/v1" + path if path.startswith("/") else "/v1/" + path
            out.append({"method": method, "path": full, "file": rel})
    return out


def collect_frontend_routes(projects_root: Path) -> List[dict]:
    web_src = projects_root / "web" / "src"
    if not web_src.exists():
        raise SystemExit(f"Frontend src directory not found: {web_src}")

    out: List[dict] = []

    # 1) High-fidelity parse for web/src/api/weall.ts
    weall_ts = web_src / "api" / "weall.ts"
    if weall_ts.exists():
        txt = read_text(weall_ts)
        rel = weall_ts.relative_to(projects_root).as_posix()

        # helper("...") string literal
        for helper, method in FRONT_HELPER_METHOD.items():
            lit = re.compile(rf"{helper}\(\s*`?[\"']([^\"']+)[\"']")
            for m in lit.finditer(txt):
                path = m.group(1)
                if path.startswith("/v1/"):
                    out.append({"method": method, "path": canon(path), "file": rel})

            # helper(`...`) template literal
            tpl = re.compile(rf"{helper}\(\s*`([^`]+)`")
            for m in tpl.finditer(txt):
                path = m.group(1)
                if path.startswith("/v1/"):
                    out.append({"method": method, "path": canon(path), "file": rel})

    # 2) Low-fidelity scan of all web/src for "/v1/..." string literals
    for fp in sorted(list(web_src.rglob("*.ts")) + list(web_src.rglob("*.tsx"))):
        rel = fp.relative_to(projects_root).as_posix()
        txt = read_text(fp)
        for m in FRONT_V1_LITERAL_RE.finditer(txt):
            path = canon(m.group(1))
            # Method unknown here; treat as GET unless you manually classify later.
            out.append({"method": "GET", "path": path, "file": rel})

    # Dedupe by (method,path) keeping one record (file list computed later)
    dedup: Dict[Tuple[str, str], dict] = {}
    for r in out:
        key = (r["method"], r["path"])
        dedup.setdefault(key, r)
    return list(dedup.values())


def group_by_key(items: List[dict]) -> Dict[Tuple[str, str], List[dict]]:
    m: Dict[Tuple[str, str], List[dict]] = {}
    for r in items:
        key = (r["method"], canon(r["path"]))
        m.setdefault(key, []).append(r)
    return m


def fmt_sources(items: List[dict]) -> str:
    return ", ".join(sorted({i["file"] for i in items}))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="Path to the 'projects' directory")
    ap.add_argument("--out", default=".", help="Output directory for report files")
    args = ap.parse_args()

    projects_root = Path(args.root).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    backend = collect_backend_routes(projects_root)
    frontend = collect_frontend_routes(projects_root)

    backend_map = group_by_key(backend)
    front_map = group_by_key(frontend)

    matches: List[Tuple[Tuple[str, str], List[dict], List[dict]]] = []
    missing_in_backend: List[Tuple[Tuple[str, str], List[dict]]] = []
    unused_in_frontend: List[Tuple[Tuple[str, str], List[dict]]] = []

    for key, frs in sorted(front_map.items()):
        if key in backend_map:
            matches.append((key, frs, backend_map[key]))
        else:
            missing_in_backend.append((key, frs))

    for key, brs in sorted(backend_map.items()):
        if key not in front_map:
            unused_in_frontend.append((key, brs))

    # Markdown report
    md: List[str] = []
    md.append("# Frontend ↔ Backend Contract Audit (Web vs Weall-Protocol)\n\n")
    md.append(f"Generated from: `{projects_root}`\n\n")
    md.append("## Summary\n")
    md.append(f"- Frontend API calls found: **{len(frontend)}**\n")
    md.append(f"- Backend public `/v1` routes found: **{len(backend)}**\n")
    md.append(f"- Frontend calls with a matching backend route: **{len(matches)} / {len(front_map)}**\n")
    md.append(f"- Frontend calls missing in backend: **{len(missing_in_backend)}**\n")
    md.append(f"- Backend routes unused by frontend: **{len(unused_in_frontend)}**\n\n")

    md.append("## Matched endpoints (frontend calls exist in backend)\n")
    md.append("| Method | Path (canonical) | Frontend locations | Backend locations |\n")
    md.append("|---|---|---|---|\n")
    for (method, cpath), frs, brs in sorted(matches, key=lambda x: (x[0][0], x[0][1])):
        md.append(f"| {method} | `{cpath}` | {fmt_sources(frs)} | {fmt_sources(brs)} |\n")

    if missing_in_backend:
        md.append("\n## Frontend calls missing in backend (needs fix)\n")
        md.append("| Method | Path (canonical) | Frontend locations |\n|---|---|---|\n")
        for (method, cpath), frs in sorted(missing_in_backend, key=lambda x: (x[0][0], x[0][1])):
            md.append(f"| {method} | `{cpath}` | {fmt_sources(frs)} |\n")
    else:
        md.append("\n## Frontend calls missing in backend\n- None ✅\n")

    md.append("\n## Backend routes not currently used by the frontend (opportunity / alignment backlog)\n")
    md.append("| Method | Path (canonical) | Backend locations |\n|---|---|---|\n")
    for (method, cpath), brs in sorted(unused_in_frontend, key=lambda x: (x[0][0], x[0][1])):
        md.append(f"| {method} | `{cpath}` | {fmt_sources(brs)} |\n")

    md.append("\n## Notes & recommended follow-ups\n")
    md.append("1) Confirm executor enforces tier gating for content writes (UI gating is not sufficient).\n")
    md.append("2) Freeze account state JSON shape (PoH tier, etc.) so UI doesn’t need fallbacks.\n")
    md.append("3) Document `/v1/tx/status/{tx_id}` semantics and enums for stable UI polling.\n")

    md_path = out_dir / "frontend_backend_contract_audit.md"
    md_path.write_text("".join(md), encoding="utf-8")

    # JSON report
    report = {
        "summary": {
            "frontend_calls_total": len(frontend),
            "backend_routes_total": len(backend),
            "frontend_unique": len(front_map),
            "backend_unique": len(backend_map),
            "matched": len(matches),
            "missing_in_backend": len(missing_in_backend),
            "unused_in_frontend": len(unused_in_frontend),
        },
        "matched": [
            {
                "method": k[0],
                "path": k[1],
                "frontend": sorted({i["file"] for i in frs}),
                "backend": sorted({i["file"] for i in brs}),
            }
            for k, frs, brs in matches
        ],
        "missing_in_backend": [
            {"method": k[0], "path": k[1], "frontend": sorted({i["file"] for i in frs})}
            for k, frs in missing_in_backend
        ],
        "unused_in_frontend": [
            {"method": k[0], "path": k[1], "backend": sorted({i["file"] for i in brs})}
            for k, brs in unused_in_frontend
        ],
    }
    js_path = out_dir / "frontend_backend_contract_audit.json"
    js_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Wrote: {md_path}")
    print(f"Wrote: {js_path}")

    # Exit non-zero if frontend references missing backend routes
    return 1 if missing_in_backend else 0


if __name__ == "__main__":
    raise SystemExit(main())
