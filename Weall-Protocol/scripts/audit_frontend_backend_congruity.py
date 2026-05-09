#!/usr/bin/env python3
"""
Audit congruity between:
  - frontend (projects/web) calls to /v1/... endpoints + tx_type usage
  - backend (projects/Weall-Protocol) FastAPI router paths + runtime tx_schema

Goal:
  stable user flow from signup -> PoH -> session -> upload -> declare -> post.

What it checks:
  A) HTTP endpoints:
     - Extracts /v1/... paths from web/src/api/weall.ts (and a few other TS/TSX files).
     - Extracts router paths from backend routes_public_parts/*.py
     - Reports missing endpoints (frontend calls that backend doesn't define).

  B) Tx types:
     - Extracts tx_type strings used in frontend TS/TSX (e.g., "CONTENT_POST_CREATE")
     - Imports weall.runtime.tx_schema.model_for_tx_type and checks that each tx_type
       is modeled (or at least known).
     - Reports unknown / unmodeled tx types (likely frontend typo or backend drift).

Usage (from repo root where "projects/" exists):
  python3 scripts/audit_frontend_backend_congruity.py

If your backend import needs PYTHONPATH:
  PYTHONPATH=projects/Weall-Protocol/src python3 scripts/audit_frontend_backend_congruity.py
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

SCRIPT_BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _resolve_layout() -> tuple[Path, Path, Path]:
    """Resolve supported repository layouts.

    Historical CI used:      <root>/projects/Weall-Protocol and <root>/projects/web
    Current export uses:     <root>/Weall-Protocol and <root>/web
    Backend-local execution: <backend>/scripts/audit_frontend_backend_congruity.py
    """
    candidates: list[tuple[Path, Path, Path]] = []

    # Current uploaded/exported layout when this script is run from backend/scripts.
    candidates.append((SCRIPT_BACKEND_ROOT.parent, SCRIPT_BACKEND_ROOT, SCRIPT_BACKEND_ROOT.parent / "web"))

    # Historical projects/ layout.
    projects = SCRIPT_BACKEND_ROOT / "projects"
    candidates.append((SCRIPT_BACKEND_ROOT, projects / "Weall-Protocol", projects / "web"))

    # If invoked from an outer checkout where scripts were copied, try sibling projects.
    outer_projects = SCRIPT_BACKEND_ROOT.parent / "projects"
    candidates.append((SCRIPT_BACKEND_ROOT.parent, outer_projects / "Weall-Protocol", outer_projects / "web"))

    for root, backend, frontend in candidates:
        if (backend / "src" / "weall").is_dir() and (frontend / "src").is_dir():
            return root.resolve(), backend.resolve(), frontend.resolve()

    searched = [
        {"root": str(root), "backend": str(backend), "frontend": str(frontend)}
        for root, backend, frontend in candidates
    ]
    raise SystemExit("layout_not_found:" + repr(searched))


REPO_ROOT, BACKEND_DIR, FRONTEND_DIR = _resolve_layout()
BACKEND_ROUTES_DIR = BACKEND_DIR / "src" / "weall" / "api" / "routes_public_parts"
FRONTEND_SRC_DIR = FRONTEND_DIR / "src"


@dataclass(frozen=True)
class Finding:
    kind: str
    item: str
    detail: str


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _iter_files(root: Path, exts: tuple[str, ...]) -> Iterable[Path]:
    if not root.exists():
        return
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            yield p


def _extract_frontend_v1_paths(paths: list[Path]) -> dict[str, set[str]]:
    """
    Returns: map endpoint -> {files...}
    Captures:
      "/v1/xyz"
      '/v1/xyz'
      `/v1/xyz/${var}`
    We normalize templates by stripping ${...} segments to the base prefix.
    """
    out: dict[str, set[str]] = {}
    # literal " /v1/.... "
    lit_pat = re.compile(r"""["'](/v1/[^"' \t\r\n]+)["']""")
    tpl_pat = re.compile(r"""`(/v1/[^`]+)`""")

    for fp in paths:
        txt = _read_text(fp)
        if not txt:
            continue

        for m in lit_pat.finditer(txt):
            raw = m.group(1).strip()
            norm = _normalize_path(raw)
            out.setdefault(norm, set()).add(str(fp.relative_to(REPO_ROOT)))

        for m in tpl_pat.finditer(txt):
            raw = m.group(1).strip()
            norm = _normalize_path(raw)
            out.setdefault(norm, set()).add(str(fp.relative_to(REPO_ROOT)))

    return out


def _normalize_path(p: str) -> str:
    """Normalize frontend/backend paths while preserving dynamic segments.

    Examples:
      /v1/accounts/${encodeURIComponent(account)}/registered -> /v1/accounts/{param}/registered
      /v1/feed${qs} -> /v1/feed
      /v1/dev/bootstrap-secret?account=${account} -> /v1/dev/bootstrap-secret
    """
    s = (p or "").strip()

    # Drop query strings before dynamic-template handling so endpoints compare
    # route path, not parameter names.
    s = s.split("?", 1)[0]

    # Replace TS template interpolations that occupy path segments with a
    # placeholder segment. Remove query-style template suffixes such as ${qs}.
    s = re.sub(r"/\$\{[^}]+\}", "/{param}", s)
    s = re.sub(r"\$\{[^}]+\}", "", s)

    # remove common "+qs" remnants
    s = s.replace("+qs", "").replace("+ qs", "").replace("${qs}", "")

    # compress double slashes
    s = re.sub(r"/{2,}", "/", s)

    if len(s) > 1 and s.endswith("/"):
        s = s[:-1]
    return s


def _extract_backend_router_paths(route_files: list[Path]) -> dict[str, set[str]]:
    """
    Extracts paths from:
      @router.get("/feed")
      @router.post("/tx/submit")
      router = APIRouter(prefix="/v1") is handled elsewhere (backend uses /v1 mount at app level),
    so we assume these are mounted under /v1 and we report them as /v1/<path>.
    """
    out: dict[str, set[str]] = {}
    # matches @router.<method>("...") or @router.<method>( "...", ...
    dec_pat = re.compile(r"""@router\.(get|post|put|delete|patch)\(\s*["']([^"']+)["']""")

    for fp in route_files:
        txt = _read_text(fp)
        if not txt:
            continue
        for m in dec_pat.finditer(txt):
            path = m.group(2).strip()
            if not path.startswith("/"):
                path = "/" + path
            full = "/v1" + path
            full = _normalize_path(full)
            out.setdefault(full, set()).add(str(fp.relative_to(REPO_ROOT)))

    return out


def _extract_frontend_tx_types(paths: list[Path]) -> dict[str, set[str]]:
    """
    Extract tx types used in frontend code.
    Captures patterns like:
      tx_type: "CONTENT_POST_CREATE"
      tx_type: 'ACCOUNT_REGISTER'
      tx_type: SOME_CONST (won't catch)
    Also captures submitTx("CONTENT_POST_CREATE", ...)
    """
    out: dict[str, set[str]] = {}

    pat1 = re.compile(r"""tx_type\s*:\s*["']([A-Z0-9_]+)["']""")
    pat2 = re.compile(r"""submitTx\(\s*["']([A-Z0-9_]+)["']""")

    for fp in paths:
        txt = _read_text(fp)
        if not txt:
            continue
        for m in pat1.finditer(txt):
            t = m.group(1).strip().upper()
            out.setdefault(t, set()).add(str(fp.relative_to(REPO_ROOT)))
        for m in pat2.finditer(txt):
            t = m.group(1).strip().upper()
            out.setdefault(t, set()).add(str(fp.relative_to(REPO_ROOT)))

    return out


def _try_import_tx_schema() -> object | None:
    """
    Attempt to import weall.runtime.tx_schema with best-effort sys.path fixes.
    """
    # Prefer caller-provided PYTHONPATH, but also try the conventional local layout.
    candidates = [
        str(BACKEND_DIR / "src"),
        str(SCRIPT_BACKEND_ROOT / "src"),
        str(REPO_ROOT / "src"),
    ]
    for c in candidates:
        if c and c not in sys.path and Path(c).exists():
            sys.path.insert(0, c)

    try:
        import weall.runtime.tx_schema as tx_schema  # type: ignore

        return tx_schema
    except Exception:
        return None


def main() -> int:
    findings: list[Finding] = []

    if not BACKEND_ROUTES_DIR.exists() or not FRONTEND_SRC_DIR.exists():
        print("ERROR: frontend/backend layout is incomplete")
        print(f"Repo root: {REPO_ROOT}")
        print(f"Frontend:  {FRONTEND_DIR}")
        print(f"Backend:   {BACKEND_DIR}")
        return 2

    # --- Frontend paths
    fe_candidates = [
        FRONTEND_SRC_DIR / "api" / "weall.ts",
        FRONTEND_SRC_DIR / "pages" / "Feed.tsx",
        FRONTEND_SRC_DIR / "pages" / "PohPage.tsx",
    ]
    # plus all api + pages to catch new calls
    fe_scan_files = list(_iter_files(FRONTEND_SRC_DIR / "api", (".ts", ".tsx"))) + list(
        _iter_files(FRONTEND_SRC_DIR / "pages", (".ts", ".tsx"))
    )
    # ensure the key ones are included
    for p in fe_candidates:
        if p.exists() and p not in fe_scan_files:
            fe_scan_files.append(p)

    fe_paths = _extract_frontend_v1_paths(fe_scan_files)

    # --- Backend router paths
    be_route_files = list(_iter_files(BACKEND_ROUTES_DIR, (".py",)))
    be_paths = _extract_backend_router_paths(be_route_files)

    # Missing endpoints
    for ep, files in sorted(fe_paths.items()):
        # Many frontend templates normalize to "/v1/accounts/" which won't exactly match
        # "/v1/accounts/{account}" style paths. We treat prefix matches as OK.
        if _endpoint_is_satisfied(ep, be_paths):
            continue
        findings.append(Finding("missing_endpoint", ep, f"called_from={sorted(files)}"))

    # --- Tx types
    fe_tx_types = _extract_frontend_tx_types(fe_scan_files)
    tx_schema = _try_import_tx_schema()

    if tx_schema is None:
        findings.append(
            Finding(
                "tx_schema_import_failed",
                "weall.runtime.tx_schema",
                f"Could not import; run with: PYTHONPATH={BACKEND_DIR / 'src'}",
            )
        )
    else:
        model_for_tx_type = getattr(tx_schema, "model_for_tx_type", None)
        if not callable(model_for_tx_type):
            findings.append(
                Finding(
                    "tx_schema_missing_api",
                    "model_for_tx_type",
                    "tx_schema.model_for_tx_type not found",
                )
            )
        else:
            for t, files in sorted(fe_tx_types.items()):
                try:
                    m = model_for_tx_type(t)
                except Exception:
                    m = None
                # NOTE: Some tx types may be valid but intentionally not pydantic-modeled.
                # Those should be explicitly handled here if you want to allow them.
                if m is None:
                    findings.append(Finding("unmodeled_tx_type", t, f"used_in={sorted(files)}"))

    # --- Report
    print("\n=== WeAll Frontend/Backend Congruity Audit ===\n")
    print(f"Repo root: {REPO_ROOT}")
    print(f"Frontend:  {FRONTEND_DIR}")
    print(f"Backend:   {BACKEND_DIR}\n")

    print(f"Frontend endpoints found: {len(fe_paths)}")
    print(f"Backend endpoints found:  {len(be_paths)}")
    print(f"Frontend tx_types found:  {len(fe_tx_types)}\n")

    if not findings:
        print("✅ PASS: No missing endpoints and no unmodeled tx types detected.\n")
        return 0

    # Group findings
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.kind, []).append(f)

    for kind, items in grouped.items():
        print(f"--- {kind} ({len(items)}) ---")
        for f in items:
            print(f"- {f.item}\n    {f.detail}")
        print()

    # Non-zero if any hard errors
    hard_fail = any(f.kind in {"missing_endpoint"} for f in findings)
    return 1 if hard_fail else 0


def _path_segments(path: str) -> list[str]:
    return [part for part in _normalize_path(path).split("/") if part]


def _segment_is_param(segment: str) -> bool:
    return segment.startswith("{") and segment.endswith("}")


def _paths_equivalent(front_ep: str, backend_ep: str) -> bool:
    front = _path_segments(front_ep)
    back = _path_segments(backend_ep)
    if len(front) != len(back):
        return False
    for a, b in zip(front, back):
        if a == b:
            continue
        if _segment_is_param(a) or _segment_is_param(b):
            continue
        return False
    return True


def _endpoint_is_satisfied(front_ep: str, backend_paths: dict[str, set[str]]) -> bool:
    """Return true when a frontend endpoint maps to a backend route."""
    if front_ep in backend_paths:
        return True
    return any(_paths_equivalent(front_ep, be) for be in backend_paths.keys())


if __name__ == "__main__":
    raise SystemExit(main())
