# tests/test_api_contracts_web_and_email_oracle.py
from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _iter_files(root: Path, *, exts: set[str]) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            yield p


_BACKEND_DECORATOR_RE = re.compile(
    r"@router\.(?:get|post|put|patch|delete|options|head)\(\s*(?:r?\"([^\"]+)\"|r?'([^']+)')",
    re.MULTILINE,
)


def _extract_backend_v1_paths(weall_protocol_root: Path) -> set[str]:
    routes_root = weall_protocol_root / "src" / "weall" / "api" / "routes_public_parts"
    assert routes_root.exists(), f"missing routes_public_parts at {routes_root}"

    out: set[str] = set()
    for f in _iter_files(routes_root, exts={".py"}):
        txt = f.read_text(encoding="utf-8", errors="replace")
        for m in _BACKEND_DECORATOR_RE.finditer(txt):
            p = (m.group(1) or m.group(2) or "").strip()
            if not p:
                continue
            if not p.startswith("/"):
                p = "/" + p
            out.add("/v1" + p)
    return out


_WEB_LITERAL_RE = re.compile(r"(?P<q>['\"`])(?P<p>/v1/[^'\"`]+?)(?P=q)")


def _replace_template_exprs(p: str) -> str:
    """Replace JS template expressions (${...}) with {var}, tolerating nested braces."""
    out: list[str] = []
    i = 0
    n = len(p)
    while i < n:
        if i + 1 < n and p[i] == "$" and p[i + 1] == "{":
            # consume until matching }
            i += 2
            depth = 1
            while i < n and depth > 0:
                ch = p[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                i += 1
            out.append("{var}")
            continue
        out.append(p[i])
        i += 1
    return "".join(out)


def _normalize_web_path(p: str) -> str:
    p = _replace_template_exprs(p)

    # IMPORTANT:
    # Web code frequently appends querystrings/fragments via template literals, e.g.
    #   `/v1/feed?${qs}`
    #   `/v1/poh/tier2/juror-cases?juror=${acct}`
    # For contract checks we only care about the PATH portion.
    if "#" in p:
        p = p.split("#", 1)[0]
    if "?" in p:
        p = p.split("?", 1)[0]

    # Some template literals append non-query suffixes via helper functions, e.g.
    #   `/v1/feed${buildQuery({...})}`
    # After substitution, that becomes /v1/feed{var}.
    # For contract checks we only care about the path portion.
    if p.endswith("{var}") and "?" not in p and not p.endswith("/{var}"):
        p = p[: -len("{var}")]

    # Strip obvious trailing JS artefacts that can leak into string-literal capture.
    while p and p[-1] in ")":
        p = p[:-1]

    # Collapse accidental double slashes
    p = re.sub(r"/{2,}", "/", p)
    return p


def _extract_web_v1_paths(projects_root: Path) -> set[str]:
    web_root = projects_root / "web" / "src"
    assert web_root.exists(), f"missing web src at {web_root}"

    out: set[str] = set()
    for f in _iter_files(web_root, exts={".ts", ".tsx"}):
        txt = f.read_text(encoding="utf-8", errors="replace")
        for m in _WEB_LITERAL_RE.finditer(txt):
            p = _normalize_web_path(m.group("p"))
            if p.startswith("/v1/"):
                out.add(p)
    return out


def _backend_matchers(backend_paths: set[str]) -> list[re.Pattern]:
    out: list[re.Pattern] = []
    for p in sorted(backend_paths):
        pat = re.escape(p)
        pat = re.sub(r"\\\{[^}]+\\\}", r"[^/]+", pat)
        out.append(re.compile(r"^" + pat + r"$"))
    return out


def _is_web_path_covered(web_path: str, backend_matchers: list[re.Pattern]) -> bool:
    wp = re.escape(web_path)
    wp = wp.replace(re.escape("{var}"), r"[^/]+")
    wre = re.compile(r"^" + wp + r"$")

    for m in backend_matchers:
        if m.match(web_path):
            return True

    for bpat in backend_matchers:
        if wre.match(bpat.pattern.strip("^").strip("$")):
            return True
    return False


def test_web_calls_are_covered_by_backend_public_api_surface() -> None:
    weall_root = _repo_root()
    projects_root = weall_root.parent  # .../projects

    backend_paths = _extract_backend_v1_paths(weall_root)
    assert "/v1/status" in backend_paths
    assert "/v1/readyz" in backend_paths

    web_paths = _extract_web_v1_paths(projects_root)

    must_cover = sorted({p for p in web_paths if p.startswith("/v1/")})
    assert must_cover, "no /v1/* paths detected in web src"

    matchers = _backend_matchers(backend_paths)

    missing: list[str] = []
    for p in must_cover:
        if not _is_web_path_covered(p, matchers):
            missing.append(p)

    assert not missing, "web references backend paths that do not exist:\n" + "\n".join(missing)


def test_email_oracle_contract_has_start_and_verify_endpoints() -> None:
    weall_root = _repo_root()
    issuer = weall_root / "cloudflare" / "email_oracle" / "src" / "index.ts"
    assert issuer.exists(), f"missing email_oracle worker at {issuer}"

    txt = issuer.read_text(encoding="utf-8", errors="replace")

    assert 'url.pathname === "/start"' in txt or 'url.pathname==="/start"' in txt
    assert 'url.pathname === "/verify"' in txt or 'url.pathname==="/verify"' in txt
