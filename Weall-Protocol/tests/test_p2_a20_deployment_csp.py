from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_documented_production_reverse_proxies_emit_csp() -> None:
    deployment = (ROOT / "web" / "DEPLOYMENT.md").read_text(encoding="utf-8")
    assert "add_header Content-Security-Policy" in deployment
    assert 'Content-Security-Policy "default-src' in deployment
    assert "script-src 'self'" in deployment
    assert "object-src 'none'" in deployment
    assert "script-src 'self' 'unsafe-inline'" not in deployment
    assert "script-src 'self' 'unsafe-eval'" not in deployment


def test_preview_and_documented_production_keep_external_scripts_blocked() -> None:
    vite = (ROOT / "web" / "vite.config.ts").read_text(encoding="utf-8")
    deployment = (ROOT / "web" / "DEPLOYMENT.md").read_text(encoding="utf-8")
    assert "const PREVIEW_CSP" in vite
    assert "\"script-src 'self'; \"" in vite
    assert deployment.count("script-src 'self'") >= 2
