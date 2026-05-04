from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_full_stack_manifest_points_browser_secret_fetch_at_backend_api():
    text = (repo_root() / "scripts" / "dev_boot_full_stack.sh").read_text(encoding="utf-8")
    assert 'api_base = os.environ.get("WEALL_API", "http://127.0.0.1:8000").rstrip("/")' in text
    assert '"apiBase": api_base' in text
    assert '"api_base": api_base' in text
    assert '"apiBase": "/"' not in text
    assert '"api_base": "/"' not in text


def test_dev_bootstrap_ignores_same_origin_manifest_slash_for_secret_fetch():
    dev_bootstrap = (repo_root() / "web" / "src" / "lib" / "devBootstrap.ts").read_text(encoding="utf-8")
    assert "function usableApiBase" in dev_bootstrap
    assert "function manifestApiBase" in dev_bootstrap
    assert "manifest.apiBase, manifest.api_base, config.defaultApiBase" in dev_bootstrap
    assert 'const base = String(manifest.apiBase || config.defaultApiBase || "").trim() || "/"' not in dev_bootstrap


def test_login_page_uses_saved_backend_target_when_manifest_api_base_is_slash():
    login_page = (repo_root() / "web" / "src" / "pages" / "LoginPage.tsx").read_text(encoding="utf-8")
    assert "function usableApiBase" in login_page
    assert "function manifestApiBase" in login_page
    assert "manifest?.apiBase, manifest?.api_base, fallback, getApiBase()" in login_page
    assert "manifestApiBase(devManifest, apiBaseInput)" in login_page
    assert "String(devManifest.apiBase || apiBaseInput || getApiBase())" not in login_page
