from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_dev_boot_uses_npm_ci_when_package_lock_exists():
    script = (repo_root() / "scripts" / "dev_boot_full_stack.sh").read_text(encoding="utf-8")
    assert 'if [ -f "$pkg_lock" ]; then' in script
    assert 'frontend package-lock.json present; running npm ci' in script
    assert "npm ci" in script


def test_dev_boot_falls_back_when_package_lock_is_missing():
    script = (repo_root() / "scripts" / "dev_boot_full_stack.sh").read_text(encoding="utf-8")
    assert 'frontend package-lock.json missing; running npm install without writing a lockfile' in script
    assert "npm install --no-package-lock --no-audit --no-fund" in script


def test_dev_boot_no_longer_unconditionally_runs_npm_ci():
    script = (repo_root() / "scripts" / "dev_boot_full_stack.sh").read_text(encoding="utf-8")
    assert 'frontend dependencies missing or stale; running npm ci' not in script
    assert 'npm ci\n  ) || fail "frontend dependency install failed"' not in script
