from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPO_ROOT / "Weall-Protocol"


def test_seeded_demo_quickstart_enables_backend_secret_route_batch271() -> None:
    text = (BACKEND_ROOT / "scripts/quickstart_tester.sh").read_text(encoding="utf-8")

    assert 'export WEALL_ENABLE_DEMO_SEED_ROUTE="${WEALL_ENABLE_DEMO_SEED_ROUTE:-1}"' in text
    assert 'export WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE="${WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE:-1}"' in text
    assert 'export WEALL_RUNTIME_PROFILE="${WEALL_RUNTIME_PROFILE:-seeded_demo}"' in text


def test_compose_passes_seeded_demo_secret_route_to_api_container_batch271() -> None:
    text = (BACKEND_ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert 'WEALL_ENABLE_DEMO_SEED_ROUTE: ${WEALL_ENABLE_DEMO_SEED_ROUTE:-1}' in text
    assert 'WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE: ${WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE:-1}' in text
    assert 'WEALL_RUNTIME_PROFILE: ${WEALL_RUNTIME_PROFILE:-seeded_demo}' in text
    assert './generated:/app/generated' in text


def test_full_stack_script_explicitly_enables_secret_route_for_browser_handoff_batch271() -> None:
    text = (REPO_ROOT / "scripts/dev_boot_full_stack.sh").read_text(encoding="utf-8")

    assert 'WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE="${WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE:-1}"' in text
    assert 'WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE="${WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE:-0}"' not in text
