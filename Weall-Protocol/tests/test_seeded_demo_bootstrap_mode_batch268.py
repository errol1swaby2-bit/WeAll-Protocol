from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_quickstart_seeded_demo_uses_dev_mode_for_open_bootstrap_batch268() -> None:
    text = (ROOT / "scripts/quickstart_tester.sh").read_text(encoding="utf-8")

    assert 'export WEALL_RUNTIME_PROFILE="${WEALL_RUNTIME_PROFILE:-seeded_demo}"' in text
    assert 'export WEALL_MODE="${WEALL_MODE:-dev}"' in text
    assert 'export WEALL_MODE="${WEALL_MODE:-demo}"' not in text
    assert 'WEALL_POH_BOOTSTRAP_OPEN: ${WEALL_POH_BOOTSTRAP_OPEN:-1}' in (
        ROOT / "docker-compose.yml"
    ).read_text(encoding="utf-8")


def test_demo_bootstrap_tester_uses_same_dev_mode_default_batch268() -> None:
    text = (ROOT / "scripts/demo_bootstrap_tester.sh").read_text(encoding="utf-8")

    assert 'export WEALL_MODE="${WEALL_MODE:-dev}"' in text
    assert 'export WEALL_RUNTIME_PROFILE="${WEALL_RUNTIME_PROFILE:-seeded_demo}"' in text
    assert 'export WEALL_AUTHORITY_PROFILE="${WEALL_AUTHORITY_PROFILE:-demo}"' in text
    assert 'export WEALL_MODE="${WEALL_MODE:-demo}"' not in text
