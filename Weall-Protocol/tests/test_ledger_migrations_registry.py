from __future__ import annotations

import inspect
import re

import weall.ledger.migrations as mig


def _extract_migration_registry_source() -> str:
    # We intentionally treat the module source as the source of truth to avoid
    # forcing you to expose internal migration dicts as part of the public API.
    return inspect.getsource(mig)


def test_migration_registry_is_contiguous() -> None:
    """
    If CURRENT_STATE_VERSION increments, you MUST add a migration step for
    every prior version (0..CURRENT_STATE_VERSION-1). This prevents "version bump
    without migration" regressions from slipping into CI.
    """
    src = _extract_migration_registry_source()

    # Find the registry assignment "_MIGRATIONS: ... = { ... }"
    m = re.search(r"_MIGRATIONS\s*:\s*Dict\[int,\s*Callable\[.*?\]\]\s*=\s*\{(.*?)\}\s*", src, re.S)
    assert m, "Could not locate _MIGRATIONS registry in weall.ledger.migrations"

    body = m.group(1)

    # Extract integer keys like "0:" or "12:"
    keys = set(int(k) for k in re.findall(r"(?m)^\s*(\d+)\s*:", body))

    # Enforce contiguous migrations from 0 up to CURRENT_STATE_VERSION-1
    expected = set(range(0, mig.CURRENT_STATE_VERSION))
    missing = sorted(expected - keys)

    assert not missing, (
        f"Missing migration steps for versions: {missing}. "
        f"CURRENT_STATE_VERSION={mig.CURRENT_STATE_VERSION} requires keys 0..{mig.CURRENT_STATE_VERSION - 1}."
    )
