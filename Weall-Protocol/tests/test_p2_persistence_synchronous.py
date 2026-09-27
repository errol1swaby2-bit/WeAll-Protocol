from __future__ import annotations

import pytest

from weall.runtime.sqlite_db import SqliteDB


def test_p2_persist002_production_rejects_sqlite_synchronous_off(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SQLITE_SYNCHRONOUS", "OFF")

    with pytest.raises(ValueError, match="unsafe_sqlite_synchronous_off_in_prod"):
        SqliteDB._sqlite_synchronous_pragma()


def test_p2_persist002_nonproduction_can_explicitly_use_off(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_SQLITE_SYNCHRONOUS", "OFF")

    assert SqliteDB._sqlite_synchronous_pragma() == "OFF"


def test_p2_persist002_production_default_remains_full(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_SQLITE_SYNCHRONOUS", raising=False)

    assert SqliteDB._sqlite_synchronous_pragma() == "FULL"
