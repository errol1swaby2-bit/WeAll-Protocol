#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQLITE_DB = ROOT / "src" / "weall" / "runtime" / "sqlite_db.py"

BROKEN = "    def _sqlite_synchronous_pragma() -> str:\n"
CORRECT = "    @staticmethod\n    def _sqlite_synchronous_pragma() -> str:\n"


def main() -> int:
    text = SQLITE_DB.read_text(encoding="utf-8")
    correct_count = text.count(CORRECT)
    broken_count = text.count(BROKEN)

    if correct_count == 1:
        print("sqlite synchronous pragma staticmethod contract already intact")
        return 0

    if correct_count != 0 or broken_count != 1:
        raise SystemExit(
            "unexpected sqlite synchronous pragma shape: "
            f"correct={correct_count} broken={broken_count}"
        )

    repaired = text.replace(BROKEN, CORRECT, 1)
    compile(repaired, str(SQLITE_DB), "exec")
    SQLITE_DB.write_text(repaired, encoding="utf-8")
    print("restored SqliteDB._sqlite_synchronous_pragma staticmethod contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
