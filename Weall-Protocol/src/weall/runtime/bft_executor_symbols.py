from __future__ import annotations

"""Shared lazy symbol binding for BFT runtime submodules.

This keeps the remaining executor-module compatibility isolated while the BFT
adapter is split into reviewable files.  A later pass can replace these bindings
with explicit dependency objects once the BFT surface has been subdivided and
locked by tests.
"""


def bind_executor_globals(target_globals: dict[str, object]) -> None:
    from weall.runtime import executor as _executor_mod

    for _name, _value in vars(_executor_mod).items():
        if _name not in target_globals:
            target_globals[_name] = _value
