from __future__ import annotations

"""Shared staged compatibility binder for extracted runtime delegates.

The executor split is moving toward explicit RuntimeContext dependency injection.
This is now the single temporary executor-module symbol mirror for both runtime
and BFT submodules; the separate BFT binder has been retired.  New code should
prefer explicit dependency objects and should not introduce additional binders.
"""

from collections.abc import Iterable


def bind_executor_globals(target_globals: dict[str, object], *, refresh: Iterable[str] = ()) -> None:
    from weall.runtime import executor as _executor_mod

    for _name, _value in vars(_executor_mod).items():
        if _name not in target_globals:
            target_globals[_name] = _value
    for _name in refresh:
        if hasattr(_executor_mod, _name):
            target_globals[_name] = getattr(_executor_mod, _name)
