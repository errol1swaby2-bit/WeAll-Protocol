from __future__ import annotations

"""Shared staged compatibility binder for extracted runtime delegates.

The executor split is moving toward explicit RuntimeContext dependency injection.
This helper keeps the remaining temporary executor-module symbol mirroring in one
small file so new extracted modules do not grow their own compatibility shims.
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
