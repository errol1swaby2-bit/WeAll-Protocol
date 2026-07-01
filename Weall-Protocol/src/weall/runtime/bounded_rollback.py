from __future__ import annotations

"""Deterministic bounded rollback journal for JSON-like state mutation.

This module provides the canonical bounded rollback primitive for transaction
execution. The legacy full-state deepcopy wrapper remains available only as a
regression/equivalence oracle.

The journal mutates the provided target state directly and records only touched
keys/lists. On failure, recorded mutations are restored in reverse order. On
success, no full-state copy or whole-state replacement is performed.
"""

import copy
from collections.abc import Callable, Iterable, Iterator
from typing import Any

Json = dict[str, Any]
_MISSING = object()


def _unwrap(value: Any) -> Any:
    if isinstance(value, JournaledDict):
        return value._target
    if isinstance(value, JournaledList):
        return value._target
    return value


class RollbackJournalError(RuntimeError):
    """Raised when journal rollback cannot be completed deterministically."""


class RollbackJournal:
    def __init__(self) -> None:
        self._records: list[Callable[[], None]] = []

    def record_dict_key(self, target: dict[Any, Any], key: Any) -> None:
        existed = key in target
        previous = copy.deepcopy(target.get(key, _MISSING)) if existed else _MISSING

        def undo() -> None:
            if previous is _MISSING:
                target.pop(key, None)
            else:
                target[key] = copy.deepcopy(previous)

        self._records.append(undo)

    def record_list_state(self, target: list[Any]) -> None:
        previous = copy.deepcopy(target)

        def undo() -> None:
            target[:] = copy.deepcopy(previous)

        self._records.append(undo)

    def rollback(self) -> None:
        errors: list[str] = []
        for undo in reversed(self._records):
            try:
                undo()
            except Exception as exc:  # pragma: no cover - fail-closed guard
                errors.append(type(exc).__name__)
        self._records.clear()
        if errors:
            raise RollbackJournalError("rollback_failed:" + ",".join(errors))

    def clear(self) -> None:
        self._records.clear()

    @property
    def record_count(self) -> int:
        return len(self._records)


def _wrap(value: Any, journal: RollbackJournal) -> Any:
    if isinstance(value, JournaledDict) or isinstance(value, JournaledList):
        return value
    if isinstance(value, dict):
        return JournaledDict(value, journal)
    if isinstance(value, list):
        return JournaledList(value, journal)
    return value


class JournaledDict(dict):
    """dict-compatible proxy that journals direct key mutations."""

    def __init__(self, target: dict[Any, Any], journal: RollbackJournal) -> None:
        # Keep the actual dict base empty; all access is delegated to _target.
        dict.__init__(self)
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_journal", journal)

    def __contains__(self, key: object) -> bool:
        return key in self._target

    def __len__(self) -> int:
        return len(self._target)

    def __iter__(self) -> Iterator[Any]:
        return iter(self._target)

    def __bool__(self) -> bool:
        return bool(self._target)

    def __getitem__(self, key: Any) -> Any:
        return _wrap(self._target[key], self._journal)

    def __setitem__(self, key: Any, value: Any) -> None:
        self._journal.record_dict_key(self._target, key)
        self._target[key] = _unwrap(value)

    def __delitem__(self, key: Any) -> None:
        self._journal.record_dict_key(self._target, key)
        del self._target[key]

    def get(self, key: Any, default: Any = None) -> Any:
        return _wrap(self._target.get(key, default), self._journal)

    def setdefault(self, key: Any, default: Any = None) -> Any:
        if key not in self._target:
            self._journal.record_dict_key(self._target, key)
            self._target[key] = _unwrap(default)
        return _wrap(self._target[key], self._journal)

    def pop(self, key: Any, default: Any = _MISSING) -> Any:
        if key in self._target:
            self._journal.record_dict_key(self._target, key)
            return _wrap(self._target.pop(key), self._journal)
        if default is _MISSING:
            raise KeyError(key)
        return default

    def popitem(self) -> tuple[Any, Any]:
        if not self._target:
            raise KeyError("popitem(): dictionary is empty")
        key = next(reversed(self._target))
        self._journal.record_dict_key(self._target, key)
        value = self._target.pop(key)
        return key, _wrap(value, self._journal)

    def clear(self) -> None:
        for key in list(self._target.keys()):
            self._journal.record_dict_key(self._target, key)
        self._target.clear()

    def update(self, *args: Any, **kwargs: Any) -> None:
        other: dict[Any, Any] = {}
        if args:
            if len(args) > 1:
                raise TypeError("update expected at most 1 positional argument")
            other.update(dict(args[0]))
        other.update(kwargs)
        for key, value in other.items():
            self[key] = value

    def keys(self):  # type: ignore[override]
        return self._target.keys()

    def values(self):  # type: ignore[override]
        for value in self._target.values():
            yield _wrap(value, self._journal)

    def items(self):  # type: ignore[override]
        for key, value in self._target.items():
            yield key, _wrap(value, self._journal)

    def copy(self) -> dict[Any, Any]:  # type: ignore[override]
        return dict(self._target)


class JournaledList(list):
    """list-compatible proxy that journals direct list mutations."""

    def __init__(self, target: list[Any], journal: RollbackJournal) -> None:
        list.__init__(self)
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_journal", journal)

    def __len__(self) -> int:
        return len(self._target)

    def __iter__(self) -> Iterator[Any]:
        for value in self._target:
            yield _wrap(value, self._journal)

    def __bool__(self) -> bool:
        return bool(self._target)

    def __getitem__(self, index: Any) -> Any:
        value = self._target[index]
        if isinstance(index, slice):
            return [_wrap(v, self._journal) for v in value]
        return _wrap(value, self._journal)

    def __setitem__(self, index: Any, value: Any) -> None:
        self._journal.record_list_state(self._target)
        if isinstance(index, slice):
            self._target[index] = [_unwrap(v) for v in value]
        else:
            self._target[index] = _unwrap(value)

    def __delitem__(self, index: Any) -> None:
        self._journal.record_list_state(self._target)
        del self._target[index]

    def append(self, value: Any) -> None:  # type: ignore[override]
        self._journal.record_list_state(self._target)
        self._target.append(_unwrap(value))

    def extend(self, values: Iterable[Any]) -> None:  # type: ignore[override]
        self._journal.record_list_state(self._target)
        self._target.extend(_unwrap(v) for v in values)

    def insert(self, index: int, value: Any) -> None:  # type: ignore[override]
        self._journal.record_list_state(self._target)
        self._target.insert(index, _unwrap(value))

    def pop(self, index: int = -1) -> Any:  # type: ignore[override]
        self._journal.record_list_state(self._target)
        return _wrap(self._target.pop(index), self._journal)

    def remove(self, value: Any) -> None:  # type: ignore[override]
        self._journal.record_list_state(self._target)
        self._target.remove(_unwrap(value))

    def clear(self) -> None:  # type: ignore[override]
        self._journal.record_list_state(self._target)
        self._target.clear()

    def sort(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        self._journal.record_list_state(self._target)
        self._target.sort(*args, **kwargs)

    def reverse(self) -> None:  # type: ignore[override]
        self._journal.record_list_state(self._target)
        self._target.reverse()

    def copy(self) -> list[Any]:  # type: ignore[override]
        return list(self._target)


def run_with_bounded_rollback(state: Json, fn: Callable[[Json], Any]) -> tuple[Any, int]:
    """Run ``fn`` against ``state`` with rollback on exception.

    Returns ``(result, record_count)`` on success. If ``fn`` raises, state is
    restored before the original exception is re-raised. Rollback failures raise
    ``RollbackJournalError`` after best-effort reverse replay.
    """

    if not isinstance(state, dict):
        raise TypeError("bounded rollback requires dict state")

    journal = RollbackJournal()
    proxy = JournaledDict(state, journal)
    try:
        result = fn(proxy)
    except Exception:
        journal.rollback()
        raise
    count = journal.record_count
    journal.clear()
    return result, count


__all__ = [
    "JournaledDict",
    "JournaledList",
    "RollbackJournal",
    "RollbackJournalError",
    "run_with_bounded_rollback",
]
