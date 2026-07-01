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
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from contextvars import ContextVar, Token
from typing import Any

Json = dict[str, Any]
_MISSING = object()

_ROLLBACK_DIAGNOSTICS_TEMPLATE: dict[str, int] = {
    "rollback_snapshot_count": 0,
    "rollback_snapshot_bytes_estimate": 0,
    "rollback_snapshot_path_count": 0,
    "rollback_snapshot_duplicate_path_count": 0,
    "rollback_scalar_snapshot_count": 0,
    "rollback_container_snapshot_count": 0,
    "rollback_list_snapshot_count": 0,
    "rollback_dict_snapshot_count": 0,
}
_ROLLBACK_DIAGNOSTICS: dict[str, int] = dict(_ROLLBACK_DIAGNOSTICS_TEMPLATE)
_ROLLBACK_TOP_LIMIT = 12
_ROLLBACK_PATH_COUNTERS: dict[str, Counter[str]] = {
    "rollback_top_snapshot_paths": Counter(),
    "rollback_top_snapshot_prefixes": Counter(),
    "rollback_top_snapshot_paths_by_estimated_bytes": Counter(),
    "rollback_top_dict_snapshot_paths": Counter(),
    "rollback_top_list_snapshot_paths": Counter(),
    "rollback_top_duplicate_snapshot_paths": Counter(),
    "rollback_snapshot_by_tx_kind": Counter(),
}
_ROLLBACK_TX_KIND: ContextVar[str] = ContextVar("weall_rollback_tx_kind", default="unknown")


def reset_rollback_diagnostics() -> None:
    """Reset process-local rollback diagnostics used by audit harnesses.

    This is intentionally observational.  Consensus execution does not read
    these counters, and clearing them has no effect on rollback behavior.
    """

    _ROLLBACK_DIAGNOSTICS.clear()
    _ROLLBACK_DIAGNOSTICS.update(_ROLLBACK_DIAGNOSTICS_TEMPLATE)
    for counter in _ROLLBACK_PATH_COUNTERS.values():
        counter.clear()


def _top_counter_items(counter: Counter[str], *, value_key: str = "count") -> list[dict[str, int | str]]:
    items = sorted(counter.items(), key=lambda item: (-int(item[1]), str(item[0])))
    return [{"path": str(path), value_key: int(value)} for path, value in items[:_ROLLBACK_TOP_LIMIT]]


def get_rollback_diagnostics() -> dict[str, Any]:
    """Return a copy of process-local rollback diagnostics."""

    out: dict[str, Any] = dict(_ROLLBACK_DIAGNOSTICS_TEMPLATE)
    out.update(_ROLLBACK_DIAGNOSTICS)
    out["rollback_top_snapshot_paths"] = _top_counter_items(_ROLLBACK_PATH_COUNTERS["rollback_top_snapshot_paths"])
    out["rollback_top_snapshot_prefixes"] = _top_counter_items(_ROLLBACK_PATH_COUNTERS["rollback_top_snapshot_prefixes"])
    out["rollback_top_snapshot_paths_by_estimated_bytes"] = _top_counter_items(
        _ROLLBACK_PATH_COUNTERS["rollback_top_snapshot_paths_by_estimated_bytes"],
        value_key="bytes_estimate",
    )
    out["rollback_top_dict_snapshot_paths"] = _top_counter_items(_ROLLBACK_PATH_COUNTERS["rollback_top_dict_snapshot_paths"])
    out["rollback_top_list_snapshot_paths"] = _top_counter_items(_ROLLBACK_PATH_COUNTERS["rollback_top_list_snapshot_paths"])
    out["rollback_top_duplicate_snapshot_paths"] = _top_counter_items(_ROLLBACK_PATH_COUNTERS["rollback_top_duplicate_snapshot_paths"])
    out["rollback_snapshot_by_tx_kind"] = dict(
        sorted(
            ((str(k), int(v)) for k, v in _ROLLBACK_PATH_COUNTERS["rollback_snapshot_by_tx_kind"].items()),
            key=lambda item: (-int(item[1]), str(item[0])),
        )
    )
    return out


def set_rollback_diagnostic_tx_kind(tx_kind: str | None) -> Token[str]:
    """Set process-local diagnostic attribution for snapshots in one tx apply."""

    normalized = str(tx_kind or "unknown").strip() or "unknown"
    return _ROLLBACK_TX_KIND.set(normalized)


def reset_rollback_diagnostic_tx_kind(token: Token[str]) -> None:
    """Restore the previous diagnostic tx-kind attribution token."""

    _ROLLBACK_TX_KIND.reset(token)


def _diagnostic_add(key: str, value: int = 1) -> None:
    _ROLLBACK_DIAGNOSTICS[key] = int(_ROLLBACK_DIAGNOSTICS.get(key, 0)) + int(value)


def _snapshot_size_estimate(value: Any) -> int:
    """Cheap deterministic size estimate for rollback diagnostics only."""

    if value is _MISSING or value is None:
        return 0
    if isinstance(value, (str, bytes, bytearray)):
        return len(value)
    if isinstance(value, (int, float, bool)):
        return len(repr(value))
    if isinstance(value, dict):
        # Avoid recursively walking large containers; the snapshot itself is
        # already the expensive operation we are measuring.
        return len(value)
    if isinstance(value, (list, tuple, set)):
        return len(value)
    return len(repr(value))


def _classify_snapshot(value: Any) -> None:
    if isinstance(value, dict):
        _diagnostic_add("rollback_dict_snapshot_count")
        _diagnostic_add("rollback_container_snapshot_count")
    elif isinstance(value, list):
        _diagnostic_add("rollback_list_snapshot_count")
        _diagnostic_add("rollback_container_snapshot_count")
    elif isinstance(value, (set, tuple)):
        _diagnostic_add("rollback_container_snapshot_count")
    else:
        _diagnostic_add("rollback_scalar_snapshot_count")


def _path_segment(value: Any) -> str:
    text = str(value)
    if not text:
        return "<empty>"
    return text.replace(".", "_")[:96]


def _path_label(path: tuple[Any, ...] | None, fallback: object) -> str:
    if path:
        return ".".join(_path_segment(part) for part in path)
    return str(fallback)


def _record_path_attribution(*, label: str, value: Any, size_estimate: int, duplicate: bool) -> None:
    kind = str(_ROLLBACK_TX_KIND.get() or "unknown")
    if duplicate:
        _ROLLBACK_PATH_COUNTERS["rollback_top_duplicate_snapshot_paths"][label] += 1
        return

    _ROLLBACK_PATH_COUNTERS["rollback_top_snapshot_paths"][label] += 1
    _ROLLBACK_PATH_COUNTERS["rollback_top_snapshot_paths_by_estimated_bytes"][label] += int(size_estimate)
    _ROLLBACK_PATH_COUNTERS["rollback_snapshot_by_tx_kind"][kind] += 1

    parts = [part for part in label.split(".") if part]
    for width in range(1, min(3, len(parts)) + 1):
        _ROLLBACK_PATH_COUNTERS["rollback_top_snapshot_prefixes"][".".join(parts[:width])] += 1

    if isinstance(value, dict):
        _ROLLBACK_PATH_COUNTERS["rollback_top_dict_snapshot_paths"][label] += 1
    elif isinstance(value, list):
        _ROLLBACK_PATH_COUNTERS["rollback_top_list_snapshot_paths"][label] += 1


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
        self._dict_paths_seen: set[tuple[int, Any]] = set()
        # list id -> "length" or "full".  A length snapshot is sufficient for
        # append/extend-only mutations.  If a later mutation reorders, deletes,
        # or overwrites list elements, a full snapshot is added after the length
        # snapshot so reverse rollback restores the exact original list.
        self._list_snapshot_mode: dict[int, str] = {}

    def _record_snapshot(
        self,
        *,
        value: Any,
        path_key: object,
        semantic_path: tuple[Any, ...] | None = None,
        duplicate: bool = False,
    ) -> None:
        label = _path_label(semantic_path, path_key)
        if duplicate:
            _diagnostic_add("rollback_snapshot_duplicate_path_count")
            _record_path_attribution(label=label, value=value, size_estimate=0, duplicate=True)
            return
        size = _snapshot_size_estimate(value)
        _diagnostic_add("rollback_snapshot_count")
        _diagnostic_add("rollback_snapshot_path_count")
        _diagnostic_add("rollback_snapshot_bytes_estimate", size)
        _classify_snapshot(value)
        _record_path_attribution(label=label, value=value, size_estimate=size, duplicate=False)

    def record_dict_key(self, target: dict[Any, Any], key: Any, *, semantic_path: tuple[Any, ...] | None = None) -> None:
        path = (id(target), key)
        if path in self._dict_paths_seen:
            self._record_snapshot(value=_MISSING, path_key=path, semantic_path=semantic_path, duplicate=True)
            return
        self._dict_paths_seen.add(path)

        existed = key in target
        raw_previous = target.get(key, _MISSING) if existed else _MISSING
        self._record_snapshot(value=raw_previous, path_key=path, semantic_path=semantic_path)
        previous = copy.deepcopy(raw_previous) if existed else _MISSING

        def undo() -> None:
            if previous is _MISSING:
                target.pop(key, None)
            else:
                target[key] = copy.deepcopy(previous)

        self._records.append(undo)

    def record_list_state(self, target: list[Any], *, semantic_path: tuple[Any, ...] | None = None) -> None:
        list_id = id(target)
        if self._list_snapshot_mode.get(list_id) == "full":
            self._record_snapshot(value=_MISSING, path_key=(list_id, "list_full"), semantic_path=semantic_path, duplicate=True)
            return

        previous = copy.deepcopy(target)
        self._list_snapshot_mode[list_id] = "full"
        self._record_snapshot(value=target, path_key=(list_id, "list_full"), semantic_path=semantic_path)

        def undo() -> None:
            target[:] = copy.deepcopy(previous)

        self._records.append(undo)

    def record_list_append(self, target: list[Any], *, semantic_path: tuple[Any, ...] | None = None) -> None:
        list_id = id(target)
        append_path = tuple(semantic_path or ()) + ("append",) if semantic_path else None
        if list_id in self._list_snapshot_mode:
            self._record_snapshot(value=_MISSING, path_key=(list_id, "list_append"), semantic_path=append_path, duplicate=True)
            return

        previous_len = len(target)
        self._list_snapshot_mode[list_id] = "length"
        self._record_snapshot(value=[], path_key=(list_id, "list_append"), semantic_path=append_path)

        def undo() -> None:
            del target[previous_len:]

        self._records.append(undo)

    def rollback(self) -> None:
        errors: list[str] = []
        for undo in reversed(self._records):
            try:
                undo()
            except Exception as exc:  # pragma: no cover - fail-closed guard
                errors.append(type(exc).__name__)
        self._records.clear()
        self._dict_paths_seen.clear()
        self._list_snapshot_mode.clear()
        if errors:
            raise RollbackJournalError("rollback_failed:" + ",".join(errors))

    def clear(self) -> None:
        self._records.clear()
        self._dict_paths_seen.clear()
        self._list_snapshot_mode.clear()

    @property
    def record_count(self) -> int:
        return len(self._records)


def _wrap(value: Any, journal: RollbackJournal, path: tuple[Any, ...] = ()) -> Any:
    if isinstance(value, JournaledDict) or isinstance(value, JournaledList):
        return value
    if isinstance(value, dict):
        return JournaledDict(value, journal, path=path)
    if isinstance(value, list):
        return JournaledList(value, journal, path=path)
    return value


class JournaledDict(dict):
    """dict-compatible proxy that journals direct key mutations."""

    def __init__(self, target: dict[Any, Any], journal: RollbackJournal, path: tuple[Any, ...] = ()) -> None:
        # Keep the actual dict base empty; all access is delegated to _target.
        dict.__init__(self)
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_journal", journal)
        object.__setattr__(self, "_path", tuple(path))

    def __contains__(self, key: object) -> bool:
        return key in self._target

    def __len__(self) -> int:
        return len(self._target)

    def __iter__(self) -> Iterator[Any]:
        return iter(self._target)

    def __bool__(self) -> bool:
        return bool(self._target)

    def __getitem__(self, key: Any) -> Any:
        return _wrap(self._target[key], self._journal, self._path + (_path_segment(key),))

    def __setitem__(self, key: Any, value: Any) -> None:
        semantic_path = self._path + (_path_segment(key),)
        self._journal.record_dict_key(self._target, key, semantic_path=semantic_path)
        self._target[key] = _unwrap(value)

    def __delitem__(self, key: Any) -> None:
        semantic_path = self._path + (_path_segment(key),)
        self._journal.record_dict_key(self._target, key, semantic_path=semantic_path)
        del self._target[key]

    def get(self, key: Any, default: Any = None) -> Any:
        return _wrap(self._target.get(key, default), self._journal, self._path + (_path_segment(key),))

    def setdefault(self, key: Any, default: Any = None) -> Any:
        semantic_path = self._path + (_path_segment(key),)
        if key not in self._target:
            self._journal.record_dict_key(self._target, key, semantic_path=semantic_path)
            self._target[key] = _unwrap(default)
        return _wrap(self._target[key], self._journal, semantic_path)

    def pop(self, key: Any, default: Any = _MISSING) -> Any:
        if key in self._target:
            semantic_path = self._path + (_path_segment(key),)
            self._journal.record_dict_key(self._target, key, semantic_path=semantic_path)
            return _wrap(self._target.pop(key), self._journal, semantic_path)
        if default is _MISSING:
            raise KeyError(key)
        return default

    def popitem(self) -> tuple[Any, Any]:
        if not self._target:
            raise KeyError("popitem(): dictionary is empty")
        key = next(reversed(self._target))
        semantic_path = self._path + (_path_segment(key),)
        self._journal.record_dict_key(self._target, key, semantic_path=semantic_path)
        value = self._target.pop(key)
        return key, _wrap(value, self._journal, semantic_path)

    def clear(self) -> None:
        for key in list(self._target.keys()):
            self._journal.record_dict_key(self._target, key, semantic_path=self._path + (_path_segment(key),))
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
        for key, value in self._target.items():
            yield _wrap(value, self._journal, self._path + (_path_segment(key),))

    def items(self):  # type: ignore[override]
        for key, value in self._target.items():
            yield key, _wrap(value, self._journal, self._path + (_path_segment(key),))

    def copy(self) -> dict[Any, Any]:  # type: ignore[override]
        return dict(self._target)


class JournaledList(list):
    """list-compatible proxy that journals direct list mutations."""

    def __init__(self, target: list[Any], journal: RollbackJournal, path: tuple[Any, ...] = ()) -> None:
        list.__init__(self)
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_journal", journal)
        object.__setattr__(self, "_path", tuple(path))

    def __len__(self) -> int:
        return len(self._target)

    def __iter__(self) -> Iterator[Any]:
        for idx, value in enumerate(self._target):
            yield _wrap(value, self._journal, self._path + (idx,))

    def __bool__(self) -> bool:
        return bool(self._target)

    def __getitem__(self, index: Any) -> Any:
        value = self._target[index]
        if isinstance(index, slice):
            start = 0 if index.start is None else int(index.start)
            return [_wrap(v, self._journal, self._path + (start + offset,)) for offset, v in enumerate(value)]
        return _wrap(value, self._journal, self._path + (index,))

    def __setitem__(self, index: Any, value: Any) -> None:
        self._journal.record_list_state(self._target, semantic_path=self._path)
        if isinstance(index, slice):
            self._target[index] = [_unwrap(v) for v in value]
        else:
            self._target[index] = _unwrap(value)

    def __delitem__(self, index: Any) -> None:
        self._journal.record_list_state(self._target, semantic_path=self._path)
        del self._target[index]

    def append(self, value: Any) -> None:  # type: ignore[override]
        self._journal.record_list_append(self._target, semantic_path=self._path)
        self._target.append(_unwrap(value))

    def extend(self, values: Iterable[Any]) -> None:  # type: ignore[override]
        self._journal.record_list_append(self._target, semantic_path=self._path)
        self._target.extend(_unwrap(v) for v in values)

    def insert(self, index: int, value: Any) -> None:  # type: ignore[override]
        self._journal.record_list_state(self._target, semantic_path=self._path)
        self._target.insert(index, _unwrap(value))

    def pop(self, index: int = -1) -> Any:  # type: ignore[override]
        self._journal.record_list_state(self._target, semantic_path=self._path)
        return _wrap(self._target.pop(index), self._journal, self._path + (index,))

    def remove(self, value: Any) -> None:  # type: ignore[override]
        self._journal.record_list_state(self._target, semantic_path=self._path)
        self._target.remove(_unwrap(value))

    def clear(self) -> None:  # type: ignore[override]
        self._journal.record_list_state(self._target, semantic_path=self._path)
        self._target.clear()

    def sort(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        self._journal.record_list_state(self._target, semantic_path=self._path)
        self._target.sort(*args, **kwargs)

    def reverse(self) -> None:  # type: ignore[override]
        self._journal.record_list_state(self._target, semantic_path=self._path)
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
    proxy = JournaledDict(state, journal, path=())
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
    "get_rollback_diagnostics",
    "reset_rollback_diagnostics",
    "reset_rollback_diagnostic_tx_kind",
    "set_rollback_diagnostic_tx_kind",
    "run_with_bounded_rollback",
]
