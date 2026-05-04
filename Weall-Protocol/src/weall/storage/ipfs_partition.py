from __future__ import annotations

import os
from pathlib import Path
from typing import Any

_DEFAULT_RESERVE_BYTES = 512 * 1024 * 1024


def _mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return int(default)
    try:
        return int(str(raw).strip())
    except Exception as exc:
        if _mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}") from exc
        return int(default)


def read_partition_config() -> tuple[str, int, int]:
    """Return API-local IPFS partition quota config.

    The returned tuple is:
      (partition_path, cap_bytes, reserve_bytes)

    If ``partition_path`` is empty, partition enforcement is disabled. Invalid
    integer environment values fail closed in production and fall back to safe
    defaults in tests/dev, matching the public media route's env posture.
    """

    path = str(os.getenv("WEALL_IPFS_PARTITION_PATH", "") or "").strip()
    cap = _env_int("WEALL_IPFS_PARTITION_CAP_BYTES", 0)
    reserve = _env_int("WEALL_IPFS_PARTITION_RESERVE_BYTES", _DEFAULT_RESERVE_BYTES)
    if cap < 0:
        cap = 0
    if reserve < 0:
        reserve = 0
    return path, int(cap), int(reserve)


def _directory_size_bytes(path: Path) -> int:
    total = 0
    for root, dirs, files in os.walk(path):
        # Do not follow symlinked directories while sizing the mounted partition.
        dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
        for name in files:
            item = Path(root) / name
            try:
                if item.is_symlink():
                    continue
                total += int(item.stat().st_size)
            except FileNotFoundError:
                continue
            except OSError:
                continue
    return int(total)


def can_accept_bytes(
    *,
    partition_path: str,
    cap_bytes: int,
    reserve_bytes: int,
    need_bytes: int,
) -> tuple[bool, str, dict[str, Any]]:
    """Return whether a node-local IPFS partition can accept an upload.

    This is deliberately API/node-local logic, not consensus logic. If no
    partition path is configured, enforcement is disabled and uploads are judged
    by the route-level max-upload limit instead.
    """

    path_s = str(partition_path or "").strip()
    need = max(0, int(need_bytes or 0))
    cap = max(0, int(cap_bytes or 0))
    reserve = max(0, int(reserve_bytes or 0))

    details: dict[str, Any] = {
        "partition_path": path_s,
        "cap_bytes": cap,
        "reserve_bytes": reserve,
        "need_bytes": need,
        "enforced": bool(path_s),
    }

    if not path_s:
        return True, "disabled", details

    path = Path(path_s)
    if not path.exists() or not path.is_dir():
        return False, "partition_missing", details

    try:
        stat = os.statvfs(path)
        free_bytes = int(stat.f_bavail) * int(stat.f_frsize)
        total_bytes = int(stat.f_blocks) * int(stat.f_frsize)
    except OSError as exc:
        details["error"] = str(exc)
        return False, "stat_failed", details

    used_bytes = _directory_size_bytes(path)
    details.update(
        {
            "free_bytes": free_bytes,
            "total_bytes": total_bytes,
            "used_bytes": used_bytes,
        }
    )

    if cap > 0 and used_bytes + need > cap:
        return False, "cap_exceeded", details

    if reserve > 0 and free_bytes - need < reserve:
        return False, "insufficient_free", details

    return True, "ok", details
