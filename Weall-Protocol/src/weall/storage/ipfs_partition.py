# projects/Weall-Protocol/src/weall/storage/ipfs_partition.py
from __future__ import annotations

"""Local IPFS partition/quota helpers.

WeAll's protocol-level storage model has operator-declared `capacity_bytes`, but
node operators also need a *real*, locally enforced budget for disk usage.

This module supports the "mounted path you control" design:

  - WEALL_IPFS_PARTITION_PATH: mount point (ideally dedicated to IPFS repo)
  - WEALL_IPFS_PARTITION_CAP_BYTES: budget enforced by WeAll (can be <= FS size)
  - WEALL_IPFS_PARTITION_FREE_RESERVE_BYTES: safety buffer to avoid filling disk

Enforcement strategy:
  - Query filesystem stats for the mount point.
  - Estimate "used" as (total - free). For a dedicated mount, this tracks IPFS
    repo growth closely.
  - Require: free_after_reserve >= need_bytes AND used + need_bytes <= cap_bytes
    (when cap_bytes > 0).
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, Tuple

Json = Dict[str, Any]


def _mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


@dataclass
class PartitionStats:
    path: str
    total_bytes: int
    free_bytes: int
    used_bytes: int


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or str(v).strip() == "":
        return int(default)
    try:
        return int(str(v).strip())
    except Exception as exc:
        if _mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}") from exc
        return int(default)


def _env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip()


def read_partition_config() -> Tuple[str, int, int]:
    """Read partition config from env.

    Returns: (partition_path, cap_bytes, reserve_bytes)
    """
    path = _env_str("WEALL_IPFS_PARTITION_PATH", "")
    cap = _env_int("WEALL_IPFS_PARTITION_CAP_BYTES", 0)
    reserve = _env_int("WEALL_IPFS_PARTITION_FREE_RESERVE_BYTES", 512 * 1024 * 1024)
    if reserve < 0:
        reserve = 0
    if cap < 0:
        cap = 0
    return path, int(cap), int(reserve)


def stat_partition(path: str) -> PartitionStats:
    p = str(path or "").strip()
    if not p:
        raise RuntimeError("missing_partition_path")
    if not os.path.exists(p):
        raise RuntimeError(f"partition_path_not_found:{p}")

    st = os.statvfs(p)
    # Use f_frsize when available; fall back to f_bsize.
    bsz = int(getattr(st, "f_frsize", 0) or getattr(st, "f_bsize", 0) or 4096)
    total = int(st.f_blocks) * bsz
    free = int(st.f_bavail) * bsz
    used = max(0, total - free)
    return PartitionStats(path=p, total_bytes=total, free_bytes=free, used_bytes=used)


def can_accept_bytes(
    *,
    partition_path: str,
    cap_bytes: int,
    reserve_bytes: int,
    need_bytes: int,
) -> Tuple[bool, str, Json]:
    """Check whether the local partition budget can accept `need_bytes`.

    If partition_path is empty, returns ok=True (feature disabled).
    """
    p = str(partition_path or "").strip()
    need = int(need_bytes or 0)
    if need < 0:
        need = 0

    if not p:
        return True, "disabled", {"need_bytes": need}

    try:
        stats = stat_partition(p)
    except Exception as e:
        return False, "partition_unavailable", {"partition_path": p, "error": str(e), "need_bytes": need}

    reserve = int(reserve_bytes or 0)
    if reserve < 0:
        reserve = 0

    free_after_reserve = max(0, int(stats.free_bytes) - reserve)
    if need > free_after_reserve:
        return (
            False,
            "insufficient_free_space",
            {
                "partition_path": p,
                "need_bytes": need,
                "free_bytes": int(stats.free_bytes),
                "reserve_bytes": reserve,
                "free_after_reserve": int(free_after_reserve),
                "total_bytes": int(stats.total_bytes),
                "used_bytes": int(stats.used_bytes),
            },
        )

    cap = int(cap_bytes or 0)
    if cap > 0:
        if int(stats.used_bytes) + need > cap:
            return (
                False,
                "capacity_cap_exceeded",
                {
                    "partition_path": p,
                    "need_bytes": need,
                    "cap_bytes": cap,
                    "used_bytes": int(stats.used_bytes),
                    "free_bytes": int(stats.free_bytes),
                    "reserve_bytes": reserve,
                    "total_bytes": int(stats.total_bytes),
                },
            )

    return (
        True,
        "ok",
        {
            "partition_path": p,
            "need_bytes": need,
            "cap_bytes": int(cap_bytes or 0),
            "free_bytes": int(stats.free_bytes),
            "reserve_bytes": reserve,
            "total_bytes": int(stats.total_bytes),
            "used_bytes": int(stats.used_bytes),
        },
    )
