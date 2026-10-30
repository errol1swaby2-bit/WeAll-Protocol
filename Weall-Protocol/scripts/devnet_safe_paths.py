#!/usr/bin/env python3
"""Constrain controlled-devnet reset and IPFS setup to approved local paths.

Only the explicit reset command deletes anything. check-devnet and check-ipfs
are read-only validation commands for the operator shell scripts.
"""
from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
from pathlib import Path


class UnsafeDevnetPath(ValueError):
    """A path cannot safely be used for the requested devnet operation."""


CONFIRMATION = "I_CONFIRM_DELETE_CUSTOM_DEVNET"
RESET_BASENAME = ".weall-devnet"
NOFOLLOW = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def checked_absolute(raw: str) -> Path:
    if not isinstance(raw, str) or not raw or raw != raw.strip() or "\x00" in raw:
        raise UnsafeDevnetPath("empty_or_malformed_path")
    if not raw.startswith("/") or "//" in raw or "\\" in raw:
        raise UnsafeDevnetPath("require_clean_absolute_posix_path")
    if any(part in (".", "..") for part in raw.split("/")):
        raise UnsafeDevnetPath("dot_component_or_path_traversal")
    result = Path(raw)
    if result == Path("/"):
        raise UnsafeDevnetPath("refuse_filesystem_root")
    if str(result) != raw:
        raise UnsafeDevnetPath("noncanonical_lexical_path")
    return result


def check_no_symlinks(path: Path) -> None:
    """Reject symlinks in any existing path component, not just the leaf."""
    current = Path("/")
    for part in path.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise UnsafeDevnetPath(f"symlink_component:{current}")


def verify_devnet_name(target: Path) -> None:
    if target.name != RESET_BASENAME:
        raise UnsafeDevnetPath("devnet_target_must_have_exact_basename")


def validate_devnet(target_raw: str) -> Path:
    target = checked_absolute(target_raw)
    verify_devnet_name(target)
    check_no_symlinks(target)
    return target


def _custom_reset_permitted(parent: Path) -> bool:
    allowed = os.environ.get("WEALL_DEVNET_RESET_ALLOWED_PARENT", "")
    acknowledgement = os.environ.get("WEALL_DEVNET_RESET_CONFIRM", "")
    if acknowledgement != CONFIRMATION or not allowed:
        return False
    try:
        approved = checked_absolute(allowed)
    except UnsafeDevnetPath:
        return False
    check_no_symlinks(approved)
    if not approved.is_dir():
        return False
    if approved in (Path.home(), Path("/"), Path("/tmp"), Path("/var"), Path("/home")):
        return False
    return parent == approved


def verify_reset_target(target: Path, repo_root: Path) -> None:
    verify_devnet_name(target)
    check_no_symlinks(target)
    if target == repo_root / RESET_BASENAME:
        return
    if not _custom_reset_permitted(target.parent):
        raise UnsafeDevnetPath(
            "custom_devnet_requires_exact_allowed_parent_and_explicit_confirmation"
        )


def open_existing_directory_nofollow(path: Path) -> int:
    """Open every component relative to an already-open directory fd."""
    fd = os.open("/", NOFOLLOW)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def reset(target_raw: str, repo_root: Path) -> Path:
    target = validate_devnet(target_raw)
    repo_root = repo_root.resolve(strict=True)
    verify_reset_target(target, repo_root)
    if not shutil.rmtree.avoids_symlink_attacks:
        raise UnsafeDevnetPath("fd_based_symlink_safe_rmtree_unavailable")
    parent_fd = open_existing_directory_nofollow(target.parent)
    try:
        try:
            mode = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False).st_mode
        except FileNotFoundError:
            mode = None
        if mode is not None and not stat.S_ISDIR(mode):
            raise UnsafeDevnetPath("target_not_real_directory")
        if mode is not None:
            shutil.rmtree(target.name, dir_fd=parent_fd)
        os.mkdir(target.name, mode=0o700, dir_fd=parent_fd)
        devnet_fd = os.open(target.name, NOFOLLOW, dir_fd=parent_fd)
        try:
            os.mkdir("node1", mode=0o700, dir_fd=devnet_fd)
            os.mkdir("node2", mode=0o700, dir_fd=devnet_fd)
        finally:
            os.close(devnet_fd)
    finally:
        os.close(parent_fd)
    return target


def check_ipfs(devnet_raw: str, ipfs_raw: str) -> Path:
    devnet = validate_devnet(devnet_raw)
    ipfs = checked_absolute(ipfs_raw)
    if ipfs.parent != devnet or ipfs.name in ("blocks", RESET_BASENAME):
        raise UnsafeDevnetPath("ipfs_partition_must_be_a_direct_devnet_child")
    # Validate all existing internal Kubo paths before the launcher can mkdir
    # or chmod them. Never follow an externally supplied blocks/temp symlink.
    for part in (ipfs, ipfs / "blocks", ipfs / "blocks" / "temp",
                 ipfs / "blocks" / "SHARDING"):
        check_no_symlinks(part)
    if not devnet.is_dir():
        raise UnsafeDevnetPath("devnet_directory_missing")
    blocks = ipfs / "blocks"
    if blocks.exists() and (not blocks.is_dir() or not (blocks / "SHARDING").is_file()):
        raise UnsafeDevnetPath("ipfs_blocks_without_valid_sharding_preserved")
    return ipfs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p_reset = commands.add_parser("reset")
    p_reset.add_argument("target")
    p_devnet = commands.add_parser("check-devnet")
    p_devnet.add_argument("target")
    p_ipfs = commands.add_parser("check-ipfs")
    p_ipfs.add_argument("devnet")
    p_ipfs.add_argument("partition")
    args = parser.parse_args()
    try:
        if args.command == "reset":
            root = Path(__file__).resolve().parents[1]
            result = reset(args.target, root)
        elif args.command == "check-devnet":
            result = validate_devnet(args.target)
        else:
            result = check_ipfs(args.devnet, args.partition)
    except (UnsafeDevnetPath, OSError) as exc:
        print(f"ERROR: unsafe controlled-devnet path: {exc}", file=sys.stderr)
        return 2
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
