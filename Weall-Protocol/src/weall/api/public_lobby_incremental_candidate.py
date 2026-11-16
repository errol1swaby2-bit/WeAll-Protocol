"""A03 offline, non-authoritative one-block incremental public-lobby projection.

This is NOT a production block-commit hook or a consensus component.
The durable SQLite ledger_state triggers installed by PublicLobbyIndexCandidate
always invalidate visible metadata on commit. A separate, opt-in post-commit
reconciler may restore only a provably consecutive, locally self-bound head.
A missing/moderation-changing/gapped head remains unavailable until rebuilding.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from weall.api.public_lobby_index_candidate import (
    _INVALIDATION_TRIGGERS,
    _MAX_BUILD_COMMENTS,
    _SCHEMA_VERSION,
    PublicLobbyIndexCandidate,
    PublicLobbyIndexUnavailable,
)
from weall.api.routes_public_parts.content import (
    _as_dict,
    _canonical_lobby_comment_index_matches,
    _comment_visible,
    _comments,
    _safe_int,
    _str_param,
)
from weall.runtime.block_commitment_validation import ensure_complete_block_commitments
from weall.runtime.sqlite_db import SqliteLedgerStore, strict_json_loads
from weall.runtime.state_hash import compute_state_root

Json = dict[str, Any]

_MAX_CHANGED_COMMENTS = 256


def prepare_comment_delta(
    before: Json, after: Json, *, max_changes: int = _MAX_CHANGED_COMMENTS
) -> tuple[list[str], list[tuple[str, str, int, str, str]]]:
    """Return changed IDs and new visible rows; conservative fallback on anything else.

    The comparison is intentionally exhaustive and therefore **not** a scalable
    mutation journal. It is an offline reference that proves SQL row-delta
    parity without allowing an incomplete caller-supplied list of changed IDs.
    """
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise PublicLobbyIndexUnavailable("invalid_delta_state")
    if before.get("disputes_by_id") != after.get("disputes_by_id") or before.get(
        "disputes_by_target"
    ) != after.get("disputes_by_target"):
        raise PublicLobbyIndexUnavailable("dispute_change_requires_full_rebuild")
    before_content = _as_dict(before.get("content"))
    after_content = _as_dict(after.get("content"))
    # Any unclassified content-domain change falls back to full projection.
    # Moderation is in this remainder; no missing target may become visible.
    if {key: value for key, value in before_content.items() if key != "comments"} != {
        key: value for key, value in after_content.items() if key != "comments"
    }:
        raise PublicLobbyIndexUnavailable("content_policy_change_requires_full_rebuild")

    old = _comments(before)
    new = _comments(after)
    if len(old) > _MAX_BUILD_COMMENTS or len(new) > _MAX_BUILD_COMMENTS:
        raise PublicLobbyIndexUnavailable("offline_delta_scan_budget_exceeded")
    bound = min(_MAX_CHANGED_COMMENTS, max(1, int(max_changes)))
    changed: list[str] = []
    rows: list[tuple[str, str, int, str, str]] = []
    for key in sorted(set(old) | set(new)):
        if old.get(key) == new.get(key) and (key in old) == (key in new):
            continue
        if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 4096:
            raise PublicLobbyIndexUnavailable("invalid_changed_comment_identity")
        changed.append(key)
        if len(changed) > bound:
            raise PublicLobbyIndexUnavailable("delta_change_budget_exceeded")
        comment = _as_dict(new.get(key))
        if str(comment.get("surface") or "").strip().lower() != "public_lobby":
            continue
        thread = str(comment.get("post_id") or "").strip()
        if not thread.startswith("public-lobby:") or len(thread.encode("utf-8")) > 2048:
            continue
        if not _canonical_lobby_comment_index_matches(comment, key):
            continue
        if not _comment_visible(after, comment, key):
            continue
        nonce = _safe_int(comment.get("created_nonce"), 0)
        if not -(2**63) <= nonce < 2**63:
            raise PublicLobbyIndexUnavailable("nonce_out_of_sqlite_range")
        rows.append(
            (
                thread,
                key,
                nonce,
                _str_param(comment.get("author")),
                _str_param(comment.get("body")),
            )
        )
    return changed, rows


def _committed_block(con: sqlite3.Connection, *, chain_id: str, height: int, block_id: str) -> Json:
    row = con.execute(
        "SELECT block_json FROM blocks WHERE height=? AND block_id=? LIMIT 1;",
        (height, block_id),
    ).fetchone()
    if row is None:
        raise PublicLobbyIndexUnavailable("locally_committed_block_missing")
    try:
        raw = strict_json_loads(row["block_json"])
        if not isinstance(raw, dict):
            raise ValueError("block_json_not_object")
        canonical, _ = ensure_complete_block_commitments(block=raw, chain_id=chain_id)
        return canonical
    except Exception as exc:
        raise PublicLobbyIndexUnavailable("locally_committed_block_invalid") from exc


def _verify_block_root(block: Json, *, state_root: str) -> None:
    header = _as_dict(block.get("header"))
    if str(header.get("state_root") or "") != state_root:
        raise PublicLobbyIndexUnavailable("committed_block_state_root_mismatch")


def _attached(con: sqlite3.Connection) -> bool:
    names = {
        str(row["name"])
        for row in con.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type='trigger' AND name IN (?, ?, ?);
            """,
            _INVALIDATION_TRIGGERS,
        ).fetchall()
    }
    return names == set(_INVALIDATION_TRIGGERS)


class PublicLobbyIncrementalCandidate:
    """Experimental one-block reconciler with durable prior-head anchor."""

    def __init__(self, index: PublicLobbyIndexCandidate):
        self.index = index

    def arm_after_verified_rebuild(self, *, chain_id: str) -> None:
        """Initialize a durable anchor only after verified same-ledger rebuild."""
        with self.index.db.write_tx() as con:
            if not _attached(con):
                raise PublicLobbyIndexUnavailable("commit_invalidation_not_attached")
            meta = con.execute(
                """
                SELECT chain_id, height, block_id, state_root, version
                FROM public_lobby_shadow_meta WHERE id=1;
                """
            ).fetchone()
            head = con.execute(
                "SELECT height, block_id, state_json FROM ledger_state WHERE id=1;"
            ).fetchone()
            if meta is None or head is None or int(meta["version"]) != _SCHEMA_VERSION:
                raise PublicLobbyIndexUnavailable("verified_rebuild_required")
            state = strict_json_loads(head["state_json"])
            if not isinstance(state, dict):
                raise PublicLobbyIndexUnavailable("local_state_corrupt")
            height = int(head["height"])
            block_id = str(head["block_id"])
            root = compute_state_root(state)
            if (
                meta["chain_id"] != chain_id
                or int(meta["height"]) != height
                or meta["block_id"] != block_id
                or meta["state_root"] != root
                or height <= 0
            ):
                raise PublicLobbyIndexUnavailable("verified_rebuild_binding_mismatch")
            block = _committed_block(con, chain_id=chain_id, height=height, block_id=block_id)
            _verify_block_root(block, state_root=root)
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS public_lobby_shadow_anchor (
                    id INTEGER PRIMARY KEY CHECK (id=1),
                    chain_id TEXT NOT NULL,
                    height INTEGER NOT NULL,
                    block_id TEXT NOT NULL,
                    state_root TEXT NOT NULL
                );
                """
            )
            con.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_public_lobby_shadow_comment
                ON public_lobby_shadow_rows(comment_id);
                """
            )
            con.execute(
                """
                INSERT INTO public_lobby_shadow_anchor(id, chain_id, height, block_id, state_root)
                VALUES(1, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    chain_id=excluded.chain_id,
                    height=excluded.height,
                    block_id=excluded.block_id,
                    state_root=excluded.state_root;
                """,
                (chain_id, height, block_id, root),
            )

    def advance_one_committed_block(self, *, previous_state: Json, chain_id: str) -> int:
        """Apply only changed comment rows after ONE locally committed block.

        Current state is read from durable local SQLite. The previous explicit
        snapshot must match the independently stored pre-commit index anchor
        and the parent's canonical block root. All proof and mutation checks
        are revalidated inside the writer transaction. Stale shadow rows are
        never readable while this process runs, including during failures.
        """
        if not isinstance(previous_state, dict) or not chain_id:
            raise PublicLobbyIndexUnavailable("previous_state_required")
        old_height = _safe_int(previous_state.get("height"), 0)
        old_id = str(previous_state.get("tip") or "")
        old_root = compute_state_root(previous_state)
        current_state = SqliteLedgerStore(db=self.index.db).read()
        if not isinstance(current_state, dict):
            raise PublicLobbyIndexUnavailable("local_state_corrupt")
        new_height = _safe_int(current_state.get("height"), 0)
        new_id = str(current_state.get("tip") or "")
        new_root = compute_state_root(current_state)
        if old_height < 1 or new_height != old_height + 1 or not new_id or not old_id:
            raise PublicLobbyIndexUnavailable("single_block_delta_required")

        changed, upserts = prepare_comment_delta(previous_state, current_state)
        with self.index.db.write_tx() as con:
            if not _attached(con):
                raise PublicLobbyIndexUnavailable("commit_invalidation_not_attached")
            anchor = con.execute(
                """
                SELECT chain_id, height, block_id, state_root
                FROM public_lobby_shadow_anchor WHERE id=1;
                """
            ).fetchone()
            if (
                anchor is None
                or anchor["chain_id"] != chain_id
                or int(anchor["height"]) != old_height
                or anchor["block_id"] != old_id
                or anchor["state_root"] != old_root
            ):
                raise PublicLobbyIndexUnavailable("parent_shadow_anchor_mismatch")
            # If the invalidation trigger was bypassed, do not publish a
            # purported delta on an index that still claims to be current.
            if (
                con.execute("SELECT 1 FROM public_lobby_shadow_meta WHERE id=1;").fetchone()
                is not None
            ):
                raise PublicLobbyIndexUnavailable("ledger_invalidation_missing")

            durable = con.execute(
                "SELECT height, block_id, state_json FROM ledger_state WHERE id=1;"
            ).fetchone()
            if (
                durable is None
                or int(durable["height"]) != new_height
                or durable["block_id"] != new_id
            ):
                raise PublicLobbyIndexUnavailable("local_head_changed_during_delta")
            try:
                durable_state = strict_json_loads(durable["state_json"])
                if (
                    not isinstance(durable_state, dict)
                    or compute_state_root(durable_state) != new_root
                ):
                    raise PublicLobbyIndexUnavailable("local_state_changed_during_delta")
            except PublicLobbyIndexUnavailable:
                raise
            except Exception as exc:
                raise PublicLobbyIndexUnavailable("local_state_corrupt") from exc

            parent = _committed_block(con, chain_id=chain_id, height=old_height, block_id=old_id)
            child = _committed_block(con, chain_id=chain_id, height=new_height, block_id=new_id)
            _verify_block_root(parent, state_root=old_root)
            _verify_block_root(child, state_root=new_root)
            if str(child.get("prev_block_id") or "") != old_id:
                raise PublicLobbyIndexUnavailable("committed_delta_parent_mismatch")
            prev_hash = str(
                _as_dict(child.get("header")).get("prev_block_hash")
                or child.get("prev_block_hash")
                or ""
            )
            if prev_hash != str(parent.get("block_hash") or ""):
                raise PublicLobbyIndexUnavailable("committed_delta_parent_hash_mismatch")

            for comment_id in changed:
                con.execute(
                    "DELETE FROM public_lobby_shadow_rows WHERE comment_id=?;",
                    (comment_id,),
                )
            if upserts:
                con.executemany(
                    """
                    INSERT INTO public_lobby_shadow_rows(
                        thread_id, comment_id, created_nonce, author, body
                    ) VALUES (?, ?, ?, ?, ?);
                    """,
                    upserts,
                )

            binding = (chain_id, new_height, new_id, new_root)
            con.execute(
                """
                INSERT INTO public_lobby_shadow_meta(
                    id, version, chain_id, height, block_id, state_root
                ) VALUES(1, ?, ?, ?, ?, ?);
                """,
                (_SCHEMA_VERSION, *binding),
            )
            con.execute(
                """
                UPDATE public_lobby_shadow_anchor
                SET chain_id=?, height=?, block_id=?, state_root=? WHERE id=1;
                """,
                binding,
            )
        return len(changed)
