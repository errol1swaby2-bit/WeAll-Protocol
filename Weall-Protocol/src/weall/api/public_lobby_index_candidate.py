"""Read-only A03 public-lobby indexed projection candidate.

This module is deliberately NOT wired to the production API, block commit, or
genesis. It proves that a SQLite-backed thread index can reproduce the existing
canonical public-lobby visibility and cursor semantics from an explicit state
snapshot. Its binding is an input assertion, not independent BFT finality.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from weall.api.routes_public_parts.common import _cursor_pack, _cursor_unpack
from weall.api.routes_public_parts.content import (
    _as_dict,
    _canonical_lobby_comment_index_matches,
    _comment_visible,
    _comments,
    _safe_int,
    _str_param,
)
from weall.runtime.sqlite_db import SqliteDB, SqliteLedgerStore
from weall.runtime.state_hash import compute_state_root

Json = dict[str, Any]

_SCHEMA_VERSION = 1
_MAX_BUILD_COMMENTS = 50_000
_INVALIDATION_TRIGGERS = (
    "trg_public_lobby_shadow_ledger_insert",
    "trg_public_lobby_shadow_ledger_update",
    "trg_public_lobby_shadow_ledger_delete",
)


class PublicLobbyIndexUnavailable(RuntimeError):
    """The shadow projection has no verified matching source binding."""


class PublicLobbyIndexCandidate:
    """Offline, non-authoritative index with transactionally replaced rows.

    Callers must independently authenticate the committed state and the exact
    chain/head/root binding. This is not a subscription to chain changes:
    a stale index MUST NOT be used by a live API, even for an empty thread.
    """

    def __init__(self, db: SqliteDB) -> None:
        self.db = db

    def initialize(self) -> None:
        """Create only derivative tables; never change the consensus schema."""
        with self.db.write_tx() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS public_lobby_shadow_meta (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    version INTEGER NOT NULL,
                    chain_id TEXT NOT NULL,
                    height INTEGER NOT NULL,
                    block_id TEXT NOT NULL,
                    state_root TEXT NOT NULL
                );
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS public_lobby_shadow_rows (
                    thread_id TEXT NOT NULL,
                    comment_id TEXT NOT NULL,
                    created_nonce INTEGER NOT NULL,
                    author TEXT NOT NULL,
                    body TEXT NOT NULL,
                    PRIMARY KEY(thread_id, comment_id)
                );
                """
            )
            con.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_public_lobby_shadow_page
                ON public_lobby_shadow_rows(
                    thread_id, created_nonce DESC, comment_id DESC
                );
                """
            )

    def attach_commit_invalidation(self) -> None:
        """Opt-in durable ledger triggers; no global runtime or route registration.

        Every ledger_state INSERT, UPDATE or DELETE invalidates published shadow
        metadata in the same SQLite transaction, including block commits,
        checkpoint imports, same-height runtime writes, and a crash rollback.
        This method requires the SAME database as the canonical ledger.
        """
        with self.db.write_tx() as con:
            present = con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='ledger_state';"
            ).fetchone()
            if present is None:
                raise PublicLobbyIndexUnavailable("local_ledger_table_required")

            existing = {
                str(row["name"])
                for row in con.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type='trigger' AND name IN (?, ?, ?);
                    """,
                    _INVALIDATION_TRIGGERS,
                ).fetchall()
            }
            for operation, name in zip(
                ("INSERT", "UPDATE", "DELETE"), _INVALIDATION_TRIGGERS, strict=True
            ):
                con.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {name}
                    AFTER {operation} ON ledger_state
                    BEGIN
                        DELETE FROM public_lobby_shadow_meta WHERE id=1;
                    END;
                    """
                )
            # A previously-built unbound or partially installed projection can
            # never become trusted just because triggers are installed later.
            if existing != set(_INVALIDATION_TRIGGERS):
                con.execute("DELETE FROM public_lobby_shadow_meta WHERE id=1;")

    def rebuild_from_local_ledger(self, *, chain_id: str) -> int:
        """Reconstruct from persisted local canonical history; not BFT finality.

        Full state_json parsing is deliberately confined to the offline rebuild.
        The exact tip block must carry the recomputed state root, with a complete
        canonical block commitment. The final writer lock checks that the head
        has not changed since the input snapshot was read.
        """
        if not chain_id:
            raise PublicLobbyIndexUnavailable("chain_id_required")
        state = SqliteLedgerStore(db=self.db).read()
        height = int(state.get("height") or 0)
        block_id = str(state.get("tip") or "").strip()
        if height < 1 or not block_id:
            raise PublicLobbyIndexUnavailable("committed_tip_required")
        state_root = compute_state_root(state)

        with self.db.connection() as con:
            persisted = con.execute(
                """
                SELECT block_json FROM blocks
                WHERE height=? AND block_id=? LIMIT 1;
                """,
                (height, block_id),
            ).fetchone()
        if persisted is None:
            raise PublicLobbyIndexUnavailable("committed_tip_block_missing")
        try:
            from weall.runtime.block_commitment_validation import ensure_complete_block_commitments

            stored = json.loads(str(persisted["block_json"]))
            if not isinstance(stored, dict):
                raise PublicLobbyIndexUnavailable("committed_tip_block_malformed")
            canonical, _binding = ensure_complete_block_commitments(
                block=stored, chain_id=chain_id
            )
            header = canonical.get("header")
            committed_root = str(
                header.get("state_root") if isinstance(header, dict) else ""
            ).strip()
            if committed_root != state_root:
                raise PublicLobbyIndexUnavailable("committed_tip_state_root_mismatch")
        except PublicLobbyIndexUnavailable:
            raise
        except Exception as exc:
            raise PublicLobbyIndexUnavailable("committed_tip_block_invalid") from exc

        return self.rebuild(
            state=state,
            chain_id=chain_id,
            height=height,
            block_id=block_id,
            state_root=state_root,
            require_local_head=True,
        )

    def rebuild(
        self,
        *,
        state: Json,
        chain_id: str,
        height: int,
        block_id: str,
        state_root: str,
        require_local_head: bool = False,
    ) -> int:
        """Replace the entire shadow index atomically from an explicit snapshot.

        Expensive and intentionally offline. It uses the existing read-route
        visibility predicate rather than inventing an independent moderation
        policy. No production path calls this method.
        """
        if not isinstance(state, dict):
            raise PublicLobbyIndexUnavailable("invalid_snapshot")
        if not chain_id or not block_id or not state_root or height < 0:
            raise PublicLobbyIndexUnavailable("invalid_source_binding")
        declared_chain = str(
            state.get("chain_id") or _as_dict(state.get("meta")).get("chain_id") or ""
        ).strip()
        if declared_chain and declared_chain != chain_id:
            raise PublicLobbyIndexUnavailable("chain_id_mismatch")
        if int(state.get("height") or 0) != height:
            raise PublicLobbyIndexUnavailable("height_mismatch")
        if str(state.get("tip") or "").strip() != block_id:
            raise PublicLobbyIndexUnavailable("block_id_mismatch")
        if compute_state_root(state) != state_root:
            raise PublicLobbyIndexUnavailable("state_root_mismatch")

        comments = _comments(state)
        if len(comments) > _MAX_BUILD_COMMENTS:
            raise PublicLobbyIndexUnavailable("offline_build_budget_exceeded")

        rows: list[tuple[str, str, int, str, str]] = []
        for key, raw in comments.items():
            comment = _as_dict(raw)
            if str(comment.get("surface") or "").strip().lower() != "public_lobby":
                continue
            thread_id = str(comment.get("post_id") or "").strip()
            if not thread_id.startswith("public-lobby:"):
                continue
            if len(thread_id.encode("utf-8")) > 2048:
                continue
            comment_id = str(key)
            if not _canonical_lobby_comment_index_matches(comment, comment_id):
                continue
            if not _comment_visible(state, comment, comment_id):
                continue
            nonce = _safe_int(comment.get("created_nonce"), 0)
            if not -(2**63) <= nonce < 2**63:
                raise PublicLobbyIndexUnavailable("nonce_out_of_sqlite_range")
            rows.append(
                (
                    thread_id,
                    comment_id,
                    nonce,
                    _str_param(comment.get("author")),
                    _str_param(comment.get("body")),
                )
            )

        # Detect an in-memory snapshot that changed while rows were derived.
        if compute_state_root(state) != state_root:
            raise PublicLobbyIndexUnavailable("snapshot_changed_during_build")

        with self.db.write_tx() as con:
            if require_local_head:
                installed = {
                    str(row["name"])
                    for row in con.execute(
                        """
                        SELECT name FROM sqlite_master
                        WHERE type='trigger' AND name IN (?, ?, ?);
                        """,
                        _INVALIDATION_TRIGGERS,
                    ).fetchall()
                }
                if installed != set(_INVALIDATION_TRIGGERS):
                    raise PublicLobbyIndexUnavailable("commit_invalidation_not_attached")
                actual = con.execute(
                    "SELECT height, block_id FROM ledger_state WHERE id=1;"
                ).fetchone()
                if (
                    actual is None
                    or int(actual["height"]) != height
                    or str(actual["block_id"]) != block_id
                ):
                    raise PublicLobbyIndexUnavailable("local_ledger_head_advanced")
            previous = con.execute(
                """
                SELECT chain_id, height, block_id, state_root
                FROM public_lobby_shadow_meta WHERE id=1;
                """
            ).fetchone()
            if previous is not None:
                previous_height = int(previous["height"])
                if previous["chain_id"] != chain_id:
                    raise PublicLobbyIndexUnavailable("chain_transition_requires_new_index")
                if height < previous_height:
                    raise PublicLobbyIndexUnavailable("index_height_regression")
                if height == previous_height and (
                    previous["block_id"] != block_id or previous["state_root"] != state_root
                ):
                    raise PublicLobbyIndexUnavailable("same_height_binding_conflict")

            con.execute("DELETE FROM public_lobby_shadow_rows;")
            if rows:
                con.executemany(
                    """
                    INSERT INTO public_lobby_shadow_rows(
                        thread_id, comment_id, created_nonce, author, body
                    ) VALUES (?, ?, ?, ?, ?);
                    """,
                    rows,
                )
            con.execute(
                """
                INSERT INTO public_lobby_shadow_meta(
                    id, version, chain_id, height, block_id, state_root
                ) VALUES (1, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    version=excluded.version,
                    chain_id=excluded.chain_id,
                    height=excluded.height,
                    block_id=excluded.block_id,
                    state_root=excluded.state_root;
                """,
                (_SCHEMA_VERSION, chain_id, height, block_id, state_root),
            )
        return len(rows)

    def page(
        self,
        *,
        thread_id: str,
        chain_id: str,
        height: int | None = None,
        block_id: str | None = None,
        state_root: str | None = None,
        limit: int = 25,
        cursor: str = "",
        require_local_head: bool = False,
    ) -> Json:
        """Read one page without deserializing global ledger state.

        The expected source binding is REQUIRED from a separately trusted
        commit/head reader. Callers cannot use the index's own metadata as
        evidence of finality or currentness.
        """
        if not thread_id.startswith("public-lobby:") or len(thread_id.encode("utf-8")) > 2048:
            raise ValueError("invalid_public_lobby_target")
        if len(cursor) > 4096:
            raise ValueError("invalid_cursor")
        cursor_nonce, cursor_id = _cursor_unpack(cursor or None)
        if cursor and (cursor_nonce is None or cursor_id is None):
            raise ValueError("invalid_cursor")
        page_limit = max(1, min(50, int(limit)))

        try:
            with self.db.connection() as con:
                # One SQLite read transaction pins metadata and page rows to
                # the same snapshot even if a rebuild commits concurrently.
                con.execute("BEGIN;")
                meta = con.execute(
                    """
                    SELECT version, chain_id, height, block_id, state_root
                    FROM public_lobby_shadow_meta WHERE id=1;
                    """
                ).fetchone()
                if (
                    meta is None
                    or meta["version"] != _SCHEMA_VERSION
                    or meta["chain_id"] != chain_id
                    or not str(meta["state_root"] or "").strip()
                ):
                    raise PublicLobbyIndexUnavailable("index_source_stale_or_unverified")
                if require_local_head:
                    installed = {
                        str(row["name"])
                        for row in con.execute(
                            """
                            SELECT name FROM sqlite_master
                            WHERE type='trigger' AND name IN (?, ?, ?);
                            """,
                            _INVALIDATION_TRIGGERS,
                        ).fetchall()
                    }
                    if installed != set(_INVALIDATION_TRIGGERS):
                        raise PublicLobbyIndexUnavailable("commit_invalidation_not_attached")
                    actual = con.execute(
                        "SELECT height, block_id FROM ledger_state WHERE id=1;"
                    ).fetchone()
                    if (
                        actual is None
                        or int(meta["height"]) != int(actual["height"])
                        or str(meta["block_id"]) != str(actual["block_id"])
                    ):
                        raise PublicLobbyIndexUnavailable("local_ledger_head_stale")
                elif (
                    height is None
                    or not block_id
                    or not state_root
                    or int(meta["height"]) != height
                    or meta["block_id"] != block_id
                    or meta["state_root"] != state_root
                ):
                    raise PublicLobbyIndexUnavailable("index_source_stale_or_unverified")

                if cursor_nonce is None or cursor_id is None:
                    records = con.execute(
                        """
                        SELECT comment_id, created_nonce, author, body
                        FROM public_lobby_shadow_rows
                        WHERE thread_id=?
                        ORDER BY created_nonce DESC, comment_id DESC
                        LIMIT ?;
                        """,
                        (thread_id, page_limit + 1),
                    ).fetchall()
                else:
                    records = con.execute(
                        """
                        SELECT comment_id, created_nonce, author, body
                        FROM public_lobby_shadow_rows
                        WHERE thread_id=?
                          AND (created_nonce < ?
                               OR (created_nonce = ? AND comment_id < ?))
                        ORDER BY created_nonce DESC, comment_id DESC
                        LIMIT ?;
                        """,
                        (thread_id, cursor_nonce, cursor_nonce, cursor_id, page_limit + 1),
                    ).fetchall()
                con.execute("COMMIT;")
        except sqlite3.Error as exc:
            raise PublicLobbyIndexUnavailable("index_storage_unavailable") from exc

        items = [
            {
                "comment_id": str(row["comment_id"]),
                "post_id": thread_id,
                "surface": "public_lobby",
                "author": str(row["author"]),
                "body": str(row["body"]),
                "created_nonce": int(row["created_nonce"]),
                "visibility": "public",
            }
            for row in records[:page_limit]
        ]
        next_cursor = None
        if len(records) > page_limit and items:
            last = items[-1]
            next_cursor = _cursor_pack(
                created_at_nonce=last["created_nonce"],
                content_id=last["comment_id"],
            )
        return {"ok": True, "thread_id": thread_id, "items": items, "next_cursor": next_cursor}

    def page_from_local_ledger(
        self, *, thread_id: str, chain_id: str, limit: int = 25, cursor: str = ""
    ) -> Json:
        """One SQLite snapshot for committed head AND indexed rows.

        This prototype method is NOT an HTTP route and NOT finality evidence.
        No global state_json read occurs in the request path.
        """
        return self.page(
            thread_id=thread_id,
            chain_id=chain_id,
            limit=limit,
            cursor=cursor,
            require_local_head=True,
        )
