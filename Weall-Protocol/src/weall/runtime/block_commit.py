from __future__ import annotations

"""Atomic block/state/mempool commit boundary delegate.

This module is intentionally a structural extraction from ``weall.runtime.executor``.
It keeps the executor public API stable while shrinking the trusted surface area of
the monolithic facade. The extracted functions still operate on ``WeAllExecutor``
instances and intentionally preserve behavior byte-for-byte where possible.
"""



from weall.runtime.executor import (
    ExecutorMeta,
    Path,
    _canon_json,
    _consensus_fail_closed,
    _format_commit_failure,
    _now_ms,
    ensure_block_hash,
    maybe_trigger_failpoint,
    os,
    prune_emitted_system_queue,
)

def commit_block_candidate(
    self,
    *,
    block: Json,
    new_state: Json,
    applied_ids: list[str],
    invalid_ids: list[str],
) -> ExecutorMeta:
    """Atomically persist a block + mempool cleanup + ledger snapshot.

    Production invariant: a node crash or SIGKILL during commit must not leave
    a partially-committed DB (e.g., block row without ledger_state update).
    """
    try:
        height = int(block.get("height") or 0)
        block_id = str(block.get("block_id") or "")
        if not block_id or height <= 0:
            return ExecutorMeta(ok=False, error="bad_block", height=0, block_id="")

        try:
            prune_emitted_system_queue(new_state)
        except Exception as exc:
            if _consensus_fail_closed():
                return ExecutorMeta(
                    ok=False,
                    error=f"system_queue_prune_failed:{type(exc).__name__}",
                    height=0,
                    block_id="",
                )

        block2, _bh = ensure_block_hash(block)
        now = _now_ms()
        block_json = _canon_json(block2)

        ids: list[str] = []
        seen: set[str] = set()
        for tx_id in list(applied_ids) + list(invalid_ids):
            t = str(tx_id or "").strip()
            if not t or t in seen:
                continue
            seen.add(t)
            ids.append(t)

        receipts_any = block2.get("receipts")
        receipts_list = receipts_any if isinstance(receipts_any, list) else []
        tx_index_rows: list[tuple[str, int, str, str, str, int, int, int]] = []
        seen_index_ids: set[str] = set()
        for rec_any in receipts_list:
            if not isinstance(rec_any, dict):
                continue
            tx_id = str(rec_any.get("tx_id") or "").strip()
            if not tx_id or tx_id in seen_index_ids:
                continue
            seen_index_ids.add(tx_id)
            tx_index_rows.append(
                (
                    tx_id,
                    int(height),
                    str(block_id),
                    str(rec_any.get("tx_type") or ""),
                    str(rec_any.get("signer") or ""),
                    int(rec_any.get("nonce") or 0),
                    1 if bool(rec_any.get("ok")) else 0,
                    int(block2.get("block_ts_ms") or now),
                )
            )

        snap_height = int(new_state.get("height", height))
        snap_tip = str(new_state.get("tip") or block_id).strip()
        state_json = _canon_json(new_state)

        with self._db.write_tx() as con:
            con.execute(
                "INSERT INTO blocks(height, block_id, block_json, created_ts_ms) VALUES(?,?,?,?);",
                (int(height), str(block_id), block_json, int(now)),
            )
            con.execute(
                """
                INSERT INTO block_hash_index(block_id, block_hash, height, created_ts_ms)
                VALUES(?,?,?,?)
                ON CONFLICT(block_id) DO UPDATE SET
                  block_hash=excluded.block_hash,
                  height=excluded.height,
                  created_ts_ms=excluded.created_ts_ms;
                """,
                (str(block_id), str(block2.get("block_hash") or ""), int(height), int(now)),
            )

            # TEST-ONLY crash hook: give tests a window to SIGKILL this process
            marker = os.environ.get("WEALL_TEST_MARKER_PATH", "").strip()
            if marker:
                try:
                    Path(marker).parent.mkdir(parents=True, exist_ok=True)
                    Path(marker).write_text("ready\n")
                except Exception:
                    pass
            # after the block insert but before ledger_state is updated.
            try:
                sleep_ms = int(os.environ.get("WEALL_TEST_SLEEP_AFTER_BLOCK_INSERT_MS", "0"))
            except Exception:
                sleep_ms = 0
            if sleep_ms > 0:
                time.sleep(sleep_ms / 1000.0)

            # TEST-ONLY fail hook: simulate an exception after the block row is inserted
            # but before mempool cleanup + ledger_state write.
            if os.environ.get("WEALL_TEST_FAIL_AFTER_BLOCK_INSERT", "").strip().lower() in {
                "1",
                "true",
                "yes",
            }:
                raise RuntimeError("test_fail_after_block_insert")

            maybe_trigger_failpoint("block_commit_after_block_insert")

            for tx_id in ids:
                con.execute("DELETE FROM mempool WHERE tx_id=?;", (tx_id,))

            if tx_index_rows:
                con.executemany(
                    """
                    INSERT INTO tx_index(
                      tx_id,
                      height,
                      block_id,
                      tx_type,
                      signer,
                      nonce,
                      ok,
                      included_ts_ms
                    )
                    VALUES(?,?,?,?,?,?,?,?)
                    ON CONFLICT(tx_id) DO UPDATE SET
                      height=excluded.height,
                      block_id=excluded.block_id,
                      tx_type=excluded.tx_type,
                      signer=excluded.signer,
                      nonce=excluded.nonce,
                      ok=excluded.ok,
                      included_ts_ms=excluded.included_ts_ms;
                    """,
                    tx_index_rows,
                )

            maybe_trigger_failpoint("block_commit_before_ledger_state")

            con.execute(
                """
                INSERT INTO ledger_state(id, height, block_id, state_json, updated_ts_ms)
                VALUES(1, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  height=excluded.height,
                  block_id=excluded.block_id,
                  state_json=excluded.state_json,
                  updated_ts_ms=excluded.updated_ts_ms;
                """,
                (int(snap_height), str(snap_tip), state_json, int(now)),
            )

            maybe_trigger_failpoint("block_commit_after_ledger_state")

        previous_epoch = self._current_validator_epoch()
        previous_set_hash = (
            self._current_validator_set_hash() if int(previous_epoch) > 0 else ""
        )
        self.state = new_state
        self._bft.load_from_state(self.state)
        self._cache_known_block_hash(str(block_id), str(block2.get("block_hash") or ""))
        self._prune_pending_bft_artifacts_on_local_validator_transition(
            previous_epoch=int(previous_epoch),
            previous_set_hash=str(previous_set_hash or ""),
        )

        return ExecutorMeta(
            ok=True,
            error="",
            height=int(height),
            block_id=str(block_id),
            applied_count=len(applied_ids),
        )
    except Exception as e:
        return ExecutorMeta(
            ok=False, error=_format_commit_failure(e), height=0, block_id=""
        )

