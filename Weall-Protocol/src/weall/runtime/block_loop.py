from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Optional

from weall.runtime.metrics import inc_counter, set_gauge


log = logging.getLogger("weall.block_loop")


@dataclass(frozen=True, slots=True)
class BlockLoopConfig:
    interval_ms: int
    produce_empty_blocks: bool
    enabled: bool
    lock_path: str
    max_block_txs: int

    # Reliability knobs
    fail_fast_after: int
    error_backoff_min_ms: int
    error_backoff_max_ms: int

    # BFT knobs (feature-flagged)
    bft_enabled: bool
    bft_timeout_ms: int
    bft_unsafe_autocommit: bool
    validator_account: str


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return int(default)


def block_loop_config_from_env() -> BlockLoopConfig:
    enabled = _env_bool("WEALL_BLOCK_LOOP_ENABLED", True)
    interval_ms = _env_int("WEALL_BLOCK_INTERVAL_MS", 20_000)
    interval_ms = max(250, int(interval_ms))
    produce_empty = _env_bool("WEALL_PRODUCE_EMPTY_BLOCKS", False)
    lock_path = os.environ.get("WEALL_BLOCK_LOOP_LOCK_PATH", "./data/block_loop.lock")
    max_block_txs = _env_int("WEALL_BLOCK_MAX_TXS", 1000)
    max_block_txs = max(1, int(max_block_txs))

    # Reliability controls
    fail_fast_after = max(3, _env_int("WEALL_BLOCK_LOOP_FAIL_FAST_AFTER", 10))
    error_backoff_min_ms = max(50, _env_int("WEALL_BLOCK_LOOP_ERROR_BACKOFF_MIN_MS", 250))
    error_backoff_max_ms = max(error_backoff_min_ms, _env_int("WEALL_BLOCK_LOOP_ERROR_BACKOFF_MAX_MS", 10_000))

    # BFT controls
    bft_enabled = _env_bool("WEALL_BFT_ENABLED", False)
    bft_timeout_ms = max(1_000, _env_int("WEALL_BFT_TIMEOUT_MS", 10_000))
    # Safety: legacy autocommit in BFT mode is UNSAFE; keep default False.
    bft_unsafe_autocommit = _env_bool("WEALL_BFT_UNSAFE_AUTOCOMMIT", False)

    # Local validator identity (account id) for leader schedule and voting.
    validator_account = (os.environ.get("WEALL_VALIDATOR_ACCOUNT") or "").strip()

    return BlockLoopConfig(
        interval_ms=int(interval_ms),
        produce_empty_blocks=bool(produce_empty),
        enabled=bool(enabled),
        lock_path=str(lock_path),
        max_block_txs=int(max_block_txs),
        fail_fast_after=int(fail_fast_after),
        error_backoff_min_ms=int(error_backoff_min_ms),
        error_backoff_max_ms=int(error_backoff_max_ms),
        bft_enabled=bool(bft_enabled),
        bft_timeout_ms=int(bft_timeout_ms),
        bft_unsafe_autocommit=bool(bft_unsafe_autocommit),
        validator_account=str(validator_account),
    )


class _FileLock:
    """Best-effort single-process lock for block loop.

    Prevent multiple web workers from each starting a producer loop.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._fh = None

    def acquire(self) -> bool:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        try:
            fh = open(self._path, "a+", encoding="utf-8")
        except Exception:
            return False

        try:
            import fcntl  # type: ignore

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            try:
                fh.close()
            except Exception:
                pass
            return False

        self._fh = fh
        try:
            fh.seek(0)
            fh.truncate()
            fh.write(f"pid={os.getpid()}\n")
            fh.flush()
        except Exception:
            pass
        return True

    def release(self) -> None:
        fh = self._fh
        self._fh = None
        if fh is None:
            return
        try:
            import fcntl  # type: ignore

            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            fh.close()
        except Exception:
            pass


def _active_validators_from_executor(executor) -> list[str]:
    st = getattr(executor, "state", None)
    if not isinstance(st, dict):
        return []
    roles = st.get("roles")
    if isinstance(roles, dict):
        validators = roles.get("validators")
        if isinstance(validators, dict):
            aset = validators.get("active_set")
            if isinstance(aset, list):
                out: list[str] = []
                seen: set[str] = set()
                for x in aset:
                    s = str(x).strip()
                    if not s or s in seen:
                        continue
                    seen.add(s)
                    out.append(s)
                return out
    return []


def _bft_view_from_executor(executor) -> int:
    st = getattr(executor, "state", None)
    if not isinstance(st, dict):
        return 0
    bft = st.get("bft")
    if not isinstance(bft, dict):
        return 0
    try:
        return int(bft.get("view") or 0)
    except Exception:
        return 0


class BlockProducerLoop:
    """Internal block producer loop.

    Legacy mode:
      - produces blocks from mempool at interval.

    BFT mode (HotStuff rollout):
      - leader-only proposal logic
      - non-leaders do not auto-produce blocks
      - this file only schedules ticks; the consensus engine must live in executor/net loop.

    Safety default:
      - In BFT mode, we DO NOT call executor.produce_block() unless explicitly
        allowed (WEALL_BFT_UNSAFE_AUTOCOMMIT=1). This prevents accidentally
        deploying "fake BFT" that still auto-commits longest-chain blocks.
    """

    def __init__(
        self,
        *,
        executor,
        mempool,
        attestation_pool,
        cfg: Optional[BlockLoopConfig] = None,
    ) -> None:
        self._executor = executor
        self._mempool = mempool
        self._att_pool = attestation_pool
        self._cfg = cfg or block_loop_config_from_env()

        self._lock = _FileLock(self._cfg.lock_path)
        self._t: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._started = False

        self._last_bft_timeout_check_ms = int(time.time() * 1000)

        self._consecutive_failures = 0
        self._last_error: str = ""

        # Expose status for health probes (best-effort; never relied on for safety)
        try:
            setattr(self._executor, "block_loop_running", False)
            setattr(self._executor, "block_loop_unhealthy", False)
            setattr(self._executor, "block_loop_last_error", "")
            setattr(self._executor, "block_loop_consecutive_failures", 0)
        except Exception:
            pass

    @property
    def started(self) -> bool:
        return self._started

    def start(self) -> bool:
        if self._started:
            return True
        if not self._cfg.enabled:
            return False
        if not self._lock.acquire():
            return False
        self._t = threading.Thread(target=self._run, name="weall-block-loop", daemon=True)
        self._t.start()
        self._started = True
        try:
            setattr(self._executor, "block_loop_running", True)
        except Exception:
            pass
        inc_counter("block_loop_start_total", 1)
        return True

    def stop(self) -> None:
        self._stop.set()
        t = self._t
        if t is not None:
            try:
                t.join(timeout=2.0)
            except Exception:
                pass
        self._lock.release()
        try:
            setattr(self._executor, "block_loop_running", False)
        except Exception:
            pass
        inc_counter("block_loop_stop_total", 1)

    def _mark_error(self, *, where: str, err: Exception) -> None:
        self._consecutive_failures += 1
        self._last_error = f"{where}:{type(err).__name__}:{err}"

        # Metrics
        inc_counter("block_loop_errors_total", 1)
        set_gauge("block_loop_consecutive_failures", self._consecutive_failures)

        # Health hooks
        try:
            setattr(self._executor, "block_loop_last_error", self._last_error)
            setattr(self._executor, "block_loop_consecutive_failures", self._consecutive_failures)
        except Exception:
            pass

        # Log with traceback; production operators need this.
        log.exception("block loop error (%s) failures=%s", where, self._consecutive_failures)

    def _clear_error(self) -> None:
        if self._consecutive_failures == 0 and not self._last_error:
            return
        self._consecutive_failures = 0
        self._last_error = ""
        set_gauge("block_loop_consecutive_failures", 0)
        try:
            setattr(self._executor, "block_loop_last_error", "")
            setattr(self._executor, "block_loop_consecutive_failures", 0)
        except Exception:
            pass

    def _sleep_backoff(self) -> None:
        # Exponential backoff with cap.
        n = max(1, int(self._consecutive_failures))
        base = int(self._cfg.error_backoff_min_ms)
        cap = int(self._cfg.error_backoff_max_ms)
        ms = min(cap, base * (2 ** min(10, n - 1)))
        time.sleep(max(0.0, float(ms) / 1000.0))

    def _trip_unhealthy_and_stop(self) -> None:
        # Mark unhealthy and stop loop.
        try:
            setattr(self._executor, "block_loop_unhealthy", True)
            setattr(self._executor, "block_loop_running", False)
        except Exception:
            pass
        set_gauge("block_loop_unhealthy", 1)
        inc_counter("block_loop_failfast_total", 1)
        log.error(
            "block loop fail-fast tripped: failures=%s last_error=%s",
            self._consecutive_failures,
            self._last_error,
        )
        self._stop.set()

    def _run(self) -> None:
        interval_s = float(self._cfg.interval_ms) / 1000.0
        next_ts = time.monotonic()

        while not self._stop.is_set():
            inc_counter("block_loop_ticks_total", 1)
            now = time.monotonic()
            if now < next_ts:
                time.sleep(min(0.25, next_ts - now))
                continue

            next_ts = now + interval_s

            # Best-effort pruning
            try:
                if hasattr(self._executor, "prune_mempool_expired"):
                    self._executor.prune_mempool_expired()
            except Exception:
                inc_counter("block_loop_prune_errors_total", 1)
                log.exception("mempool prune failed")
            try:
                if hasattr(self._executor, "prune_attestations_expired"):
                    self._executor.prune_attestations_expired()
            except Exception:
                inc_counter("block_loop_prune_errors_total", 1)
                log.exception("attestation prune failed")

            # --------------------------
            # BFT mode scheduling
            # --------------------------
            if self._cfg.bft_enabled:
                try:
                    self._tick_bft()
                    self._clear_error()
                except Exception as err:
                    self._mark_error(where="bft_tick", err=err)
                    if self._consecutive_failures >= int(self._cfg.fail_fast_after):
                        self._trip_unhealthy_and_stop()
                        break
                    self._sleep_backoff()
                continue

            # --------------------------
            # Legacy mode: produce blocks
            # --------------------------
            try:
                m = int(self._mempool.size())
            except Exception:
                m = 0
            try:
                a = int(self._att_pool.size())
            except Exception:
                a = 0

            if (m <= 0 and a <= 0) and (not self._cfg.produce_empty_blocks):
                continue

            try:
                if hasattr(self._executor, "produce_block_from_pools"):
                    self._executor.produce_block_from_pools(mempool=self._mempool, attestation_pool=self._att_pool)
                else:
                    self._executor.produce_block(max_txs=int(self._cfg.max_block_txs))
                inc_counter("block_loop_produce_ok_total", 1)
                self._clear_error()
            except Exception as err:
                self._mark_error(where="produce_block", err=err)
                if self._consecutive_failures >= int(self._cfg.fail_fast_after):
                    self._trip_unhealthy_and_stop()
                    break
                self._sleep_backoff()
                continue

    def _tick_bft(self) -> None:
        # Determine leader for current view
        from weall.runtime.bft_hotstuff import leader_for_view  # local import

        aset = _active_validators_from_executor(self._executor)
        view = _bft_view_from_executor(self._executor)
        leader = leader_for_view(aset, view)

        local = (self._cfg.validator_account or "").strip()

        # If executor exposes a proper BFT tick, always prefer it.
        # These hooks will be implemented in the next step (net loop + executor changes).
        if hasattr(self._executor, "bft_tick"):
            try:
                self._executor.bft_tick()
            except Exception:
                raise
            return

        # Leader vs non-leader behavior (safe default: do nothing unless you opt in)
        if not local or not leader or local != leader:
            # Non-leader: allow a non-leader hook if present.
            if hasattr(self._executor, "bft_non_leader_tick"):
                try:
                    self._executor.bft_non_leader_tick()
                except Exception:
                    raise
            # Timeout hook (optional)
            self._maybe_timeout()
            return

        # Leader:
        if hasattr(self._executor, "bft_leader_tick"):
            try:
                self._executor.bft_leader_tick()
            except Exception:
                raise
            self._maybe_timeout()
            return

        # Unsafe fallback (explicitly opted-in): leader directly commits blocks.
        # This is NOT real BFT; it's only for bringing up the network while wiring
        # votes/QCs. Keep OFF in production.
        if self._cfg.bft_unsafe_autocommit:
            try:
                self._executor.produce_block(max_txs=int(self._cfg.max_block_txs))
            except Exception:
                raise

        self._maybe_timeout()

    def _maybe_timeout(self) -> None:
        now_ms = int(time.time() * 1000)
        if (now_ms - self._last_bft_timeout_check_ms) < int(self._cfg.bft_timeout_ms):
            return
        self._last_bft_timeout_check_ms = now_ms
        if hasattr(self._executor, "bft_timeout_check"):
            try:
                self._executor.bft_timeout_check()
            except Exception:
                raise
