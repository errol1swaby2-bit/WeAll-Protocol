"""
Block producer service.

This module is used two ways:
1) Imported by the API to run a background thread.
2) Executed as a standalone service (docker compose) via: python -m weall.services.block_producer

Historically this file only defined a thread-based producer, which meant
`python -m weall.services.block_producer` would import and then exit immediately.
That causes the producer container to restart-loop with no logs.

This file now includes a proper foreground `main()` run-loop.
"""

from __future__ import annotations

import inspect
import os
import signal
import sys
import time
from dataclasses import dataclass

from weall.runtime.executor_boot import build_executor


class ProducerLifecycleError(RuntimeError):
    """Raised when the standalone producer cannot safely continue in production."""


@dataclass(frozen=True)
class ProducerConfig:
    interval_ms: int
    max_txs: int
    allow_empty: bool


def _mode() -> str:
    # Mirror other runtime modules: tests default to non-prod unless explicitly pinned.
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v == "":
        return default
    try:
        return int(v)
    except ValueError as e:
        raise SystemExit(f"{name} must be an int, got: {v!r}") from e


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None or v == "":
        return default
    vl = v.strip().lower()
    if vl in {"1", "true", "yes", "y", "on"}:
        return True
    if vl in {"0", "false", "no", "n", "off"}:
        return False
    raise SystemExit(f"{name} must be a boolean, got: {v!r}")


def _load_cfg() -> ProducerConfig:
    interval_ms = _env_int("WEALL_PRODUCER_INTERVAL_MS", 20_000)
    max_txs = _env_int("WEALL_PRODUCER_MAX_TXS", 1000)
    allow_empty = _env_bool("WEALL_PRODUCER_ALLOW_EMPTY", False)

    if interval_ms < 50:
        raise SystemExit("WEALL_PRODUCER_INTERVAL_MS too small; must be >= 50ms")
    if max_txs < 0:
        raise SystemExit("WEALL_PRODUCER_MAX_TXS must be >= 0")

    return ProducerConfig(interval_ms=interval_ms, max_txs=max_txs, allow_empty=allow_empty)


def _log(msg: str) -> None:
    # Keep it extremely simple so logs always show up in Docker.
    sys.stdout.write(msg.rstrip() + "\n")
    sys.stdout.flush()


def _produce_once(executor, cfg: ProducerConfig) -> None:
    produced = False

    if hasattr(executor, "produce_block"):
        produce = executor.produce_block
        try:
            sig = inspect.signature(produce)
            if "allow_empty" in sig.parameters:
                produce(max_txs=cfg.max_txs, allow_empty=cfg.allow_empty)
            else:
                produce(max_txs=cfg.max_txs)
        except TypeError:
            produce(max_txs=cfg.max_txs)
        produced = True
    elif hasattr(executor, "maybe_produce_block"):
        maybe = executor.maybe_produce_block
        try:
            sig = inspect.signature(maybe)
            if "allow_empty" in sig.parameters:
                maybe(max_txs=cfg.max_txs, allow_empty=cfg.allow_empty)
            else:
                maybe(max_txs=cfg.max_txs)
        except TypeError:
            maybe(max_txs=cfg.max_txs)
        produced = True
    elif hasattr(executor, "tick_block_producer"):
        tick = executor.tick_block_producer
        try:
            sig = inspect.signature(tick)
            if "allow_empty" in sig.parameters:
                tick(max_txs=cfg.max_txs, allow_empty=cfg.allow_empty)
            else:
                tick(max_txs=cfg.max_txs)
        except TypeError:
            tick(max_txs=cfg.max_txs)
        produced = True

    if not produced:
        raise ProducerLifecycleError(
            "producer_method_missing:expected_one_of=produce_block|maybe_produce_block|tick_block_producer"
        )


def run_forever() -> None:
    """
    Foreground service loop. Builds the executor and periodically tries to produce a block.
    """
    cfg = _load_cfg()

    # Build the runtime executor from env (WEALL_DB_PATH, WEALL_CHAIN_ID, WEALL_MODE, etc.)
    executor = build_executor()

    _log(
        "weall-producer starting "
        f"(interval_ms={cfg.interval_ms}, max_txs={cfg.max_txs}, allow_empty={int(cfg.allow_empty)})"
    )

    stop = {"flag": False}

    def _handle(sig: int, _frame: object | None) -> None:
        stop["flag"] = True
        _log(f"weall-producer received signal {sig}; shutting down...")

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)

    # Main loop
    while not stop["flag"]:
        t0 = time.time()
        try:
            _produce_once(executor, cfg)
        except Exception as e:
            if _mode() == "prod":
                raise ProducerLifecycleError(f"producer_tick_failed:{type(e).__name__}:{e}") from e
            _log(f"weall-producer error: {type(e).__name__}: {e}")

        elapsed_ms = int((time.time() - t0) * 1000)
        sleep_ms = max(0, cfg.interval_ms - elapsed_ms)
        time.sleep(sleep_ms / 1000.0)

    _log("weall-producer stopped.")


def main() -> int:
    try:
        run_forever()
        return 0
    except SystemExit as e:
        if e.code in (None, 0):
            return 0
        _log(str(e))
        try:
            return int(e.code)
        except Exception:
            return 2
    except Exception as e:
        _log(f"fatal: {type(e).__name__}: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
