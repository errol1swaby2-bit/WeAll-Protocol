from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Optional

from weall.runtime.executor import WeAllExecutor


def _safe_int(v: str, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


@dataclass
class BlockProducerConfig:
    block_interval_ms: int
    max_txs_per_block: int


def block_producer_config_from_env() -> BlockProducerConfig:
    interval = _safe_int(os.environ.get("WEALL_BLOCK_INTERVAL_MS", "20000"), 20000)
    max_txs = _safe_int(os.environ.get("WEALL_MAX_TXS_PER_BLOCK", "1000"), 1000)
    if interval < 250:
        interval = 250
    if max_txs <= 0:
        max_txs = 1
    return BlockProducerConfig(block_interval_ms=interval, max_txs_per_block=max_txs)


class BlockProducer(threading.Thread):
    """Simple block producer loop.

    This runs in-process (thread) and relies on SQLite for persistence, so it can
    safely coexist with the API server as long as SQLite is in WAL mode.

    NOTE: We keep transactions short and commit atomically per block.
    """

    def __init__(self, executor: WeAllExecutor, cfg: Optional[BlockProducerConfig] = None) -> None:
        super().__init__(daemon=True)
        self.executor = executor
        self.cfg = cfg or block_producer_config_from_env()
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        interval = int(self.cfg.block_interval_ms)
        max_txs = int(self.cfg.max_txs_per_block)

        while not self._stop.is_set():
            try:
                # Cleanup (cheap, safe).
                self.executor.prune_mempool_expired()
                self.executor.prune_attestations_expired()

                # Produce a block if possible.
                self.executor.produce_block(max_txs=max_txs)
            except Exception:
                # Fail-closed: do not crash the node due to producer loop exceptions.
                pass

            # Sleep in small increments so stop() is responsive.
            end = time.time() + (interval / 1000.0)
            while time.time() < end:
                if self._stop.is_set():
                    break
                time.sleep(0.25)
