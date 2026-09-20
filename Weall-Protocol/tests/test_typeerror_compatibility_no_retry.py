from __future__ import annotations

import pytest

from weall.runtime.parallel_execution import _serial_execute_lane
from weall.services.block_producer import ProducerConfig, _produce_once


class _ProducerInternalTypeError:
    def __init__(self) -> None:
        self.calls = 0

    def produce_block(self, *, max_txs: int, allow_empty: bool) -> None:
        self.calls += 1
        raise TypeError("internal producer bug")


def test_block_producer_internal_typeerror_is_not_retried() -> None:
    executor = _ProducerInternalTypeError()
    cfg = ProducerConfig(interval_ms=1000, max_txs=10, allow_empty=False)

    with pytest.raises(TypeError, match="internal producer bug"):
        _produce_once(executor, cfg)

    assert executor.calls == 1


def test_helper_serial_executor_internal_typeerror_is_not_retried() -> None:
    calls = 0

    def serial_executor(txs, context):
        nonlocal calls
        calls += 1
        raise TypeError("internal serial bug")

    with pytest.raises(TypeError, match="internal serial bug"):
        _serial_execute_lane(
            [{"tx_id": "tx:one"}],
            serial_executor,
            {"height": 1},
        )

    assert calls == 1
