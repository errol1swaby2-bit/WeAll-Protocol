from __future__ import annotations

from weall.net.net_loop import NetLoopConfig, NetMeshLoop


class _Exec:
    chain_id = "weall-dev"

    def snapshot(self):
        return {"height": 0}

    def tx_index_hash(self):
        return "0"

    def _schema_version(self):
        return "1"


class _Mempool:
    pass


def _loop() -> NetMeshLoop:
    return NetMeshLoop(
        executor=_Exec(),
        mempool=_Mempool(),
        cfg=NetLoopConfig(
            enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"
        ),
    )


def test_bft_dedupe_cache_is_capped_and_evicts_oldest() -> None:
    loop = _loop()
    cache: dict[str, int] = {}

    assert loop._dedupe_seen(cache, "k1", ttl_ms=10_000, now_ms=100, max_entries=2) is False
    assert loop._dedupe_seen(cache, "k2", ttl_ms=10_000, now_ms=200, max_entries=2) is False
    assert set(cache) == {"k1", "k2"}

    assert loop._dedupe_seen(cache, "k3", ttl_ms=10_000, now_ms=300, max_entries=2) is False
    assert set(cache) == {"k2", "k3"}
    assert loop._dedupe_seen(cache, "k1", ttl_ms=10_000, now_ms=400, max_entries=2) is False


def test_bft_dedupe_cache_prunes_expired_before_size_eviction() -> None:
    loop = _loop()
    cache = {"old": 1, "fresh": 9_901}

    assert loop._dedupe_seen(cache, "new", ttl_ms=100, now_ms=10_000, max_entries=2) is False
    assert set(cache) == {"fresh", "new"}


def test_tx_seen_cache_is_capped_and_reaccepts_evicted_oldest() -> None:
    loop = _loop()
    loop._tx_seen_max = 2
    loop._tx_seen_ttl_ms = 10_000

    assert loop._tx_seen_has("tx1", 100) is False
    assert loop._tx_seen_has("tx2", 200) is False
    assert set(loop._tx_seen) == {"tx1", "tx2"}

    assert loop._tx_seen_has("tx3", 300) is False
    assert set(loop._tx_seen) == {"tx2", "tx3"}

    # tx1 was evicted due to the cap, so seeing it again should be treated as new.
    assert loop._tx_seen_has("tx1", 400) is False
