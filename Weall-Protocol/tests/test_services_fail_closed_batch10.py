from __future__ import annotations

import pytest


class _StopLoop(RuntimeError):
    pass


class _ProducerBoomExecutor:
    def produce_block(self, *, max_txs: int, allow_empty: bool = False):
        raise RuntimeError("boom")


class _ProducerNoMethodExecutor:
    pass


class _ProducerOkExecutor:
    def __init__(self) -> None:
        self.calls = 0

    def produce_block(self, *, max_txs: int, allow_empty: bool = False):
        self.calls += 1
        return {"ok": True}


def test_block_producer_prod_fails_closed_on_tick_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.services import block_producer as svc

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setattr(svc, "build_executor", lambda: _ProducerBoomExecutor())
    monkeypatch.setattr(svc.signal, "signal", lambda *args, **kwargs: None)

    with pytest.raises(svc.ProducerLifecycleError, match="producer_tick_failed"):
        svc.run_forever()


def test_block_producer_prod_fails_closed_when_executor_exposes_no_producer_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.services import block_producer as svc

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setattr(svc, "build_executor", lambda: _ProducerNoMethodExecutor())
    monkeypatch.setattr(svc.signal, "signal", lambda *args, **kwargs: None)

    with pytest.raises(svc.ProducerLifecycleError, match="producer_method_missing"):
        svc.run_forever()


def test_block_producer_dev_still_logs_and_continues_for_testability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.services import block_producer as svc

    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setattr(svc, "build_executor", lambda: _ProducerBoomExecutor())
    monkeypatch.setattr(svc.signal, "signal", lambda *args, **kwargs: None)

    sleeps = {"count": 0}

    def _sleep(_seconds: float) -> None:
        sleeps["count"] += 1
        raise _StopLoop()

    monkeypatch.setattr(svc.time, "sleep", _sleep)

    with pytest.raises(_StopLoop):
        svc.run_forever()
    assert sleeps["count"] == 1


class _AttesterHttpStub:
    def __init__(self, responses):
        self._responses = list(responses)

    def __call__(self, method: str, url: str, body=None, timeout_s: float = 10.0):
        assert self._responses, f"unexpected http call: {method} {url}"
        return self._responses.pop(0)


def test_validator_attester_prod_fails_closed_on_snapshot_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.services import validator_attester as svc

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setattr(svc, "_http_json", _AttesterHttpStub([{"ok": False, "error": "url_error"}]))

    with pytest.raises(svc.ValidatorAttesterError, match="attester_snapshot_failed:url_error"):
        svc.run_attester_loop(
            producer_url="http://127.0.0.1:8000",
            signer="val1",
            privkey="00" * 32,
            poll_seconds=1.0,
            encoding="hex",
            once=True,
            verbose=False,
        )


def test_validator_attester_prod_fails_closed_on_nonce_parse_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.services import validator_attester as svc

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setattr(
        svc,
        "_http_json",
        _AttesterHttpStub(
            [
                {"ok": True, "tip": "blk1", "height": 1, "tip_round": 2},
                {"ok": True, "nonce": "not-an-int"},
            ]
        ),
    )

    with pytest.raises(svc.ValidatorAttesterError, match="attester_nonce_invalid"):
        svc.run_attester_loop(
            producer_url="http://127.0.0.1:8000",
            signer="val1",
            privkey="00" * 32,
            poll_seconds=1.0,
            encoding="hex",
            once=True,
            verbose=False,
        )


def test_validator_attester_main_fails_closed_on_invalid_producer_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.services import validator_attester as svc

    rc = svc.main(
        [
            "--producer-url",
            "not-a-url",
            "--signer",
            "val1",
            "--privkey",
            "00" * 32,
            "--once",
        ]
    )
    assert rc == 2
