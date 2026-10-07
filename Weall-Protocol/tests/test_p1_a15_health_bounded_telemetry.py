from __future__ import annotations

import threading
from pathlib import Path

import yaml

from weall.api.routes_public_parts.health import _try_executor_state
from weall.runtime.executor import WeAllExecutor

ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = ROOT / "generated" / "tx_index.json"


def _executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=f"a15-health-{name}",
        tx_index_path=str(TX_INDEX),
    )


def test_a15_f004_real_executor_health_never_reads_or_parses_full_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ex = _executor(tmp_path, "bounded")

    def forbidden_full_read():
        raise AssertionError("health_must_not_read_full_state_json")

    monkeypatch.setattr(ex._ledger_store, "read", forbidden_full_read)

    telemetry = ex.health_telemetry()
    routed = _try_executor_state(ex)

    assert telemetry == routed
    assert telemetry["chain_id"] == "a15-health-bounded"
    assert telemetry["height"] == 0
    assert telemetry["tip"] == ""
    assert isinstance(telemetry["durable_updated_ts_ms"], int)


def test_a15_f004_repeated_health_probes_use_only_constant_size_head_query(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ex = _executor(tmp_path, "flood")
    ex.state["synthetic_large_state"] = {f"row-{idx:04d}": "x" * 4096 for idx in range(256)}

    full_reads = 0
    head_reads = 0
    original_head = ex._ledger_store.read_head

    def forbidden_full_read():
        nonlocal full_reads
        full_reads += 1
        raise AssertionError("health_must_not_read_full_state_json")

    def counted_head_read():
        nonlocal head_reads
        head_reads += 1
        return original_head()

    monkeypatch.setattr(ex._ledger_store, "read", forbidden_full_read)
    monkeypatch.setattr(ex._ledger_store, "read_head", counted_head_read)

    for _ in range(500):
        out = _try_executor_state(ex)
        assert isinstance(out, dict)
        assert out["height"] == 0

    assert full_reads == 0
    assert head_reads == 500


def test_a15_f004_health_telemetry_does_not_wait_for_branch_lock(
    tmp_path: Path,
) -> None:
    ex = _executor(tmp_path, "sync-load")

    branch_held = threading.Event()
    release_branch = threading.Event()
    probe_done = threading.Event()
    errors: list[BaseException] = []
    result: dict = {}

    def hold_checkpoint_ordering_domain() -> None:
        with ex._bft_branch_guard_lock():
            branch_held.set()
            assert release_branch.wait(timeout=10)

    def probe() -> None:
        try:
            result.update(ex.health_telemetry())
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)
        finally:
            probe_done.set()

    holder = threading.Thread(target=hold_checkpoint_ordering_domain, daemon=True)
    holder.start()
    assert branch_held.wait(timeout=10)

    probe_thread = threading.Thread(target=probe, daemon=True)
    probe_thread.start()

    # A health probe must not queue behind state-sync/checkpoint branch work.
    assert probe_done.wait(timeout=1.0) is True
    assert errors == []
    assert result["chain_id"] == "a15-health-sync-load"

    release_branch.set()
    holder.join(timeout=10)
    probe_thread.join(timeout=10)
    assert not holder.is_alive()
    assert not probe_thread.is_alive()


def test_a15_f004_production_deployment_keeps_health_on_private_operator_boundary() -> None:
    compose_path = ROOT / "docker-compose.prod.yml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    service = compose["services"]["weall-node"]

    exposed = {str(value) for value in (service.get("expose") or [])}
    published = {str(value) for value in (service.get("ports") or [])}
    assert "8000" in exposed
    assert all("8000" not in value for value in published)

    healthcheck = " ".join(str(value) for value in service["healthcheck"]["test"])
    assert "/v1/readyz" in healthcheck
    assert "127.0.0.1:8000" in healthcheck

    runbook = (ROOT / "docs" / "operator_runbook_prod.md").read_text(encoding="utf-8")
    assert "operator/orchestrator surface" in runbook
    assert "must not route" in runbook
    for route in (
        "/health",
        "/healthz",
        "/readyz",
        "/v1/health",
        "/v1/healthz",
        "/v1/readyz",
    ):
        assert route in runbook
