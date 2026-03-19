from weall.runtime.operator_recovery import evaluate_recovery_readiness, network_resume_decision


def _report(*, severity: str, height: int = 10, tip_hash: str = "aaa", chain_id: str = "weall"):
    return {
        "summary": {"severity": severity},
        "snapshot": {"height": height, "tip_hash": tip_hash},
        "startup_fingerprint": {"chain_id": chain_id},
    }


def test_recovery_readiness_requires_quorum_of_agreeing_healthy_peers() -> None:
    peers = [
        _report(severity="ok", height=10, tip_hash="aaa"),
        _report(severity="ok", height=10, tip_hash="aaa"),
        _report(severity="warning", height=10, tip_hash="aaa"),
    ]
    out = evaluate_recovery_readiness(peer_reports=peers, min_agreeing_peers=2)
    assert out["ready_to_resume"] is True
    assert out["healthy_peer_count"] == 2
    assert out["agreeing_peer_count"] >= 2


def test_recovery_readiness_rejects_divergent_peers() -> None:
    peers = [
        _report(severity="ok", height=10, tip_hash="aaa"),
        _report(severity="ok", height=11, tip_hash="bbb"),
    ]
    out = evaluate_recovery_readiness(peer_reports=peers, min_agreeing_peers=2)
    assert out["ready_to_resume"] is False


def test_network_resume_decision_blocks_when_local_is_critical() -> None:
    local = _report(severity="critical")
    peers = [
        _report(severity="ok"),
        _report(severity="ok"),
    ]
    out = network_resume_decision(local_report=local, peer_reports=peers, min_agreeing_peers=2)
    assert out["allow_resume"] is False


def test_network_resume_decision_allows_resume_when_local_not_critical_and_peers_agree() -> None:
    local = _report(severity="warning")
    peers = [
        _report(severity="ok"),
        _report(severity="ok"),
    ]
    out = network_resume_decision(local_report=local, peer_reports=peers, min_agreeing_peers=2)
    assert out["allow_resume"] is True
