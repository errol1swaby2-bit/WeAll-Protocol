from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent


def _read(path: str) -> str:
    return (OUTER / path).read_text(encoding="utf-8")


def test_economics_read_model_route_and_router_registered_batch457() -> None:
    route = _read("Weall-Protocol/src/weall/api/routes_public_parts/economics.py")
    routes = _read("Weall-Protocol/src/weall/api/routes_public.py")
    api = _read("web/src/api/weall.ts")
    page = _read("web/src/pages/Economics.tsx")
    router = _read("web/src/lib/router.ts")

    assert "def economics_status_from_state" in route
    assert '@router.get("/economics/status")' in route
    assert '@router.get("/wallet/{account}")' in route
    assert "civic_social_governance_fee_free" in route
    assert "balance_transfer_enabled" in route
    assert "economics_router" in routes
    assert "include_router(economics_router" in routes
    assert "economicsStatus" in api
    assert "walletStatus" in api
    assert "Economics & Treasury" in page
    assert "Genesis economics locked" in page
    assert 'href: "/economics"' in router


def test_block_production_readiness_endpoint_and_script_batch457() -> None:
    consensus = _read("Weall-Protocol/src/weall/api/routes_public_parts/consensus.py")
    script = _read("Weall-Protocol/scripts/production_block_production_proof_gate.sh")

    assert '@router.get("/consensus/block-production/readiness")' in consensus
    assert "observer_cannot_produce" in consensus
    assert "public_multi_validator_bft_ready" in consensus
    assert "does not grant authority" in consensus
    assert "/v1/consensus/block-production/readiness" in script
    assert "observer_reported_as_producer" in script


def test_messaging_peer_trust_removed_by_public_only_rule_batch457() -> None:
    crypto = _read("web/src/lib/messageCrypto.ts")
    messaging = _read("web/src/pages/Messaging.tsx")

    assert "PRIVATE_MESSAGING_UNSUPPORTED" in crypto
    assert "readTrustedMessagingPeer" in crypto
    assert "status: \"changed\"" not in crypto
    assert "Recipient keys are trusted on first use" not in messaging
    assert "trustMessagingPeerKey" not in messaging
    assert "Open activity" in messaging
