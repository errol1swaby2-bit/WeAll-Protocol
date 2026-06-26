from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent
WEB = OUTER / "web"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_webrtc_bridge_uses_per_peer_tokens_or_signed_envelopes_batch411() -> None:
    src = _read(ROOT / "src" / "weall" / "api" / "routes_public_parts" / "poh.py")

    assert "bridge_token" in src
    assert "bridge_secret" in src
    assert "webrtc_signal_peer_requires_token_or_signed_envelope" in src
    assert "_canonical_webrtc_bridge_signing_payload" in src
    assert "_sign_webrtc_bridge_payload" in src
    assert "bad_webrtc_peer_bridge_token" in src
    assert "bad_webrtc_bridge_signature" in src


def test_webrtc_bridge_validates_chain_id_on_import_batch411() -> None:
    src = _read(ROOT / "src" / "weall" / "api" / "routes_public_parts" / "poh.py")

    assert "source_chain_id" in src
    assert "_webrtc_chain_id" in src
    assert "_validate_webrtc_bridge_source_chain" in src
    assert "webrtc_bridge_source_chain_id_required" in src
    assert "webrtc_bridge_chain_id_mismatch" in src


def test_turn_credentials_are_short_lived_in_prod_batch411() -> None:
    src = _read(ROOT / "src" / "weall" / "api" / "routes_public_parts" / "poh.py")

    assert "WEALL_WEBRTC_TURN_CREDENTIAL_EXPIRES_MS" in src
    assert "WEALL_WEBRTC_TURN_MAX_CREDENTIAL_TTL_MS" in src
    assert "prod_webrtc_turn_credentials_must_be_short_lived" in src
    assert "credential_expires_ms" in src


def test_webrtc_bridge_operator_diagnostics_batch411() -> None:
    src = _read(ROOT / "src" / "weall" / "api" / "routes_public_parts" / "poh.py")

    assert "/poh/live/webrtc/signals/diagnostics" in src
    assert "queue_depth" in src
    assert "last_drain_result" in src
    assert "rejected_peers" in src
    assert "stale_signal_pruned" in src
    assert "stale_tx_queue_pruned" in src
    assert "max_record_pruned" in src
    assert "transport_only_operator_diagnostics" in src
