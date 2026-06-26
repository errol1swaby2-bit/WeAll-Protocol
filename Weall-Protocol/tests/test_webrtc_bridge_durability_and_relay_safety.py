from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent
WEB = OUTER / "web"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_webrtc_signals_are_pruned_by_ttl_batch410() -> None:
    src = _read(ROOT / "src" / "weall" / "api" / "routes_public_parts" / "poh.py")

    assert "WEALL_P2P_SIGNAL_TTL_MS" in src
    assert "def _webrtc_signal_ttl_ms()" in src
    assert "def _prune_webrtc_session_records" in src
    assert "now - ts_ms > ttl_ms" in src
    assert "WEALL_P2P_SIGNAL_MAX_RECORDS_PER_SESSION" in src


def test_webrtc_bridge_uses_durable_tx_queue_batch410() -> None:
    src = _read(ROOT / "src" / "weall" / "api" / "routes_public_parts" / "poh.py")
    app = _read(ROOT / "src" / "weall" / "api" / "app.py")

    assert "WEALL_WEBRTC_SIGNAL_QUEUE_PATH" in src
    assert "webrtc_signal_bridge_tx_queue.json" in src
    assert "def _enqueue_webrtc_signal_bridge" in src
    assert "def _drain_webrtc_signal_queue" in src
    assert "/poh/live/webrtc/signals/queue/drain" in src
    assert "WEALL_WEBRTC_SIGNAL_BRIDGE_AUTODRAIN" in src
    assert "start_webrtc_signal_bridge_autodrain" in src
    assert "stop_webrtc_signal_bridge_autodrain" in src
    assert "start_webrtc_signal_bridge_autodrain" in app
    assert "stop_webrtc_signal_bridge_autodrain" in app


def test_webrtc_bridge_peers_are_node_pinned_for_prod_batch410() -> None:
    src = _read(ROOT / "src" / "weall" / "api" / "routes_public_parts" / "poh.py")

    assert "WEALL_WEBRTC_SIGNAL_PEERS_JSON" in src
    assert "WEALL_WEBRTC_SIGNAL_PEER_MANIFEST_PATH" in src
    assert "prod_webrtc_signal_peers_must_be_node_pinned" in src
    assert "webrtc_signal_peer_requires_node_id_and_url" in src
    assert "def _allowed_webrtc_bridge_source_nodes" in src
    assert "webrtc_bridge_source_node_not_allowed" in src
    assert "source_node" in src


def test_webrtc_relay_config_endpoint_and_frontend_ice_servers_batch410() -> None:
    src = _read(ROOT / "src" / "weall" / "api" / "routes_public_parts" / "poh.py")
    api = _read(WEB / "src" / "api" / "weall.ts")
    lib = _read(WEB / "src" / "lib" / "webrtcLiveRoom.ts")
    room = _read(WEB / "src" / "pages" / "LiveVerificationRoom.tsx")

    assert "/poh/live/webrtc/relay-config" in src
    assert "WEALL_WEBRTC_ICE_SERVERS_JSON" in src
    assert "WEALL_WEBRTC_STUN_URLS" in src
    assert "WEALL_WEBRTC_TURN_URLS" in src
    assert "WEALL_WEBRTC_TURN_USERNAME" in src
    assert "WEALL_WEBRTC_TURN_CREDENTIAL" in src

    assert "pohLiveWebRTCRelayConfig" in api
    assert "normalizeWeAllIceServers" in lib
    assert "configuredWeAllIceServers" in lib
    assert "RTCPeerConnection({ iceServers:" in lib
    assert "pohLiveWebRTCRelayConfig" in room
    assert "Optional STUN/TURN relay discovery" in room


def test_local_rehearsal_configures_two_way_pinned_bridge_batch410() -> None:
    script = _read(ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh")

    assert "WEALL_WEBRTC_SIGNAL_BRIDGE_AUTODRAIN=1" in script
    assert "WEALL_WEBRTC_SIGNAL_PEERS_JSON" in script
    assert '"node_id":"@local-observer"' in script
    assert "GENESIS_ACCOUNT" in script
    assert '"node_id":"' in script
    assert "WEALL_WEBRTC_STUN_URLS" in script
