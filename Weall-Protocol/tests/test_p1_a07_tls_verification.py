from __future__ import annotations

import pytest

from weall.net import transport_tls


def _configure_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_NET_TLS_CA", raising=False)
    monkeypatch.delenv("WEALL_NET_TLS_INSECURE_OK", raising=False)


def test_prod_tls_direct_construction_without_ca_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_prod(monkeypatch)

    with pytest.raises(RuntimeError, match="requires WEALL_NET_TLS_CA"):
        transport_tls.TlsTransport(
            server_cert="unused-cert.pem",
            server_key="unused-key.pem",
        )


def test_prod_tls_insecure_mode_requires_explicit_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_prod(monkeypatch)
    monkeypatch.setenv("WEALL_NET_TLS_INSECURE_OK", "1")

    monkeypatch.setattr(transport_tls.TlsTransport, "_make_server_ctx", lambda self: object())
    monkeypatch.setattr(transport_tls.TlsTransport, "_make_client_ctx", lambda self: object())

    transport = transport_tls.TlsTransport(
        server_cert="unused-cert.pem",
        server_key="unused-key.pem",
    )
    try:
        assert transport.ca_file == ""
    finally:
        transport.close()
