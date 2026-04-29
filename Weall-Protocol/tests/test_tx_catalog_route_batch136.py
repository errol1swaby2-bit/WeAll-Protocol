from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


def test_tx_catalog_route_returns_summary_and_items() -> None:
    app = create_app(boot_runtime=False)
    client = TestClient(app)

    response = client.get('/v1/tx/catalog')
    assert response.status_code == 200
    body = response.json()

    assert body['ok'] is True
    assert int(body['total']) >= 200
    assert int(body['count']) >= 200
    assert isinstance(body.get('items'), list)
    assert isinstance(body.get('summary', {}).get('by_context'), list)
    assert isinstance(body.get('summary', {}).get('by_domain'), list)

    names = {str(item.get('name') or '') for item in body['items']}
    assert 'ACCOUNT_REGISTER' in names
    assert 'BLOCK_ATTEST' in names


def test_tx_catalog_route_filters_by_context_and_search() -> None:
    app = create_app(boot_runtime=False)
    client = TestClient(app)

    response = client.get('/v1/tx/catalog?context=mempool&search=account')
    assert response.status_code == 200
    body = response.json()

    assert body['ok'] is True
    assert body['filters']['context'] == 'mempool'
    assert body['filters']['search'] == 'account'
    assert body['count'] > 0
    for item in body['items']:
        assert str(item.get('context') or '').lower() == 'mempool'
