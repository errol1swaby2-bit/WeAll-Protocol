from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


def test_tx_catalog_route_exposes_public_entrypoints() -> None:
    app = create_app(boot_runtime=False)
    client = TestClient(app)

    response = client.get('/v1/tx/catalog?search=tier3')
    assert response.status_code == 200
    body = response.json()

    items = {str(item.get('name') or ''): item for item in body['items']}
    assert 'POH_TIER3_ATTENDANCE_MARK' in items
    assert '/v1/poh/tier3/tx/attendance' in list(items['POH_TIER3_ATTENDANCE_MARK'].get('api_entrypoints') or [])
    assert '/v1/tx/submit' in list(items['POH_TIER3_ATTENDANCE_MARK'].get('api_entrypoints') or [])


def test_tx_catalog_route_summary_is_filter_scoped() -> None:
    app = create_app(boot_runtime=False)
    client = TestClient(app)

    response = client.get('/v1/tx/catalog?context=mempool&domain=identity')
    assert response.status_code == 200
    body = response.json()

    contexts = body.get('summary', {}).get('by_context') or []
    assert contexts == [{'name': 'mempool', 'count': int(body['count'])}]
