from fastapi.testclient import TestClient

from app.main import create_app


def test_devices_empty():
    app = create_app(start_scanner=False, db_url="sqlite+pysqlite:///:memory:")
    client = TestClient(app)

    r = client.get("/devices")
    assert r.status_code == 200
    assert r.json() == []


def test_scan_status_shape():
    app = create_app(start_scanner=False, db_url="sqlite+pysqlite:///:memory:")
    client = TestClient(app)

    r = client.get("/scan/status")
    assert r.status_code == 200
    body = r.json()

    # stable keys (don’t over-specify values)
    assert "running" in body
    assert "last_started" in body
    assert "last_finished" in body
    assert "last_error" in body


def test_device_detail_404():
    app = create_app(start_scanner=False, db_url="sqlite+pysqlite:///:memory:")
    client = TestClient(app)

    r = client.get("/devices/999999")
    assert r.status_code == 404
    assert r.json()["detail"] == "device not found"