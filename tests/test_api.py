def test_devices_empty(client):
    r = client.get("/devices")
    assert r.status_code == 200
    assert r.json() == []


def test_scan_status_shape(client):
    r = client.get("/scan/status")
    assert r.status_code == 200
    body = r.json()

    # stable keys (don’t over-specify values)
    assert "running" in body
    assert "last_started" in body
    assert "last_finished" in body
    assert "last_error" in body


def test_device_detail_404(client):
    r = client.get("/devices/999999")
    assert r.status_code == 404
    assert r.json()["detail"] == "device not found"