

from app.scanner import ScanHost


def test_sync_scan_populates_devices(monkeypatch, client):
    def fake_run_nmap_discovery(cidr: str):
        return [
            ScanHost(ip="192.168.1.10", hostname="iphone.lan", mac="AA:BB:CC:DD:EE:01", vendor="Apple"),
            ScanHost(ip="192.168.1.20", hostname="pihole.lan", mac="AA:BB:CC:DD:EE:02", vendor="Raspberry Pi"),
        ]

    # Patch the reference used inside app.main
    monkeypatch.setattr("app.main.run_nmap_discovery", fake_run_nmap_discovery)

    # Ensure we're in test-mode behavior: background scanning disabled
    client.app.state.background_scanner_enabled = False

    r = client.post("/scan?sync=1")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["mode"] == "sync"

    devices = client.get("/devices").json()
    macs = {d["mac"] for d in devices}
    assert "AA:BB:CC:DD:EE:01" in macs
    assert "AA:BB:CC:DD:EE:02" in macs


def test_sync_scan_disallowed_when_background_enabled(client):
    # Simulate a production app with background scanning enabled.
    client.app.state.background_scanner_enabled = True

    r = client.post("/scan?sync=1")
    assert r.status_code == 409
    assert "background scanner" in r.json()["detail"].lower()


def test_sync_scan_returns_409_when_scan_already_running(client):
    # Ensure background scanner is not enabled so we hit the lock-contention path.
    client.app.state.background_scanner_enabled = False

    # Simulate an in-progress scan by acquiring the lock.
    acquired = client.app.state.scan_lock.acquire(blocking=False)
    assert acquired is True
    try:
        r = client.post("/scan?sync=1")
        assert r.status_code == 409
        assert r.json()["detail"] == "Scan already running"
    finally:
        client.app.state.scan_lock.release()