
from app.scanner import ScanHost
import app.main as main


def test_sync_scan_populates_devices(monkeypatch, client):
    def fake_run_nmap_discovery(cidr: str):
        return [
            ScanHost(ip="192.168.1.10", hostname="iphone.lan", mac="AA:BB:CC:DD:EE:01", vendor="Apple"),
            ScanHost(ip="192.168.1.20", hostname="pihole.lan", mac="AA:BB:CC:DD:EE:02", vendor="Raspberry Pi"),
        ]

    # Patch the reference used inside app.main
    monkeypatch.setattr("app.main.run_nmap_discovery", fake_run_nmap_discovery)
    # Disable mDNS in tests to avoid multicast/network dependence and the mDNS browse sleep.
    monkeypatch.setattr(main.settings, "enable_mdns", False)

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


def test_last_seen_updates_on_rescan(monkeypatch, client):
    # Same device returned across scans
    def fake_run_nmap_discovery(cidr: str):
        return [
            ScanHost(ip="192.168.1.10", hostname="iphone.lan", mac="AA:BB:CC:DD:EE:01", vendor="Apple"),
        ]

    monkeypatch.setattr("app.main.run_nmap_discovery", fake_run_nmap_discovery)
    # Disable mDNS in tests to avoid multicast/network dependence and the mDNS browse sleep.
    monkeypatch.setattr(main.settings, "enable_mdns", False)

    # Ensure sync scans are allowed
    client.app.state.background_scanner_enabled = False

    # Patch datetime.now(timezone.utc) used in app.main so we don't need to sleep.
    class _FakeDateTime:
        _base = __import__("datetime").datetime(2025, 1, 1, 0, 0, 0)

        @classmethod
        def now(cls, tz=None):
            dt_mod = __import__("datetime")
            if not hasattr(cls, "_current"):
                cls._current = cls._base
            else:
                cls._current = cls._current + dt_mod.timedelta(seconds=1)

            dt = cls._current
            # Match datetime.now(tz=...) semantics.
            if tz is not None and getattr(dt, "tzinfo", None) is None:
                dt = dt.replace(tzinfo=tz)
            return dt

    monkeypatch.setattr(main, "datetime", _FakeDateTime)

    r1 = client.post("/scan?sync=1")
    assert r1.status_code == 200

    d1 = client.get("/devices").json()[0]
    last_seen_1 = __import__("datetime").datetime.fromisoformat(d1["last_seen"])

    r2 = client.post("/scan?sync=1")
    assert r2.status_code == 200

    d2 = client.get("/devices").json()[0]
    last_seen_2 = __import__("datetime").datetime.fromisoformat(d2["last_seen"])

    assert last_seen_2 > last_seen_1