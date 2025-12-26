
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


def test_mac_addresses_are_normalized_and_deduped(monkeypatch, client):
    scans = [
        [ScanHost(ip="192.168.1.10", hostname="iphone.lan", mac="aa:bb:cc:dd:ee:01", vendor="Apple")],
        [ScanHost(ip="192.168.1.11", hostname="iphone.lan", mac="AA:BB:CC:DD:EE:01", vendor="Apple")],
    ]

    def fake_run_nmap_discovery(cidr: str):
        return scans.pop(0)

    monkeypatch.setattr("app.main.run_nmap_discovery", fake_run_nmap_discovery)
    monkeypatch.setattr(main.settings, "enable_mdns", False)
    client.app.state.background_scanner_enabled = False

    r1 = client.post("/scan?sync=1")
    assert r1.status_code == 200

    r2 = client.post("/scan?sync=1")
    assert r2.status_code == 200

    devices = client.get("/devices").json()
    assert len(devices) == 1
    assert devices[0]["mac"] == "AA:BB:CC:DD:EE:01"


def test_macless_hosts_are_skipped_but_reported(monkeypatch, client):
    def fake_run_nmap_discovery(cidr: str):
        return [
            ScanHost(ip="192.168.1.50", hostname="nomac.lan", mac=None, vendor="Acme"),
        ]

    monkeypatch.setattr("app.main.run_nmap_discovery", fake_run_nmap_discovery)
    monkeypatch.setattr(main.settings, "enable_mdns", False)
    client.app.state.background_scanner_enabled = False

    r = client.post("/scan?sync=1")
    assert r.status_code == 200

    devices = client.get("/devices").json()
    assert devices == []

    status = client.get("/scan/status").json()
    assert status["macless_hosts"] == [
        {"ip": "192.168.1.50", "hostname": "nomac.lan", "vendor": "Acme", "mdns_name": None}
    ]


def test_device_and_friendly_names_derived_from_mdns(monkeypatch, client):
    def fake_run_nmap_discovery(cidr: str):
        return [
            ScanHost(ip="192.168.1.168", hostname="Google-Home-Mini-6DA1.lan", mac="38:8b:59:49:6d:a1", vendor="Google"),
        ]

    mdns_signals = {
        "192.168.1.168": {
            "hostname": "Google-Home-Mini-6DA1",
            "service_types": ["_googlecast._tcp.local."],
            "instances": ["Google-Home-Mini-9d95500e3427e9fd2f59ac62adcbd649._googlecast._tcp.local."],
            "txt": {"id": "9d95500e3427e9fd2f59ac62adcbd649", "md": "Google Home Mini", "fn": "Dawn's Study Speaker"},
            "best_name": "Google Home Mini",
        }
    }

    monkeypatch.setattr("app.main.run_nmap_discovery", fake_run_nmap_discovery)
    monkeypatch.setattr("app.main.collect_mdns_signals", lambda timeout_seconds=6: mdns_signals)
    client.app.state.background_scanner_enabled = False

    r = client.post("/scan?sync=1")
    assert r.status_code == 200

    device = client.get("/devices").json()[0]
    assert device["device_name"] == "Google Home Mini"
    assert device["friendly_name"] == "Dawn's Study Speaker"
    assert device["display_name"] == "Dawn's Study Speaker"
    assert device["mdns_name"] == "Google Home Mini"
    assert device["mac"] == "38:8B:59:49:6D:A1"


def test_display_name_updates_when_friendly_name_arrives(monkeypatch, client):
    scans = [
        [ScanHost(ip="192.168.1.168", hostname="Google-Home-Mini.lan", mac="38:8b:59:49:6d:a1", vendor="Google")],
        [ScanHost(ip="192.168.1.168", hostname="Google-Home-Mini.lan", mac="38:8b:59:49:6d:a1", vendor="Google")],
    ]

    mdns_sequences = [
        {
            "192.168.1.168": {
                "hostname": "Google-Home-Mini",
                "service_types": ["_googlecast._tcp.local."],
                "instances": ["Google-Home-Mini._googlecast._tcp.local."],
                "txt": {"md": "Google Home Mini"},
                "best_name": "Google Home Mini",
            }
        },
        {
            "192.168.1.168": {
                "hostname": "Google-Home-Mini",
                "service_types": ["_googlecast._tcp.local."],
                "instances": ["Google-Home-Mini._googlecast._tcp.local."],
                "txt": {"md": "Google Home Mini", "fn": "Dawn's Study Speaker"},
                "best_name": "Google Home Mini",
            }
        },
    ]

    def fake_run_nmap_discovery(cidr: str):
        return scans.pop(0)

    monkeypatch.setattr("app.main.run_nmap_discovery", fake_run_nmap_discovery)
    monkeypatch.setattr("app.main.collect_mdns_signals", lambda timeout_seconds=6: mdns_sequences.pop(0))
    client.app.state.background_scanner_enabled = False

    r1 = client.post("/scan?sync=1")
    assert r1.status_code == 200
    device1 = client.get("/devices").json()[0]
    assert device1["display_name"] == "Google Home Mini"
    assert device1["friendly_name"] == "Google Home Mini"

    r2 = client.post("/scan?sync=1")
    assert r2.status_code == 200
    device2 = client.get("/devices").json()[0]
    assert device2["display_name"] == "Dawn's Study Speaker"
    assert device2["friendly_name"] == "Dawn's Study Speaker"


def test_friendly_falls_back_to_best_name_when_fn_missing(monkeypatch, client):
    def fake_run_nmap_discovery(cidr: str):
        return [
            ScanHost(ip="192.168.1.173", hostname="Eisvogel-Laptop.lan", mac="7E:53:46:09:C7:AE", vendor=None),
        ]

    mdns_signals = {
        "192.168.1.173": {
            "hostname": "Eisvogel-Laptop",
            "service_types": ["_airplay._tcp.local."],
            "instances": ["Eisvogel Laptop._airplay._tcp.local."],
            "txt": {"md": "0,1,2", "model": "Mac14,2"},
            "best_name": "Eisvogel-Laptop",
        }
    }

    monkeypatch.setattr("app.main.run_nmap_discovery", fake_run_nmap_discovery)
    monkeypatch.setattr("app.main.collect_mdns_signals", lambda timeout_seconds=6: mdns_signals)
    client.app.state.background_scanner_enabled = False

    r = client.post("/scan?sync=1")
    assert r.status_code == 200

    device = client.get("/devices").json()[0]
    assert device["device_name"] == "Mac14,2"  # uses model when md is junk
    assert device["friendly_name"] == "Eisvogel-Laptop"  # falls back to best_name
    assert device["display_name"] == "Eisvogel-Laptop"


def test_mdns_srv_records_are_persisted(monkeypatch, client):
    def fake_run_nmap_discovery(cidr: str):
        return [
            ScanHost(ip="192.168.1.168", hostname="Google-Home-Mini-6DA1.lan", mac="38:8b:59:49:6d:a1", vendor="Google"),
        ]

    mdns_signals = {
        "192.168.1.168": {
            "hostname": "Google-Home-Mini-6DA1",
            "service_types": ["_googlecast._tcp.local."],
            "instances": ["Google-Home-Mini-9d95500e3427e9fd2f59ac62adcbd649._googlecast._tcp.local."],
            "txt": {"id": "9d95500e3427e9fd2f59ac62adcbd649", "md": "Google Home Mini", "fn": "Dawn's Study Speaker"},
            "best_name": "Google Home Mini",
            "srv": [
                {
                    "instance": "Google-Home-Mini-9d95500e3427e9fd2f59ac62adcbd649._googlecast._tcp.local.",
                    "service_type": "_googlecast._tcp.local.",
                    "target": "google-home-mini.local",
                    "port": 8009,
                }
            ],
        }
    }

    monkeypatch.setattr("app.main.run_nmap_discovery", fake_run_nmap_discovery)
    monkeypatch.setattr("app.main.collect_mdns_signals", lambda timeout_seconds=6: mdns_signals)
    client.app.state.background_scanner_enabled = False

    r = client.post("/scan?sync=1")
    assert r.status_code == 200

    device = client.get("/devices").json()[0]
    assert device["mdns_srv"] == mdns_signals["192.168.1.168"]["srv"]


def test_async_scan_returns_409_when_scan_already_running(client):
    client.app.state.background_scanner_enabled = False

    acquired = client.app.state.scan_lock.acquire(blocking=False)
    assert acquired is True
    try:
        r = client.post("/scan")
        assert r.status_code == 409
        assert r.json()["detail"] == "Scan already running"
    finally:
        client.app.state.scan_lock.release()
