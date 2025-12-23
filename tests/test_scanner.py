from types import SimpleNamespace
import subprocess

from app.scanner import run_nmap_discovery, ScanHost

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:01" addrtype="mac" vendor="Apple"/>
    <hostnames><hostname name="iphone.lan"/></hostnames>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.185" addrtype="ipv4"/>
    <hostnames><hostname name="home-net-inventory.lan"/></hostnames>
  </host>
</nmaprun>
"""

def test_run_nmap_discovery_parses_hosts(monkeypatch):
    def fake_run(args, capture_output, text):
        return SimpleNamespace(returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    # also avoid depending on local machine identity in this test
    monkeypatch.setattr("app.scanner.get_local_identity", lambda: None)

    hosts = run_nmap_discovery("192.168.1.0/24")

    assert len(hosts) == 2
    assert hosts[0].ip == "192.168.1.10"
    assert hosts[0].mac == "AA:BB:CC:DD:EE:01"
    assert hosts[0].vendor == "Apple"
    assert hosts[0].hostname == "iphone.lan"

def test_local_identity_replaces_missing_mac(monkeypatch):
    def fake_run(args, capture_output, text):
        return SimpleNamespace(returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    # Pretend the scanner VM is 192.168.1.185 with a real MAC
    local = ScanHost(
        ip="192.168.1.185",
        hostname="home-net-inventory",
        mac="DE:AD:BE:EF:00:01",
        vendor=None,
    )
    monkeypatch.setattr("app.scanner.get_local_identity", lambda: local)

    hosts = run_nmap_discovery("192.168.1.0/24")

    # Find the self host
    self_host = next(h for h in hosts if h.ip == "192.168.1.185")
    assert self_host.mac == "DE:AD:BE:EF:00:01"
    # keep hostname if nmap provided it
    assert self_host.hostname in ("home-net-inventory.lan", "home-net-inventory")