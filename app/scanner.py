import ipaddress
import socket
import struct
import fcntl
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional
from .config import settings

@dataclass
class ScanHost:
    ip: str
    hostname: Optional[str]
    mac: Optional[str]
    vendor: Optional[str]

def _get_default_iface() -> Optional[str]:
    """Best-effort: determine the default route interface inside the Linux network namespace."""
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            next(f)  # header
            for line in f:
                parts = line.strip().split()
                if len(parts) < 11:
                    continue
                iface, destination, flags = parts[0], parts[1], parts[3]
                # Destination 00000000 == default route
                if destination == "00000000":
                    return iface
    except OSError:
        return None
    return None


def _get_iface_mac(iface: str) -> Optional[str]:
    try:
        with open(f"/sys/class/net/{iface}/address", "r", encoding="utf-8") as f:
            mac = f.read().strip().upper()
            if mac and mac != "00:00:00:00:00:00":
                return mac
    except OSError:
        return None
    return None


def _get_iface_ipv4(iface: str) -> Optional[str]:
    """Return IPv4 for an interface using ioctl; avoids depending on iproute2."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = struct.pack('256s', iface.encode('utf-8')[:15])
        res = fcntl.ioctl(s.fileno(), 0x8915, ifreq)  # SIOCGIFADDR
        ip = socket.inet_ntoa(res[20:24])
        return ip
    except OSError:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def get_local_identity() -> Optional[ScanHost]:
    """Identify the scanner host itself (IP+MAC) so it can be represented reliably in inventory."""
    iface = _get_default_iface()
    if not iface or iface == "lo":
        return None

    ip = _get_iface_ipv4(iface)
    mac = _get_iface_mac(iface)

    if not ip:
        # Fallback: ask the kernel which source IP it would use to reach the internet.
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("1.1.1.1", 53))
            ip = s.getsockname()[0]
        except OSError:
            ip = None
        finally:
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass

    if not ip:
        return None

    # Hostname inside the VM/container (often matches local DNS entry)
    hostname = socket.gethostname()
    return ScanHost(ip=ip, hostname=hostname, mac=mac, vendor=None)

def run_nmap_discovery(cidr: str) -> list[ScanHost]:
    # Prefer XML output to stdout
    args = ["nmap", *settings.nmap_args.split(), "-oX", "-", cidr]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"nmap failed: {proc.stderr.strip()}")

    root = ET.fromstring(proc.stdout)
    hosts: list[ScanHost] = []

    local = get_local_identity()
    network = None
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        network = None

    for h in root.findall("host"):
        status = h.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = None
        mac = None
        vendor = None

        for addr in h.findall("address"):
            atype = addr.get("addrtype")
            if atype == "ipv4":
                ip = addr.get("addr")
            elif atype == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")

        if not ip:
            continue

        hostname = None
        hostnames = h.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        hosts.append(ScanHost(ip=ip, hostname=hostname, mac=mac, vendor=vendor))


    # Polishing: nmap may report the local host IP without a MAC; fix that using OS-derived identity.
    if local is not None and (network is None or ipaddress.ip_address(local.ip) in network):
        replaced = False
        for i, h in enumerate(hosts):
            if h.ip == local.ip:
                if h.mac is None and local.mac is not None:
                    hosts[i] = ScanHost(ip=h.ip, hostname=h.hostname or local.hostname, mac=local.mac, vendor=h.vendor)
                replaced = True
                break
        if not replaced:
            hosts.append(local)

    return hosts