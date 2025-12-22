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

def run_nmap_discovery(cidr: str) -> list[ScanHost]:
    # Prefer XML output to stdout
    args = ["nmap", *settings.nmap_args.split(), "-oX", "-", cidr]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"nmap failed: {proc.stderr.strip()}")

    root = ET.fromstring(proc.stdout)
    hosts: list[ScanHost] = []

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

    return hosts