from fastapi import FastAPI, HTTPException, Request, Query, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
from sqlalchemy import select, desc, asc, func
import threading
import time
import os
import sys
import re
from datetime import datetime, timezone
import json
import pathlib

from .db import make_engine, make_sessionmaker, Base
from .models import Device
from .config import settings
from .scanner import run_nmap_discovery
from zeroconf import Zeroconf, ServiceBrowser


def create_app(*, start_scanner: bool = True, db_url: str | None = None) -> FastAPI:
    """Create the FastAPI app.

    - Creates engine/sessionmaker
    - Creates tables
    - Optionally starts the background scan loop (disable in tests)
    """

    def scan_loop():
        while True:
            do_scan()
            time.sleep(settings.scan_interval_seconds)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if start_scanner:
            t = threading.Thread(target=scan_loop, daemon=True)
            t.start()
        yield

    app = FastAPI(title="Home Net Inventory", lifespan=lifespan)
    templates = Jinja2Templates(directory="templates")
    SERVICE_LABELS: dict[str, str] = {
        "_afpovertcp._tcp": "AFP File Sharing",
        "_airplay._tcp": "AirPlay",
        "_androidtvremote2._tcp": "Android TV Remote",
        "_apple-mobdev2._tcp": "Apple Mobile Device",
        "_appletv-v2._tcp": "Apple TV (v2)",
        "_asquic._udp": "Apple QUIC",
        "_companion-link._tcp": "Apple Companion Link",
        "_daap._tcp": "DAAP / iTunes",
        "_dlna._tcp": "DLNA/UPnP",
        "_googcrossdevice._tcp": "Google Cross-Device",
        "_googlecast._tcp": "Chromecast / Google Cast",
        "_googlerpc._tcp": "Google RPC",
        "_googlezone._tcp": "Google Cast Audio Group",
        "_hap._tcp": "HomeKit / HAP",
        "_http._tcp": "HTTP",
        "_https._tcp": "HTTPS",
        "_home-assistant._tcp": "Home Assistant",
        "_home-sharing._tcp": "Home Sharing",
        "_ipp._tcp": "Internet Printing Protocol",
        "_ipps._tcp": "Internet Printing Protocol over TLS",
        "_ippusb._tcp": "Internet Printing Protocolover USB",
        "_matter._tcp": "Matter (IP)",
        "_meshcop._udp": "Thread Mesh Commissioning",
        "_orb._tcp": "Orb Sensor",
        "_pdl-datastream._tcp": "Printer Data Stream",
        "_printer._tcp": "Printer",
        "_raop._tcp": "AirPlay Audio (RAOP)",     
        "_rdlink._tcp": "Remote Desktop Link",
        "_remotepairing._tcp": "Remote Pairing",
        "_rfb._tcp": "Screen Sharing (RFB)",
        "_sftp-ssh._tcp": "SFTP",
        "_sleep-proxy._udp": "Sleep Proxy",
        "_smartthings._tcp": "SmartThings",
        "_smartthings-hedge._tcp": "SmartThings Hedge",
        "_smb._tcp": "SMB File Sharing",
        "_sonos._tcp": "Sonos",
        "_spotify-connect._tcp": "Spotify Connect",
        "_srpl-tls._tcp": "Sleep Proxy (TLS)",
        "_ssh._tcp": "SSH",
        "_touch-able._tcp": "legacy Apple DMAP",
        "_trel._udp": "Thread TREL",
        "_uscan._tcp": "AirScan (eSCL)",
        "_uscans._tcp": "AirScan (eSCL) over TLS",
        "_workstation._tcp": "Workstation",
    }

    resolved_url = db_url or settings.resolved_db_url()
    engine = make_engine(resolved_url)
    SessionLocal = make_sessionmaker(engine)

    Base.metadata.create_all(bind=engine)

    app.state.engine = engine
    app.state.SessionLocal = SessionLocal
    app.state.scan_lock = threading.Lock()
    app.state.scan_state = {
        "running": False,
        "last_started": None,
        "last_finished": None,
        "last_error": None,
        "last_macless_hosts": [],
    }
    app.state.background_scanner_enabled = start_scanner

    def get_db(request: Request):
        db = request.app.state.SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def _debug_enabled() -> bool:
        return bool(getattr(settings, "enable_debug_logs", False))

    def _debug_path() -> pathlib.Path:
        return pathlib.Path(getattr(settings, "debug_dir", "/data/debug"))

    def _write_debug_text(filename: str, text: str) -> None:
        if not _debug_enabled():
            return
        d = _debug_path()
        d.mkdir(parents=True, exist_ok=True)
        (d / filename).write_text(text, encoding="utf-8")

    def _append_debug_text(filename: str, text: str) -> None:
        if not _debug_enabled():
            return
        d = _debug_path()
        d.mkdir(parents=True, exist_ok=True)
        path = d / filename
        try:
            existing = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            existing = ""
        path.write_text(existing + text, encoding="utf-8")


    def _write_debug_json(filename: str, payload: object) -> None:
        if not _debug_enabled():
            return
        d = _debug_path()
        d.mkdir(parents=True, exist_ok=True)
        (d / filename).write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )

    def _cast_debug_name(ip: str, tag: str, ext: str = "txt") -> str:
        ts = _utcnow().strftime("%Y%m%d-%H%M%S")
        return f"{ts}-cast-{ip}-{tag}.{ext}"

    def _utcnow() -> datetime:
        # Always generate UTC-aware timestamps (UTC+0)
        return datetime.now(timezone.utc)

    def _dt_iso(dt: datetime | None) -> str | None:
        # Human-readable ISO-8601 with explicit UTC offset.
        if dt is None:
            return None
        if dt.tzinfo is None:
            # Since you plan to recreate the DB, we don't aim for legacy support,
            # but normalize defensively in case SQLite returns naive datetimes.
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()

    def _normalize_mac(mac: str | None) -> str | None:
        if not mac:
            return None
        mac = str(mac).strip()
        if not mac:
            return None
        return mac.upper()

    def _normalize_str(val: str | None) -> str | None:
        if not isinstance(val, str):
            return None
        s = val.strip()
        if not s:
            return None
        # Normalize curly apostrophes to ASCII for consistency.
        s = s.replace("\u2019", "'").replace("\u2018", "'")
        return s

    def _fetch_googlecast_info(ip: str, port: int | None = None) -> dict[str, object] | None:
        url = f"http://{ip}:{port or 8008}/setup/eureka_info?options=detail"
        try:
            import httpx as _httpx  # local import to avoid module-level missing httpx issues
            r = _httpx.get(url, timeout=2.0, headers={"Accept": "application/json"})
            if r.status_code != 200:
                _append_debug_text(_cast_debug_name(ip, "error"), f"{url} returned {r.status_code}\n")
                return None
            try:
                data = r.json()
            except Exception as e:
                _append_debug_text(_cast_debug_name(ip, "error"), f"{url} json error: {e}; body[:500]={r.text[:500]!r}\n")
                return None
            if isinstance(data, dict):
                _write_debug_json(_cast_debug_name(ip, "success", "json"), data)
                return data
            _append_debug_text(_cast_debug_name(ip, "error"), f"{url} returned non-dict JSON\n")
        except Exception as e:
            _append_debug_text(_cast_debug_name(ip, "error"), f"{url} failed: {e}\n")
            return None
        return None

    def _try_googlecast_info(ip: str, srv_list: list[dict[str, object]] | None) -> dict[str, object] | None:
        # Try common ports and any discovered cast ports.
        seen_ports: set[int] = set()
        for port in (8008, 8009, 8443):
            seen_ports.add(port)
            _append_debug_text(_cast_debug_name(ip, "attempt"), f"Trying {ip}:{port}\n")
            info = _fetch_googlecast_info(ip, port=port)
            if info:
                return info
        if srv_list:
            for s in srv_list:
                if not isinstance(s, dict):
                    continue
                stype = s.get("service_type")
                if not (isinstance(stype, str) and "_googlecast._tcp" in stype):
                    continue
                port = s.get("port")
                tgt = s.get("target") or ip
                try:
                    port_int = int(port) if port is not None else None
                except Exception:
                    port_int = None
                if port_int and port_int in seen_ports:
                    continue
                if port_int:
                    seen_ports.add(port_int)
                _append_debug_text(_cast_debug_name(ip, "attempt"), f"Trying {tgt}:{port_int or '(default)'} via SRV\n")
                info = _fetch_googlecast_info(str(tgt), port=port_int)
                if info:
                    return info
        return None

    def _mdns_device_and_friendly(txt: dict[str, str] | None, best_name: str | None) -> tuple[str | None, str | None]:
        """Derive model-like (device_name) and friendly names from TXT/best_name."""
        if not isinstance(txt, dict):
            txt = {}

        def _pick(candidates: list[str | None]) -> str | None:
            for c in candidates:
                s = _normalize_str(c)
                if s:
                    # Skip obviously placeholder numeric blobs (e.g., "0,1,2")
                    if all(ch in "0123456789, " for ch in s):
                        continue
                    return s
            return None

        model = _pick([txt.get("model"), txt.get("md"), best_name])
        friendly = _pick([txt.get("fn"), txt.get("name"), best_name])
        return model, friendly

    def _serialize_devices(db: Session, limit: int | None = None) -> list[dict[str, object]]:
        query = select(Device).order_by(asc(Device.ip))
        if limit and limit > 0:
            query = query.limit(limit)
        devices = db.scalars(query).all()
        out = []
        for d in devices:
            out.append(
                {
                    "id": d.id,
                    "mac": d.mac,
                    "vendor": d.vendor,
                    "ip": d.ip,
                    "hostname": d.hostname,
                    "device_name": d.device_name,
                    "friendly_name": d.friendly_name,
                    "display_name": d.display_name,
                    "mdns_name": d.mdns_name,
                    "mdns_srv": d.mdns_srv,
                    "mdns_service_types": d.mdns_service_types,
                    "mdns_instances": d.mdns_instances,
                    "mdns_txt": d.mdns_txt,
                    "googlecast_info": d.googlecast_info,
                    "first_seen": _dt_iso(d.first_seen),
                    "last_seen": _dt_iso(d.last_seen),
                }
            )
        return out

    def _decode_txt(props: dict[bytes, bytes] | None) -> dict[str, str]:
        if not props:
            return {}
        out: dict[str, str] = {}
        for k, v in props.items():
            try:
                ks = k.decode("utf-8", errors="ignore")
            except Exception:
                continue
            try:
                vs = v.decode("utf-8", errors="ignore")
            except Exception:
                vs = ""
            out[ks] = vs
        return out

    def _filter_mdns_txt(txt: dict[str, str]) -> dict[str, str]:
        # Keep keys that are useful for device identification; drop likely-sensitive tokens.
        deny = {"authtag", "authTag", "token", "access_token", "password", "passwd"}
        allow_prefixes = ("id", "identifier", "model", "md", "mf", "mfg", "manufacturer", "ver", "minver", "pv", "flags", "fn", "name", "device", "type")
        out: dict[str, str] = {}
        for k, v in txt.items():
            if k in deny:
                continue
            kl = k.lower()
            if kl in deny:
                continue
            if kl.startswith(allow_prefixes):
                out[k] = v
        # Cap size defensively
        if len(out) > 25:
            out = dict(list(out.items())[:25])
        for k in list(out.keys()):
            if out[k] is not None and len(out[k]) > 256:
                out[k] = out[k][:256]
        return out

    _HEXISH_TAIL = re.compile(r"[0-9a-f]{16,}$", re.IGNORECASE)

    def _service_instance_to_friendly(instance: str) -> str:
        # Example: "Google-Nest-Mini-9770..._googlecast._tcp.local." -> "Google Nest Mini"
        s = instance
        s = s.rstrip(".")
        # Drop the service type suffix if present
        for suffix in (
            "._googlecast._tcp.local",
            "._hap._tcp.local",
            "._airplay._tcp.local",
            "._raop._tcp.local",
            "._companion-link._tcp.local",
            "._rdlink._tcp.local",
            "._remotepairing._tcp.local",
            "._rfb._tcp.local",
        ):
            if s.lower().endswith(suffix):
                s = s[: -len(suffix)]
                break
        # Remove long hex-ish tail after a dash
        if "-" in s:
            head, tail = s.rsplit("-", 1)
            if _HEXISH_TAIL.match(tail):
                s = head
        # Replace separators with spaces
        s = s.replace("_", " ").replace("-", " ").strip()
        return s

    def _server_to_hostname(server: str | None) -> str | None:
        if not server:
            return None
        s = server.rstrip(".")
        # Most are like "Larrys-iPhone.local." or "Sucia.local."
        if s.lower().endswith(".local"):
            s = s[: -len(".local")]
        s = s.strip()
        if not s:
            return None
        # Filter out very machine-id-ish hostnames
        if len(s) >= 24 and re.fullmatch(r"[0-9a-f\-]{24,}", s, flags=re.IGNORECASE):
            return None
        return s

    def _pick_best_name(hostname: str | None, instances: list[str]) -> str | None:
        # Prefer a real hostname, otherwise derive from best-looking instance name.
        if hostname:
            return hostname
        best: str | None = None
        for inst in instances:
            cand = _service_instance_to_friendly(inst)
            if not cand:
                continue
            # Prefer names that don't look like UUIDs/hex blobs
            if re.fullmatch(r"[0-9a-f\-]{16,}", cand, flags=re.IGNORECASE):
                continue
            if best is None or len(cand) > len(best):
                best = cand
        return best

    def collect_mdns_signals(timeout_seconds: int = 6) -> dict[str, dict[str, object]]:
        """Collect best-effort mDNS identity/type signals.

        Returns a mapping: ip -> {
            "hostname": str|None,
            "service_types": list[str],
            "instances": list[str],
            "srv": list[dict],           # SRV target/port per instance
            "txt": dict[str,str],
        }
        """

        base_service_types = [
            "_googlecast._tcp.local.",
            "_hap._tcp.local.",
            "_airplay._tcp.local.",
            "_raop._tcp.local.",
            "_companion-link._tcp.local.",
            "_rdlink._tcp.local.",
            "_remotepairing._tcp.local.",
            "_ssh._tcp.local.",
            "_sftp-ssh._tcp.local.",
            "_workstation._tcp.local.",
            "_printer._tcp.local.",
            "_ipp._tcp.local.",
            "_ipps._tcp.local.",
            "_http._tcp.local.",
            "_https._tcp.local.",
            "_device-info._tcp.local.",
            "_spotify-connect._tcp.local.",
            "_sonos._tcp.local.",
            "_daap._tcp.local.",
            "_dlna._tcp.local.",
            "_smb._tcp.local.",
        ]

        zc = Zeroconf()
        results: dict[str, dict[str, object]] = {}
        discovered_types: set[str] = set()

        def upsert_ip(ip: str) -> dict[str, object]:
            if ip not in results:
                results[ip] = {"hostname": None, "service_types": [], "instances": [], "srv": [], "txt": {}}
            return results[ip]

        class _ServiceTypeListener:
            def add_service(self, zc_obj, stype: str, name: str):
                if name:
                    discovered_types.add(name)

            def remove_service(self, zc_obj, service_type: str, name: str):
                return

            def update_service(self, zc_obj, service_type: str, name: str):
                return

        class Listener:
            def add_service(self, zc_obj, service_type: str, name: str):
                info = zc_obj.get_service_info(service_type, name, timeout=1500)
                if not info:
                    return

                # Prefer IPv4 for device association; capture target/port for identity.
                ips: list[str] = []
                try:
                    for addr in info.addresses or []:
                        if len(addr) == 4:
                            ips.append(".".join(str(b) for b in addr))
                except Exception:
                    ips = []

                if not ips:
                    return

                hostname = _server_to_hostname(getattr(info, "server", None))
                txt = _filter_mdns_txt(_decode_txt(getattr(info, "properties", None)))
                target = _server_to_hostname(getattr(info, "server", None))
                port = getattr(info, "port", None)

                for ip in ips:
                    rec = upsert_ip(ip)
                    # Merge hostname
                    if hostname and not rec.get("hostname"):
                        rec["hostname"] = hostname

                    # Merge service types (unique)
                    st = rec.get("service_types")
                    if isinstance(st, list) and service_type not in st:
                        st.append(service_type)

                    # Merge instances (unique)
                    inst = rec.get("instances")
                    if isinstance(inst, list) and name not in inst:
                        inst.append(name)

                    # Merge SRV targets/ports
                    srv_list = rec.get("srv")
                    if isinstance(srv_list, list):
                        entry = {
                            "instance": name,
                            "service_type": service_type,
                            "target": target,
                            "port": port,
                        }
                        if entry not in srv_list:
                            srv_list.append(entry)

                    # Merge TXT (prefer existing keys; fill missing)
                    t = rec.get("txt")
                    if isinstance(t, dict) and txt:
                        for k, v in txt.items():
                            if k not in t:
                                t[k] = v

            def remove_service(self, zc_obj, service_type: str, name: str):
                return

            def update_service(self, zc_obj, service_type: str, name: str):
                return

        listeners = []
        browsers = []
        try:
            # Discover additional service types first.
            type_listener = _ServiceTypeListener()
            browsers.append(ServiceBrowser(zc, "_services._dns-sd._udp.local.", type_listener))
            time.sleep(min(2, timeout_seconds))

            # Union base + discovered types (deduped).
            service_types = sorted(set(base_service_types).union(discovered_types))

            for stype in service_types:
                l = Listener()
                listeners.append(l)
                browsers.append(ServiceBrowser(zc, stype, l))
            time.sleep(timeout_seconds)
        finally:
            try:
                zc.close()
            except Exception:
                pass

        # Add derived best_name into each record.
        for ip, rec in results.items():
            hostname = rec.get("hostname") if isinstance(rec.get("hostname"), str) else None
            instances = rec.get("instances") if isinstance(rec.get("instances"), list) else []
            best = _pick_best_name(hostname, [str(x) for x in instances])
            rec["best_name"] = best

        return results
    # Expose for testing/monkeypatching.
    sys.modules[__name__].collect_mdns_signals = collect_mdns_signals

    # update/insert device info into inventory
    def upsert_device_and_observation(
        db: Session,
        ip: str,
        hostname: str | None,
        mac: str | None,
        vendor: str | None,
        mdns: dict[str, object] | None = None,
    ) -> Device:
        mac = _normalize_mac(mac)

        device = None

        if mac:
            device = db.scalar(select(Device).where(Device.mac == mac))

        if device is None:
            now = _utcnow()
            device = Device(mac=mac, vendor=vendor, first_seen=now, last_seen=now)
            db.add(device)
            db.flush()

        if vendor and not device.vendor:
            device.vendor = vendor

        # Update last-known mDNS identity/type signals on the Device.
        if mdns:
            best_name = mdns.get("best_name")
            txt = mdns.get("txt") if isinstance(mdns.get("txt"), dict) else {}
            model_name, friendly_name = _mdns_device_and_friendly(txt, best_name if isinstance(best_name, str) else None)
            if isinstance(best_name, str) and best_name:
                if not device.mdns_name:
                    device.mdns_name = best_name

            if model_name and not device.device_name:
                device.device_name = model_name

            if friendly_name:
                # Allow updates when a friendly name becomes available later.
                if device.friendly_name != friendly_name:
                    device.friendly_name = friendly_name

            # Keep display_name synced to best available signal (friendly > model > mdns best > hostname).
            preferred_display = (
                friendly_name
                or model_name
                or (best_name if isinstance(best_name, str) else None)
                or (hostname if isinstance(hostname, str) and hostname else None)
            )
            if preferred_display:
                device.display_name = preferred_display
            stypes = mdns.get("service_types")
            if isinstance(stypes, list):
                existing = set(device.mdns_service_types or [])
                merged = list(existing.union({str(x) for x in stypes if x}))
                device.mdns_service_types = sorted(merged)

            inst = mdns.get("instances")
            if isinstance(inst, list):
                existing = set(device.mdns_instances or [])
                merged = list(existing.union({str(x) for x in inst if x}))
                # Cap to keep the DB from growing unbounded
                device.mdns_instances = sorted(merged)[:50]

            txt = mdns.get("txt")
            if isinstance(txt, dict):
                current = dict(device.mdns_txt or {})
                for k, v in txt.items():
                    if k not in current and isinstance(v, str):
                        current[k] = v
                device.mdns_txt = current

            srv = mdns.get("srv")
            if isinstance(srv, list):
                existing = {(s.get("instance"), s.get("service_type"), s.get("target"), s.get("port")) for s in device.mdns_srv or []}
                merged: list[dict[str, object]] = list(device.mdns_srv or [])
                for s in srv:
                    if not isinstance(s, dict):
                        continue
                    key = (s.get("instance"), s.get("service_type"), s.get("target"), s.get("port"))
                    if key in existing:
                        continue
                    merged.append(
                        {
                            "instance": s.get("instance"),
                            "service_type": s.get("service_type"),
                            "target": s.get("target"),
                            "port": s.get("port"),
                        }
                    )
                    existing.add(key)
                device.mdns_srv = merged
        else:
            # No mDNS data: fall back to hostname for display_name if empty.
            if hostname and not device.display_name:
                device.display_name = hostname

        # Opportunistically fetch Google Cast info if present and not yet stored.
        if ip and device.googlecast_info is None:
            has_cast = False
            for st in device.mdns_service_types or []:
                if st and "_googlecast._tcp" in st:
                    has_cast = True
                    break
            if has_cast:
                _append_debug_text(_cast_debug_name(ip, "attempt"), "Attempting Cast info fetch\n")
                info = _try_googlecast_info(ip, device.mdns_srv)
                if info:
                    device.googlecast_info = info
                else:
                    _append_debug_text(_cast_debug_name(ip, "error"), "Cast fetch returned no data\n")

        # Use one timestamp so device fields stay consistent.
        now = _utcnow()
        device.last_seen = now
        device.ip = ip
        device.hostname = hostname

        return device

    def do_scan() -> bool:
        if not app.state.scan_lock.acquire(blocking=False):
            return False

        try:
            app.state.scan_state["running"] = True
            app.state.scan_state["last_error"] = None
            app.state.scan_state["last_started"] = _utcnow()
            app.state.scan_state["last_macless_hosts"] = []

            scan_tag = _utcnow().strftime("%Y%m%d-%H%M%S")

            db = SessionLocal()
            try:
                mdns_by_ip: dict[str, dict[str, object]] = {}
                if settings.enable_mdns:
                    # Allow monkeypatching via module attribute in tests.
                    collect_fn = getattr(sys.modules[__name__], "collect_mdns_signals", collect_mdns_signals)
                    data = collect_fn(timeout_seconds=6)
                    if isinstance(data, dict):
                        mdns_by_ip = data
                _write_debug_json(f"{scan_tag}-mdns.json", mdns_by_ip)

                scan_summary = {
                    "cidrs": settings.cidr_list(),
                    "nmap_hosts": {},
                    "devices_upserted": 0,
                    "macless_hosts": [],
                }
                for cidr in settings.cidr_list():
                    hosts = run_nmap_discovery(cidr)

                    # Debug: write the parsed nmap results (hosts list). Raw nmap XML is not available here
                    # without enhancing `scanner.py` to return stdout; this still helps diagnose "missing" devices.
                    safe_cidr = cidr.replace("/", "_").replace(":", "-")
                    _write_debug_json(
                        f"{scan_tag}-nmap-{safe_cidr}.json",
                        [
                            {"ip": h.ip, "hostname": h.hostname, "mac": h.mac, "vendor": h.vendor}
                            for h in hosts
                        ],
                    )
                    scan_summary["nmap_hosts"][cidr] = len(hosts)

                    for h in hosts:
                        normalized_mac = _normalize_mac(h.mac)
                        if not normalized_mac:
                            mdns = mdns_by_ip.get(h.ip, {})
                            scan_summary["macless_hosts"].append(
                                {
                                    "ip": h.ip,
                                    "hostname": h.hostname,
                                    "vendor": h.vendor,
                                    "mdns_name": mdns.get("best_name"),
                                }
                            )
                            continue

                        upsert_device_and_observation(
                            db,
                            h.ip,
                            h.hostname,
                            normalized_mac,
                            h.vendor,
                            mdns=mdns_by_ip.get(h.ip),
                        )
                        scan_summary["devices_upserted"] += 1
                db.commit()
                _write_debug_json(f"{scan_tag}-summary.json", scan_summary)
                # Keep a lightweight record of mac-less hosts in memory for visibility via /scan/status
                app.state.scan_state["last_macless_hosts"] = scan_summary["macless_hosts"]
            finally:
                db.close()

            app.state.scan_state["last_finished"] = _utcnow()
        except Exception as e:
            app.state.scan_state["last_error"] = str(e)
            _write_debug_text(f"{_utcnow().strftime('%Y%m%d-%H%M%S')}-error.txt", str(e))
        finally:
            app.state.scan_state["running"] = False
            app.state.scan_lock.release()

        return True

    @app.post("/scan")
    def trigger_scan(sync: bool = Query(False)):
        if sync:
            if app.state.background_scanner_enabled:
                raise HTTPException(
                    status_code=409,
                    detail="Sync scan not allowed while background scanner is enabled",
                )

            ran = do_scan()
            if not ran:
                raise HTTPException(status_code=409, detail="Scan already running")
            return {"ok": True, "mode": "sync"}

        # Refuse to launch another async scan if one is already running.
        if not app.state.scan_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="Scan already running")
        # Release immediately; the background thread will acquire before scanning.
        app.state.scan_lock.release()

        threading.Thread(target=do_scan, daemon=True).start()
        return {"ok": True, "mode": "async"}

    @app.get("/scan/status")
    def scan_status():
        st = app.state.scan_state
        return {
            "running": st["running"],
            "last_started": _dt_iso(st["last_started"]),
            "last_finished": _dt_iso(st["last_finished"]),
            "last_error": st["last_error"],
            "macless_hosts": st.get("last_macless_hosts", []),
        }

    @app.get("/devices")
    def list_devices(db: Session = Depends(get_db), limit: int | None = None):
        return _serialize_devices(db, limit=limit)

    @app.get("/devices/{device_id}")
    def device_detail(device_id: int, db: Session = Depends(get_db)):
        d = db.scalar(select(Device).where(Device.id == device_id))
        if not d:
            raise HTTPException(status_code=404, detail="device not found")

        return {
            "id": d.id,
            "mac": d.mac,
            "vendor": d.vendor,
            "ip": d.ip,
            "hostname": d.hostname,
            "device_name": d.device_name,
            "friendly_name": d.friendly_name,
            "display_name": d.display_name,
            "mdns_name": d.mdns_name,
            "mdns_srv": d.mdns_srv,
            "mdns_service_types": d.mdns_service_types,
            "mdns_instances": d.mdns_instances,
            "mdns_txt": d.mdns_txt,
            "first_seen": _dt_iso(d.first_seen),
            "last_seen": _dt_iso(d.last_seen),
            "googlecast_info": d.googlecast_info,
        }

    @app.get("/ui/devices", response_class=HTMLResponse)
    def ui_devices(request: Request, db: Session = Depends(get_db), limit: int | None = None, partial: bool = False):
        devices = _serialize_devices(db, limit=limit)
        total_devices = db.scalar(select(func.count()).select_from(Device))
        st = app.state.scan_state
        scan_status = {
            "running": bool(st.get("running")),
            "last_started": _dt_iso(st.get("last_started")),
            "last_finished": _dt_iso(st.get("last_finished")),
            "last_error": st.get("last_error"),
        }
        template_name = "devices_table.html" if partial else "devices.html"
        return templates.TemplateResponse(
            template_name,
            {
                "request": request,
                "devices": devices,
                "limit": limit,
                "count": len(devices),
                "total": total_devices or 0,
                "title": "Devices",
                "scan_status": scan_status,
                "service_labels": SERVICE_LABELS,
            },
        )

    return app


# Default app instance for uvicorn/docker: `uvicorn app.main:app`
_is_pytest = ("pytest" in sys.modules) or ("PYTEST_CURRENT_TEST" in os.environ)
if _is_pytest:
    app = create_app(
        start_scanner=False,
        db_url=os.getenv("INVENTORY_DB_URL", "sqlite+pysqlite:///:memory:"),
    )
else:
    app = create_app()
