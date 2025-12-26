from fastapi import FastAPI, HTTPException, Request, Query, Depends
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
from sqlalchemy import select, desc
import threading
import time
import os
import sys
import re
from datetime import datetime, timezone
import json
import pathlib

from .db import make_engine, make_sessionmaker, Base
from .models import Device, Observation
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


    def _write_debug_json(filename: str, payload: object) -> None:
        if not _debug_enabled():
            return
        d = _debug_path()
        d.mkdir(parents=True, exist_ok=True)
        (d / filename).write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )

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

    def _mdns_device_and_friendly(txt: dict[str, str] | None, best_name: str | None) -> tuple[str | None, str | None]:
        """Derive model-like and friendly names from TXT/best_name."""
        if not isinstance(txt, dict):
            txt = {}
        model = txt.get("md") or txt.get("model") or best_name
        friendly = txt.get("fn") or txt.get("name")
        model = model.strip() if isinstance(model, str) and model.strip() else None
        friendly = friendly.strip() if isinstance(friendly, str) and friendly.strip() else None
        return model, friendly

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

        Returns a mapping: ip -> {"hostname": str|None, "service_types": list[str], "instances": list[str], "txt": dict[str,str]}
        """

        # High-signal service types for identification on typical home networks.
        service_types = [
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
        ]

        zc = Zeroconf()
        results: dict[str, dict[str, object]] = {}

        def upsert_ip(ip: str) -> dict[str, object]:
            if ip not in results:
                results[ip] = {"hostname": None, "service_types": [], "instances": [], "txt": {}}
            return results[ip]

        class Listener:
            def add_service(self, zc_obj, service_type: str, name: str):
                info = zc_obj.get_service_info(service_type, name, timeout=1500)
                if not info:
                    return

                # Prefer IPv4; keep IPv6-host-only data out for now.
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

            if friendly_name and not device.friendly_name:
                device.friendly_name = friendly_name

            # Keep display_name synced to best available signal (friendly > model > mdns best).
            preferred_display = friendly_name or model_name or (best_name if isinstance(best_name, str) else None)
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

        # Use one timestamp for both the observation and the device so they stay consistent.
        now = _utcnow()

        obs = Observation(device_id=device.id, ip=ip, hostname=hostname, seen_at=now)
        db.add(obs)

        # Ensure Device.last_seen advances whenever we record a new observation.
        device.last_seen = now

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
                mdns_by_ip = collect_mdns_signals(timeout_seconds=6) if settings.enable_mdns else {}
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
    def list_devices(db: Session = Depends(get_db), limit: int = 200):
        devices = db.scalars(select(Device).order_by(desc(Device.last_seen)).limit(limit)).all()
        out = []
        for d in devices:
            last_obs = db.scalar(
                select(Observation)
                .where(Observation.device_id == d.id)
                .order_by(desc(Observation.seen_at))
                .limit(1)
            )
            out.append(
                {
                    "id": d.id,
                    "mac": d.mac,
                    "vendor": d.vendor,
                    "device_name": d.device_name,
                    "friendly_name": d.friendly_name,
                    "display_name": d.display_name,
                    "mdns_name": d.mdns_name,
                    "mdns_service_types": d.mdns_service_types,
                    "mdns_instances": d.mdns_instances,
                    "mdns_txt": d.mdns_txt,
                    "first_seen": _dt_iso(d.first_seen),
                    "last_seen": _dt_iso(d.last_seen),
                    "last_ip": last_obs.ip if last_obs else None,
                    "last_hostname": last_obs.hostname if last_obs else None,
                }
            )
        return out

    @app.get("/devices/{device_id}")
    def device_detail(device_id: int, db: Session = Depends(get_db)):
        d = db.scalar(select(Device).where(Device.id == device_id))
        if not d:
            raise HTTPException(status_code=404, detail="device not found")

        obs = db.scalars(
            select(Observation)
            .where(Observation.device_id == device_id)
            .order_by(desc(Observation.seen_at))
            .limit(200)
        ).all()

        return {
            "id": d.id,
            "mac": d.mac,
            "vendor": d.vendor,
            "device_name": d.device_name,
            "friendly_name": d.friendly_name,
            "display_name": d.display_name,
            "mdns_name": d.mdns_name,
            "mdns_service_types": d.mdns_service_types,
            "mdns_instances": d.mdns_instances,
            "mdns_txt": d.mdns_txt,
            "first_seen": _dt_iso(d.first_seen),
            "last_seen": _dt_iso(d.last_seen),
            "observations": [{"seen_at": _dt_iso(o.seen_at), "ip": o.ip, "hostname": o.hostname} for o in obs],
        }

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
