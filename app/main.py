from fastapi import FastAPI, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import select, desc
import threading
import time

from .db import make_engine, make_sessionmaker, Base
from .models import Device, Observation
from .config import settings
from .scanner import run_nmap_discovery


def create_app(*, start_scanner: bool = True, db_url: str | None = None) -> FastAPI:
    """
    App factory:
      - Creates engine/sessionmaker
      - Creates tables
      - Optionally starts the scan loop (disable in tests)
    """
    app = FastAPI(title="Home Net Inventory")

    resolved_url = db_url or settings.resolved_db_url()
    engine = make_engine(resolved_url)
    SessionLocal = make_sessionmaker(engine)

    Base.metadata.create_all(bind=engine)

    # Per-app state (important for tests and avoiding module-level globals)
    app.state.engine = engine
    app.state.SessionLocal = SessionLocal
    app.state.scan_lock = threading.Lock()
    app.state.scan_state = {"running": False, "last_started": None, "last_finished": None, "last_error": None}

    def get_db(request: Request):
        db = request.app.state.SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def upsert_device_and_observation(db: Session, ip: str, hostname: str | None, mac: str | None, vendor: str | None):
        device = None

        if mac:
            device = db.scalar(select(Device).where(Device.mac == mac))

        if device is None:
            device = Device(mac=mac, vendor=vendor)
            db.add(device)
            db.flush()

        if vendor and not device.vendor:
            device.vendor = vendor

        obs = Observation(device_id=device.id, ip=ip, hostname=hostname)
        db.add(obs)
        return device

    def do_scan():
        if not app.state.scan_lock.acquire(blocking=False):
            return

        try:
            app.state.scan_state["running"] = True
            app.state.scan_state["last_error"] = None
            app.state.scan_state["last_started"] = time.time()

            db = SessionLocal()
            try:
                for cidr in settings.cidr_list():
                    hosts = run_nmap_discovery(cidr)
                    for h in hosts:
                        upsert_device_and_observation(db, h.ip, h.hostname, h.mac, h.vendor)
                db.commit()
            finally:
                db.close()

            app.state.scan_state["last_finished"] = time.time()
        except Exception as e:
            app.state.scan_state["last_error"] = str(e)
        finally:
            app.state.scan_state["running"] = False
            app.state.scan_lock.release()

    def scan_loop():
        while True:
            do_scan()
            time.sleep(settings.scan_interval_seconds)

    @app.on_event("startup")
    def startup():
        if start_scanner:
            t = threading.Thread(target=scan_loop, daemon=True)
            t.start()

    @app.post("/scan")
    def trigger_scan():
        threading.Thread(target=do_scan, daemon=True).start()
        return {"ok": True}

    @app.get("/scan/status")
    def scan_status():
        return app.state.scan_state

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
            out.append({
                "id": d.id,
                "mac": d.mac,
                "vendor": d.vendor,
                "display_name": d.display_name,
                "first_seen": str(d.first_seen),
                "last_seen": str(d.last_seen),
                "last_ip": last_obs.ip if last_obs else None,
                "last_hostname": last_obs.hostname if last_obs else None,
            })
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
            "display_name": d.display_name,
            "first_seen": str(d.first_seen),
            "last_seen": str(d.last_seen),
            "observations": [
                {"seen_at": str(o.seen_at), "ip": o.ip, "hostname": o.hostname}
                for o in obs
            ]
        }

    return app


# Default app instance for uvicorn/docker: `uvicorn app.main:app`
app = create_app()