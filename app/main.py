from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select, desc
import threading
import time

from .db import SessionLocal, engine, Base
from .models import Device, Observation
from .config import settings
from .scanner import run_nmap_discovery

app = FastAPI(title="Home Net Inventory")

Base.metadata.create_all(bind=engine)

_scan_lock = threading.Lock()
_scan_state = {"running": False, "last_started": None, "last_finished": None, "last_error": None}

def get_db():
    db = SessionLocal()
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

    # update vendor if we learned it later
    if vendor and not device.vendor:
        device.vendor = vendor

    obs = Observation(device_id=device.id, ip=ip, hostname=hostname)
    db.add(obs)
    device.last_seen  # touch on update
    return device

def do_scan():
    if not _scan_lock.acquire(blocking=False):
        return  # already scanning

    try:
        _scan_state["running"] = True
        _scan_state["last_error"] = None
        _scan_state["last_started"] = time.time()

        db = SessionLocal()
        try:
            for cidr in settings.cidr_list():
                hosts = run_nmap_discovery(cidr)
                for h in hosts:
                    upsert_device_and_observation(db, h.ip, h.hostname, h.mac, h.vendor)
            db.commit()
        finally:
            db.close()

        _scan_state["last_finished"] = time.time()
    except Exception as e:
        _scan_state["last_error"] = str(e)
    finally:
        _scan_state["running"] = False
        _scan_lock.release()

def scan_loop():
    # background scan loop inside the container
    while True:
        do_scan()
        time.sleep(settings.scan_interval_seconds)

@app.on_event("startup")
def startup():
    t = threading.Thread(target=scan_loop, daemon=True)
    t.start()

@app.post("/scan")
def trigger_scan():
    threading.Thread(target=do_scan, daemon=True).start()
    return {"ok": True}

@app.get("/scan/status")
def scan_status():
    return _scan_state

@app.get("/devices")
def list_devices(db: Session = Depends(get_db), limit: int = 200):
    # latest observation per device (simple approach: query per device)
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