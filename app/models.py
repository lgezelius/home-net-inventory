from sqlalchemy import String, Integer, DateTime, ForeignKey, UniqueConstraint, func, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base
from datetime import datetime

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mac: Mapped[str | None] = mapped_column(String, index=True)      # stable identity when available
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    ip: Mapped[str | None] = mapped_column(String, index=True)
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)
    device_name: Mapped[str | None] = mapped_column(String, nullable=True)    # model-like name (e.g., "Google Home Mini")
    friendly_name: Mapped[str | None] = mapped_column(String, nullable=True)  # user-friendly name (e.g., "Dawn's Study Speaker")
    display_name: Mapped[str | None] = mapped_column(String, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Last-known mDNS identity/type signals (best-effort, derived during scans).
    # These are stored on Device (not Observation) to avoid duplicating large blobs per scan.
    mdns_name: Mapped[str | None] = mapped_column(String, nullable=True)
    mdns_service_types: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    mdns_instances: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    mdns_txt: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)
    mdns_srv: Mapped[list[dict[str, object]] | None] = mapped_column(JSON, nullable=True)  # SRV targets/ports per instance

    __table_args__ = (
        UniqueConstraint("mac", name="uq_devices_mac"),
    )
