from sqlalchemy import String, Integer, DateTime, ForeignKey, UniqueConstraint, func, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base
from datetime import datetime

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mac: Mapped[str | None] = mapped_column(String, index=True)      # stable identity when available
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    display_name: Mapped[str | None] = mapped_column(String, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Last-known mDNS identity/type signals (best-effort, derived during scans).
    # These are stored on Device (not Observation) to avoid duplicating large blobs per scan.
    mdns_name: Mapped[str | None] = mapped_column(String, nullable=True)
    mdns_service_types: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    mdns_instances: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    mdns_txt: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)

    observations: Mapped[list["Observation"]] = relationship(back_populates="device", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("mac", name="uq_devices_mac"),
    )

class Observation(Base):
    __tablename__ = "observations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    ip: Mapped[str | None] = mapped_column(String, index=True)
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)

    device: Mapped["Device"] = relationship(back_populates="observations")