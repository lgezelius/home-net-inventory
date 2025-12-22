from sqlalchemy import String, Integer, DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mac: Mapped[str | None] = mapped_column(String, index=True)      # stable identity when available
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    display_name: Mapped[str | None] = mapped_column(String, nullable=True)
    first_seen: Mapped[str] = mapped_column(DateTime, server_default=func.now())
    last_seen: Mapped[str] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    observations: Mapped[list["Observation"]] = relationship(back_populates="device", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("mac", name="uq_devices_mac"),
    )

class Observation(Base):
    __tablename__ = "observations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    seen_at: Mapped[str] = mapped_column(DateTime, server_default=func.now(), index=True)

    ip: Mapped[str | None] = mapped_column(String, index=True)
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)

    device: Mapped["Device"] = relationship(back_populates="observations")