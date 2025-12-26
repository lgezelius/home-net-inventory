from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Existing behavior: a filesystem path for SQLite
    db_path: str = Field(default="/data/inventory.db", alias="INVENTORY_DB")

    # New: allow a full SQLAlchemy URL override (used by tests)
    # Example: sqlite+pysqlite:///:memory:
    db_url: str | None = Field(default=None, alias="INVENTORY_DB_URL")

    scan_cidrs: str = Field(default="192.168.1.0/24", alias="INVENTORY_SCAN_CIDRS")
    scan_interval_seconds: int = Field(default=1800, alias="INVENTORY_SCAN_INTERVAL_SECONDS")
    nmap_args: str = Field(default="-sn", alias="INVENTORY_NMAP_ARGS")
    enable_mdns: bool = True
    enable_debug_logs: bool = False
    debug_dir: str = "/data/debug"

    def cidr_list(self) -> list[str]:
        return [c.strip() for c in self.scan_cidrs.split(",") if c.strip()]

    def resolved_db_url(self) -> str:
        # Prefer explicit URL if provided, otherwise build from path.
        if self.db_url:
            return self.db_url
        return f"sqlite+pysqlite:///{self.db_path}"


settings = Settings()