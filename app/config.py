from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    db_path: str = Field(default="/data/inventory.db", alias="INVENTORY_DB")
    scan_cidrs: str = Field(default="192.168.1.0/24", alias="INVENTORY_SCAN_CIDRS")
    scan_interval_seconds: int = Field(default=1800, alias="INVENTORY_SCAN_INTERVAL_SECONDS")
    nmap_args: str = Field(default="-sn", alias="INVENTORY_NMAP_ARGS")

    def cidr_list(self) -> list[str]:
        return [c.strip() for c in self.scan_cidrs.split(",") if c.strip()]

settings = Settings()