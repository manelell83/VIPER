from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List

# Absolute path so SQLite is always created next to the backend package
_BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    APP_NAME: str = "ViperV2 Network Scanner"
    VERSION: str = "2.0.0"
    DEBUG: bool = Field(default=False)

    DATABASE_URL: str = f"sqlite:///{_BASE_DIR / 'viperv2.db'}"

    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:4173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    SCAN_TIMEOUT: int = 300
    ARP_TIMEOUT: float = 3.0
    PORT_SCAN_RANGE: str = "1-1024"
    NMAP_ARGUMENTS: str = "-sV -O --host-timeout 60s -T4"

    NVD_API_KEY: str = ""
    CVE_CACHE_TTL: int = 3600
    VULN_SCAN_ENABLED: bool = True

    MAX_ATTACK_PATHS: int = 30
    MAX_ATTACK_HOPS: int = 6

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
