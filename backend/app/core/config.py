from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "ViperV2 Network Scanner"
    VERSION: str = "2.0.0"
    DEBUG: bool = True

    DATABASE_URL: str = "sqlite:///./viperv2.db"

    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    SCAN_TIMEOUT: int = 300
    ARP_TIMEOUT: float = 3.0
    PORT_SCAN_RANGE: str = "1-1024"
    NMAP_ARGUMENTS: str = "-sV -O --host-timeout 60s -T4"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
