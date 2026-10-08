from pathlib import Path
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/ directory — the SQLite file and the .env file live here
_BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """Application settings, read from environment variables or backend/.env.

    See backend/.env.example for a documented template.
    """

    APP_NAME: str = "ViperV2 Network Scanner"
    VERSION: str = "2.0.0"

    # Database (SQLite)
    DATABASE_URL: str = f"sqlite:///{_BASE_DIR / 'viperv2.db'}"

    # Security — JWT_SECRET is required and has no default: the app refuses to
    # start without it, so it can never run with a publicly known key.
    JWT_SECRET: str = Field(min_length=32)
    JWT_EXPIRATION_HOURS: int = Field(default=8, ge=1, le=24)

    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:4173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    # NVD API (optional key: raises the rate limit from 5 to 50 requests / 30 s)
    NVD_API_KEY: str = ""
    CVE_CACHE_TTL: int = 3600

    # Attack graph
    MAX_ATTACK_PATHS: int = 30
    MAX_ATTACK_HOPS: int = 6

    # Absolute path so the .env file is found whatever the working directory
    model_config = SettingsConfigDict(env_file=_BASE_DIR / ".env", extra="ignore")


settings = Settings()
