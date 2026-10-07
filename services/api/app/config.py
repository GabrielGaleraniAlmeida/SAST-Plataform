"""Application settings, loaded from environment variables (or .env)."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore")

    APP_NAME: str = "SAST Platform API"
    DEBUG: bool = False
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    DATABASE_URL: str = "postgresql+asyncpg://sast_user:sast_pass@localhost:5432/sast_db"
    REDIS_URL: str = "redis://localhost:6379/0"

    ANALYZER_URL: str = "http://analyzer:8001"
    ANALYZER_TIMEOUT: int = 600

    AI_URL: str = "http://ai:8001"
    AI_TIMEOUT: int = 600


settings: Settings = Settings()
