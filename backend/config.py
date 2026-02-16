from __future__ import annotations

import os
from urllib.parse import quote, unquote, urlparse, urlunparse

from pydantic import field_validator
from pydantic_settings import BaseSettings


def fix_database_url(url: str) -> str:
    """Fix database URL by properly encoding password with special characters"""
    try:
        parsed = urlparse(url)
        if "@" in parsed.netloc and ":" in parsed.netloc:
            # Split into auth and host:port
            auth, hostport = parsed.netloc.rsplit("@", 1)
            if ":" in auth:
                user, password = auth.split(":", 1)
                # Check if password needs encoding (contains unencoded special chars)
                # If password already has % encoding, don't double-encode
                try:
                    decoded = unquote(password)
                    # If decoding changes it, it was already encoded
                    if decoded != password:
                        # Already encoded, use as-is
                        encoded_password = password
                    else:
                        # Not encoded, encode it
                        encoded_password = quote(password, safe="")
                except ValueError:
                    # If unquote fails, just encode it
                    encoded_password = quote(password, safe="")

                fixed_netloc = f"{user}:{encoded_password}@{hostport}"
                return urlunparse(parsed._replace(netloc=fixed_netloc))
    except Exception:
        # If parsing fails, return original
        pass
    return url


class Settings(BaseSettings):
    # Database
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://threatcalc:changeme@localhost:5432/threatcalc",
    )

    @field_validator("database_url", mode="before")
    @classmethod
    def fix_url(cls, v: str) -> str:
        """Fix database URL by properly encoding password with special characters"""
        if isinstance(v, str):
            return fix_database_url(v)
        return v

    # Redis
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Security
    secret_key: str = os.getenv("SECRET_KEY", "changeme_generate_strong_secret_key")
    admin_username: str = os.getenv("ADMIN_USERNAME", "admin")
    admin_password: str = os.getenv("ADMIN_PASSWORD", "changeme")

    # Rate Limiting
    api_rate_limit_per_hour: int = 100
    admin_rate_limit_per_hour: int = 1000

    # Ingestion Schedule
    ingestion_schedule_hour: int = 2
    score_recalculation_schedule_hour: int = 3

    # Source Reliability Scores (1-10)
    source_reliability_mitre: int = 10
    source_reliability_cisa: int = 9
    source_reliability_fbi: int = 8
    source_reliability_public_reports: int = 7
    source_reliability_scraped: int = 6

    # Scoring Algorithm
    recency_decay_factor: float = 0.5
    industry_match_bonus: float = 1.5

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
