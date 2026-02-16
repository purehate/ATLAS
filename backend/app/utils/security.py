from __future__ import annotations

from typing import Optional

import redis.asyncio as redis
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext

from config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBasic()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)


async def verify_admin(credentials: HTTPBasicCredentials = Security(security)):
    """Verify admin credentials"""
    if credentials.username != settings.admin_username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    # In production, hash and compare. For MVP, simple comparison
    if credentials.password != settings.admin_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username


class RateLimiter:
    """Simple rate limiter using Redis"""

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    async def check_rate_limit(
        self, key: str, limit: int, window_seconds: int = 3600
    ) -> tuple[bool, Optional[int]]:
        """
        Check if request is within rate limit
        Returns: (is_allowed, remaining_requests)
        """
        try:
            current = await self.redis.get(key)
            if current is None:
                await self.redis.setex(key, window_seconds, 1)
                return True, limit - 1

            current_count = int(current)
            if current_count >= limit:
                return False, 0

            await self.redis.incr(key)
            return True, limit - current_count - 1
        except Exception:
            # If Redis is down, allow request (fail open)
            return True, None


async def get_rate_limiter() -> RateLimiter:
    """Get rate limiter instance"""
    redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    return RateLimiter(redis_client)
